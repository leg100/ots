package agent

import (
	"context"
	"fmt"
	"slices"

	"github.com/leg100/otf/internal/pubsub"
	"github.com/leg100/otf/internal/workspace"
)

// AllocatorLockID guarantees only one allocator on a cluster is running at any
// time.
const AllocatorLockID int64 = 5577006791947779412

// allocator allocates jobs to agents. Only one allocator must be active on
// an OTF cluster at any one time.
type allocator struct {
	// Subscriber for receiving stream of job and agent events
	pubsub.Subscriber
	// service for seeding allocator with pools, agents, and jobs, and for
	// allocating jobs to agents.
	*service
	// cache of agent pools
	pools map[string]*Pool
	// agents to allocate jobs to, keyed by agent ID
	agents map[string]*Agent
	// jobs awaiting allocation to an agent, keyed by job ID
	jobs map[JobSpec]*Job
	// capacities keeps track of the number of available workers each agent has,
	// keyed by agentID
	capacities map[string]int
}

// Start the allocator. Should be invoked in a go routine.
func (a *allocator) Start(ctx context.Context) error {
	// Subscribe to job and agent events and unsubscribe before returning.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sub, err := a.Subscribe(ctx, "job-allocator-")
	if err != nil {
		return err
	}
	// seed allocator with pools, agents, capacities, and jobs
	pools, err := a.listAgentPools(ctx, listPoolOptions{})
	if err != nil {
		return err
	}
	agents, err := a.listAgents(ctx)
	if err != nil {
		return err
	}
	jobs, err := a.listJobs(ctx)
	if err != nil {
		return err
	}
	a.pools = make(map[string]*Pool, len(pools))
	for _, pool := range pools {
		a.pools[pool.ID] = pool
	}
	a.agents = make(map[string]*Agent, len(agents))
	a.capacities = make(map[string]int, len(agents))
	for _, agent := range agents {
		a.agents[agent.ID] = agent
		a.capacities[agent.ID] = agent.Concurrency
	}
	a.jobs = make(map[JobSpec]*Job, len(jobs))
	for _, job := range jobs {
		a.jobs[job.JobSpec] = job
	}
	// now seeding has finished, allocate jobs
	a.allocate(ctx)
	// consume events until subscriber channel is closed.
	for event := range sub {
		switch payload := event.Payload.(type) {
		case *Pool:
			switch event.Type {
			case pubsub.DeletedEvent:
				delete(a.pools, payload.ID)
			default:
				a.pools[payload.ID] = payload
			}
		case *Agent:
			switch event.Type {
			case pubsub.DeletedEvent:
				delete(a.agents, payload.ID)
				delete(a.capacities, payload.ID)
			default:
				if _, ok := a.agents[payload.ID]; !ok {
					// new agent, initialize its capacity
					a.capacities[payload.ID] = payload.Concurrency
				}
				a.agents[payload.ID] = payload
			}
		case *Job:
			switch event.Type {
			case pubsub.DeletedEvent:
				delete(a.jobs, payload.JobSpec)
			default:
				a.jobs[payload.JobSpec] = payload
			}
		}
		if err := a.allocate(ctx); err != nil {
			return err
		}
	}
	return pubsub.ErrSubscriptionTerminated
}

// allocate jobs to agents.
func (a *allocator) allocate(ctx context.Context) error {
	for _, job := range a.jobs {
		switch job.Status {
		case JobUnallocated:
			// allocate job to available agent
			if candidate, err := a.findCandidateAgent(job); err != nil {
				return err
			} else if candidate != nil {
				if err := a.allocateJob(ctx, candidate, job); err != nil {
					return err
				}
			}
		case JobAllocated:
			// check agent the job is allocated to, if the agent is no longer in a fit state then try to allocate job to another agent
			agent, ok := a.agents[*job.AgentID]
			if !ok {
				return fmt.Errorf("agent %s not found in cache", *job.AgentID)
			}
			if agent.Status == AgentIdle || agent.Status == AgentBusy {
				// agent still healthy, wait for agent to start job
				continue
			}
			// agent no longer healthy, try reallocating job to another agent
			if candidate, err := a.findCandidateAgent(job); err != nil {
				return err
			} else if candidate != nil {
				if err := a.reallocateJob(ctx, candidate, job); err != nil {
					return err
				}
			}
		case JobFinished, JobCanceled, JobErrored:
			// job has completed: remove and adjust agent capacity
			delete(a.jobs, job.JobSpec)
			a.capacities[*job.AgentID]++
		}
	}
	return nil
}

// findCandidateAgent finds a suitable candidate agent for executing a job.
func (a *allocator) findCandidateAgent(job *Job) (*Agent, error) {
	var candidates []*Agent
	for _, agent := range a.agents {
		if agent.Status != AgentIdle && agent.Status != AgentBusy {
			// skip agents that are not ready for jobs
			continue
		}
		// skip agents with insufficient capacity
		if a.capacities[agent.ID] == 0 {
			continue
		}
		switch job.ExecutionMode {
		case workspace.RemoteExecutionMode:
			// only server agents handle jobs with remote execution mode.
			if agent.IsServer() {
				candidates = append(candidates, agent)
			}
			continue
		case workspace.AgentExecutionMode:
			// only pool agents handle jobs with agent execution mode.
			if agent.IsServer() {
				continue
			}
			// pool agents belong to a pool.
			pool, ok := a.pools[*agent.AgentPoolID]
			if !ok {
				return nil, fmt.Errorf("missing cache entry for agent pool: %s", *agent.AgentPoolID)
			}
			if !slices.Contains(pool.AssignedWorkspaces, job.WorkspaceID) {
				// job's workspace is configured to use a different pool
				continue
			}
			candidates = append(candidates, agent)
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	// return agent that has most recently sent a ping
	slices.SortFunc(candidates, func(a, b *Agent) int {
		if a.LastPingAt.After(b.LastPingAt) {
			return 1
		} else {
			return 0
		}
	})
	return candidates[0], nil
}

func (a *allocator) allocateJob(ctx context.Context, agent *Agent, job *Job) error {
	allocated, err := a.service.allocateJob(ctx, job.JobSpec, agent.ID)
	if err != nil {
		return err
	}
	a.jobs[job.JobSpec] = allocated
	a.capacities[agent.ID]--
	return nil
}

func (a *allocator) reallocateJob(ctx context.Context, agent *Agent, job *Job) error {
	reallocated, err := a.service.reallocateJob(ctx, job.JobSpec, agent.ID)
	if err != nil {
		return err
	}
	a.jobs[job.JobSpec] = reallocated
	a.capacities[*job.AgentID]++
	a.capacities[agent.ID]--
	return nil
}
