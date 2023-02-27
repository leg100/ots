package vcsprovider

import (
	"github.com/go-logr/logr"
	"github.com/leg100/otf"
	"github.com/leg100/otf/cloud"
)

type Service struct {
	application
	*web
}

func NewService(opts Options) *Service {
	app := &app{
		OrganizationAuthorizer: opts.OrganizationAuthorizer,
		db:                     newDB(opts.DB, opts.Service),
		factory: &factory{
			Service: opts.Service,
		},
		Logger: opts.Logger,
	}

	return &Service{
		application: app,
		web: &web{
			Renderer: opts.Renderer,
			app:      app,
		},
	}
}

type Options struct {
	otf.OrganizationAuthorizer
	cloud.Service
	otf.DB
	otf.Renderer
	logr.Logger
}
