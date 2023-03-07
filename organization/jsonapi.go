package organization

import (
	"github.com/leg100/otf"
	"github.com/leg100/otf/http/jsonapi"
)

func newFromJSONAPI(from jsonapi.Organization) *otf.Organization {
	return &otf.Organization{
		ID:              from.ExternalID,
		CreatedAt:       from.CreatedAt,
		Name:            from.Name,
		SessionRemember: from.SessionRemember,
		SessionTimeout:  from.SessionTimeout,
	}
}

// ToJSONAPI assembles a JSONAPI DTO
func toJSONAPI(org *otf.Organization) *jsonapi.Organization {
	return &jsonapi.Organization{
		Name:            org.Name,
		CreatedAt:       org.CreatedAt,
		ExternalID:      org.ID,
		Permissions:     &jsonapi.DefaultOrganizationPermissions,
		SessionRemember: org.SessionRemember,
		SessionTimeout:  org.SessionTimeout,
	}
}

// ToJSONAPI assembles a JSON-API DTO.
func listToJSONAPI(from *otf.OrganizationList) *jsonapi.OrganizationList {
	to := &jsonapi.OrganizationList{
		Pagination: from.Pagination.ToJSONAPI(),
	}
	for _, item := range from.Items {
		to.Items = append(to.Items, toJSONAPI(item))
	}
	return to
}