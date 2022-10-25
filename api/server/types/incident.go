package types

import "time"

type SeverityType string

const (
	SeverityCritical SeverityType = "critical"
	SeverityNormal   SeverityType = "normal"
)

type InvolvedObjectKind string

const (
	InvolvedObjectDeployment InvolvedObjectKind = "deployment"
	InvolvedObjectJob        InvolvedObjectKind = "job"
	InvolvedObjectPod        InvolvedObjectKind = "pod"
)

type IncidentStatus string

const (
	IncidentStatusResolved IncidentStatus = "resolved"
	IncidentStatusActive   IncidentStatus = "active"
)

type IncidentMeta struct {
	ID                      string             `json:"id" form:"required"`
	ReleaseName             string             `json:"release_name" form:"required"`
	ReleaseNamespace        string             `json:"release_namespace" form:"required"`
	ChartName               string             `json:"chart_name" form:"required"`
	CreatedAt               time.Time          `json:"created_at" form:"required"`
	UpdatedAt               time.Time          `json:"updated_at" form:"required"`
	LastSeen                *time.Time         `json:"last_seen" form:"required"`
	Status                  IncidentStatus     `json:"status" form:"required"`
	Summary                 string             `json:"summary" form:"required"`
	ShortSummary            string             `json:"short_summary"`
	Severity                SeverityType       `json:"severity" form:"required"`
	InvolvedObjectKind      InvolvedObjectKind `json:"involved_object_kind" form:"required"`
	InvolvedObjectName      string             `json:"involved_object_name" form:"required"`
	InvolvedObjectNamespace string             `json:"involved_object_namespace" form:"required"`
	ShouldViewLogs          bool               `json:"should_view_logs"`
	Revision                string             `json:"revision"`
	PorterDocLink           string             `json:"porter_doc_link"`
}

type PaginationRequest struct {
	Page int64 `schema:"page"`
}

type PaginationResponse struct {
	NumPages    int64 `json:"num_pages" form:"required"`
	CurrentPage int64 `json:"current_page" form:"required"`
	NextPage    int64 `json:"next_page" form:"required"`
}

type ListIncidentsRequest struct {
	*PaginationRequest
	Status           *IncidentStatus `schema:"status"`
	ReleaseName      *string         `schema:"release_name"`
	ReleaseNamespace *string         `schema:"release_namespace"`
}

type ListIncidentsResponse struct {
	Incidents  []*IncidentMeta     `json:"incidents" form:"required"`
	Pagination *PaginationResponse `json:"pagination"`
}

type Incident struct {
	*IncidentMeta
	Pods   []string `json:"pods" form:"required"`
	Detail string   `json:"detail" form:"required"`
}

type IncidentEvent struct {
	ID           string     `json:"id" form:"required"`
	LastSeen     *time.Time `json:"last_seen" form:"required"`
	PodName      string     `json:"pod_name" form:"required"`
	PodNamespace string     `json:"pod_namespace" form:"required"`
	Summary      string     `json:"summary" form:"required"`
	Detail       string     `json:"detail" form:"required"`
	Revision     string     `json:"revision"`
}

type ListIncidentEventsRequest struct {
	*PaginationRequest
	IncidentID   *string `schema:"incident_id"`
	PodName      *string `schema:"pod_name"`
	PodNamespace *string `schema:"pod_namespace"`
	Summary      *string `schema:"summary"`
	PodPrefix    *string `schema:"pod_prefix"`
}

type ListIncidentEventsResponse struct {
	Events     []*IncidentEvent    `json:"events" form:"required"`
	Pagination *PaginationResponse `json:"pagination"`
}
