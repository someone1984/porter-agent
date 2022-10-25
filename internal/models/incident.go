package models

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/porter-dev/porter-agent/api/server/types"
	"gorm.io/gorm"
)

type Incident struct {
	gorm.Model

	UniqueID string `gorm:"unique"`
	EventID  uint

	LastAlerted *time.Time
	LastSeen    *time.Time

	ResolvedTime       *time.Time
	ResolvedRetryCount uint

	IncidentStatus types.IncidentStatus

	ReleaseName      string
	ReleaseNamespace string
	ChartName        string

	InvolvedObjectKind      types.InvolvedObjectKind
	InvolvedObjectName      string
	InvolvedObjectNamespace string

	ShouldViewLogs bool

	PorterDocLink string

	Revision string

	Severity types.SeverityType

	Events []IncidentEvent
}

func NewIncident() *Incident {
	randStr, _ := GenerateRandomBytes(16)

	return &Incident{
		UniqueID: randStr,
	}
}

func (i *Incident) ToAPITypeMeta() *types.IncidentMeta {
	lastSeen := time.Now()
	lastSeenEvent := i.getLastSeenEvent()

	if lastSeenEvent != nil {
		lastSeen = *lastSeenEvent.LastSeen
	}

	return &types.IncidentMeta{
		ID:                      i.UniqueID,
		ReleaseName:             i.ReleaseName,
		ReleaseNamespace:        i.ReleaseNamespace,
		UpdatedAt:               i.UpdatedAt,
		CreatedAt:               i.CreatedAt,
		ChartName:               i.ChartName,
		Status:                  i.IncidentStatus,
		InvolvedObjectKind:      i.InvolvedObjectKind,
		InvolvedObjectName:      i.InvolvedObjectName,
		InvolvedObjectNamespace: i.InvolvedObjectNamespace,
		Severity:                i.Severity,
		LastSeen:                &lastSeen,
		Summary:                 i.toExternalSummary(),
		ShortSummary:            i.GetInternalSummary(),
		ShouldViewLogs:          i.ShouldViewLogs,
		Revision:                i.Revision,
		PorterDocLink:           i.PorterDocLink,
	}
}

func (i *Incident) ToAPIType() *types.Incident {
	incident := &types.Incident{
		IncidentMeta: i.ToAPITypeMeta(),
		Pods:         i.getUniquePods(),
	}

	incident.Detail = "The release failed"

	for _, e := range i.Events {
		if e.IsPrimaryCause {
			incident.Detail = e.Detail
			break
		}
	}

	return incident
}

func (i *Incident) GetInternalSummary() string {
	summary := "The release failed"

	for _, e := range i.Events {
		if e.IsPrimaryCause {
			summary = e.Summary
			break
		}
	}

	return summary
}

func (i *Incident) getLatestRevisionName() string {
	// we first look for revisions that can be parsed as an integer. if these exists, we
	// pick the greatest revision.
	currRevision := 0

	for _, e := range i.Events {
		if i, err := strconv.ParseInt(e.Revision, 10, 64); err == nil {
			if i >= int64(currRevision) {
				currRevision = int(i)
			}
		}
	}

	if currRevision != 0 {
		return fmt.Sprintf("%d", currRevision)
	}

	// next, we look for an event with the latest lastSeen time and pick the revision from that
	// event
	lastSeenEvent := i.getLastSeenEvent()

	if lastSeenEvent != nil {
		return lastSeenEvent.Revision
	}

	return ""
}

func (i *Incident) getLastSeenEvent() *IncidentEvent {
	if len(i.Events) > 0 {
		lastSeenEvent := i.Events[0]

		for _, e := range i.Events {
			if e.LastSeen.After(*lastSeenEvent.LastSeen) {
				lastSeenEvent = e
			}
		}

		return &lastSeenEvent
	}

	return nil
}

func (i *Incident) getUniquePods() []string {
	lastRevision := i.getLatestRevisionName()

	uniquePods := make(map[string]string, 0)

	for _, ev := range i.Events {
		if ev.Revision == lastRevision {
			uniquePods[ev.PodName] = ev.PodName
		}
	}

	res := make([]string, 0)

	for _, podName := range uniquePods {
		res = append(res, podName)
	}

	return res
}

func (i *Incident) toExternalSummary() string {
	uniquePods := i.getUniquePods()

	// if the incident is part of a deployment, we count the number of unique
	// pods involved and generate a message.
	if strings.ToLower(string(i.InvolvedObjectKind)) == "deployment" {
		if len(uniquePods) > 1 {
			if i.Severity == types.SeverityCritical {
				return fmt.Sprintf(
					"Your application %s in namespace %s is currently experiencing downtime. %d replicas are crashing because %s.",
					i.ReleaseName, i.ReleaseNamespace, len(uniquePods), strings.ToLower(i.GetInternalSummary()),
				)
			} else {
				return fmt.Sprintf(
					"%d replicas for the application %s in namespace %s have crashed because %s.",
					len(uniquePods), i.ReleaseName, i.ReleaseNamespace, strings.ToLower(i.GetInternalSummary()),
				)
			}
		} else {
			if i.Severity == types.SeverityCritical {
				return fmt.Sprintf(
					"Your application %s in namespace %s is currently experiencing downtime because %s.",
					i.ReleaseName, i.ReleaseNamespace, strings.ToLower(i.GetInternalSummary()),
				)
			} else {
				return fmt.Sprintf(
					"Your application %s in namespace %s has crashed because %s.",
					i.ReleaseName, i.ReleaseNamespace, strings.ToLower(i.GetInternalSummary()),
				)
			}
		}
	}

	// if the incident is part of a job, we indicate that this was part of a job run
	if strings.ToLower(string(i.InvolvedObjectKind)) == "job" {
		return fmt.Sprintf(
			"A job run for %s in namespace %s crashed because %s.",
			i.ReleaseName, i.ReleaseNamespace, strings.ToLower(i.GetInternalSummary()),
		)
	}

	// otherwise, we just incidate that a single replica failed
	return fmt.Sprintf(
		"Your application %s in namespace %s has crashed because %s.",
		i.ReleaseName, i.ReleaseNamespace, strings.ToLower(i.GetInternalSummary()),
	)
}
