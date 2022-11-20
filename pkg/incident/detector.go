package incident

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/porter-dev/porter-agent/api/server/types"
	"github.com/porter-dev/porter-agent/internal/logger"
	"github.com/porter-dev/porter-agent/internal/models"
	"github.com/porter-dev/porter-agent/internal/repository"
	"github.com/porter-dev/porter-agent/internal/utils"
	"github.com/porter-dev/porter-agent/pkg/alerter"
	"github.com/porter-dev/porter-agent/pkg/event"
	"gorm.io/gorm"
	"k8s.io/client-go/kubernetes"
)

type IncidentDetector struct {
	KubeClient  *kubernetes.Clientset
	KubeVersion KubernetesVersion
	EventStore  event.EventStore
	Repository  *repository.Repository
	Alerter     *alerter.Alerter
	Logger      *logger.Logger
}

// DetectIncident returns an incident if one should be triggered, if there is no incident it will return
// a nil incident and nil error message.
//
// It determines if an incident should be alerted based on the following algorithm:
// 1. What is the event type?
//  1. `Normal`: do not alert
//  2. `Critical`: 2
//
// 2. Did the event trigger a container restart or prevent the pod from starting up?
//  1. Yes: 3
//  2. No: do not alert
//
// 3a. (If Deployment) Are there more pods unavailable than the deployments `maxUnavailable` field permits?
//  1. Yes: 4
//  2. No: 5
//
// 3b. (If Job) Does the alerting threshold match configuration for this job?
//  1. Yes: 4
//  2. No: 5
//  4. Trigger an immediate alert and create a critical incident for the user.
//  5. Query for past events from this pod. If the event has been triggered a certain number of times
//     (configurable) in a certain time window (configurable), create a warning incident for the user.
func (d *IncidentDetector) DetectIncident(es []*event.FilteredEvent) error {
	alertedEvents := make([]*event.FilteredEvent, 0)

	for _, e := range es {
		// if the event severity is low, do not alert
		if e == nil || e.Severity == event.EventSeverityLow {
			continue
		}

		alertedEvents = append(alertedEvents, e)
	}

	if len(alertedEvents) == 0 {
		return nil
	}

	// at this point, populate the owner reference for the first alerted event - we assume that
	// all alerted events have the same owner
	err := alertedEvents[0].Populate(*d.KubeClient)

	if err != nil {
		d.Logger.Error().Caller().Msgf("could not populate alerted event: %v", err)
		return err
	}

	// populate all other alerted events with the same data
	for i := range alertedEvents {
		alertedEvents[i].Pod = alertedEvents[0].Pod
		alertedEvents[i].Owner = alertedEvents[0].Owner
		alertedEvents[i].ReleaseName = alertedEvents[0].ReleaseName
		alertedEvents[i].ChartName = alertedEvents[0].ChartName
		alertedEvents[i].ChartVersion = alertedEvents[0].ChartVersion
	}

	// get event matches
	matches := make(map[event.FilteredEvent]*EventMatch)

	for _, e := range alertedEvents {
		matchCandidate := GetEventMatchFromEvent(d.KubeVersion, d.KubeClient, e)

		// we only add match candidates which have a primary cause at the moment
		if matchCandidate != nil && matchCandidate.IsPrimaryCause {
			matches[*e] = matchCandidate
		}
	}

	// iterate through incident events
	for alertedEvent, match := range matches {
		// construct the basic incident event model
		incident := getIncidentMetaFromEvent(&alertedEvent, match)
		incident.Events = matchesToIncidentEvent(d.KubeVersion, map[event.FilteredEvent]*EventMatch{
			alertedEvent: match,
		})

		ownerRef := alertedEvent.Owner
		ownerKind := strings.ToLower(ownerRef.Kind)

		switch {
		case alertedEvent.Source == event.AlertManager:
			d.Logger.Info().Caller().Msgf("an alert is being fired for pod %s/%s, storing new incident", alertedEvent.PodNamespace, alertedEvent.PodName)
			switch alertedEvent.Severity {
			case event.EventSeverityCritical, event.EventSeverityHigh:
				incident.Severity = types.SeverityCritical
			default:
				incident.Severity = types.SeverityNormal
			}
			incident.InvolvedObjectKind = types.InvolvedObjectPod
			incident.InvolvedObjectName = alertedEvent.PodName
			incident.InvolvedObjectNamespace = alertedEvent.PodNamespace

			if err := d.saveIncident(incident, ownerRef, alertedEvent.PodName); err != nil {
				return err
			}
			continue
		case ownerKind == "deployment":
			d.Logger.Info().Caller().Msgf("determing if deployment %s is failing", ownerRef.Name)

			// if the deployment is in a failure state, create a high severity incident
			if isDeploymentFailing(d.KubeClient, ownerRef.Namespace, ownerRef.Name) {
				d.Logger.Info().Caller().Msgf("deployment %s/%s is failing, storing new incident", ownerRef.Namespace, ownerRef.Name)

				incident.Severity = types.SeverityCritical
				incident.InvolvedObjectKind = types.InvolvedObjectDeployment
				incident.InvolvedObjectName = ownerRef.Name
				incident.InvolvedObjectNamespace = ownerRef.Namespace

				err := d.saveIncident(incident, ownerRef, alertedEvent.PodName)

				if err != nil {
					return err
				}

				continue
			}
		case ownerKind == "job":
			d.Logger.Info().Caller().Msgf("job %s/%s is failing, storing new incident", ownerRef.Namespace, ownerRef.Name)

			incident.Severity = types.SeverityNormal
			incident.InvolvedObjectKind = types.InvolvedObjectJob
			incident.InvolvedObjectName = ownerRef.Name
			incident.InvolvedObjectNamespace = ownerRef.Namespace

			err := d.saveIncident(incident, ownerRef, alertedEvent.PodName)

			if err != nil {
				return err
			}

			continue
		}

		// if the controller cases did not match, we simply store a pod-based incident
		d.Logger.Info().Caller().Msgf("pod %s/%s is failing, storing new incident", alertedEvent.PodNamespace, alertedEvent.PodName)

		incident.Severity = types.SeverityNormal
		incident.InvolvedObjectKind = types.InvolvedObjectPod
		incident.InvolvedObjectName = alertedEvent.PodName
		incident.InvolvedObjectNamespace = alertedEvent.PodNamespace

		err := d.saveIncident(incident, ownerRef, alertedEvent.PodName)

		if err != nil {
			return err
		}
	}

	return nil
}

func (d *IncidentDetector) saveIncident(incident *models.Incident, ownerRef *event.EventOwner, triggeringPodName string) error {
	// if mergeWithMatchingIncident returns a non-nil incident, then we simply update the incident in the DB
	if mergedIncident := d.mergeWithMatchingIncident(incident, ownerRef); mergedIncident != nil {
		d.Logger.Info().Caller().Msgf("found matching incident %s", mergedIncident.UniqueID)

		incident, err := d.Repository.Incident.UpdateIncident(mergedIncident)

		if err != nil {
			return err
		}

		err = d.saveEventFromIncident(incident)

		if err != nil {
			return err
		}

		return d.Alerter.HandleIncident(incident, triggeringPodName)
	}

	d.Logger.Info().Caller().Msgf("creating new incident %s - %s of kind %s", incident.UniqueID, incident.InvolvedObjectName, incident.InvolvedObjectKind)

	incident, err := d.Repository.Incident.CreateIncident(incident)

	if err != nil {
		return err
	}

	err = d.saveEventFromIncident(incident)

	if err != nil {
		return err
	}

	return d.Alerter.HandleIncident(incident, triggeringPodName)
}

func (d *IncidentDetector) saveEventFromIncident(incident *models.Incident) error {
	// query to see if event is already stored
	var event *models.Event
	var doesExist bool
	var err error

	incidentBytes, err := json.Marshal(incident.ToAPIType())

	if err != nil {
		return err
	}

	if incident.EventID != 0 {
		event, err = d.Repository.Event.ReadEvent(incident.EventID)

		if err != nil && !errors.Is(gorm.ErrRecordNotFound, err) {
			return err
		}

		if event != nil {
			doesExist = true
		}
	}

	if !doesExist {
		event = models.NewIncidentEventV1()
	}

	event.ReleaseName = incident.ReleaseName
	event.ReleaseNamespace = incident.ReleaseNamespace
	event.Timestamp = incident.LastSeen
	event.Data = incidentBytes

	if strings.ToLower(string(incident.InvolvedObjectKind)) == "job" {
		event.AdditionalQueryMeta = fmt.Sprintf("job/%s", incident.InvolvedObjectName)
	}

	if doesExist {
		event, err = d.Repository.Event.UpdateEvent(event)
	} else {
		event, err = d.Repository.Event.CreateEvent(event)
	}

	if incident.EventID == 0 {
		incident.EventID = event.ID

		d.Repository.Incident.UpdateIncident(incident)
	}

	return err
}

func (d *IncidentDetector) mergeWithMatchingIncident(incident *models.Incident, ownerRef *event.EventOwner) *models.Incident {
	// we look for a matching incident - the matching incident should refer to the same
	// release name and namespace, should be active, and the incident event should have
	// a primary cause event with the same summary as the candidate incident.
	statusActive := types.IncidentStatusActive

	filter := &utils.ListIncidentsFilter{
		Status:           &statusActive,
		ReleaseName:      &incident.ReleaseName,
		ReleaseNamespace: &incident.ReleaseNamespace,
	}

	// we case on jobs differently - we only merge jobs with the same involved object name
	if strings.ToLower(string(incident.InvolvedObjectKind)) == "job" {
		kindFilter := string(incident.InvolvedObjectKind)

		filter.InvolvedObjectKind = &kindFilter
		filter.InvolvedObjectName = &incident.InvolvedObjectName
	}

	candidateMatches, _, err := d.Repository.Incident.ListIncidents(filter)

	if err != nil {
		return nil
	}

	d.Logger.Info().Caller().Msgf("found %d matching candidates for incident %s", len(candidateMatches), incident.UniqueID)

	var primaryCauseSummary string

	for _, currIncidentEvent := range incident.Events {
		if currIncidentEvent.IsPrimaryCause {
			primaryCauseSummary = currIncidentEvent.Summary
			break
		}
	}

	for _, candidateMatch := range candidateMatches {
		for _, candidateMatchEvent := range candidateMatch.Events {
			if candidateMatchEvent.IsPrimaryCause && candidateMatchEvent.Summary == primaryCauseSummary {
				// in this case, we've found a match, and we merge and return

				// take the greater of the last seen time
				if incident.LastSeen.After(*candidateMatch.LastSeen) {
					candidateMatch.LastSeen = incident.LastSeen
				}

				// if incident revision is greater than candidate revision, set candidate revision to incident revision
				revisionInt, revisionErr := strconv.ParseInt(incident.Revision, 10, 64)

				if revisionErr == nil {
					cRevisionInt, cRevisionErr := strconv.ParseInt(incident.Revision, 10, 64)

					if cRevisionErr != nil || revisionInt > cRevisionInt {
						candidateMatch.Revision = incident.Revision
					}
				}

				mergedEvents := mergeEvents(candidateMatch.Events, incident.Events)
				candidateMatch.Events = mergedEvents

				// if there are different pods listed in the events, we promote this to a "Deployment" or "Job" event
				if numDistinctPods(mergedEvents) > 1 {
					candidateMatch.InvolvedObjectKind = types.InvolvedObjectKind(ownerRef.Kind)
					candidateMatch.InvolvedObjectName = ownerRef.Name
					candidateMatch.InvolvedObjectNamespace = ownerRef.Namespace
				}

				return candidateMatch
			}
		}
	}

	return nil
}

func mergeEvents(events1, events2 []models.IncidentEvent) []models.IncidentEvent {
	// we construct a key for events1 by looking at the pod name, namespace, primary cause, and
	// summary fields
	keyMap := make(map[string]models.IncidentEvent)

	for _, e1 := range events1 {
		keyMap[fmt.Sprintf("%s/%s-%v-%s", e1.PodName, e1.PodNamespace, e1.IsPrimaryCause, e1.Summary)] = e1
	}

	// any matched events are updated, other events are appended
	for _, e2 := range events2 {
		key := fmt.Sprintf("%s/%s-%v-%s", e2.PodName, e2.PodNamespace, e2.IsPrimaryCause, e2.Summary)

		if e1, exists := keyMap[key]; exists {
			// take the later of the last seen times
			if e2.LastSeen.After(*e1.LastSeen) {
				e1.LastSeen = e2.LastSeen
			}

			e1.Detail = e2.Detail
		} else {
			keyMap[key] = e2
		}
	}

	res := make([]models.IncidentEvent, 0)

	for _, e := range keyMap {
		res = append(res, e)
	}

	return res
}

func numDistinctPods(events []models.IncidentEvent) int {
	podMap := make(map[string]string)

	for _, e := range events {
		key := fmt.Sprintf("%s/%s", e.PodNamespace, e.PodName)
		podMap[key] = key
	}

	return len(podMap)
}
