package event

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/porter-dev/porter-agent/api/server/types"
	alertmanager "github.com/prometheus/alertmanager/notify/webhook"
)

type EventSeverity string

const (
	EventSeverityCritical EventSeverity = "critical"
	EventSeverityHigh     EventSeverity = "high"
	EventSeverityLow      EventSeverity = "low"
)

type EventSource string

const (
	Pod          EventSource = "pod"
	K8sEvent     EventSource = "event"
	AlertManager EventSource = "alert-manager"
)

type FilteredEvent struct {
	Source EventSource

	PodName      string
	PodNamespace string

	KubernetesReason  string
	KubernetesMessage string

	Severity EventSeverity

	Timestamp *time.Time

	// (optional) The exit code of the application, if applicable
	ExitCode uint

	// (optional) The pod config, if applicable or present
	// TODO
	Pod *v1.Pod

	// (optional) The owner data, if applicable or present
	Owner *EventOwner

	// (optional) The release data, if applicable or present
	ReleaseName  string
	ChartName    string
	ChartVersion string
}

type EventOwner struct {
	Namespace, Name, Kind, Revision string
}

// SetPodData is used to set the data for the pod directly. This is useful for cases where querying the
// live status of the pod via PopulatePodData may fail if the pod has been deleted.
func (e *FilteredEvent) SetPodData(pod *v1.Pod) {
	e.Pod = pod
}

func (e *FilteredEvent) PopulatePodData(k8sClient kubernetes.Clientset) error {
	if e.Pod != nil {
		return nil
	}

	pod, err := k8sClient.CoreV1().Pods(e.PodNamespace).Get(
		context.Background(),
		e.PodName,
		metav1.GetOptions{},
	)

	if err != nil {
		return err
	}

	e.Pod = pod
	return nil
}

func (e *FilteredEvent) PopulateEventOwner(k8sClient kubernetes.Clientset) error {
	if e.Owner != nil {
		return nil
	}

	// determine if pod is owned by a ReplicaSet or Job
	if e.Pod == nil {
		err := e.PopulatePodData(k8sClient)

		if err != nil {
			return err
		}
	}

	if len(e.Pod.OwnerReferences) != 1 {
		return fmt.Errorf("unable to populate event owner: pod has multiple owners")
	}

	// if pod has a revision annotation set, store the revision
	var revision string

	if rev, exists := e.Pod.Annotations["helm.sh/revision"]; exists {
		revision = rev
	}

	switch o := e.Pod.OwnerReferences[0]; strings.ToLower(o.Kind) {
	case "replicaset":
		rs, err := k8sClient.AppsV1().ReplicaSets(e.PodNamespace).Get(
			context.Background(),
			o.Name,
			metav1.GetOptions{},
		)

		if err != nil {
			return err
		}

		if len(rs.OwnerReferences) != 1 {
			return fmt.Errorf("unable to populate event owner: replicaset has multiple owners")
		}

		if strings.ToLower(rs.OwnerReferences[0].Kind) != "deployment" {
			return fmt.Errorf("only replicasets with deployment owners are supported")
		}

		if revision == "" {
			revision = rs.Name
		}

		e.Owner = &EventOwner{
			Namespace: e.PodNamespace,
			Name:      rs.OwnerReferences[0].Name,
			Kind:      string(types.InvolvedObjectDeployment),
			Revision:  revision,
		}

		return nil
	case "job":
		if revision == "" {
			revision = o.Name
		}

		e.Owner = &EventOwner{
			Namespace: e.PodNamespace,
			Name:      o.Name,
			Kind:      o.Kind,
			Revision:  revision,
		}

		return nil
	}

	return fmt.Errorf("unsupported owner reference kind")
}

func (e *FilteredEvent) Populate(k8sClient kubernetes.Clientset) error {
	// populate the event owner
	if err := e.PopulateEventOwner(k8sClient); err != nil {
		return err
	}

	e.ReleaseName = e.Pod.Labels["app.kubernetes.io/instance"]

	// query the owner reference to determine chart name
	var chartLabel string

	switch strings.ToLower(e.Owner.Kind) {
	case "deployment":
		depl, err := k8sClient.AppsV1().Deployments(e.Owner.Namespace).Get(
			context.Background(),
			e.Owner.Name,
			metav1.GetOptions{},
		)

		if err != nil {
			return err
		}

		chartLabel = depl.Labels["helm.sh/chart"]
	case "job":
		job, err := k8sClient.BatchV1().Jobs(e.Owner.Namespace).Get(
			context.Background(),
			e.Owner.Name,
			metav1.GetOptions{},
		)

		if err != nil {
			return err
		}

		// if the release name hasn't been populated, attempt to populate it from the job
		if e.ReleaseName == "" {
			e.ReleaseName = job.Labels["app.kubernetes.io/instance"]
		}

		chartLabel = job.Labels["helm.sh/chart"]
	}

	if spl := strings.Split(chartLabel, "-"); len(spl) == 2 {
		e.ChartName = spl[0]
		e.ChartVersion = spl[1]
	} else {
		e.ChartName = chartLabel
	}

	return nil
}

type EventStore interface {
	Store(e *FilteredEvent) error
	GetEventsByPodName(namespace, name string) *FilteredEvent
	GetEventsByOwner(owner *EventOwner) *FilteredEvent
}

func NewFilteredEventFromK8sEvent(k8sEvent *v1.Event) *FilteredEvent {
	var severity EventSeverity

	if k8sEvent.Type == "Normal" {
		severity = EventSeverityLow
	} else if k8sEvent.Type == "Warning" {
		severity = EventSeverityHigh
	}

	if k8sEvent.Reason == "Created" && strings.Contains(k8sEvent.Message, "Created container job") {
		return &FilteredEvent{
			Source:            K8sEvent,
			PodName:           k8sEvent.InvolvedObject.Name,
			PodNamespace:      k8sEvent.InvolvedObject.Namespace,
			KubernetesReason:  "Running",
			KubernetesMessage: k8sEvent.Message,
			Severity:          EventSeverityLow,
			Timestamp:         &k8sEvent.LastTimestamp.Time,
		}
	}

	return &FilteredEvent{
		Source:            K8sEvent,
		PodName:           k8sEvent.InvolvedObject.Name,
		PodNamespace:      k8sEvent.InvolvedObject.Namespace,
		KubernetesReason:  k8sEvent.Reason,
		KubernetesMessage: k8sEvent.Message,
		Severity:          severity,
		Timestamp:         &k8sEvent.LastTimestamp.Time,
	}
}

func NewFilteredEventsFromPod(pod *v1.Pod) []*FilteredEvent {
	res := make([]*FilteredEvent, 0)

	// if the pod has failed to get scheduled in over 15 minutes, we generate a high-severity event
	for _, condition := range pod.Status.Conditions {
		if condition.Type == "PodScheduled" && (condition.Status == v1.ConditionFalse || condition.Status == v1.ConditionUnknown) {
			now := time.Now()

			// check if the last transition time was before 15 minutes ago
			if condition.LastTransitionTime.Time.Before(now.Add(-15 * time.Minute)) {
				elapsedTime := now.Sub(condition.LastTransitionTime.Time)
				elapsedMinutes := elapsedTime.Truncate(time.Minute).Minutes()

				res = append(res, &FilteredEvent{
					Source:            Pod,
					PodName:           pod.Name,
					PodNamespace:      pod.Namespace,
					KubernetesReason:  "Pending",
					KubernetesMessage: fmt.Sprintf("Pod has been pending for %.0f minutes due to %s", elapsedMinutes, condition.Message),
					Severity:          EventSeverityHigh,
					Timestamp:         &now,
				})
			}
		}
	}

	isJob := len(pod.ObjectMeta.OwnerReferences) > 0 && pod.ObjectMeta.OwnerReferences[0].Kind == "Job"

	// if one or more containers failed to start, we generate a set of events
	for _, containerStatus := range pod.Status.ContainerStatuses {
		// if the pod's owner reference is a job and the container is sidecar, we ignore waiting and terminated conditions, as the sidecar
		// is treated as an optional process
		if isJob && containerStatus.Name == "sidecar" {
			continue
		}

		// if the container is currently in a waiting state, we check to see if the last state is terminated -
		// if so, we generate an event
		if waitingState := containerStatus.State.Waiting; waitingState != nil {
			// if the waiting state is an image error, we store this as an event as well
			if waitingState.Reason == "ImagePullBackOff" || waitingState.Reason == "ErrImagePull" || waitingState.Reason == "InvalidImageName" {
				now := time.Now()

				res = append(res, &FilteredEvent{
					Source:            Pod,
					PodName:           pod.Name,
					PodNamespace:      pod.Namespace,
					KubernetesReason:  waitingState.Reason,
					KubernetesMessage: waitingState.Message,
					Severity:          EventSeverityHigh,
					// If the image is currently in a waiting or image pull back off state, we want to alert on that
					// immediately. We also don't have a good reference time for when image pull back off started.
					Timestamp: &now,
				})
			}

			if lastTermState := containerStatus.LastTerminationState.Terminated; lastTermState != nil {
				// add the last termination state as an event if it was last terminated within 12 hours
				if e := getEventFromTerminationState(pod.Name, pod.Namespace, lastTermState); e != nil {
					res = append(res, e)
				}
			}
		} else if termState := containerStatus.State.Terminated; termState != nil {
			if e := getEventFromTerminationState(pod.Name, pod.Namespace, termState); e != nil {
				res = append(res, e)
			}
		}
	}

	// if the pod is owned by a job, we add low-severity filtered events to indicate when the job has started and
	// completed. These events will be de-duplicated by the caller.
	if isJob {
		for _, containerStatus := range pod.Status.ContainerStatuses {
			// we look explicitly for the `job` container
			if containerStatus.Name == "job" {
				if runningState := containerStatus.State.Running; runningState != nil {
					res = append(res, &FilteredEvent{
						Source:           Pod,
						PodName:          pod.Name,
						PodNamespace:     pod.Namespace,
						KubernetesReason: "Running",
						Severity:         EventSeverityLow,
						Timestamp:        &runningState.StartedAt.Time,
					})
				}

				if termState := containerStatus.State.Terminated; termState != nil {
					res = append(res, &FilteredEvent{
						Source:           Pod,
						PodName:          pod.Name,
						PodNamespace:     pod.Namespace,
						KubernetesReason: "Completed",
						Severity:         EventSeverityLow,
						Timestamp:        &termState.FinishedAt.Time,
					})
				}
			}

			// we look for a terminated sidecar container to see if the job sidecar ran for approximately the timeout
			// period. if it did, we generate a new filtered event to indicate that the job got close to it's timeout
			if containerStatus.Name == "sidecar" {
				if termState := containerStatus.State.Terminated; termState != nil {
					startTime := pod.Status.StartTime.Time
					endTime := termState.FinishedAt.Time
					timeoutValue := getPodSidecarTimeoutValue(pod)

					// if the end time minus the start time is greater than the timeout period (with a 30 second buffer),
					// we generate a new timeout event for the job
					if endTime.Sub(startTime).Seconds() >= timeoutValue-30 {
						res = append(res, &FilteredEvent{
							Source:            Pod,
							PodName:           pod.Name,
							PodNamespace:      pod.Namespace,
							KubernetesReason:  "Timeout",
							KubernetesMessage: fmt.Sprintf("Your job exceeded its timeout value of %.0f. You can increase this timeout value from the Advanced tab.", timeoutValue),
							Severity:          EventSeverityHigh,
							Timestamp:         &termState.FinishedAt.Time,
						})
					}
				}
			}
		}
	}

	return res
}

// NewFilteredEventsFromAMMessage creates a new set of filtered events from an
// AlertManager message.
func NewFilteredEventsFromAMMessage(msg *alertmanager.Message) []*FilteredEvent {
	var res []*FilteredEvent

	for _, alert := range msg.Alerts {
		if alert.Status != "firing" {
			continue
		}
		res = append(res, &FilteredEvent{
			Source:            AlertManager,
			PodName:           alert.Labels["pod"],
			PodNamespace:      alert.Labels["namespace"],
			KubernetesReason:  alert.Labels["alertname"],
			KubernetesMessage: alert.Annotations["summary"],
			Severity:          EventSeverity(alert.Labels["severity"]),
			Timestamp:         &alert.StartsAt,
		})
	}

	return res
}

func getPodSidecarTimeoutValue(pod *v1.Pod) float64 {
	for _, container := range pod.Spec.Containers {
		if container.Name == "sidecar" {
			for _, envVal := range container.Env {
				if envVal.Name == "TIMEOUT" {
					if timeout, err := strconv.ParseFloat(envVal.Value, 64); err == nil && timeout != 0 {
						return timeout
					}
				}
			}
		}
	}

	// if not set, use the default from the sidecar service
	// ref: https://github.com/porter-dev/porter/blob/06c311fa749406580a1e5be873a710c0914a6171/services/job_sidecar_container/job_killer.sh#L37
	return 3600
}

func getEventFromTerminationState(podName, podNamespace string, termState *v1.ContainerStateTerminated) *FilteredEvent {
	if termState.Reason == "Completed" {
		return nil
	}

	event := &FilteredEvent{
		Source:       Pod,
		PodName:      podName,
		PodNamespace: podNamespace,
		Severity:     EventSeverityHigh,
		Timestamp:    &termState.FinishedAt.Time,
		ExitCode:     uint(termState.ExitCode),
	}

	if termState.Reason == "" {
		if termState.ExitCode != 0 {
			event.KubernetesReason = "ApplicationError"
			event.KubernetesMessage = termState.Message
			return event
		}
	} else {
		event.KubernetesReason = termState.Reason
		event.KubernetesMessage = termState.Message
		return event
	}

	return nil
}
