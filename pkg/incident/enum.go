package incident

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/porter-dev/porter-agent/pkg/event"
	"k8s.io/client-go/kubernetes"
)

// This file enumerates well-known event messages as regexes from pod controllers
type KubernetesVersion string

const (
	KubernetesVersion_1_20 KubernetesVersion = "1.20"
	KubernetesVersion_1_21 KubernetesVersion = "1.21"
	KubernetesVersion_1_22 KubernetesVersion = "1.22"
)

const RFC1123Name = `[a-z0-9]([-a-z0-9]*[a-z0-9])`

type EventMatchSummary string

const (
	FailingHealthCheck        EventMatchSummary = "The application is failing its health check"
	StuckPending              EventMatchSummary = "The application cannot be scheduled"
	NonZeroExitCode           EventMatchSummary = "The application exited with a non-zero exit code"
	OutOfMemory               EventMatchSummary = "The application ran out of memory"
	InvalidImage              EventMatchSummary = "The application has an invalid image"
	InvalidStartCommand       EventMatchSummary = "The application has an invalid start command"
	GenericApplicationRestart EventMatchSummary = "The application was restarted due to an error"
)

type EventMatch struct {
	Summary         EventMatchSummary
	DetailGenerator func(e *event.FilteredEvent) string

	SourceMatch  event.EventSource
	ReasonMatch  string
	MessageMatch *regexp.Regexp
	MatchFunc    func(e *event.FilteredEvent, k8sClient *kubernetes.Clientset) bool

	// IsPrimaryCause refers to whether an event match is the primary cause for a reconciliation
	// loop, or simply a proximate cause. For example, an application which is continuously failing
	// its liveness probe may be emitting critical "BackOff" events which are proximate causes.
	IsPrimaryCause bool
}

var EventEnum map[KubernetesVersion][]EventMatch
var PrimaryCauseCandidates map[EventMatchSummary][]EventMatchSummary

func init() {
	EventEnum = make(map[KubernetesVersion][]EventMatch)

	// Kubernetes 1.20 event matches
	eventMatch1_20 := make([]EventMatch, 0)

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.K8sEvent,
		Summary:     FailingHealthCheck,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return "Your application was restarted because it failing its liveness health check. You can configure the liveness health check from the Advanced tab of your application settings."
		},
		ReasonMatch: "Killing",
		MessageMatch: regexp.MustCompile(
			fmt.Sprintf(`Container %s failed liveness probe, will be restarted`, RFC1123Name),
		),
		IsPrimaryCause: true,
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.K8sEvent,
		Summary:     GenericApplicationRestart,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return fmt.Sprintf("The application is stuck in a restart loop")
		},
		ReasonMatch:    "BackOff",
		MessageMatch:   regexp.MustCompile("Back-off.*restarting failed container"),
		IsPrimaryCause: false,
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.Pod,
		Summary:     NonZeroExitCode,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return fmt.Sprintf("The application restarted with exit code %d", e.ExitCode)
		},
		ReasonMatch:    "ApplicationError",
		MessageMatch:   regexp.MustCompile("Back-off restarting failed container"),
		IsPrimaryCause: true,
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.Pod,
		Summary:     NonZeroExitCode,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return fmt.Sprintf("The application restarted with exit code %d", e.ExitCode)
		},
		ReasonMatch:    "Error",
		MessageMatch:   regexp.MustCompile(".*"),
		IsPrimaryCause: true,
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.Pod,
		Summary:     OutOfMemory,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return fmt.Sprintf("Your application ran out of memory. Reduce the amount of memory your application is consuming or bump up its memory limit from the Resources tab")
		},
		ReasonMatch:    "OOMKilled",
		MessageMatch:   regexp.MustCompile(".*"),
		IsPrimaryCause: true,
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.Pod,
		Summary:     InvalidImage,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return fmt.Sprintf("Your application cannot pull from the image registry.")
		},
		ReasonMatch:    "ImagePullBackOff",
		MessageMatch:   regexp.MustCompile(".*"),
		IsPrimaryCause: true,
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.Pod,
		Summary:     InvalidStartCommand,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return fmt.Sprintf("The start command %s was not found in $PATH", strings.Join(e.Pod.Spec.Containers[0].Command, " "))
		},
		ReasonMatch:    "ContainerCannotRun",
		MessageMatch:   regexp.MustCompile(".*executable file not found in.*"),
		IsPrimaryCause: true,
	})

	EventEnum[KubernetesVersion_1_20] = eventMatch1_20

	PrimaryCauseCandidates = make(map[EventMatchSummary][]EventMatchSummary)
	PrimaryCauseCandidates[GenericApplicationRestart] = []EventMatchSummary{
		FailingHealthCheck,
		NonZeroExitCode,
		OutOfMemory,
	}
}

func GetEventMatchFromEvent(k8sVersion KubernetesVersion, k8sClient *kubernetes.Clientset, filteredEvent *event.FilteredEvent) *EventMatch {
	if filteredEvent == nil {
		return nil
	}

	for _, candidate := range EventEnum[k8sVersion] {
		if candidate.SourceMatch != filteredEvent.Source {
			continue
		}

		if candidate.ReasonMatch != "" && candidate.ReasonMatch != filteredEvent.KubernetesReason {
			continue
		}

		if candidate.MessageMatch != nil && !candidate.MessageMatch.Match([]byte(filteredEvent.KubernetesMessage)) {
			continue
		}

		if candidate.MatchFunc != nil && !candidate.MatchFunc(filteredEvent, k8sClient) {
			continue
		}

		return &candidate
	}

	return nil
}
