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
	JobTimeout                EventMatchSummary = "The job timed out"
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

	// ShouldViewLogs refers to whether logs would be useful in order to debug this event. For events
	// that require more application context (oom killed, non-zero exit code), logs could be helpful.
	ShouldViewLogs bool

	// (optional) DocLink contains a link to the Porter documentation for common errors.
	DocLink string
}

var EventEnum map[KubernetesVersion][]EventMatch

func init() {
	EventEnum = make(map[KubernetesVersion][]EventMatch)

	// Kubernetes 1.20 event matches
	// Image error reference: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/images/types.go
	// Container error reference: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/container/sync_result.go
	eventMatch1_20 := make([]EventMatch, 0)

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch:     event.K8sEvent,
		Summary:         FailingHealthCheck,
		DetailGenerator: generateFailingStartupMessage,
		ReasonMatch:     "Killing",
		MessageMatch: regexp.MustCompile(
			fmt.Sprintf(`Container %s failed startup probe, will be restarted`, RFC1123Name),
		),
		IsPrimaryCause: true,
		ShouldViewLogs: true,
		DocLink:        "https://docs.porter.run/managing-applications/application-troubleshooting#failing-liveness-or-startup-probes",
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch:     event.K8sEvent,
		Summary:         FailingHealthCheck,
		DetailGenerator: generateFailingLivenessMessage,
		ReasonMatch:     "Killing",
		MessageMatch: regexp.MustCompile(
			fmt.Sprintf(`Container %s failed liveness probe, will be restarted`, RFC1123Name),
		),
		IsPrimaryCause: true,
		ShouldViewLogs: true,
		DocLink:        "https://docs.porter.run/managing-applications/application-troubleshooting#failing-liveness-or-startup-probes",
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
		ShouldViewLogs: true,
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.K8sEvent,
		Summary:     InvalidImage,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return fmt.Sprintf("Your application cannot pull from the image registry. Details: %s", e.KubernetesMessage)
		},
		ReasonMatch:  "Failed",
		MessageMatch: regexp.MustCompile("Failed to pull image.*"),
		MatchFunc: func(e *event.FilteredEvent, k8sClient *kubernetes.Clientset) bool {
			// we don't want to match events with failing images from the job-sidecar container -
			// this typically indicates a rate limit or connection issue from ECR and we still treat
			// the sidecar as an optional process
			return !strings.Contains(e.KubernetesMessage, "public.ecr.aws/o1j4x7p4/job-sidecar")
		},
		IsPrimaryCause: true,
		DocLink:        "https://docs.porter.run/managing-applications/application-troubleshooting#image-pull-errors",
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
		ShouldViewLogs: true,
		DocLink:        "https://docs.porter.run/managing-applications/application-troubleshooting#application-issues-and-non-zero-exit-codes",
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.Pod,
		Summary:     JobTimeout,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return e.KubernetesMessage
		},
		ReasonMatch:    "Timeout",
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
		ShouldViewLogs: true,
		DocLink:        "https://docs.porter.run/managing-applications/application-troubleshooting#application-issues-and-non-zero-exit-codes",
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch:     event.Pod,
		Summary:         OutOfMemory,
		DetailGenerator: generateOutOfMemoryMessage,
		ReasonMatch:     "OOMKilled",
		MessageMatch:    regexp.MustCompile(".*"),
		IsPrimaryCause:  true,
		ShouldViewLogs:  true,
		DocLink:         "https://docs.porter.run/managing-applications/application-troubleshooting#memory-usage",
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.Pod,
		Summary:     InvalidImage,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return fmt.Sprintf("Your application cannot pull from the image registry. Details: %s", e.KubernetesMessage)
		},
		ReasonMatch:    "ImagePullBackOff",
		MessageMatch:   regexp.MustCompile(".*"),
		IsPrimaryCause: true,
		DocLink:        "https://docs.porter.run/managing-applications/application-troubleshooting#image-pull-errors",
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.Pod,
		Summary:     InvalidImage,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return fmt.Sprintf("Your application cannot pull from the image registry. Details: %s", e.KubernetesMessage)
		},
		ReasonMatch:    "ErrImagePull",
		MessageMatch:   regexp.MustCompile(".*"),
		IsPrimaryCause: true,
		DocLink:        "https://docs.porter.run/managing-applications/application-troubleshooting#image-pull-errors",
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.Pod,
		Summary:     InvalidImage,
		DetailGenerator: func(e *event.FilteredEvent) string {
			return fmt.Sprintf("Your image name is not valid.")
		},
		ReasonMatch:    "InvalidImageName",
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
		DocLink:        "https://docs.porter.run/managing-applications/application-troubleshooting#start-command",
	})

	eventMatch1_20 = append(eventMatch1_20, EventMatch{
		SourceMatch: event.Pod,
		Summary:     StuckPending,
		DetailGenerator: func(e *event.FilteredEvent) string {
			// in this case, we have constructed the kubernetes message
			return e.KubernetesMessage
		},
		ReasonMatch:    "Pending",
		MessageMatch:   regexp.MustCompile("Pod has been pending for.*"),
		IsPrimaryCause: true,
	})

	EventEnum[KubernetesVersion_1_20] = eventMatch1_20
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

func generateFailingStartupMessage(e *event.FilteredEvent) string {
	// we show the user what their health check was set to, which should indicate why the health check failed
	sentences := make([]string, 0)

	sentences = append(sentences, "Your application was restarted because it failed its startup health check.")

	if e.Pod != nil {
		startup := e.Pod.Spec.Containers[0].StartupProbe

		if startup != nil && startup.HTTPGet != nil {
			sentences = append(sentences, fmt.Sprintf("Your startup health check is set to the path %s. Please make sure that your application responds with a 200-level response code on this endpoint", startup.HTTPGet.Path))
		}
	}

	sentences = append(sentences, "If the health check is configured correctly, there are several other reasons why the startup health check may be failing. Consult the documentation here: https://docs.porter.run/deploying-applications/zero-downtime-deployments/#health-checks.")

	return strings.Join(sentences, " ")
}

func generateFailingLivenessMessage(e *event.FilteredEvent) string {
	// we show the user what their health check was set to, which should indicate why the health check failed
	sentences := make([]string, 0)

	sentences = append(sentences, "Your application was restarted because it failed its health check.")

	if e.Pod != nil {
		liveness := e.Pod.Spec.Containers[0].LivenessProbe

		if liveness != nil && liveness.HTTPGet != nil {
			sentences = append(sentences, fmt.Sprintf("Your liveness health check is set to the path %s. Please make sure that your application responds with a 200-level response code on this endpoint", liveness.HTTPGet.Path))

		}
	}

	sentences = append(sentences, "If the health check is configured correctly, there are several other reasons why the startup health check may be failing. Consult the documentation here: https://docs.porter.run/deploying-applications/zero-downtime-deployments/#health-checks.")

	return strings.Join(sentences, " ")
}

func generateOutOfMemoryMessage(e *event.FilteredEvent) string {
	sentences := make([]string, 0)

	// get the memory limit, if it exists
	if e.Pod != nil {
		resources := e.Pod.Spec.Containers[0].Resources

		if memLimit := resources.Limits.Memory(); memLimit != nil {
			sentences = append(sentences, fmt.Sprintf("Your application was restarted because it exceeded its memory limit of %s.", memLimit.String()))
		}
	}

	if len(sentences) == 0 {
		sentences = append(sentences, "Your application was restarted because it ran out of memory.")
	}

	sentences = append(sentences, "Reduce the amount of memory your application is consuming or increase its memory limit from the Resources tab.")

	return strings.Join(sentences, " ")
}
