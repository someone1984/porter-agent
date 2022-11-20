package receiver

import (
	"encoding/json"
	"fmt"
	"github.com/porter-dev/porter-agent/api/server/config"
	"github.com/porter-dev/porter-agent/pkg/event"
	"github.com/porter-dev/porter/api/server/shared/apierrors"
	alertmanagertmpl "github.com/prometheus/alertmanager/template"
	"net/http"
	"strings"
)

type Detector interface {
	DetectIncident(events []*event.FilteredEvent) error
}

// NewAlertManagerWebhook returns a new AlertManagerWebhook receiver.
func NewAlertManagerWebhook(config *config.Config, detector Detector) *AlertManagerWebhook {
	return &AlertManagerWebhook{
		config:   config,
		detector: detector,
	}
}

// AlertManagerWebhook is a receiver that receives alerts from alert-manager and records them
// as incidents to be consumed by Porter.
type AlertManagerWebhook struct {
	config   *config.Config
	detector Detector
}

// ServeHTTP handles the incoming alert-manager message.
func (h *AlertManagerWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// NOTE(muvaf): We do not use the original Message type because the data we
	// need is under its embedded Data struct which has much less dependencies
	// that would be needed to be vendored.
	msg := &alertmanagertmpl.Data{}
	if err := json.NewDecoder(r.Body).Decode(msg); err != nil {
		apierrors.HandleAPIError(h.config.Logger, h.config.Alerter, w, r, apierrors.NewErrInternal(err), true)
		return
	}
	h.config.Logger.Debug().Msgf("received %d alerts: %s", len(msg.Alerts), stringAlerts(msg))
	// NOTE(muvaf): We re-use the existing utilities regarding incidents but they
	// are optimized for Kubernetes events and don't always match the nature of
	// AlertManager alerts. For example, alerts start as "firing" and they
	// transition to "resolved" after a while rather than being fired once at a
	// timestamp - which fits neither Incident nor Event model at their current
	// shape.
	//
	// Every alert is treated as an event, which is the least disrupting change
	// to incorporate them. The other candidate would've been to treat them as
	// incidents but that would require a lot more changes to the existing
	// incident mechanisms since we'd not want to re-implement IncidentDetector,
	// hence refactor the common mechanics.
	fe := event.NewFilteredEventsFromAMMessage(msg)
	if err := h.detector.DetectIncident(fe); err != nil {
		apierrors.HandleAPIError(h.config.Logger, h.config.Alerter, w, r, apierrors.NewErrInternal(err), true)
		return
	}
	return
}

func stringAlerts(data *alertmanagertmpl.Data) string {
	var alerts string
	for _, alert := range data.Alerts {
		alerts += fmt.Sprintf("%s:%s for pod %s/%s ", alert.Labels["alertname"], alert.Status, alert.Labels["namespace"], alert.Labels["pod"])
	}
	return strings.TrimSpace(alerts)
}
