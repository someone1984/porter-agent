package receiver

import (
	"encoding/json"
	"github.com/porter-dev/porter-agent/api/server/config"
	"github.com/porter-dev/porter-agent/pkg/event"
	"github.com/porter-dev/porter/api/server/shared/apierrors"
	"net/http"

	alertmanager "github.com/prometheus/alertmanager/notify/webhook"
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

// ServeHTTP handles the incoming alert-manager request.
func (h *AlertManagerWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	msg := &alertmanager.Message{}
	if err := json.NewDecoder(r.Body).Decode(msg); err != nil {
		apierrors.HandleAPIError(h.config.Logger, h.config.Alerter, w, r, apierrors.NewErrInternal(err), true)
		return
	}
	fe := event.NewFilteredEventsFromAMMessage(msg)
	if err := h.detector.DetectIncident(fe); err != nil {
		apierrors.HandleAPIError(h.config.Logger, h.config.Alerter, w, r, apierrors.NewErrInternal(err), true)
		return
	}
	return
}
