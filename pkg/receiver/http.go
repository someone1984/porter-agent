package receiver

import (
	"encoding/json"
	"fmt"
	"github.com/porter-dev/porter-agent/api/server/config"
	"github.com/porter-dev/porter/api/server/shared/apierrors"
	"net/http"

	alertmanager "github.com/prometheus/alertmanager/notify/webhook"
)

// NewHTTP returns a new HTTP receiver.
func NewHTTP(config *config.Config) *HTTP {
	return &HTTP{
		config: config,
	}
}

// HTTP is a receiver that receives alerts from alert-manager and records them
// as incidents to be consumed by Porter.
type HTTP struct {
	config *config.Config
}

// ServeHTTP handles the incoming alert-manager request.
func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	msg := &alertmanager.Message{}
	if err := json.NewDecoder(r.Body).Decode(msg); err != nil {
		apierrors.HandleAPIError(h.config.Logger, h.config.Alerter, w, r, apierrors.NewErrInternal(err), true)
		return
	}
	if err := h.saveAsIncident(msg); err != nil {
		apierrors.HandleAPIError(h.config.Logger, h.config.Alerter, w, r, apierrors.NewErrInternal(err), true)
		return
	}
	return
}

func (h *HTTP) saveAsIncident(msg *alertmanager.Message) error {
	alerts := msg.Alerts.Firing()
	for _, a := range alerts {
		fmt.Printf("Alert status: %s\n", a.Status)
		for k, v := range a.Labels {
			fmt.Printf("Label %s: %s\n", k, v)
		}
	}
	return nil
}
