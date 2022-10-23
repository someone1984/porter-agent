package log

import (
	"net/http"
	"time"

	"github.com/porter-dev/porter-agent/api/server/config"
	"github.com/porter-dev/porter-agent/api/server/types"
	"github.com/porter-dev/porter-agent/pkg/logstore"
	"github.com/porter-dev/porter/api/server/shared"
	"github.com/porter-dev/porter/api/server/shared/apierrors"
)

type GetPodValuesHandler struct {
	decoderValidator shared.RequestDecoderValidator
	resultWriter     shared.ResultWriter

	Config *config.Config
}

func NewGetPodValuesHandler(config *config.Config) *GetPodValuesHandler {
	return &GetPodValuesHandler{
		resultWriter:     shared.NewDefaultResultWriter(config.Logger, config.Alerter),
		decoderValidator: shared.NewDefaultRequestDecoderValidator(config.Logger, config.Alerter),
		Config:           config,
	}
}

func (h *GetPodValuesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req := &types.GetPodValuesRequest{}

	if ok := h.decoderValidator.DecodeAndValidate(w, r, req); !ok {
		return
	}

	if req.StartRange == nil {
		days29 := time.Now().Add(-29 * 24 * time.Hour)
		req.StartRange = &days29
	}

	if req.EndRange == nil {
		now := time.Now()
		req.EndRange = &now
	}

	podVals, err := h.Config.LogStore.GetPodLabelValues(logstore.LabelValueOptions{
		Start:     *req.StartRange,
		End:       *req.EndRange,
		PodPrefix: req.MatchPrefix,
		Revision:  req.Revision,
		Namespace: req.Namespace,
	})

	if err != nil {
		apierrors.HandleAPIError(h.Config.Logger, h.Config.Alerter, w, r, apierrors.NewErrInternal(err), true)
		return
	}

	// res := make([]string, 0)

	// for _, candidateVal := range candidateVals {
	// 	if strings.HasPrefix(candidateVal, req.MatchPrefix) {
	// 		res = append(res, candidateVal)
	// 	}
	// }

	h.resultWriter.WriteResult(w, r, podVals)
}
