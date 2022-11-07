package controllers

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/porter-dev/porter-agent/internal/logger"
	"github.com/porter-dev/porter-agent/internal/models"
	"github.com/porter-dev/porter-agent/internal/repository"
	"github.com/porter-dev/porter-agent/pkg/incident"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"helm.sh/helm/v3/pkg/chart"
	rspb "helm.sh/helm/v3/pkg/release"
)

// HelmSecretController watches helm secrets on the cluster and generates events for those secrets. It stores deployment_triggered
// and deployment_finished events.
type HelmSecretController struct {
	KubeClient  *kubernetes.Clientset
	KubeVersion incident.KubernetesVersion
	Logger      *logger.Logger
	Repository  *repository.Repository

	startedAt *time.Time
}

func (h *HelmSecretController) Start() {
	started := time.Now()
	h.startedAt = &started

	tweakListOptionsFunc := func(options *metav1.ListOptions) {
		options.LabelSelector = "owner=helm,status=deployed"
	}

	factory := informers.NewSharedInformerFactoryWithOptions(
		h.KubeClient,
		0,
		informers.WithTweakListOptions(tweakListOptionsFunc),
	)

	informer := factory.Core().V1().Secrets().Informer()

	stopper := make(chan struct{})
	errorchan := make(chan error)

	informer.SetWatchErrorHandler(func(r *cache.Reflector, err error) {
		if strings.HasSuffix(err.Error(), ": Unauthorized") {
			errorchan <- &AuthError{}
		}
	})

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: h.processUpdateHelmSecret,
		AddFunc:    h.processAddHelmSecret,
		DeleteFunc: h.processDeleteHelmSecret,
	})

	h.Logger.Info().Caller().Msgf("started helm secret controller")

	informer.Run(stopper)
}

func (h *HelmSecretController) processAddHelmSecret(obj interface{}) {
	secret := obj.(*v1.Secret)
	h.processHelmSecret(secret)
}

func (h *HelmSecretController) processUpdateHelmSecret(oldObj, newObj interface{}) {
	secret := newObj.(*v1.Secret)
	h.processHelmSecret(secret)
}

func (h *HelmSecretController) processDeleteHelmSecret(obj interface{}) {
	// do nothing
}

func (h *HelmSecretController) processHelmSecret(secret *v1.Secret) {
	h.Logger.Info().Caller().Msgf("processing helm secret: %s", secret.Name)

	// check against helm cache immediately by parsing the secret data
	revision := secret.Labels["version"]
	name := secret.Labels["name"]
	namespace := secret.Namespace

	if helmCaches, _ := h.Repository.HelmSecretCache.ListHelmSecretCachesForRevision(revision, name, namespace); len(helmCaches) > 0 {
		return
	}

	// in this case, we should case on the data that we receieved, but newly added secrets should
	// generally be in an installing state
	release, err := parseSecretToHelmRelease(*secret)

	if err != nil {
		h.Logger.Error().Caller().Msgf("could not parse secret to helm release: %s", err.Error())
		return
	}

	h.Logger.Info().Caller().Msgf("decoded helm secret to release %s with status %s", release.Name, release.Info.Status)

	if release != nil {
		switch release.Info.Status {
		case rspb.StatusDeployed:
			// save to the helm cache immediately
			now := time.Now()

			h.Repository.HelmSecretCache.CreateHelmSecretCache(&models.HelmSecretCache{
				Name:      name,
				Namespace: namespace,
				Revision:  revision,
				Timestamp: &now,
			})

			h.Logger.Info().Caller().Msgf("helm release processed for deployed: %s, deployed at %s, compared to %s", release.Name, release.Info.LastDeployed.Time, h.startedAt)

			// create a new event
			event := models.NewDeploymentFinishedEventV1()

			ts := release.Info.LastDeployed.Time.UTC()

			event.Version = "v1"
			event.ReleaseName = release.Name
			event.ReleaseNamespace = release.Namespace
			event.Timestamp = &ts

			eventData := helmReleaseToReleaseEventData(release)

			eventDataBytes, err := json.Marshal(eventData)

			if err != nil {
				h.Logger.Error().Caller().Msgf("could not marshal event data to json: %s", err.Error())
				return
			}

			event.Data = eventDataBytes

			event, err = h.Repository.Event.CreateEvent(event)

			if err != nil {
				h.Logger.Error().Caller().Msgf("could not save new event: %s", err.Error())
				return
			}

		case rspb.StatusPendingInstall:
		case rspb.StatusPendingUpgrade:
		case rspb.StatusPendingRollback:
		}
	}
}

var magicGzip = []byte{0x1f, 0x8b, 0x08}
var b64 = base64.StdEncoding

func parseSecretToHelmRelease(secret v1.Secret) (*rspb.Release, error) {
	if secret.Type != "helm.sh/release.v1" {
		return nil, fmt.Errorf("not a helm secret")
	}

	releaseData, ok := secret.Data["release"]

	if !ok {
		return nil, fmt.Errorf("release field not found")
	}

	helm_object, err := decodeRelease(string(releaseData))

	if err != nil {
		return nil, err
	}

	return helm_object, nil
}

func decodeRelease(data string) (*rspb.Release, error) {
	// base64 decode string
	b, err := b64.DecodeString(data)
	if err != nil {
		return nil, err
	}

	// For backwards compatibility with releases that were stored before
	// compression was introduced we skip decompression if the
	// gzip magic header is not found
	if bytes.Equal(b[0:3], magicGzip) {
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		b2, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
		b = b2
	}

	var rls rspb.Release
	// unmarshal release object bytes
	if err := json.Unmarshal(b, &rls); err != nil {
		return nil, err
	}
	return &rls, nil
}

type ReleaseEventData struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Revision  string `json:"revision,omitempty"`

	Info  *rspb.Info             `json:"info,omitempty"`
	Chart *ReleaseEventDataChart `json:"chart,omitempty"`
}

type ReleaseEventDataChart struct {
	Metadata *chart.Metadata `json:"metadata"`
}

func helmReleaseToReleaseEventData(rel *rspb.Release) *ReleaseEventData {
	return &ReleaseEventData{
		Name:      rel.Name,
		Namespace: rel.Namespace,
		Revision:  fmt.Sprintf("%d", rel.Version),
		Info:      rel.Info,
		Chart: &ReleaseEventDataChart{
			Metadata: rel.Chart.Metadata,
		},
	}
}
