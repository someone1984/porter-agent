package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"gorm.io/gorm"
	"k8s.io/client-go/kubernetes"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/porter-dev/porter-agent/internal/envconf"
	"github.com/porter-dev/porter-agent/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/joeshaw/envdecode"
	"github.com/porter-dev/porter-agent/internal/adapter"
	"github.com/porter-dev/porter-agent/internal/logger"
	"github.com/porter-dev/porter-agent/internal/repository"
	"github.com/porter-dev/porter-agent/pkg/alerter"
	"github.com/porter-dev/porter-agent/pkg/controllers"
	"github.com/porter-dev/porter-agent/pkg/httpclient"
	"github.com/porter-dev/porter-agent/pkg/incident"
	"github.com/porter-dev/porter-agent/pkg/job"
	"github.com/porter-dev/porter-agent/pkg/logstore"
	"github.com/porter-dev/porter-agent/pkg/logstore/lokistore"
	"github.com/porter-dev/porter-agent/pkg/logstore/memorystore"
	"github.com/porter-dev/porter-agent/pkg/pulsar"

	"github.com/porter-dev/porter-agent/api/server/config"
	eventHandlers "github.com/porter-dev/porter-agent/api/server/handlers/event"
	healthcheckHandlers "github.com/porter-dev/porter-agent/api/server/handlers/healthcheck"
	incidentHandlers "github.com/porter-dev/porter-agent/api/server/handlers/incident"
	logHandlers "github.com/porter-dev/porter-agent/api/server/handlers/log"
	statusHandlers "github.com/porter-dev/porter-agent/api/server/handlers/status"
	"github.com/porter-dev/porter-agent/pkg/receiver"
)

var (
	httpServer *gin.Engine
)

func main() {
	kubeClient := kubernetes.NewForConfigOrDie(ctrl.GetConfigOrDie())

	var envDecoderConf envconf.EnvDecoderConf = envconf.EnvDecoderConf{}

	if err := envdecode.StrictDecode(&envDecoderConf); err != nil {
		logger.NewErrorConsole(true).Fatal().Caller().Msgf("could not decode env conf: %v", err)

		os.Exit(1)
	}

	l := logger.NewConsole(envDecoderConf.Debug)

	client := httpclient.NewClient(&envDecoderConf.HTTPClientConf, l)

	// create database connection through adapter
	db, err := adapter.New(&envDecoderConf.DBConf)

	if err != nil {
		l.Fatal().Caller().Msgf("could not create database connection: %v", err)
	}

	if err := repository.AutoMigrate(db, false); err != nil {
		l.Fatal().Caller().Msgf("auto migration failed: %v", err)
	}

	var logStore logstore.LogStore
	var logStoreKind string
	if envDecoderConf.LogStoreConf.LogStoreKind == "memory" {
		logStoreKind = "memory"
		logStore, err = memorystore.New("test", memorystore.Options{})
	} else {
		logStoreKind = "loki"
		lokistore.SetupLokiStatus(envDecoderConf.LogStoreConf.LogStoreAddress)
		logStore, err = lokistore.New("test", lokistore.LogStoreConfig{
			Address:     envDecoderConf.LogStoreConf.LogStoreAddress,
			HTTPAddress: envDecoderConf.LogStoreConf.LogStoreHTTPAddress,
		})
	}

	if err != nil {
		l.Fatal().Caller().Msgf("%s-based log store setup failed: %v", logStoreKind, err)
	}

	go cleanupEventCache(db, l)

	repo := repository.NewRepository(db)

	alerter := &alerter.Alerter{
		Client:     client,
		Repository: repo,
		Logger:     l,
		AlertConfiguration: &alerter.AlertConfiguration{
			DefaultJobAlertConfiguration: alerter.JobAlertConfigurationEvery,
		},
	}

	detector := &incident.IncidentDetector{
		KubeClient: kubeClient,
		// TODO: don't hardcode to 1.20
		KubeVersion: incident.KubernetesVersion_1_20,
		Repository:  repo,
		Alerter:     alerter,
		Logger:      l,
	}

	resolver := &incident.IncidentResolver{
		KubeClient: kubeClient,
		// TODO: don't hardcode to 1.20
		KubeVersion: incident.KubernetesVersion_1_20,
		Repository:  repo,
		Alerter:     alerter,
		Logger:      l,
	}

	jobProducer := &job.JobEventProducer{
		KubeClient: *kubeClient,
		Repository: repo,
		Logger:     l,
	}

	// trigger resolver through pulsar
	go func() {
		p := pulsar.NewPulsar(1, time.Minute) // pulse every 1 minute

		for range p.Pulsate() {
			err := resolver.Run()

			if err != nil {
				l.Error().Caller().Msgf("resolver exited with error: %v", err)
			}
		}
	}()

	eventController := controllers.EventController{
		KubeClient: kubeClient,
		// TODO: don't hardcode to 1.20
		KubeVersion:      incident.KubernetesVersion_1_20,
		IncidentDetector: detector,
		Repository:       repo,
		LogStore:         logStore,
		Logger:           l,
		JobProducer:      jobProducer,
	}

	go eventController.Start()

	podController := controllers.PodController{
		KubeClient: kubeClient,
		// TODO: don't hardcode to 1.20
		KubeVersion:      incident.KubernetesVersion_1_20,
		IncidentDetector: detector,
		Logger:           l,
		JobProducer:      jobProducer,
	}

	go podController.Start()

	helmSecretController := controllers.HelmSecretController{
		KubeClient: kubeClient,
		// TODO: don't hardcode to 1.20
		KubeVersion: incident.KubernetesVersion_1_20,
		Logger:      l,
		Repository:  repo,
	}

	go helmSecretController.Start()

	conf, err := config.GetConfig(&envDecoderConf, repo, logStore)

	if err != nil {
		l.Fatal().Caller().Msgf("server config loading failed: %v", err)
	}

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	r.Mount("/debug", middleware.Profiler())

	r.Method("GET", "/livez", healthcheckHandlers.NewLivezHandler(conf))
	r.Method("GET", "/readyz", healthcheckHandlers.NewReadyzHandler(conf))

	r.Method("GET", "/incidents", incidentHandlers.NewListIncidentsHandler(conf))

	// NOTE(muvaf): POST handler on "/incidents" path could be used to accept a
	// Porter-specific payload. Since we can't control the payload coming from
	// alert-manager, a separate path is used.
	r.Method("POST", "/incidents/alertmanager", receiver.NewAlertManagerWebhook(conf, detector))

	r.Method("GET", "/incidents", incidentHandlers.NewListIncidentsHandler(conf))
	r.Method("GET", "/incidents/{uid}", incidentHandlers.NewGetIncidentHandler(conf))
	r.Method("GET", "/incidents/events", incidentHandlers.NewListIncidentEventsHandler(conf))

	r.Method("GET", "/logs", logHandlers.NewGetLogHandler(conf))
	r.Method("GET", "/logs/pod_values", logHandlers.NewGetPodValuesHandler(conf))
	r.Method("GET", "/logs/revision_values", logHandlers.NewGetRevisionValuesHandler(conf))

	r.Method("GET", "/events", eventHandlers.NewListEventsHandler(conf))
	r.Method("GET", "/events/job", eventHandlers.NewListJobEventsHandler(conf))

	r.Method("GET", "/status", statusHandlers.NewGetStatusHandler(conf))

	if err := http.ListenAndServe(fmt.Sprintf(":%d", envDecoderConf.ServerPort), r); err != nil {
		l.Error().Caller().Msgf("error starting API server: %v", err)
	}
}

func cleanupEventCache(db *gorm.DB, l *logger.Logger) {
	for {
		l.Info().Caller().Msgf("cleaning up old event caches")

		var olderCache []*models.EventCache

		if err := db.Model(&models.EventCache{}).Where("timestamp <= ?", time.Now().Add(-time.Hour)).Find(&olderCache).Error; err == nil {
			numDeleted := 0

			for _, cache := range olderCache {
				if err := db.Delete(cache).Error; err != nil {
					l.Error().Caller().Msgf("error deleting old event cache with ID: %d. Error: %v\n", cache.ID, err)
					numDeleted++
				}
			}

			l.Info().Caller().Msgf("deleted %d event cache objects from database", numDeleted)
		} else {
			l.Error().Caller().Msgf("error querying for older event cache DB entries: %v\n", err)
		}

		time.Sleep(time.Hour)
	}
}
