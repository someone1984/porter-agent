package httpclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/porter-dev/porter-agent/api/server/types"
	"github.com/porter-dev/porter-agent/internal/logger"
)

type HTTPClientConf struct {
	PorterHost  string `env:"PORTER_HOST"`
	PorterToken string `env:"PORTER_TOKEN"`
	ClusterID   string `env:"CLUSTER_ID"`
	ProjectID   string `env:"PROJECT_ID"`
}

type Client struct {
	client               *http.Client
	token                string
	host                 string
	projectID, clusterID string
	logger               *logger.Logger
}

func NewClient(conf *HTTPClientConf, logger *logger.Logger) *Client {
	return &Client{
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
		token:     conf.PorterToken,
		host:      conf.PorterHost,
		projectID: conf.ProjectID,
		clusterID: conf.ClusterID,
		logger:    logger,
	}
}

func (c *Client) NotifyNew(incident *types.Incident) error {
	err := c.post(fmt.Sprintf("/api/projects/%s/clusters/%s/incidents/notify_new", c.projectID, c.clusterID), incident)

	if err != nil {
		c.logger.Error().Caller().Msgf("could not notify new for incident %s of %s %s/%s: %v", incident.ID, incident.InvolvedObjectKind, incident.InvolvedObjectNamespace, incident.InvolvedObjectName, err)
	} else {
		c.logger.Info().Caller().Msgf("successfully notified new incident %s of %s %s/%s", incident.ID, incident.InvolvedObjectKind, incident.InvolvedObjectNamespace, incident.InvolvedObjectName)
	}

	return err
}

func (c *Client) NotifyResolved(incident *types.Incident) error {
	err := c.post(fmt.Sprintf("/api/projects/%s/clusters/%s/incidents/notify_resolved", c.projectID, c.clusterID), incident)

	if err != nil {
		c.logger.Error().Caller().Msgf("could not notify resolved for incident %s of %s %s/%s: %v", incident.ID, incident.InvolvedObjectKind, incident.InvolvedObjectNamespace, incident.InvolvedObjectName, err)
	} else {
		c.logger.Info().Caller().Msgf("successfully notified resolved incident %s of %s %s/%s", incident.ID, incident.InvolvedObjectKind, incident.InvolvedObjectNamespace, incident.InvolvedObjectName)
	}

	return err
}

func (c *Client) post(path string, body interface{}) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s%s", c.host, path)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	res, err := c.client.Do(req)

	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		bodyBytes, err := ioutil.ReadAll(res.Body)

		if err == nil {
			return fmt.Errorf("http client error, status code: %d. response body: %s. request body: %s", res.StatusCode, string(bodyBytes), string(jsonBody))
		} else {
			return fmt.Errorf("unknown error, status code: %d", res.StatusCode)
		}
	}

	return nil
}
