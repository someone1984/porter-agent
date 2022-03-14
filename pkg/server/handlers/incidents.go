package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/porter-dev/porter-agent/pkg/models"
	"github.com/porter-dev/porter-agent/pkg/utils"
)

func GetAllIncidents(c *gin.Context) {
	incidentIDs, err := redisClient.GetAllIncidents(c.Copy())
	if err != nil {
		httpLogger.Error(err, "error getting list of all incidents")

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	var incidents []*models.Incident

	for _, id := range incidentIDs {
		incidentObj, err := utils.NewIncidentFromString(id)
		if err != nil {
			httpLogger.Error(err, "error getting incident object from ID:", id)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "internal server error",
			})
			return
		}

		incident := &models.Incident{
			ID:          id,
			ReleaseName: incidentObj.GetReleaseName(),
		}

		resolved, err := redisClient.IsIncidentResolved(c.Copy(), id)
		if err != nil {
			httpLogger.Error(err, "error checking if incident with ID: %s resolved:", id)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "internal server error",
			})
			return
		}

		if resolved {
			incident.LatestState = "RESOLVED"
		} else {
			incident.LatestState = "ONGOING"
		}

		incident.LatestReason, incident.LatestMessage, err = redisClient.GetLatestReasonAndMessage(c.Copy(), id)
		if err != nil {
			httpLogger.Error(err, "error fetching latest reason and messaged for incident ID:", id)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "internal server error",
			})
			return
		}

		incidents = append(incidents, incident)
	}

	c.JSON(http.StatusOK, gin.H{
		"incidents": incidents,
	})
}

func GetIncidentsByReleaseName(c *gin.Context) {
	releaseName := c.Param("releaseName")

	incidentIDs, err := redisClient.GetIncidentsByReleaseName(c.Copy(), releaseName)
	if err != nil {
		httpLogger.Error(err, "error getting incidents for release:", releaseName)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	var incidents []*models.Incident

	for _, id := range incidentIDs {
		incidentObj, err := utils.NewIncidentFromString(id)
		if err != nil {
			httpLogger.Error(err, "error getting incident object from ID:", id)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "internal server error",
			})
			return
		}

		incident := &models.Incident{
			ID:          id,
			ReleaseName: incidentObj.GetReleaseName(),
		}

		resolved, err := redisClient.IsIncidentResolved(c.Copy(), id)
		if err != nil {
			httpLogger.Error(err, "error checking if incident with ID: %s resolved:", id)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "internal server error",
			})
			return
		}

		if resolved {
			incident.LatestState = "RESOLVED"
		} else {
			incident.LatestState = "ONGOING"
		}

		incident.LatestReason, incident.LatestMessage, err = redisClient.GetLatestReasonAndMessage(c.Copy(), id)
		if err != nil {
			httpLogger.Error(err, "error fetching latest reason and messaged for incident ID:", id)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "internal server error",
			})
			return
		}

		incidents = append(incidents, incident)
	}

	c.JSON(http.StatusOK, gin.H{
		"incidents": incidents,
	})
}

func GetIncidentEventsByID(c *gin.Context) {
	incidentID := c.Param("incidentID")

	exists, err := redisClient.IncidentExists(c.Copy(), incidentID)
	if err != nil {
		httpLogger.Error(err, "error checking for existence of incident ID:", incidentID)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "invalid incident ID",
		})
		return
	}

	events, err := redisClient.GetIncidentEventsByID(c.Copy(), incidentID)
	if err != nil {
		httpLogger.Error(err, "error getting incidents incident ID:", incidentID)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"incident_id": incidentID,
		"events":      events,
	})
}

func GetLogs(c *gin.Context) {
	logID := c.Param("logID")

	logs, err := redisClient.GetLogs(c.Copy(), logID)
	if err != nil {
		if strings.Contains(err.Error(), "no such logs") {
			httpLogger.Error(err, "no such logs with log ID:", logID)

			c.JSON(http.StatusNotFound, gin.H{
				"error": "no such logs",
			})
			return
		}

		httpLogger.Error(err, "error getting logs log ID:", logID)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"contents": logs,
	})
}
