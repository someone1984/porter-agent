package repository

import (
	"testing"
	"time"

	"github.com/porter-dev/porter-agent/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestListHelmSecretCache(t *testing.T) {
	tester := &tester{
		dbFileName: "./helm_secret_cache_test.db",
	}

	setupTestEnv(tester, t)
	defer cleanup(tester, t)

	now := time.Now()

	helmCache := &models.HelmSecretCache{
		Timestamp: &now,
		Revision:  "3",
		Name:      "test-application",
		Namespace: "applications",
	}

	helmCache, err := tester.repo.HelmSecretCache.CreateHelmSecretCache(helmCache)

	if err != nil {
		t.Fatalf("Expected no error after creating helm secret cache, got %v", err)
	}

	helmCaches, err := tester.repo.HelmSecretCache.ListHelmSecretCachesForRevision("3", "test-application", "applications")

	if err != nil {
		t.Fatalf("Expected no error after reading helm secret cache, got %v", err)
	}

	assert.Equal(t, 1, len(helmCaches), "expected length of helm secret cache result to be 1")
}
