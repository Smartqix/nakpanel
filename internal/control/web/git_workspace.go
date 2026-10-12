package web

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/nakroteck/nakpanel/internal/types"
	"regexp"
	"strings"
)

var gitOutputURL = regexp.MustCompile(`(?i)(?:https?|ssh)://[^\s<>]+|git@[^\s<>]+`)

func gitSafeOutput(value string) string {
	return gitOutputURL.ReplaceAllString(value, "[repository URL redacted]")
}

func gitLogOutput(value, status string) string {
	if value == "" || strings.TrimSpace(value) == "null" || strings.TrimSpace(value) == "[]" {
		if status == "pending" || status == "running" || status == "queued" {
			return "No log output yet."
		}
		if status == "failed" {
			return "No log output available."
		}
		return "Operation completed."
	}
	return gitSafeOutput(value)
}

func gitActionRevision(repository types.GitRepository, action string) string {
	if action == "rollback" {
		return repository.PreviousRevision
	}
	if action == "deploy" || action == "preview" {
		return repository.FetchedRevision
	}
	return ""
}

func gitActionDisabled(repository types.GitRepository, action string) bool {
	if repository.ConnectionStatus != "connected" || repository.ConvergenceStatus == "pending" {
		return true
	}
	if action == "preview" {
		return repository.FetchedRevision == ""
	}
	return repository.DeploymentMode == "disabled" || gitActionRevision(repository, action) == ""
}

func gitHostFingerprint(key string) string {
	fields := strings.Fields(key)
	if len(fields) < 3 {
		return "No verified SSH host key saved"
	}
	raw, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return "Invalid SSH host key"
	}
	digest := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func gitDisplay(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func gitConnectionVisible(repository types.GitRepository) bool {
	return repository.ConnectionStatus != "disconnected" || repository.ConvergenceStatus != "in_sync"
}

func gitNewRepository(repositories []types.GitRepository, siteID int64) types.GitRepository {
	repository, _ := gitForSite(repositories, siteID)
	return types.GitRepository{ID: repository.ID, OperationRevision: repository.OperationRevision, Mode: "remote", Branch: "main", DeployTarget: "."}
}

func gitDestination(target string) string {
	if target == "" || target == "." {
		return "public_html"
	}
	return "public_html/" + strings.TrimPrefix(target, "./")
}
