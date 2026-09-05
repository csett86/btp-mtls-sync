package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	annotationFingerprint = "btp-mtls-sync/fingerprint"
	annotationSyncedAt    = "btp-mtls-sync/synced-at"
)

type config struct {
	DestinationTokenURL      string
	DestinationClientID      string
	DestinationClientSecret  string
	DestinationAPIURL        string
	CFAPIURL                 string
	CFTokenURL               string
	CFClientID               string
	CFClientSecret           string
	CFDefaultServiceInstance string
	NamePrefix               string
	DryRun                   bool
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

type destinationCertificate struct {
	Name        string `json:"name"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
}

type cfRelationshipData struct {
	GUID string `json:"guid"`
}

type cfServiceKeyResource struct {
	GUID          string `json:"guid"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	Relationships struct {
		ServiceInstance struct {
			Data *cfRelationshipData `json:"data"`
		} `json:"service_instance"`
	} `json:"relationships"`
	Metadata struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
}

type cfPagination struct {
	Next *struct {
		Href string `json:"href"`
	} `json:"next"`
}

type cfServiceKeyListResponse struct {
	Resources  []cfServiceKeyResource `json:"resources"`
	Pagination cfPagination           `json:"pagination"`
}

type cfJob struct {
	State  string `json:"state"`
	Errors []struct {
		Detail string `json:"detail"`
		Title  string `json:"title"`
	} `json:"errors"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("sync failed: %v", err)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	ctx := context.Background()
	client := &http.Client{Timeout: 30 * time.Second}

	destinationToken, err := fetchClientCredentialsToken(ctx, client, cfg.DestinationTokenURL, cfg.DestinationClientID, cfg.DestinationClientSecret)
	if err != nil {
		return fmt.Errorf("fetch destination token: %w", err)
	}

	cfToken, err := fetchClientCredentialsToken(ctx, client, cfg.CFTokenURL, cfg.CFClientID, cfg.CFClientSecret)
	if err != nil {
		return fmt.Errorf("fetch cf token: %w", err)
	}

	certificates, err := listDestinationCertificates(ctx, client, cfg.DestinationAPIURL, destinationToken)
	if err != nil {
		return fmt.Errorf("list destination certificates: %w", err)
	}

	serviceKeys, err := listCFServiceKeys(ctx, client, cfg.CFAPIURL, cfToken)
	if err != nil {
		return fmt.Errorf("list cf service keys: %w", err)
	}

	created, updated, skipped, err := syncCertificates(ctx, client, cfg, cfToken, certificates, serviceKeys)
	if err != nil {
		return err
	}

	log.Printf("sync complete: certificates=%d created=%d updated=%d skipped=%d dry_run=%t", len(certificates), created, updated, skipped, cfg.DryRun)
	return nil
}

func loadConfig() (config, error) {
	cfg := config{
		DestinationTokenURL:      strings.TrimSpace(os.Getenv("DESTINATION_TOKEN_URL")),
		DestinationClientID:      strings.TrimSpace(os.Getenv("DESTINATION_CLIENT_ID")),
		DestinationClientSecret:  strings.TrimSpace(os.Getenv("DESTINATION_CLIENT_SECRET")),
		DestinationAPIURL:        strings.TrimRight(strings.TrimSpace(os.Getenv("DESTINATION_API_URL")), "/"),
		CFAPIURL:                 strings.TrimRight(strings.TrimSpace(os.Getenv("CF_API_URL")), "/"),
		CFTokenURL:               strings.TrimSpace(os.Getenv("CF_TOKEN_URL")),
		CFClientID:               strings.TrimSpace(os.Getenv("CF_CLIENT_ID")),
		CFClientSecret:           strings.TrimSpace(os.Getenv("CF_CLIENT_SECRET")),
		CFDefaultServiceInstance: strings.TrimSpace(os.Getenv("CF_DEFAULT_SERVICE_INSTANCE_GUID")),
		NamePrefix:               strings.TrimSpace(os.Getenv("SYNC_NAME_PREFIX")),
	}

	dryRunValue := strings.TrimSpace(os.Getenv("DRY_RUN"))
	if dryRunValue != "" {
		dryRun, err := strconv.ParseBool(dryRunValue)
		if err != nil {
			return config{}, fmt.Errorf("invalid DRY_RUN value %q: %w", dryRunValue, err)
		}
		cfg.DryRun = dryRun
	}

	missing := []string{}
	required := map[string]string{
		"DESTINATION_TOKEN_URL":     cfg.DestinationTokenURL,
		"DESTINATION_CLIENT_ID":     cfg.DestinationClientID,
		"DESTINATION_CLIENT_SECRET": cfg.DestinationClientSecret,
		"DESTINATION_API_URL":       cfg.DestinationAPIURL,
		"CF_API_URL":                cfg.CFAPIURL,
		"CF_TOKEN_URL":              cfg.CFTokenURL,
		"CF_CLIENT_ID":              cfg.CFClientID,
		"CF_CLIENT_SECRET":          cfg.CFClientSecret,
	}
	for key, value := range required {
		if value == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return config{}, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}

	return cfg, nil
}

func fetchClientCredentialsToken(ctx context.Context, client *http.Client, tokenURL, clientID, clientSecret string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return "", fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	if tokenResp.AccessToken == "" {
		return "", errors.New("token endpoint returned empty access_token")
	}
	return tokenResp.AccessToken, nil
}

func listDestinationCertificates(ctx context.Context, client *http.Client, apiURL, token string) ([]destinationCertificate, error) {
	endpoint := apiURL + "/destination-configuration/v1/certificates"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return nil, fmt.Errorf("destination certificates status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	type wrapped struct {
		Certificates []map[string]any `json:"certificates"`
	}

	wrappedResp := wrapped{}
	if err := json.Unmarshal(payload, &wrappedResp); err == nil && len(wrappedResp.Certificates) > 0 {
		return normalizeCertificates(wrappedResp.Certificates), nil
	}

	arrayResp := []map[string]any{}
	if err := json.Unmarshal(payload, &arrayResp); err != nil {
		return nil, fmt.Errorf("decode destination certificates: %w", err)
	}
	return normalizeCertificates(arrayResp), nil
}

func normalizeCertificates(entries []map[string]any) []destinationCertificate {
	certs := make([]destinationCertificate, 0, len(entries))
	for _, item := range entries {
		cert := destinationCertificate{
			Name:        getFirstString(item, "name", "Name", "alias"),
			Certificate: getFirstString(item, "certificate", "content", "cert", "clientcert", "pem"),
			Key:         getFirstString(item, "key", "privateKey", "private_key", "clientkey"),
		}
		if cert.Name == "" {
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}

func getFirstString(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := data[key]; ok {
			if s, ok := value.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func listCFServiceKeys(ctx context.Context, client *http.Client, apiURL, token string) ([]cfServiceKeyResource, error) {
	nextURL := apiURL + "/v3/service_credential_bindings?type=key&per_page=5000"
	all := []cfServiceKeyResource{}

	for nextURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			resp.Body.Close()
			return nil, fmt.Errorf("cf list service keys status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var page cfServiceKeyListResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}

		all = append(all, page.Resources...)
		nextURL = ""
		if page.Pagination.Next != nil {
			nextURL = strings.TrimSpace(page.Pagination.Next.Href)
		}
	}

	return all, nil
}

func syncCertificates(
	ctx context.Context,
	client *http.Client,
	cfg config,
	cfToken string,
	certificates []destinationCertificate,
	serviceKeys []cfServiceKeyResource,
) (created int, updated int, skipped int, err error) {
	keysByName := make(map[string]cfServiceKeyResource, len(serviceKeys))
	for _, key := range serviceKeys {
		if _, exists := keysByName[key.Name]; exists {
			return created, updated, skipped, fmt.Errorf("multiple CF service keys found with name %q", key.Name)
		}
		keysByName[key.Name] = key
	}

	for _, cert := range certificates {
		if cfg.NamePrefix != "" && !strings.HasPrefix(cert.Name, cfg.NamePrefix) {
			continue
		}

		fingerprint := certificateFingerprint(cert)
		key, found := keysByName[cert.Name]
		if found {
			if key.Metadata.Annotations != nil && key.Metadata.Annotations[annotationFingerprint] == fingerprint {
				skipped++
				log.Printf("skip %q (fingerprint unchanged)", cert.Name)
				continue
			}
			if key.Relationships.ServiceInstance.Data == nil || strings.TrimSpace(key.Relationships.ServiceInstance.Data.GUID) == "" {
				skipped++
				log.Printf("skip %q (existing key has no managed service instance GUID)", cert.Name)
				continue
			}

			log.Printf("update %q (recreate existing service key)", cert.Name)
			if !cfg.DryRun {
				if err := deleteServiceKey(ctx, client, cfg.CFAPIURL, cfToken, key.GUID); err != nil {
					return created, updated, skipped, fmt.Errorf("delete service key %q: %w", cert.Name, err)
				}
				if err := createServiceKey(ctx, client, cfg.CFAPIURL, cfToken, cert.Name, key.Relationships.ServiceInstance.Data.GUID, cert, fingerprint); err != nil {
					return created, updated, skipped, fmt.Errorf("recreate service key %q: %w", cert.Name, err)
				}
			}
			updated++
			continue
		}

		if cfg.CFDefaultServiceInstance == "" {
			skipped++
			log.Printf("skip %q (no existing matching service key and CF_DEFAULT_SERVICE_INSTANCE_GUID not set)", cert.Name)
			continue
		}

		log.Printf("create %q", cert.Name)
		if !cfg.DryRun {
			if err := createServiceKey(ctx, client, cfg.CFAPIURL, cfToken, cert.Name, cfg.CFDefaultServiceInstance, cert, fingerprint); err != nil {
				return created, updated, skipped, fmt.Errorf("create service key %q: %w", cert.Name, err)
			}
		}
		created++
	}

	return created, updated, skipped, nil
}

func createServiceKey(
	ctx context.Context,
	client *http.Client,
	apiURL string,
	token string,
	name string,
	serviceInstanceGUID string,
	cert destinationCertificate,
	fingerprint string,
) error {
	payload := map[string]any{
		"type": "key",
		"name": name,
		"relationships": map[string]any{
			"service_instance": map[string]any{
				"data": map[string]string{"guid": serviceInstanceGUID},
			},
		},
		"parameters": map[string]any{
			"certificate": cert.Certificate,
			"key":         cert.Key,
			"name":        cert.Name,
		},
		"metadata": map[string]any{
			"annotations": map[string]string{
				annotationFingerprint: fingerprint,
				annotationSyncedAt:    time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/v3/service_credential_bindings", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("create service key status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if resp.StatusCode == http.StatusAccepted {
		if err := waitForCFJob(ctx, client, apiURL, token, resp.Header.Get("Location")); err != nil {
			return fmt.Errorf("create service key async job failed: %w", err)
		}
	}

	return nil
}

func deleteServiceKey(ctx context.Context, client *http.Client, apiURL string, token string, guid string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, apiURL+"/v3/service_credential_bindings/"+guid, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("delete service key status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if resp.StatusCode == http.StatusAccepted {
		if err := waitForCFJob(ctx, client, apiURL, token, resp.Header.Get("Location")); err != nil {
			return fmt.Errorf("delete service key async job failed: %w", err)
		}
	}
	return nil
}

func waitForCFJob(ctx context.Context, client *http.Client, apiURL string, token string, location string) error {
	jobURL := strings.TrimSpace(location)
	if jobURL == "" {
		return errors.New("missing CF job location header")
	}
	if strings.HasPrefix(jobURL, "/") {
		jobURL = strings.TrimRight(apiURL, "/") + jobURL
	}

	deadline := time.Now().Add(2 * time.Minute)
	for {
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for CF async job")
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jobURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			resp.Body.Close()
			return fmt.Errorf("job status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var job cfJob
		decodeErr := json.NewDecoder(resp.Body).Decode(&job)
		resp.Body.Close()
		if decodeErr != nil {
			return decodeErr
		}

		switch strings.ToUpper(strings.TrimSpace(job.State)) {
		case "COMPLETE":
			return nil
		case "FAILED":
			if len(job.Errors) > 0 {
				return fmt.Errorf("%s: %s", strings.TrimSpace(job.Errors[0].Title), strings.TrimSpace(job.Errors[0].Detail))
			}
			return errors.New("job failed")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func certificateFingerprint(cert destinationCertificate) string {
	hash := sha256.Sum256([]byte(cert.Certificate + "\n" + cert.Key))
	return hex.EncodeToString(hash[:])
}
