package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCertificateFingerprintStable(t *testing.T) {
	cert := destinationCertificate{Name: "cert-a", Certificate: "CERTDATA", Key: "KEYDATA"}

	first := certificateFingerprint(cert)
	second := certificateFingerprint(cert)

	if first == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if first != second {
		t.Fatalf("expected stable fingerprint, got %q and %q", first, second)
	}
}

func TestCertificateFingerprintChangesWithCertificate(t *testing.T) {
	base := destinationCertificate{Name: "cert-a", Certificate: "CERTDATA", Key: "KEYDATA"}
	changed := destinationCertificate{Name: "cert-a", Certificate: "CERTDATA-NEW", Key: "KEYDATA"}

	if certificateFingerprint(base) == certificateFingerprint(changed) {
		t.Fatal("expected fingerprint to change when certificate changes")
	}
}

func TestCertificateFingerprintChangesWithKey(t *testing.T) {
	base := destinationCertificate{Name: "cert-a", Certificate: "CERTDATA", Key: "KEYDATA"}
	changed := destinationCertificate{Name: "cert-a", Certificate: "CERTDATA", Key: "KEYDATA-NEW"}

	if certificateFingerprint(base) == certificateFingerprint(changed) {
		t.Fatal("expected fingerprint to change when key changes")
	}
}

func TestCertificateFingerprintIgnoresName(t *testing.T) {
	base := destinationCertificate{Name: "cert-a", Certificate: "CERTDATA", Key: "KEYDATA"}
	renamed := destinationCertificate{Name: "cert-b", Certificate: "CERTDATA", Key: "KEYDATA"}

	if certificateFingerprint(base) != certificateFingerprint(renamed) {
		t.Fatal("expected fingerprint to stay the same when only name changes")
	}
}

func TestParseDestinationCertificatesWrappedEmpty(t *testing.T) {
	certs, err := parseDestinationCertificates([]byte(`{"certificates":[]}`))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected zero certificates, got %d", len(certs))
	}
}

func TestParseDestinationCertificatesWrappedNonEmpty(t *testing.T) {
	certs, err := parseDestinationCertificates([]byte(`{"certificates":[{"name":"a","certificate":"CERT-A","key":"KEY-A"}]}`))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected one certificate, got %d", len(certs))
	}
	if certs[0].Name != "a" || certs[0].Certificate != "CERT-A" || certs[0].Key != "KEY-A" {
		t.Fatalf("unexpected certificate: %+v", certs[0])
	}
}

func TestParseDestinationCertificatesNormalizesAndFilters(t *testing.T) {
	payload := []byte(`[
		{"name":"a","certificate":"CERT-A","key":"KEY-A"},
		{"Name":"b","clientcert":"CERT-B","clientkey":"KEY-B"},
		{"name":"missing-cert","key":"KEY"},
		{"certificate":"CERT-NO-NAME","key":"KEY-NO-NAME"}
	]`)

	certs, err := parseDestinationCertificates(payload)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(certs))
	}
	if certs[0].Name != "a" || certs[0].Certificate != "CERT-A" || certs[0].Key != "KEY-A" {
		t.Fatalf("unexpected first certificate: %+v", certs[0])
	}
	if certs[1].Name != "b" || certs[1].Certificate != "CERT-B" || certs[1].Key != "KEY-B" {
		t.Fatalf("unexpected second certificate: %+v", certs[1])
	}
}

func TestParseDestinationCertificatesInvalidWrappedValue(t *testing.T) {
	_, err := parseDestinationCertificates([]byte(`{"certificates":"invalid"}`))
	if err == nil {
		t.Fatal("expected an error for invalid wrapped certificate payload")
	}
}

func TestSyncCertificatesDetectsTargetNameCollisionAfterPrefixTrim(t *testing.T) {
	cfg := config{
		CFDefaultServiceInstance: "service-instance-guid",
		NamePrefix:               "pre-",
		DryRun:                   true,
	}
	client := &http.Client{Timeout: 1 * time.Second}
	certs := []destinationCertificate{
		{Name: "pre-a", Certificate: "CERT-A", Key: "KEY-A"},
		{Name: "pre- a", Certificate: "CERT-B", Key: "KEY-B"},
	}

	_, _, _, err := syncCertificates(context.Background(), client, cfg, "token", certs, nil)
	if err == nil {
		t.Fatal("expected collision error")
	}
	if !strings.Contains(err.Error(), "multiple certificates resolve to target key name") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSameOriginTreatsDefaultHttpsPortAsEquivalent(t *testing.T) {
	a, _ := url.Parse("https://api.example.com")
	b, _ := url.Parse("https://api.example.com:443")
	if !sameOrigin(a, b) {
		t.Fatal("expected same origin with implicit and explicit default HTTPS port")
	}
}

func TestWaitForCFJobResolvesRelativeLocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/jobs/abc" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"state":"COMPLETE"}`))
	}))
	defer server.Close()

	err := waitForCFJob(context.Background(), server.Client(), server.URL, "token", "/v3/jobs/abc")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestWaitForCFJobRejectsCrossOriginLocation(t *testing.T) {
	serverA := httptest.NewServer(http.NotFoundHandler())
	defer serverA.Close()
	serverB := httptest.NewServer(http.NotFoundHandler())
	defer serverB.Close()

	err := waitForCFJob(context.Background(), serverA.Client(), serverA.URL, "token", serverB.URL+"/v3/jobs/abc")
	if err == nil {
		t.Fatal("expected cross-origin rejection")
	}
	if !strings.Contains(err.Error(), "host does not match CF API host") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateServiceKeyDisablesCertificatePinning(t *testing.T) {
	var captured map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/service_credential_bindings" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	err := createServiceKey(
		context.Background(),
		server.Client(),
		server.URL,
		"token",
		"key-name",
		"instance-guid",
		destinationCertificate{Name: "cert-a", Certificate: "CERT", Key: "KEY"},
		"fingerprint",
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	parameters, ok := captured["parameters"].(map[string]any)
	if !ok {
		t.Fatalf("expected parameters object, got %#v", captured["parameters"])
	}

	certificatePinning, ok := parameters["certificate_pinning"].(bool)
	if !ok {
		t.Fatalf("expected certificate_pinning bool, got %#v", parameters["certificate_pinning"])
	}
	if certificatePinning {
		t.Fatal("expected certificate_pinning to be false")
	}
}
