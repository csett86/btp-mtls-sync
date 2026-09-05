package main

import "testing"

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
