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
