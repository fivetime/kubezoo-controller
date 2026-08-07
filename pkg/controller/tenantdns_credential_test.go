/*
Copyright 2024 The KubeZoo Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// writeTestCA puts a throwaway CA on disk, because the signing helper takes file
// paths rather than material.
func writeTestCA(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kubezoo-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 3650),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signing the CA: %v", err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "ca.pem")
	keyFile = filepath.Join(dir, "ca-key.pem")
	write := func(path, blockType string, b []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: b}), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	write(certFile, "CERTIFICATE", der)
	write(keyFile, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	return certFile, keyFile
}

// TestEnsureTenantDNSCredentialCreatesWhenAbsent is the regression guard for a
// bug that reached a live cluster.
//
// ⛔ The not-found from the initial Get used to be re-read off `err` further
// down -- but `err` had been reassigned by the kubeconfig build in between, so
// a missing Secret took the UPDATE branch. Update on something that does not
// exist fails, so every tenant got "secrets <tid> not found" on every pass and
// no resolver was ever provisioned.
//
// ⚠️ The unit tests that existed at the time all passed: they covered the pure
// functions -- the Corefile, the renewal predicate -- and this bug lives
// entirely in the control flow around the client. That is why this test drives
// the real client path rather than another helper.
func TestEnsureTenantDNSCredentialCreatesWhenAbsent(t *testing.T) {
	caFile, caKeyFile := writeTestCA(t)
	client := fake.NewSimpleClientset()
	tc := &TenantController{
		upstreamCoreClient: client.CoreV1(),
		clientCAFile:       caFile,
		clientCAKeyFile:    caKeyFile,
		kubeZooHostAddress: "10.0.0.1:6443",
	}

	if err := tc.ensureTenantDNSCredential("111111"); err != nil {
		t.Fatalf("provisioning a credential for a tenant that has none: %v\n\n"+
			"a not-found Secret must be CREATED; taking the update branch here is what "+
			"stopped every tenant from ever getting a resolver", err)
	}
	secret, err := client.CoreV1().Secrets(TenantDNSNamespace).Get(context.TODO(), "111111", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the Secret was not created: %v", err)
	}
	if len(secret.Data["kubeconfig"]) == 0 {
		t.Error("the Secret carries no kubeconfig, so CoreDNS would start with no credential")
	}
	if secret.Labels[tenantDNSTenantLabelKey] != "111111" {
		t.Errorf("tenant label = %q, want 111111", secret.Labels[tenantDNSTenantLabelKey])
	}
	if _, ok := secret.Annotations["kubezoo.io/not-after"]; !ok {
		t.Error("no expiry annotation was written, so the renewal path would reissue on every pass")
	}
}

// TestEnsureTenantDNSCredentialIsIdempotent -- syncResources runs on update as
// well as create, so a second pass must not reissue. Reissuing every pass would
// churn the Secret and restart nothing, which reads as working right up until
// someone counts the certificates.
func TestEnsureTenantDNSCredentialIsIdempotent(t *testing.T) {
	caFile, caKeyFile := writeTestCA(t)
	client := fake.NewSimpleClientset()
	tc := &TenantController{
		upstreamCoreClient: client.CoreV1(),
		clientCAFile:       caFile,
		clientCAKeyFile:    caKeyFile,
		kubeZooHostAddress: "10.0.0.1:6443",
	}
	if err := tc.ensureTenantDNSCredential("111111"); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	first, _ := client.CoreV1().Secrets(TenantDNSNamespace).Get(context.TODO(), "111111", metav1.GetOptions{})
	if err := tc.ensureTenantDNSCredential("111111"); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	second, _ := client.CoreV1().Secrets(TenantDNSNamespace).Get(context.TODO(), "111111", metav1.GetOptions{})
	if string(first.Data["kubeconfig"]) != string(second.Data["kubeconfig"]) {
		t.Error("the credential was reissued on a second pass; reconciliation runs constantly, " +
			"so this would sign a new certificate every few minutes for every tenant")
	}
}

// TestEnsureTenantDNSCredentialRenewsWhenExpiring -- the other side of the same
// branch. A credential inside the renewal window must be replaced, or it expires
// and the tenant's DNS stops with no error anywhere in kubezoo.
func TestEnsureTenantDNSCredentialRenewsWhenExpiring(t *testing.T) {
	caFile, caKeyFile := writeTestCA(t)
	client := fake.NewSimpleClientset()
	tc := &TenantController{
		upstreamCoreClient: client.CoreV1(),
		clientCAFile:       caFile,
		clientCAKeyFile:    caKeyFile,
		kubeZooHostAddress: "10.0.0.1:6443",
	}
	if err := tc.ensureTenantDNSCredential("111111"); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	stale, _ := client.CoreV1().Secrets(TenantDNSNamespace).Get(context.TODO(), "111111", metav1.GetOptions{})
	stale.Annotations["kubezoo.io/not-after"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	stale.Data["kubeconfig"] = []byte("about-to-expire")
	if _, err := client.CoreV1().Secrets(TenantDNSNamespace).Update(context.TODO(), stale, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("seeding an expiring credential: %v", err)
	}

	if err := tc.ensureTenantDNSCredential("111111"); err != nil {
		t.Fatalf("renewal pass: %v", err)
	}
	renewed, _ := client.CoreV1().Secrets(TenantDNSNamespace).Get(context.TODO(), "111111", metav1.GetOptions{})
	if string(renewed.Data["kubeconfig"]) == "about-to-expire" {
		t.Error("an expiring credential was left in place; when it lapses the resolver gets 401s " +
			"from kubezoo and serves an ever-staler cache, with nothing in kubezoo reporting it")
	}
}
