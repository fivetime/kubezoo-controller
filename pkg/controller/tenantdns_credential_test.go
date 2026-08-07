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
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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

// TestTenantKubernetesServiceIsHeadless -- the record has to hand the pod
// kubezoo's own address.
//
// ⛔ A ClusterIP here would need the datapath to carry traffic to an address in
// ANOTHER cluster, and the serverless nodes in this deployment do not implement
// ClusterIP at all -- measured: a ClusterIP in the tenant cluster timed out from
// such a pod while kubezoo's own address answered. A headless record works on
// both kinds of node because nothing has to be programmed for it.
func TestTenantKubernetesServiceIsHeadless(t *testing.T) {
	client := fake.NewSimpleClientset()
	tc := &TenantController{
		upstreamCoreClient:          client.CoreV1(),
		upstreamEndpointSliceClient: client.DiscoveryV1(),
		kubeZooHostAddress:          "10.224.18.51:6443",
	}
	if err := tc.ensureTenantKubernetesService("111111"); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	svc, err := client.CoreV1().Services("111111-default").Get(context.TODO(), "kubernetes", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the Service was not created: %v", err)
	}
	if svc.Spec.ClusterIP != "None" {
		t.Errorf("clusterIP = %q, want None", svc.Spec.ClusterIP)
	}
	slice, err := client.DiscoveryV1().EndpointSlices("111111-default").Get(context.TODO(), "kubernetes-kubezoo", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the EndpointSlice was not created: %v", err)
	}
	if len(slice.Endpoints) != 1 || len(slice.Endpoints[0].Addresses) != 1 ||
		slice.Endpoints[0].Addresses[0] != "10.224.18.51" {
		t.Errorf("endpoints = %+v, want the kubezoo address 10.224.18.51", slice.Endpoints)
	}
	if len(slice.Ports) != 1 || slice.Ports[0].Port == nil || *slice.Ports[0].Port != 443 {
		t.Errorf("port = %+v, want 443 -- a client resolving kubernetes.default.svc and dialling "+
			"https:// uses 443, so an SRV record saying anything else disagrees with reality",
			slice.Ports)
	}
}

// TestTenantKubernetesServiceIsRepaired -- this one lives in a namespace the
// TENANT can write, unlike the rest of the resolver. A tenant that replaces it
// with an ordinary Service must get the headless one back; clusterIP is
// immutable, so the repair has to delete and recreate rather than update.
func TestTenantKubernetesServiceIsRepaired(t *testing.T) {
	client := fake.NewSimpleClientset()
	tc := &TenantController{
		upstreamCoreClient:          client.CoreV1(),
		upstreamEndpointSliceClient: client.DiscoveryV1(),
		kubeZooHostAddress:          "10.224.18.51:6443",
	}
	if err := tc.ensureTenantKubernetesService("111111"); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	hijacked, _ := client.CoreV1().Services("111111-default").Get(context.TODO(), "kubernetes", metav1.GetOptions{})
	hijacked.Spec.ClusterIP = "254.51.9.9"
	if _, err := client.CoreV1().Services("111111-default").Update(context.TODO(), hijacked, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("seeding a hijacked Service: %v", err)
	}

	if err := tc.ensureTenantKubernetesService("111111"); err != nil {
		t.Fatalf("repair pass: %v", err)
	}
	repaired, _ := client.CoreV1().Services("111111-default").Get(context.TODO(), "kubernetes", metav1.GetOptions{})
	if repaired.Spec.ClusterIP != "None" {
		t.Errorf("clusterIP = %q after repair, want None; the tenant's own pods would keep "+
			"resolving kubernetes.default.svc to an address nothing answers on",
			repaired.Spec.ClusterIP)
	}
}

// TestTenantKubernetesServiceSkippedForANonIPAddress -- an EndpointSlice address
// must be an IP, and configuring kubezoo by DNS name is legitimate. Skipping
// beats writing an invalid object that the apiserver refuses on every pass.
func TestTenantKubernetesServiceSkippedForANonIPAddress(t *testing.T) {
	client := fake.NewSimpleClientset()
	tc := &TenantController{
		upstreamCoreClient:          client.CoreV1(),
		upstreamEndpointSliceClient: client.DiscoveryV1(),
		kubeZooHostAddress:          "kubezoo.example.com:6443",
	}
	if err := tc.ensureTenantKubernetesService("111111"); err != nil {
		t.Fatalf("a non-IP address must be skipped, not fail the whole reconcile: %v", err)
	}
	if _, err := client.CoreV1().Services("111111-default").Get(context.TODO(), "kubernetes", metav1.GetOptions{}); err == nil {
		t.Error("a Service was created whose EndpointSlice cannot be written")
	}
}

// TestResolverCredentialIsNotTheTenantAdmin is the regression guard for a
// defect that reached a live cluster and was found by reading a Secret.
//
// ⛔ The resolver used to authenticate as CN=<tid>-admin -- byte-for-byte the
// same subject as the tenant's own kubeconfig. So a DNS server, a process that
// accepts UDP from the network, held full write over every one of that tenant's
// namespaces; and the platform stored that key permanently, which is precisely
// what credential-retention exists to prevent ("the platform hands it over once
// and then stops holding the tenant's private key").
//
// The OU must still name the tenant -- that is how kubezoo decides whose objects
// a request concerns -- so this checks the two halves separately.
func TestResolverCredentialIsNotTheTenantAdmin(t *testing.T) {
	caFile, caKeyFile := writeTestCA(t)
	client := fake.NewSimpleClientset()
	tc := &TenantController{
		upstreamCoreClient: client.CoreV1(),
		clientCAFile:       caFile,
		clientCAKeyFile:    caKeyFile,
		kubeZooHostAddress: "10.0.0.1:6443",
	}
	if err := tc.ensureTenantDNSCredential("111111"); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	secret, _ := client.CoreV1().Secrets(TenantDNSNamespace).Get(context.TODO(), "111111", metav1.GetOptions{})

	var certPEM []byte
	for _, line := range strings.Split(string(secret.Data["kubeconfig"]), "\n") {
		if strings.Contains(line, "client-certificate-data:") {
			raw := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			decoded, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				t.Fatalf("decoding the embedded certificate: %v", err)
			}
			certPEM = decoded
		}
	}
	if certPEM == nil {
		t.Fatal("the kubeconfig carries no client certificate")
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("the client certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the client certificate: %v", err)
	}

	if cert.Subject.CommonName == "111111-admin" {
		t.Error("the resolver authenticates as the tenant ADMINISTRATOR. It needs get/list/watch " +
			"on three resource kinds; this gives a network-facing DNS server write over every one " +
			"of the tenant's namespaces, and makes the platform a permanent holder of a key that " +
			"acts as the tenant")
	}
	if cert.Subject.CommonName != "111111-dns" {
		t.Errorf("CN = %q, want 111111-dns", cert.Subject.CommonName)
	}
	// ⚠️ The other half. Dropping the OU would not fail any RBAC assertion -- it
	// would make kubezoo unable to tell whose objects the resolver is asking
	// about, which surfaces as an empty zone rather than an error.
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "111111" {
		t.Errorf("OU = %v, want [111111]; kubezoo derives the tenant from it",
			cert.Subject.OrganizationalUnit)
	}
}

// TestCorefileDoesNotWatchPods -- "pods verified" makes CoreDNS hold an informer
// over every pod the tenant runs, which is where a resolver's memory actually
// goes. The 256Mi limit then becomes an OOMKill that arrives at whatever pod
// count a given tenant reaches, with "DNS is flaky" as the only symptom. What it
// buys is 10-1-2-3.ns.pod.<zone> records, which almost nothing uses.
func TestCorefileDoesNotWatchPods(t *testing.T) {
	corefile := tenantDNSCorefile("111111", "cluster.local")
	if strings.Contains(corefile, "pods verified") || strings.Contains(corefile, "pods insecure") {
		t.Errorf("the resolver watches pods:\n%s\n\nmemory then scales with the tenant's pod "+
			"count against a fixed limit", corefile)
	}
	if !strings.Contains(corefile, "pods disabled") {
		t.Errorf("the pod-watching mode is not stated explicitly:\n%s\n\nleaving it out takes "+
			"CoreDNS's default rather than a decision", corefile)
	}
}
