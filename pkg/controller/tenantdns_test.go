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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestCorefileForwardsWhatItCannotAnswer guards the line whose absence would be
// the most damaging thing in this file.
//
// ⛔ Pods get dnsPolicy: None with this resolver as their ONLY nameserver. So
// anything the resolver does not answer, they cannot resolve at all -- every
// name outside the cluster included. Dropping the forward line would take a
// tenant's public DNS away as the price of fixing its internal DNS, and the
// cluster-internal tests would all still pass.
func TestCorefileForwardsWhatItCannotAnswer(t *testing.T) {
	corefile := tenantDNSCorefile("111111", "cluster.local")
	if !strings.Contains(corefile, "forward . /etc/resolv.conf") {
		t.Errorf("the Corefile does not forward:\n%s\n\n"+
			"pods point at this resolver and nothing else, so without a forward they lose "+
			"every name outside the cluster", corefile)
	}
	if !strings.Contains(corefile, "kubernetes cluster.local") {
		t.Errorf("the Corefile does not serve the cluster domain:\n%s", corefile)
	}
	if !strings.Contains(corefile, "kubeconfig /etc/coredns-kubeconfig/kubeconfig") {
		t.Errorf("the Corefile does not read kubezoo with the tenant credential:\n%s\n\n"+
			"without it CoreDNS falls back to in-cluster config and builds records from the "+
			"UPSTREAM view, which is the leak this whole thing exists to close", corefile)
	}
}

// TestCorefileUsesTheConfiguredClusterDomain -- the domain the resolver serves
// and the search suffixes the gateway writes into pods have to agree. They
// disagree silently: short names simply stop resolving.
func TestCorefileUsesTheConfiguredClusterDomain(t *testing.T) {
	corefile := tenantDNSCorefile("111111", "zoo.internal")
	if !strings.Contains(corefile, "kubernetes zoo.internal") {
		t.Errorf("a non-default cluster domain was ignored:\n%s", corefile)
	}
}

// TestCredentialRenewal locks the reissue window.
//
// ⭐ A certificate that just expires takes the tenant's DNS down with no error
// anywhere in kubezoo: the resolver gets 401s, serves a stale cache, and names
// stop resolving. Renewing early is the whole defence, so the boundary cases are
// worth pinning.
func TestCredentialRenewal(t *testing.T) {
	secretExpiring := func(in time.Duration) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
				"kubezoo.io/not-after": time.Now().Add(in).UTC().Format(time.RFC3339),
			}},
			Data: map[string][]byte{"kubeconfig": []byte("x")},
		}
	}
	cases := map[string]struct {
		secret *corev1.Secret
		want   bool
	}{
		"fresh":                   {secretExpiring(300 * 24 * time.Hour), false},
		"inside the renew window": {secretExpiring(10 * 24 * time.Hour), true},
		"already expired":         {secretExpiring(-time.Hour), true},
		"no kubeconfig": {&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{"kubezoo.io/not-after": time.Now().Add(300 * 24 * time.Hour).UTC().Format(time.RFC3339)},
		}}, true},
		// ⚠️ An unannotated secret predates the renewal logic. Treating it as
		// fine would leave exactly the silent expiry this guards against.
		"no annotation":          {&corev1.Secret{Data: map[string][]byte{"kubeconfig": []byte("x")}}, true},
		"unparseable annotation": {&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"kubezoo.io/not-after": "soon"}}, Data: map[string][]byte{"kubeconfig": []byte("x")}}, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tenantDNSCredentialNeedsRenewal(c.secret); got != c.want {
				t.Errorf("needsRenewal = %v, want %v", got, c.want)
			}
		})
	}
}

// TestPerTenantDNSIsOffUnlessFullyConfigured -- a half-configured resolver is
// worse than none. syncTenantDNS keys off a nil apps client rather than a
// boolean so the two cannot disagree; this pins what makes it nil.
func TestPerTenantDNSIsOffUnlessFullyConfigured(t *testing.T) {
	notNil := fake.NewSimpleClientset().AppsV1()
	for name, o := range map[string]TenantDNSOptions{
		"disabled":          {Enabled: false, Image: "i", ClusterDomain: "cluster.local"},
		"no image":          {Enabled: true, ClusterDomain: "cluster.local"},
		"no cluster domain": {Enabled: true, Image: "i"},
	} {
		t.Run(name, func(t *testing.T) {
			if appsClientIfEnabled(notNil, o) != nil {
				t.Error("the apps client was kept for an incompletely configured resolver; " +
					"provisioning would then run with an empty image or domain")
			}
		})
	}
	if appsClientIfEnabled(notNil, TenantDNSOptions{Enabled: true, Image: "i", ClusterDomain: "cluster.local"}) == nil {
		t.Error("a fully configured resolver was disabled anyway, which turns the feature off silently")
	}
}
