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
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"github.com/fivetime/kubezoo-contract/pkg/common"
	"github.com/fivetime/kubezoo-contract/pkg/util"
)

const (
	// LegacyTenantDNSNamespace is the platform namespace resolvers used to live
	// in, kept only so the reconciler can clean up what it no longer owns.
	//
	// A tenant billed for a pod has to be able to see that pod, and a resolver in
	// a platform namespace is invisible to the tenant paying for it. That is why
	// it moved; the objection recorded here before -- that a tenant holds write
	// on its own namespaces and could repoint its resolver -- is real but
	// self-inflicted: the pods reading it are that same tenant's, so the blast
	// radius stops at the tenant that did it.
	LegacyTenantDNSNamespace = "kubezoo-tenant-dns"

	// TenantDNSName is what every resolver object is called inside the tenant's
	// own kube-system.
	//
	// ⚠️ Fixed rather than per-tenant, and that is load-bearing: the gateway
	// watches EndpointSlices with the static label selector
	// kubernetes.io/service-name=<this>, which is only possible because the
	// Service has the same name in every tenant. A per-tenant name would force a
	// selector-free cluster-wide EndpointSlice watch -- every slice in the
	// cluster, for three objects.
	TenantDNSName = "kubezoo-dns"

	// tenantDNSServiceLabelKey and tenantDNSTenantLabelKey are what the gateway
	// selects and keys on. Changing either here without changing pkg/tenantdns
	// there makes every lookup miss -- and a miss fails open, so the only symptom
	// is tenants quietly going back to the platform resolver.
	//
	// ⚠️ Duplicated in the gateway's pkg/tenantdns, and NOTHING checks the two
	// against each other -- they are separate repositories, so no test can see
	// both. These belong in kubezoo-contract, which both already depend on;
	// moving them there costs a contract release, which is why it has not
	// happened yet. TenantDNSName above is now duplicated the same way.

	tenantDNSServiceLabelKey = "kubezoo.io/tenant-dns"
	tenantDNSTenantLabelKey  = "kubezoo.io/tenant"

	// tenantDNSPlatformLabelKey marks a pod the platform runs inside a tenant's
	// namespace, so admission policies written for tenant workloads can exclude
	// it. See where it is set for why this one cannot be skipped.
	tenantDNSPlatformLabelKey = "kubezoo.io/platform-workload"

	// tenantDNSSpecHashAnnotation records the spec this controller asked for,
	// so a change to it reaches tenants that already have a resolver.
	tenantDNSSpecHashAnnotation = "kubezoo.io/spec-hash"
	// tenantDNSSubjectAnnotation records WHICH identity a stored credential was
	// issued for, and tenantDNSCredentialHashAnnotation carries a fingerprint of
	// it onto the Deployment.
	//
	// ⛔ Both exist because reconciling on expiry alone converges on time and
	// nothing else: when the identity changed from <tid>-admin to <tid>-dns,
	// every tenant already holding a year-long credential kept the admin one,
	// forever. The same shape as comparing only the image on the Deployment --
	// a reconciler that watches a chosen subset stops converging the moment the
	// interesting change falls outside it.
	tenantDNSSubjectAnnotation        = "kubezoo.io/subject-cn"
	tenantDNSCredentialHashAnnotation = "kubezoo.io/credential-hash"

	// tenantKubernetesServicePort is what the tenant's own kubernetes Service
	// reports. 443 rather than kubezoo's configured port because a client that
	// resolves kubernetes.default.svc and dials https:// uses 443 -- so kubezoo's
	// Service has to publish 443, and this has to agree with it.
	tenantKubernetesServicePort = 443

	tenantDNSPort     = 5353
	tenantDNSReadyPrt = 8181

	// tenantDNSCredentialValidity is how long the resolver's own client
	// certificate is good for, and tenantDNSCredentialRenewAt is how much
	// remaining life triggers reissue.
	//
	// ⚠️ This credential is NOT the tenant's issued kubeconfig. That one is
	// handed over once and then deliberately forgotten by the platform, so it
	// cannot be reused here; this is a separate certificate carrying the same
	// tenant identity, held by the platform for as long as the tenant exists.
	tenantDNSCredentialValidity = 365 * 24 * time.Hour
	tenantDNSCredentialRenewAt  = 30 * 24 * time.Hour

	// TenantDNSOptOutAnnotation, on a Tenant, means "this tenant resolves names
	// somewhere else -- do not give it a resolver".
	//
	// ⭐ This is what keeps the pod spec honest. The gateway only injects
	// dnsPolicy: None when a resolver exists, so opting a tenant out means its
	// pods keep the platform resolver and their stored spec says so. Provisioning
	// a resolver for a tenant whose data plane ignores dnsConfig -- an OpenStack
	// Zun capsule resolving through Designate, measured -- would store a
	// nameserver that nothing on that node ever reads: the object would claim a
	// resolver the pod does not use, and no component anywhere would report the
	// disagreement.
	TenantDNSOptOutAnnotation = "kubezoo.io/tenant-dns"
	tenantDNSOptOutValue      = "disabled"

	// tenantDNSReaderRole is the read-only ClusterRole the resolver's own
	// identity is bound to.
	tenantDNSReaderRole = "kubezoo:tenant-dns-reader"
)

// tenantDNSReaderBinding names the per-tenant ClusterRoleBinding that carries
// the resolver's read. Per tenant, never one shared binding: the subject is what
// keeps one tenant's resolver out of another's, so a shared binding would have
// to list every tenant and would grant each of them the others' reach.
func tenantDNSReaderBinding(tenantID string) string {
	return tenantDNSReaderRole + ":" + tenantID
}

// tenantDNSUser is the identity the resolver authenticates as.
//
// ⛔ NOT the tenant's admin user. It used to be: buildTenantDNSKubeconfig called
// util.NewTenantCertAndKey, which mints CN=<tid>-admin, so a DNS server -- a
// process that accepts UDP from the network -- held full write over every one of
// that tenant's namespaces, and the platform stored that key permanently. That
// second half contradicts the whole point of credential-retention, which exists
// so the platform stops holding a key that can act as the tenant.
//
// Measured on the lab cluster before the change: the resolver's certificate and
// the tenant's own were byte-for-byte the same subject, OU=<tid> CN=<tid>-admin,
// and the resolver's expired nine months later.
func tenantDNSUser(tenantID string) string { return tenantID + "-dns" }

// tenantDNSName is the name every per-tenant object gets. Constant now that the
// objects live in the tenant's own namespace: the namespace carries the tenant,
// so the name no longer has to, and a constant is what lets the gateway watch
// EndpointSlices with a static selector.
func tenantDNSName(string) string { return TenantDNSName }

// tenantDNSNamespace is the tenant's own kube-system.
//
// ⭐ The resolver lives where the tenant can see it because the tenant is billed
// for it. A pod charged to someone who cannot list it is a line on an invoice
// with nothing behind it.
//
// ⚠️ Two consequences worth being deliberate about rather than surprised by:
//   - The tenant can read the Secret holding the resolver's credential. That
//     credential is strictly narrower than the tenant's own -- three resources,
//     read-only, and usable only through kubezoo -- so reading it gains nothing.
//     It is still a platform-held private key sitting somewhere the tenant can
//     read, which is the strongest remaining argument for a ServiceAccount.
//   - The tenant can delete or edit these objects. The reconciler puts them
//     back; in between, that tenant's own pods lose DNS. Nobody else's do.
func tenantDNSNamespace(tenantID string) string {
	return tenantID + "-kube-system"
}

// syncTenantDNS provisions the tenant's own resolver, idempotently.
//
// Everything here converges: syncResources runs on update as well as create, so
// a hand-deleted Deployment comes back on the next pass, exactly like
// syncNamespaces.
func (tc *TenantController) syncTenantDNS(tenantID string) error {
	if tc.upstreamAppsClient == nil {
		// No apps client means the controller was built without per-tenant DNS.
		// Silent is right here -- but only because the gateway fails open, so
		// the tenant keeps the platform resolver rather than getting none.
		return nil
	}
	if tc.tenantOptedOutOfDNS(tenantID) {
		// ⭐ Torn down rather than merely skipped. A tenant that had a resolver and
		// is then opted out must stop having one, or the gateway keeps finding its
		// Service and keeps writing a nameserver into pods that will not use it.
		return tc.deleteTenantDNS(tenantID)
	}
	if err := tc.removeLegacyTenantDNS(tenantID); err != nil {
		return err
	}
	if err := tc.ensureTenantDNSRBAC(tenantID); err != nil {
		return err
	}
	if err := tc.ensureTenantDNSCredential(tenantID); err != nil {
		return err
	}
	if err := tc.ensureTenantDNSConfig(tenantID); err != nil {
		return err
	}
	// ⭐ Service BEFORE Deployment. The gateway reads the Service's ClusterIP to
	// decide what to write into pods; creating the Deployment first would leave a
	// window where a resolver is running that nothing points at, which is merely
	// wasteful -- but the reverse order costs nothing and closes it.
	if err := tc.ensureTenantDNSService(tenantID); err != nil {
		return err
	}
	if err := tc.ensureTenantDNSDeployment(tenantID); err != nil {
		return err
	}
	return tc.ensureTenantKubernetesService(tenantID)
}

// ensureTenantKubernetesService gives the tenant a kubernetes Service of its own
// that points at kubezoo.
//
// ⭐ Without it, kubernetes.default.svc.cluster.local is NXDOMAIN once a tenant
// is on its own resolver -- the tenant cannot see the platform's kubernetes
// Service, so the resolver has nothing to build that record from. Failing closed
// is the safe direction, but it is still a regression: nearly everything written
// to run in a cluster reaches for that name.
//
// ⛔ Headless, with the endpoint written by hand. A ClusterIP would need the
// datapath to program a route to an address in ANOTHER cluster, and on node
// types that do not implement ClusterIP at all -- the serverless ones here --
// nothing would carry it. A headless record hands the pod kubezoo's own address
// and the pod connects to it directly, which works on both.
//
// ⚠️ The port. A headless Service does no proxying, so the number below decides
// only what an SRV lookup reports; a client resolving kubernetes.default.svc and
// dialling https:// uses 443 whatever this says. That is why kubezoo's own
// Service must publish 443 alongside its 6443 -- and why this declares 443
// rather than kubezoo's configured port, so the SRV record agrees with where
// traffic actually goes.
//
// ⚠️ Not a substitute for the KUBERNETES_SERVICE_HOST injection. kubelet skips
// env vars for headless Services, so a pod still gets that variable from the
// platform's own kubernetes Service. DNS and the environment point at different
// places until the policy layer sets the variable too.
func (tc *TenantController) ensureTenantKubernetesService(tenantID string) error {
	host, _, err := net.SplitHostPort(tc.kubeZooHostAddress)
	if err != nil || net.ParseIP(host) == nil {
		// An EndpointSlice address must be an IP. A DNS name for kubezoo is a
		// legitimate configuration, it just cannot be expressed here.
		klog.InfoS("skipping the tenant kubernetes Service: kubezoo's address is not an IP",
			"tenant", tenantID, "address", tc.kubeZooHostAddress)
		return nil
	}

	ctx := context.TODO()
	ns := tenantID + "-default"
	labels := map[string]string{
		tenantDNSServiceLabelKey: "true",
		tenantDNSTenantLabelKey:  tenantID,
	}

	// ⚠️ Repaired rather than left alone if it already exists. This one lives in
	// a namespace the TENANT can write, unlike everything else here, so a tenant
	// that deletes or edits it gets it back on the next pass. Its own doing and
	// its own breakage either way, but converging costs nothing.
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: ns, Labels: labels},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Ports: []corev1.ServicePort{
				{Name: "https", Port: tenantKubernetesServicePort, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	existingSvc, err := tc.upstreamCoreClient.Services(ns).Get(ctx, "kubernetes", metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, cerr := tc.upstreamCoreClient.Services(ns).Create(ctx, svc, metav1.CreateOptions{}); cerr != nil &&
			!apierrors.IsAlreadyExists(cerr) {
			return cerr
		}
	case err != nil:
		return err
	case existingSvc.Spec.ClusterIP != corev1.ClusterIPNone:
		// A tenant replaced it with an ordinary Service. clusterIP is immutable,
		// so the only repair is to replace the object.
		if derr := tc.upstreamCoreClient.Services(ns).Delete(ctx, "kubernetes", metav1.DeleteOptions{}); derr != nil {
			return derr
		}
		if _, cerr := tc.upstreamCoreClient.Services(ns).Create(ctx, svc, metav1.CreateOptions{}); cerr != nil &&
			!apierrors.IsAlreadyExists(cerr) {
			return cerr
		}
	}

	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes-kubezoo",
			Namespace: ns,
			Labels: map[string]string{
				discoveryv1.LabelServiceName: "kubernetes",
				tenantDNSServiceLabelKey:     "true",
				tenantDNSTenantLabelKey:      tenantID,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports: []discoveryv1.EndpointPort{{
			Name:     ptr.To("https"),
			Port:     ptr.To[int32](tenantKubernetesServicePort),
			Protocol: ptr.To(corev1.ProtocolTCP),
		}},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{host},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		}},
	}
	existingSlice, err := tc.upstreamEndpointSliceClient.EndpointSlices(ns).Get(ctx, slice.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, cerr := tc.upstreamEndpointSliceClient.EndpointSlices(ns).Create(ctx, slice, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(cerr) {
			return nil
		}
		return cerr
	}
	if err != nil {
		return err
	}
	if len(existingSlice.Endpoints) == 1 && len(existingSlice.Endpoints[0].Addresses) == 1 &&
		existingSlice.Endpoints[0].Addresses[0] == host {
		return nil
	}
	slice.ResourceVersion = existingSlice.ResourceVersion
	_, err = tc.upstreamEndpointSliceClient.EndpointSlices(ns).Update(ctx, slice, metav1.UpdateOptions{})
	return err
}

// deleteTenantDNS removes what syncTenantDNS made.
//
// ⚠️ Needed explicitly. Everything else this controller provisions for a tenant
// lives in the tenant's own namespaces and is garbage-collected when those are
// deleted; these objects live in a platform namespace and would outlive the
// tenant, holding a ClusterIP and a running pod each.
func (tc *TenantController) deleteTenantDNS(tenantID string) error {
	if tc.upstreamAppsClient == nil {
		return nil
	}
	name := tenantDNSName(tenantID)
	ctx := context.TODO()
	var firstErr error
	record := func(err error) {
		if err != nil && !apierrors.IsNotFound(err) && firstErr == nil {
			firstErr = err
		}
	}
	record(tc.upstreamAppsClient.Deployments(tenantDNSNamespace(tenantID)).Delete(ctx, name, metav1.DeleteOptions{}))
	record(tc.upstreamCoreClient.Services(tenantDNSNamespace(tenantID)).Delete(ctx, name, metav1.DeleteOptions{}))
	record(tc.upstreamCoreClient.ConfigMaps(tenantDNSNamespace(tenantID)).Delete(ctx, name, metav1.DeleteOptions{}))
	record(tc.upstreamCoreClient.Secrets(tenantDNSNamespace(tenantID)).Delete(ctx, name, metav1.DeleteOptions{}))

	// ⚠️ And the tenant's own kubernetes Service, which lives in the TENANT's
	// namespace rather than the platform one and so was missed the first time.
	// Without a resolver it serves nothing -- the platform's CoreDNS builds that
	// tenant's records under the upstream namespace, so nothing ever asks for
	// kubernetes.default.svc in the tenant's view -- and an orphan Service named
	// "kubernetes" sitting in a tenant namespace is the kind of leftover that
	// gets explained as deliberate years later.
	tenantNS := tenantID + "-default"
	record(tc.upstreamCoreClient.Services(tenantNS).Delete(ctx, "kubernetes", metav1.DeleteOptions{}))
	if tc.upstreamEndpointSliceClient != nil {
		record(tc.upstreamEndpointSliceClient.EndpointSlices(tenantNS).Delete(ctx, "kubernetes-kubezoo", metav1.DeleteOptions{}))
	}

	// ⛔ And the authorization. This was missed entirely: teardown removed every
	// object that costs something to run and left the grant behind, so a tenant
	// that had DNS once kept a standing cluster-wide read for an identity with
	// no pod to use it. Cluster-scoped, so nothing garbage-collects it with the
	// tenant's namespaces either -- an audit found twelve of these still bound.
	//
	// The ClusterRole itself is shared by every tenant and deliberately survives:
	// it grants nothing once no binding names it, and deleting it while another
	// tenant still resolves would take that tenant's DNS down.
	record(tc.upstreamRbacClient.ClusterRoleBindings().Delete(ctx, tenantDNSReaderBinding(tenantID), metav1.DeleteOptions{}))
	if err := tc.removeTenantDNSNamespaceBindings(ctx, tenantID); err != nil && firstErr == nil {
		firstErr = err
	}
	// ⚠️ And whatever this tenant still has in the platform namespace. Teardown
	// runs on opt-out too, so a tenant opting out before the reconciler had
	// migrated it would otherwise keep a resolver nobody looks at any more.
	if err := tc.removeLegacyTenantDNS(tenantID); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// removeLegacyTenantDNS deletes the resolver this tenant used to have in the
// platform namespace.
//
// ⭐ Part of the reconcile path, not a migration script. A reconciler that
// creates the new shape and leaves the old one running is how a cluster ends up
// with two resolvers per tenant, one of them serving an address nothing points
// at any more -- and the tenant is billed for neither, because the leftover is
// in a namespace it cannot see.
//
// Deliberately does not delete the platform namespace itself: it may hold
// resolvers for tenants this loop has not reached yet, and an empty namespace
// costs nothing.
func (tc *TenantController) removeLegacyTenantDNS(tenantID string) error {
	ctx := context.TODO()
	legacy := tenantID
	var firstErr error
	record := func(err error) {
		if err != nil && !apierrors.IsNotFound(err) && firstErr == nil {
			firstErr = err
		}
	}
	record(tc.upstreamAppsClient.Deployments(LegacyTenantDNSNamespace).Delete(ctx, legacy, metav1.DeleteOptions{}))
	record(tc.upstreamCoreClient.Services(LegacyTenantDNSNamespace).Delete(ctx, legacy, metav1.DeleteOptions{}))
	record(tc.upstreamCoreClient.ConfigMaps(LegacyTenantDNSNamespace).Delete(ctx, legacy, metav1.DeleteOptions{}))
	record(tc.upstreamCoreClient.Secrets(LegacyTenantDNSNamespace).Delete(ctx, legacy, metav1.DeleteOptions{}))
	return firstErr
}

// ensureTenantDNSCredential mints, and later renews, the certificate the
// resolver authenticates to kubezoo with.
//
// ⭐ Renewal is the point. A certificate that simply expires would take the
// tenant's DNS down with no error anywhere in kubezoo -- the resolver would get
// 401s from kubezoo, serve an increasingly stale cache, and the tenant would see
// names stop resolving. That is the silent-cliff shape, and the answer is to
// reissue before it arrives rather than to alert once it has.
func (tc *TenantController) ensureTenantDNSCredential(tenantID string) error {
	ctx := context.TODO()
	name := tenantDNSName(tenantID)
	existing, err := tc.upstreamCoreClient.Secrets(tenantDNSNamespace(tenantID)).Get(ctx, name, metav1.GetOptions{})
	// ⛔ Recorded as a bool BEFORE anything else can touch err. It was read off
	// err further down at first, and by then err had been reassigned by the
	// kubeconfig build below -- so a missing secret took the update branch, which
	// updates nothing and returns "secrets <tid> not found" forever. Every tenant
	// failed to get a resolver, and the only symptom outside the controller log
	// was that per-tenant DNS silently never appeared, because the gateway fails
	// open. Found on a live cluster, not by a test.
	missing := apierrors.IsNotFound(err)
	switch {
	case err == nil:
		if !tenantDNSCredentialNeedsRenewal(existing, tenantDNSUser(tenantID)) {
			return nil
		}
		klog.InfoS("reissuing the tenant resolver credential", "tenant", tenantID,
			"storedSubject", existing.Annotations[tenantDNSSubjectAnnotation],
			"wantSubject", tenantDNSUser(tenantID))
	case missing:
	default:
		return err
	}

	kubeconfig, notAfter, err := tc.buildTenantDNSKubeconfig(tenantID)
	if err != nil {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: tenantDNSNamespace(tenantID),
			Labels: map[string]string{
				tenantDNSServiceLabelKey: "true",
				tenantDNSTenantLabelKey:  tenantID,
			},
			Annotations: map[string]string{
				// Read back by tenantDNSCredentialNeedsRenewal rather than parsing
				// the certificate on every pass.
				"kubezoo.io/not-after":     notAfter.UTC().Format(time.RFC3339),
				tenantDNSSubjectAnnotation: tenantDNSUser(tenantID),
			},
		},
		Data: map[string][]byte{"kubeconfig": kubeconfig},
	}
	if missing {
		_, cerr := tc.upstreamCoreClient.Secrets(tenantDNSNamespace(tenantID)).Create(ctx, secret, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(cerr) {
			return nil
		}
		return cerr
	}
	secret.ResourceVersion = existing.ResourceVersion
	_, err = tc.upstreamCoreClient.Secrets(tenantDNSNamespace(tenantID)).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

func tenantDNSCredentialNeedsRenewal(secret *corev1.Secret, wantSubject string) bool {
	if len(secret.Data["kubeconfig"]) == 0 {
		return true
	}
	// ⛔ Checked before the expiry. A credential issued for a different identity
	// is wrong however much life it has left -- and the one this replaced was
	// the tenant's own administrator.
	if secret.Annotations[tenantDNSSubjectAnnotation] != wantSubject {
		return true
	}
	raw, ok := secret.Annotations["kubezoo.io/not-after"]
	if !ok {
		// ⚠️ An unannotated secret predates the renewal logic. Reissue rather
		// than assume it is fine: assuming leaves exactly the expiry this
		// function exists to prevent, and reissuing costs one certificate.
		return true
	}
	notAfter, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return true
	}
	return time.Until(notAfter) < tenantDNSCredentialRenewAt
}

// buildTenantDNSKubeconfig signs a client certificate carrying the tenant's
// identity and wraps it in a kubeconfig pointed at kubezoo.
func (tc *TenantController) buildTenantDNSKubeconfig(tenantID string) ([]byte, time.Time, error) {
	// ⛔ Signed here rather than through util.NewTenantCertAndKey, which hardcodes
	// CN=<tid>-admin. A resolver needs get/list/watch on three resource kinds; it
	// was being handed the tenant's administrator.
	tlsCert, err := tls.LoadX509KeyPair(tc.clientCAFile, tc.clientCAKeyFile)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("loading the tenant CA: %w", err)
	}
	caKey, ok := tlsCert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, time.Time{}, fmt.Errorf("the tenant CA key is not a crypto.Signer")
	}
	caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parsing the tenant CA: %w", err)
	}
	cert, key, err := util.NewCertAndKey(caCert, caKey, &util.Config{
		// The OU still names the tenant -- that is how kubezoo decides whose
		// objects a request is about, and the resolver must see that tenant's.
		// Only the CN changes, and the CN is the RBAC subject.
		OrganizationalUnit: []string{tenantID},
		CommonName:         tenantDNSUser(tenantID),
		Usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Validity:           tenantDNSCredentialValidity,
	})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("signing the resolver credential for tenant %s: %w", tenantID, err)
	}
	caCertPEM, err := os.ReadFile(tc.clientCAFile)
	if err != nil {
		return nil, time.Time{}, err
	}
	// ⚠️ The resolver runs in the UPSTREAM cluster and kubezoo does not, so this
	// is a cross-cluster connection and the address has to be the external one --
	// the same kubeZooHostAddress a tenant's own kubeconfig gets. A Service name
	// would resolve to nothing from here.
	kubeconfig, err := util.GenKubeconfig("https://"+tc.kubeZooHostAddress, tenantID, caCertPEM,
		util.EncodePrivateKeyPEM(key), util.EncodeCertPEM(cert))
	if err != nil {
		return nil, time.Time{}, err
	}
	return kubeconfig, cert.NotAfter, nil
}

// tenantDNSCorefile is what the resolver serves.
//
// ⛔ The forward line is not optional. Pods get dnsPolicy: None with this
// resolver as their only nameserver, so anything this does not answer, they
// cannot resolve at all -- including every name outside the cluster. Without it
// the change would take the tenant's public DNS away as the price of fixing
// its internal DNS.
func tenantDNSCorefile(tenantID, clusterDomain string) string {
	return fmt.Sprintf(`.:%d {
    errors
    health :8080
    ready :%d
    prometheus :9153
    kubernetes %s in-addr.arpa ip6.arpa {
        kubeconfig /etc/coredns-kubeconfig/kubeconfig
        # ⛔ Disabled, not "verified". Verified makes CoreDNS watch EVERY pod the
        # tenant runs, and that informer cache is where a resolver's memory
        # actually goes -- so the 256Mi limit below becomes an OOMKill that
        # arrives at whatever pod count a particular tenant happens to reach,
        # with "DNS is flaky" as the only symptom. What it buys is
        # 10-1-2-3.ns.pod.<zone> records, which almost nothing uses.
        pods disabled
        ttl 5
    }
    forward . /etc/resolv.conf
    cache 30
    reload 5s
}
`, tenantDNSPort, tenantDNSReadyPrt, clusterDomain)
}

func (tc *TenantController) ensureTenantDNSConfig(tenantID string) error {
	ctx := context.TODO()
	name := tenantDNSName(tenantID)
	want := tenantDNSCorefile(tenantID, tc.tenantDNSClusterDomain)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: tenantDNSNamespace(tenantID),
			Labels: map[string]string{
				tenantDNSServiceLabelKey: "true",
				tenantDNSTenantLabelKey:  tenantID,
			},
		},
		Data: map[string]string{"Corefile": want},
	}
	existing, err := tc.upstreamCoreClient.ConfigMaps(tenantDNSNamespace(tenantID)).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, cerr := tc.upstreamCoreClient.ConfigMaps(tenantDNSNamespace(tenantID)).Create(ctx, cm, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(cerr) {
			return nil
		}
		return cerr
	}
	if err != nil {
		return err
	}
	if existing.Data["Corefile"] == want {
		return nil
	}
	// Drift, from a hand edit or from a change to the template. CoreDNS reloads
	// the file on its own (reload 5s), so no restart is needed.
	cm.ResourceVersion = existing.ResourceVersion
	_, err = tc.upstreamCoreClient.ConfigMaps(tenantDNSNamespace(tenantID)).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

func (tc *TenantController) ensureTenantDNSService(tenantID string) error {
	ctx := context.TODO()
	name := tenantDNSName(tenantID)
	_, err := tc.upstreamCoreClient.Services(tenantDNSNamespace(tenantID)).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		// ⚠️ Not repaired in place. The ClusterIP is what the gateway has already
		// written into every pod this tenant is running; rewriting the Service
		// could reallocate it and leave those pods pointed at nothing, and a pod
		// cannot be updated to a new one because dnsConfig is immutable.
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	_, err = tc.upstreamCoreClient.Services(tenantDNSNamespace(tenantID)).Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: tenantDNSNamespace(tenantID),
			Labels: map[string]string{
				tenantDNSServiceLabelKey: "true",
				tenantDNSTenantLabelKey:  tenantID,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{tenantDNSTenantLabelKey: tenantID, "app": "kubezoo-tenant-dns"},
			Ports: []corev1.ServicePort{
				{Name: "dns-udp", Port: 53, TargetPort: intstr.FromInt32(tenantDNSPort), Protocol: corev1.ProtocolUDP},
				{Name: "dns-tcp", Port: 53, TargetPort: intstr.FromInt32(tenantDNSPort), Protocol: corev1.ProtocolTCP},
			},
		},
	}, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func (tc *TenantController) ensureTenantDNSDeployment(tenantID string) error {
	ctx := context.TODO()
	name := tenantDNSName(tenantID)
	// ⛔ tenantDNSPlatformLabelKey is what keeps the placement policy off this pod,
	// and it is load-bearing now that the resolver lives in the tenant's own
	// kube-system. That policy matches every namespace carrying kubezoo.io/tenant
	// -- which <tid>-kube-system does -- and injects nodeSelector
	// kubezoo.io/pool=<tid>. On this deployment that pool is a virtual kubelet
	// that does not implement ClusterIP, so the resolver would be scheduled onto
	// a node where it cannot serve, and the only symptom would be a resolver that
	// never becomes ready. The policy in kubezoo-contract excludes this label;
	// a deployment running some other placement policy has to do the same.
	labels := map[string]string{
		tenantDNSTenantLabelKey:   tenantID,
		tenantDNSPlatformLabelKey: "true",
		"app":                     "kubezoo-tenant-dns",
	}

	// ⛔ The credential's fingerprint rides on the POD TEMPLATE, so reissuing it
	// rolls the pods. CoreDNS builds its client once at startup and never rereads
	// the kubeconfig, so a rotated Secret lands in the mounted file and changes
	// nothing: the resolver keeps presenting the old certificate until something
	// restarts it. Without this, credential rotation is a no-op that looks like
	// it worked right up to the day the old one expires.
	credHash := ""
	if sec, err := tc.upstreamCoreClient.Secrets(tenantDNSNamespace(tenantID)).Get(ctx, name, metav1.GetOptions{}); err == nil {
		sum := sha256.Sum256(sec.Data["kubeconfig"])
		credHash = hex.EncodeToString(sum[:8])
	}

	want := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: tenantDNSNamespace(tenantID),
			Labels: map[string]string{
				tenantDNSServiceLabelKey: "true",
				tenantDNSTenantLabelKey:  tenantID,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](tc.tenantDNSReplicas),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labels,
					Annotations: map[string]string{tenantDNSCredentialHashAnnotation: credHash},
				},
				Spec: corev1.PodSpec{
					// ⛔ Explicitly the platform's own DNS, not this pod's tenant.
					// A resolver configured to resolve through itself cannot start:
					// it needs DNS to reach kubezoo, and it is what would answer.
					DNSPolicy:                    corev1.DNSClusterFirst,
					AutomountServiceAccountToken: ptr.To(false),
					Containers: []corev1.Container{{
						Name:  "coredns",
						Image: tc.tenantDNSImage,
						Args:  []string{"-conf", "/etc/coredns/Corefile"},
						Ports: []corev1.ContainerPort{
							{ContainerPort: tenantDNSPort, Protocol: corev1.ProtocolUDP},
							{ContainerPort: tenantDNSPort, Protocol: corev1.ProtocolTCP},
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "config", MountPath: "/etc/coredns"},
							{Name: "kubeconfig", MountPath: "/etc/coredns-kubeconfig", ReadOnly: true},
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
								Path: "/ready", Port: intstr.FromInt32(tenantDNSReadyPrt)}},
							InitialDelaySeconds: 5, PeriodSeconds: 5,
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							RunAsNonRoot:             ptr.To(true),
							RunAsUser:                ptr.To[int64](65532),
							// ⛔ NET_BIND_SERVICE is not optional, and not because
							// anything binds a low port -- the resolver listens on
							// 5353. The CoreDNS binary carries the FILE capability
							// cap_net_bind_service, and allowPrivilegeEscalation:
							// false sets no_new_privs, under which the kernel
							// refuses to exec a file whose permitted set is not
							// within the container's bounding set. The pod does not
							// fail a probe or log a DNS error; it never starts, with
							// "exec container process /coredns: Operation not
							// permitted" and nothing else. Measured on cri-o+crun.
							//
							// This is what the upstream CoreDNS manifest does, and
							// NET_BIND_SERVICE is the one capability PodSecurity
							// "restricted" allows to be added, so the namespace label
							// below still holds.
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
								Add:  []corev1.Capability{"NET_BIND_SERVICE"},
							},
							ReadOnlyRootFilesystem: ptr.To(true),
							SeccompProfile:         &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
							Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "config", VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: name}}}},
						{Name: "kubeconfig", VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{SecretName: name}}},
					},
				},
			},
		},
	}

	// ⭐ A hash of what this function WANTS, stamped on the object.
	//
	// ⚠️ Comparing a few fields instead -- the image and the replica count were
	// the first attempt -- converges on those and nothing else, so a fix to the
	// pod spec never reaches the tenants that already have a resolver. The
	// securityContext repair that made these pods able to start at all would
	// have shipped and changed nothing.
	//
	// ⚠️ And comparing the whole spec cannot work either: the apiserver defaults
	// fields this does not set, so the stored object never equals the desired one
	// and every pass would issue an Update. The hash is over what was ASKED for,
	// which is stable.
	hash := specHash(&want.Spec)
	want.Annotations = map[string]string{tenantDNSSpecHashAnnotation: hash}

	existing, err := tc.upstreamAppsClient.Deployments(tenantDNSNamespace(tenantID)).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, cerr := tc.upstreamAppsClient.Deployments(tenantDNSNamespace(tenantID)).Create(ctx, want, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(cerr) {
			return nil
		}
		return cerr
	}
	if err != nil {
		return err
	}
	if existing.Annotations[tenantDNSSpecHashAnnotation] == hash {
		return nil
	}
	want.ResourceVersion = existing.ResourceVersion
	_, err = tc.upstreamAppsClient.Deployments(tenantDNSNamespace(tenantID)).Update(ctx, want, metav1.UpdateOptions{})
	return err
}

// specHash summarises the spec this controller asked for.
func specHash(spec *appsv1.DeploymentSpec) string {
	encoded, err := json.Marshal(spec)
	if err != nil {
		// Cannot happen for a spec built above, and returning a constant would
		// make every object look up to date forever.
		return "unhashable"
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:8])
}

// tenantOptedOutOfDNS reports whether this tenant resolves names elsewhere.
//
// ⭐ Exists because a resolver a tenant's pods cannot use is worse than no
// resolver: the gateway would write dnsPolicy: None and a nameserver into every
// pod, the stored spec would claim a resolver the runtime ignores, and nothing
// would report the disagreement. Measured on an OpenStack Zun capsule, whose DNS
// comes from Designate and which discards dnsConfig entirely -- by design, not
// as a gap: that data plane has its own DNS story.
func (tc *TenantController) tenantOptedOutOfDNS(tenantID string) bool {
	tenant, err := tc.tenantLister.Get(tenantID)
	if err != nil {
		// ⚠️ Treated as opted IN, matching suspensionModeOf: assuming the
		// restrictive answer on a transient cache miss would tear down every
		// tenant's resolver at once, which is far worse than briefly leaving one
		// standing for a tenant that asked not to have it.
		klog.Warningf("cannot read tenant %s to check its DNS opt-out, provisioning a resolver: %v",
			tenantID, err)
		return false
	}
	return tenant.Annotations[TenantDNSOptOutAnnotation] == tenantDNSOptOutValue
}

// ensureTenantDNSRBAC grants the resolver's own identity what it reads, and
// nothing else.
//
// ⛔ This used to bind the ClusterRole with namespace RoleBindings only, on the
// reasoning that a cluster-scoped grant held by a USER is a grant over every
// tenant's cluster-scoped objects. That reasoning was wrong here, and the cost
// of the mistake was that CoreDNS could never start: a RoleBinding cannot grant
// list/watch on `namespaces`, which is cluster-scoped, and the kubernetes plugin
// needs it. The resolver sat at Plugins not ready: "kubernetes" forever, and the
// gateway -- which by then refuses a resolver that is not serving -- correctly
// declined to inject it, so the whole feature was silently off.
//
// ⭐ What makes the ClusterRoleBinding safe is that the subject is per-tenant.
// The premise behind the old comment was that kubezoo strips the tenant prefix
// from a certificate's CN, so every tenant's resolver would authenticate as the
// same bare `dns` and one cluster-wide grant would cover them all. It does not
// strip it: CommonNameUserConversion sets Name = CommonName verbatim, so the
// subject really is `<tid>-dns` and the grant reaches one tenant's resolver.
// (The prefix does get stripped from the NAME QUOTED BACK in a Forbidden
// message, which is what made it look otherwise -- read the subject of the
// binding that works, not the error text of the one that does not.)
//
// ⭐ And the grant cannot leak across tenants even though the rule is
// cluster-wide, because the resolver reaches the API only through kubezoo, which
// filters a cluster-scoped list to the tenant's own objects. Measured on the
// live cluster: the resolver for 111111 listing namespaces gets its own four,
// prefix-stripped, and nothing belonging to 222222.
func (tc *TenantController) ensureTenantDNSRBAC(tenantID string) error {
	ctx := context.TODO()
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: tenantDNSReaderRole},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"services", "namespaces"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"discovery.k8s.io"},
				Resources: []string{"endpointslices"},
				Verbs:     []string{"get", "list", "watch"},
			},
			// ⚠️ No pods. The Corefile says "pods disabled" for the memory reason
			// written there, and a grant for something nothing reads is a grant
			// that outlives the reason it was added.
		},
	}
	if _, err := tc.upstreamRbacClient.ClusterRoles().Create(ctx, role, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("creating %s: %w", tenantDNSReaderRole, err)
		}
		if _, err := tc.upstreamRbacClient.ClusterRoles().Update(ctx, role, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("reconciling %s: %w", tenantDNSReaderRole, err)
		}
	}

	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: tenantDNSReaderBinding(tenantID)},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: tenantDNSReaderRole,
		},
		Subjects: []rbacv1.Subject{{
			APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: tenantDNSUser(tenantID),
		}},
	}
	// ⚠️ Create-then-Update, not Create-and-swallow-AlreadyExists. A binding
	// reconciled only on creation is a binding whose Subjects and RoleRef stop
	// converging the moment either changes -- and the identity in Subjects is
	// exactly the field a future change to how the resolver authenticates would
	// move. The existing objects on the live cluster were written by hand while
	// diagnosing this and have to be reconciled into shape, not left alone.
	if _, err := tc.upstreamRbacClient.ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("granting the resolver read for %s: %w", tenantID, err)
		}
		existing, getErr := tc.upstreamRbacClient.ClusterRoleBindings().Get(ctx, binding.Name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("reading %s: %w", binding.Name, getErr)
		}
		// RoleRef is immutable, so a binding pointing somewhere else has to be
		// replaced rather than updated.
		if existing.RoleRef != binding.RoleRef {
			if err := tc.upstreamRbacClient.ClusterRoleBindings().Delete(ctx, binding.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("replacing %s: %w", binding.Name, err)
			}
			if _, err := tc.upstreamRbacClient.ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("replacing %s: %w", binding.Name, err)
			}
		} else {
			existing.Subjects = binding.Subjects
			if _, err := tc.upstreamRbacClient.ClusterRoleBindings().Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("reconciling %s: %w", binding.Name, err)
			}
		}
	}

	return tc.removeTenantDNSNamespaceBindings(ctx, tenantID)
}

// removeTenantDNSNamespaceBindings clears the per-namespace RoleBindings this
// function used to write.
//
// ⚠️ They granted the resolver nothing it does not now hold cluster-wide, so
// leaving them would be invisible rather than harmful -- which is the reason to
// remove them deliberately instead of trusting that. A grant nobody can explain
// is a grant nobody dares delete later.
func (tc *TenantController) removeTenantDNSNamespaceBindings(ctx context.Context, tenantID string) error {
	namespaces, err := tc.upstreamCoreClient.Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{common.TenantNamespaceLabelKey: tenantID}).String(),
	})
	if err != nil {
		return err
	}
	for i := range namespaces.Items {
		ns := namespaces.Items[i]
		if ns.Status.Phase == corev1.NamespaceTerminating {
			continue
		}
		err := tc.upstreamRbacClient.RoleBindings(ns.Name).Delete(ctx, tenantDNSReaderRole, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("removing the superseded resolver binding in %s: %w", ns.Name, err)
		}
	}
	return nil
}
