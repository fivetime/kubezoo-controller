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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"github.com/fivetime/kubezoo-contract/pkg/util"
)

const (
	// TenantDNSNamespace is where every tenant's resolver lives.
	//
	// ⛔ A PLATFORM namespace, never the tenant's own <tid>-kube-system. A tenant
	// holds namespaced write on every namespace kubezoo makes for it, so a
	// resolver kept there is one the tenant can repoint at an address of its
	// choosing -- and because the pods reading it are that same tenant's, nothing
	// upstream would report an error. It would simply resolve differently.
	//
	// ⚠️ Duplicated in the gateway's pkg/tenantdns, and NOTHING checks the two
	// against each other -- they are separate repositories, so no test can see
	// both. A change to one alone makes every lookup miss, and a miss fails open,
	// so the only symptom is tenants quietly going back to the platform resolver.
	// These belong in kubezoo-contract, which both already depend on; moving them
	// there costs a contract release, which is why it has not happened yet.
	TenantDNSNamespace = "kubezoo-tenant-dns"

	// tenantDNSServiceLabelKey and tenantDNSTenantLabelKey are what the gateway
	// selects and keys on. Changing either here without changing pkg/tenantdns
	// there makes every lookup miss -- and a miss fails open, so the only symptom
	// is tenants quietly going back to the platform resolver.
	tenantDNSServiceLabelKey = "kubezoo.io/tenant-dns"
	tenantDNSTenantLabelKey  = "kubezoo.io/tenant"

	// tenantDNSSpecHashAnnotation records the spec this controller asked for,
	// so a change to it reaches tenants that already have a resolver.
	tenantDNSSpecHashAnnotation = "kubezoo.io/spec-hash"

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
)

// tenantDNSName is the name every per-tenant object gets. The Service being
// named for its tenant is what makes the gateway's lookup a keyed one.
func tenantDNSName(tenantID string) string { return tenantID }

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
	if err := tc.ensureTenantDNSNamespace(); err != nil {
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
	record(tc.upstreamAppsClient.Deployments(TenantDNSNamespace).Delete(ctx, name, metav1.DeleteOptions{}))
	record(tc.upstreamCoreClient.Services(TenantDNSNamespace).Delete(ctx, name, metav1.DeleteOptions{}))
	record(tc.upstreamCoreClient.ConfigMaps(TenantDNSNamespace).Delete(ctx, name, metav1.DeleteOptions{}))
	record(tc.upstreamCoreClient.Secrets(TenantDNSNamespace).Delete(ctx, name, metav1.DeleteOptions{}))
	return firstErr
}

func (tc *TenantController) ensureTenantDNSNamespace() error {
	ctx := context.TODO()
	_, err := tc.upstreamCoreClient.Namespaces().Get(ctx, TenantDNSNamespace, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	_, err = tc.upstreamCoreClient.Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: TenantDNSNamespace,
			Labels: map[string]string{
				"kubezoo.io/managed": "true",
				// The resolver runs unprivileged and the pod spec is written to
				// satisfy this, NET_BIND_SERVICE included -- which is the one
				// capability "restricted" permits to be added.
				"pod-security.kubernetes.io/enforce": "restricted",
			},
		},
	}, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
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
	existing, err := tc.upstreamCoreClient.Secrets(TenantDNSNamespace).Get(ctx, name, metav1.GetOptions{})
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
		if !tenantDNSCredentialNeedsRenewal(existing) {
			return nil
		}
		klog.InfoS("renewing the tenant resolver credential before it expires", "tenant", tenantID)
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
			Namespace: TenantDNSNamespace,
			Labels: map[string]string{
				tenantDNSServiceLabelKey: "true",
				tenantDNSTenantLabelKey:  tenantID,
			},
			Annotations: map[string]string{
				// Read back by tenantDNSCredentialNeedsRenewal rather than parsing
				// the certificate on every pass.
				"kubezoo.io/not-after": notAfter.UTC().Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{"kubeconfig": kubeconfig},
	}
	if missing {
		_, cerr := tc.upstreamCoreClient.Secrets(TenantDNSNamespace).Create(ctx, secret, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(cerr) {
			return nil
		}
		return cerr
	}
	secret.ResourceVersion = existing.ResourceVersion
	_, err = tc.upstreamCoreClient.Secrets(TenantDNSNamespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

func tenantDNSCredentialNeedsRenewal(secret *corev1.Secret) bool {
	if len(secret.Data["kubeconfig"]) == 0 {
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
	cert, key, err := util.NewTenantCertAndKey(tc.clientCAFile, tc.clientCAKeyFile, tenantID,
		tenantDNSCredentialValidity)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("signing the resolver credential for tenant %s: %w", tenantID, err)
	}
	caCert, err := os.ReadFile(tc.clientCAFile)
	if err != nil {
		return nil, time.Time{}, err
	}
	// ⚠️ The resolver runs in the UPSTREAM cluster and kubezoo does not, so this
	// is a cross-cluster connection and the address has to be the external one --
	// the same kubeZooHostAddress a tenant's own kubeconfig gets. A Service name
	// would resolve to nothing from here.
	kubeconfig, err := util.GenKubeconfig("https://"+tc.kubeZooHostAddress, tenantID, caCert,
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
        pods verified
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
			Namespace: TenantDNSNamespace,
			Labels: map[string]string{
				tenantDNSServiceLabelKey: "true",
				tenantDNSTenantLabelKey:  tenantID,
			},
		},
		Data: map[string]string{"Corefile": want},
	}
	existing, err := tc.upstreamCoreClient.ConfigMaps(TenantDNSNamespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, cerr := tc.upstreamCoreClient.ConfigMaps(TenantDNSNamespace).Create(ctx, cm, metav1.CreateOptions{})
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
	_, err = tc.upstreamCoreClient.ConfigMaps(TenantDNSNamespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

func (tc *TenantController) ensureTenantDNSService(tenantID string) error {
	ctx := context.TODO()
	name := tenantDNSName(tenantID)
	_, err := tc.upstreamCoreClient.Services(TenantDNSNamespace).Get(ctx, name, metav1.GetOptions{})
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
	_, err = tc.upstreamCoreClient.Services(TenantDNSNamespace).Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: TenantDNSNamespace,
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
	labels := map[string]string{tenantDNSTenantLabelKey: tenantID, "app": "kubezoo-tenant-dns"}
	want := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: TenantDNSNamespace,
			Labels: map[string]string{
				tenantDNSServiceLabelKey: "true",
				tenantDNSTenantLabelKey:  tenantID,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](tc.tenantDNSReplicas),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
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

	existing, err := tc.upstreamAppsClient.Deployments(TenantDNSNamespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, cerr := tc.upstreamAppsClient.Deployments(TenantDNSNamespace).Create(ctx, want, metav1.CreateOptions{})
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
	_, err = tc.upstreamAppsClient.Deployments(TenantDNSNamespace).Update(ctx, want, metav1.UpdateOptions{})
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
