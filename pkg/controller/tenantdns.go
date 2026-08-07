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
	"fmt"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
	return tc.ensureTenantDNSDeployment(tenantID)
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
				// Baseline rather than restricted: CoreDNS runs unprivileged, and
				// saying so here keeps a cluster with PodSecurity enforcement from
				// refusing the Deployment with an admission error that reads as a
				// kubezoo bug.
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
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
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
	// Only the two things an operator changes between releases. Rewriting the
	// whole spec every pass would fight anything else that legitimately edits it.
	if len(existing.Spec.Template.Spec.Containers) == 1 &&
		existing.Spec.Template.Spec.Containers[0].Image == tc.tenantDNSImage &&
		ptr.Deref(existing.Spec.Replicas, 1) == tc.tenantDNSReplicas {
		return nil
	}
	want.ResourceVersion = existing.ResourceVersion
	_, err = tc.upstreamAppsClient.Deployments(TenantDNSNamespace).Update(ctx, want, metav1.UpdateOptions{})
	return err
}
