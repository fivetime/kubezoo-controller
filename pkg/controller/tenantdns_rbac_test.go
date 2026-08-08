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
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/fivetime/kubezoo-contract/pkg/common"
)

func rbacFixture(tenantIDs ...string) (*fake.Clientset, *TenantController) {
	objects := []runtime.Object{}
	for _, id := range tenantIDs {
		for _, suffix := range []string{"-default", "-kube-system"} {
			objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name:   id + suffix,
				Labels: map[string]string{common.TenantNamespaceLabelKey: id},
			}})
		}
	}
	client := fake.NewSimpleClientset(objects...)
	return client, &TenantController{
		upstreamCoreClient: client.CoreV1(),
		upstreamRbacClient: client.RbacV1(),
	}
}

// TestResolverReadIsBoundAtClusterScope is the regression guard for a grant that
// was written at the wrong scope for the resource it had to cover.
//
// ⛔ The read was bound with per-namespace RoleBindings, on the reasoning that a
// cluster-scoped grant held by a user reaches every tenant. But `namespaces` is
// itself cluster-scoped, and no RoleBinding can grant list/watch on it, so
// CoreDNS's kubernetes plugin never synced: the pod stayed at
// Plugins not ready: "kubernetes" and the gateway -- correctly refusing a
// resolver that is not serving -- left the whole feature off.
//
// ⚠️ Nothing failed loudly. Services and EndpointSlices resolved fine under the
// RoleBindings, so the credential, the Corefile and the Service all tested good;
// the one resource that needed a different scope was the one nothing checked.
func TestResolverReadIsBoundAtClusterScope(t *testing.T) {
	client, tc := rbacFixture("111111")
	if err := tc.ensureTenantDNSRBAC("111111"); err != nil {
		t.Fatalf("granting the resolver its read: %v", err)
	}

	binding, err := client.RbacV1().ClusterRoleBindings().Get(
		context.TODO(), tenantDNSReaderBinding("111111"), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("no ClusterRoleBinding for the resolver: %v\n\n"+
			"a RoleBinding cannot grant list/watch on namespaces, which is cluster-scoped, "+
			"so CoreDNS never syncs and the resolver never becomes ready", err)
	}
	if binding.RoleRef.Name != tenantDNSReaderRole || binding.RoleRef.Kind != "ClusterRole" {
		t.Errorf("roleRef = %s/%s, want ClusterRole/%s",
			binding.RoleRef.Kind, binding.RoleRef.Name, tenantDNSReaderRole)
	}

	// ⭐ The subject is the whole isolation argument. The grant is cluster-wide,
	// so if it named anything shared between tenants it would be a grant over
	// every tenant at once. It is safe only because `<tid>-dns` belongs to one
	// tenant -- kubezoo passes the certificate's CN through unchanged -- and
	// because kubezoo filters a cluster-scoped list to that tenant's objects.
	if len(binding.Subjects) != 1 {
		t.Fatalf("subjects = %v, want exactly one", binding.Subjects)
	}
	subject := binding.Subjects[0]
	if subject.Kind != rbacv1.UserKind || subject.Name != tenantDNSUser("111111") {
		t.Errorf("subject = %s/%q, want User/%q -- a cluster-wide grant to any name not "+
			"unique to this tenant reaches every tenant's resolver",
			subject.Kind, subject.Name, tenantDNSUser("111111"))
	}
}

// TestResolverBindingConvergesOnSubjectChange -- the binding used to be created
// and never reconciled, so the field most likely to change (who the resolver
// authenticates as) was the field that would silently stop converging. The live
// cluster already holds bindings written by hand during diagnosis.
func TestResolverBindingConvergesOnSubjectChange(t *testing.T) {
	client, tc := rbacFixture("111111")
	stale := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: tenantDNSReaderBinding("111111")},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: tenantDNSReaderRole,
		},
		Subjects: []rbacv1.Subject{{
			APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: "111111-admin",
		}},
	}
	if _, err := client.RbacV1().ClusterRoleBindings().Create(context.TODO(), stale, metav1.CreateOptions{}); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if err := tc.ensureTenantDNSRBAC("111111"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}
	got, err := client.RbacV1().ClusterRoleBindings().Get(
		context.TODO(), tenantDNSReaderBinding("111111"), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the binding disappeared: %v", err)
	}
	if got.Subjects[0].Name != tenantDNSUser("111111") {
		t.Errorf("subject = %q, want %q -- an existing binding was left holding a stale "+
			"identity, which is how a changed identity never reaches an existing tenant",
			got.Subjects[0].Name, tenantDNSUser("111111"))
	}
}

// TestTeardownRemovesTheGrant -- teardown deleted everything that costs money to
// run and left the authorization behind, so a tenant that once had DNS kept a
// standing cluster-wide read for an identity with no pod. Cluster-scoped, so the
// tenant's namespaces being deleted does not collect it either.
func TestTeardownRemovesTheGrant(t *testing.T) {
	client, tc := rbacFixture("111111")
	tc.upstreamAppsClient = client.AppsV1()
	if err := tc.ensureTenantDNSRBAC("111111"); err != nil {
		t.Fatalf("granting: %v", err)
	}
	if err := tc.deleteTenantDNS("111111"); err != nil {
		t.Fatalf("tearing down: %v", err)
	}
	_, err := client.RbacV1().ClusterRoleBindings().Get(
		context.TODO(), tenantDNSReaderBinding("111111"), metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("the resolver's cluster-wide read survived teardown (err=%v); "+
			"an audit found twelve of these still bound to tenants with no resolver", err)
	}
}

// TestSupersededNamespaceBindingsAreRemoved -- every tenant provisioned before
// this change carries four RoleBindings that the cluster-scoped grant now covers.
// They authorize nothing new, which is exactly why they would never be noticed.
func TestSupersededNamespaceBindingsAreRemoved(t *testing.T) {
	client, tc := rbacFixture("111111")
	for _, ns := range []string{"111111-default", "111111-kube-system"} {
		_, err := client.RbacV1().RoleBindings(ns).Create(context.TODO(), &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: tenantDNSReaderRole, Namespace: ns},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: tenantDNSReaderRole,
			},
			Subjects: []rbacv1.Subject{{
				APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: tenantDNSUser("111111"),
			}},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("seeding %s: %v", ns, err)
		}
	}
	if err := tc.ensureTenantDNSRBAC("111111"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}
	for _, ns := range []string{"111111-default", "111111-kube-system"} {
		_, err := client.RbacV1().RoleBindings(ns).Get(context.TODO(), tenantDNSReaderRole, metav1.GetOptions{})
		if !apierrors.IsNotFound(err) {
			t.Errorf("the superseded RoleBinding in %s was left behind (err=%v)", ns, err)
		}
	}
}

// TestOneTenantsGrantDoesNotNameAnother -- the binding name and its subject both
// carry the tenant id, so a mistake in either would be one tenant's resolver
// holding a grant issued for someone else.
func TestOneTenantsGrantDoesNotNameAnother(t *testing.T) {
	client, tc := rbacFixture("111111", "222222")
	for _, id := range []string{"111111", "222222"} {
		if err := tc.ensureTenantDNSRBAC(id); err != nil {
			t.Fatalf("granting for %s: %v", id, err)
		}
	}
	bindings, err := client.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(bindings.Items) != 2 {
		t.Fatalf("got %d bindings, want one per tenant", len(bindings.Items))
	}
	for _, b := range bindings.Items {
		want := tenantDNSUser(b.Name[len(b.Name)-6:])
		if b.Subjects[0].Name != want {
			t.Errorf("binding %q names subject %q, want %q", b.Name, b.Subjects[0].Name, want)
		}
	}
}

// TestResolverDoesNotClaimTheClusterDNSLabel is the regression guard for a
// label that read as cosmetic and was an instruction to another controller.
//
// ⛔ k8s-app=kube-dns is cilium-operator's default --pod-restart-selector
// (cilium/operator/unmanagedpods/cell.go). It deletes every Running pod
// carrying it that has no CiliumEndpoint, on a 15s sweep. A resolver on a
// tenant's own data plane never has one -- it is not on the Cilium data path --
// so wearing this label had it deleted roughly every 60s, forever.
//
// ⚠️ Cilium's own safety valve does not damp it: the 5-minute cooldown is keyed
// by namespace/name and the ReplicaSet renames every replacement, so the key
// never matches. Nor is there an Event; that package emits a metric and one log
// line, which is why this cost five wrong guesses to find.
//
// ⭐ The claim is what was wrong, not the mechanism. A pod off Cilium's data
// path saying "I am the cluster's kube-dns" is a false statement to a
// controller entitled to act on it. The stock NAMES stay -- Deployment coredns,
// Service kube-dns -- because those are what a tenant reads and they collide
// with nothing.
func TestResolverDoesNotClaimTheClusterDNSLabel(t *testing.T) {
	if tenantDNSAppLabel == "kube-dns" {
		t.Fatal("the resolver claims k8s-app=kube-dns again; cilium-operator will " +
			"delete its pods every ~60s and say so only in its own log")
	}
}

// TestSelectorChangeReplacesTheDeployment -- spec.selector is immutable, so a
// label change cannot be applied by Update at all. Left to the spec-hash path
// it would be rejected on every pass: retried forever, converged never.
func TestSelectorChangeReplacesTheDeployment(t *testing.T) {
	client, tc := rbacFixture("111111")
	tc.upstreamAppsClient = client.AppsV1()
	tc.tenantDNSImage = "coredns:test"
	tc.tenantDNSReplicas = 2
	tc.tenantDNSClusterDomain = "cluster.local"

	stale := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: TenantDNSName, Namespace: tenantDNSNamespace("111111")},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
				tenantDNSTenantLabelKey: "111111", "k8s-app": "kube-dns", // the old claim
			}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
				tenantDNSTenantLabelKey: "111111", "k8s-app": "kube-dns",
			}}},
		},
	}
	if _, err := client.AppsV1().Deployments(tenantDNSNamespace("111111")).
		Create(context.TODO(), stale, metav1.CreateOptions{}); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	client.ClearActions()
	if err := tc.ensureTenantDNSDeployment("111111"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}

	// ⛔ Asserted on the ACTIONS, not on the resulting object. The fake clientset
	// does not enforce the real API's immutability, so an Update that the real
	// apiserver rejects outright succeeds here -- and a test that only read the
	// object back would pass with the replacement branch removed. Measured: it
	// did. That is the same shape as a reconciler whose guard covers exactly the
	// subset the code compares, and it is why this looks at what was CALLED.
	var deleted, created bool
	for _, a := range client.Actions() {
		if a.GetResource().Resource != "deployments" {
			continue
		}
		switch a.GetVerb() {
		case "delete":
			deleted = true
		case "create":
			created = true
		}
	}
	if !deleted || !created {
		t.Errorf("delete=%v create=%v; want both. spec.selector is immutable, so an "+
			"Update is rejected by the real apiserver on every pass: retried forever, "+
			"converged never", deleted, created)
	}

	got, err := client.AppsV1().Deployments(tenantDNSNamespace("111111")).
		Get(context.TODO(), TenantDNSName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the Deployment did not come back: %v", err)
	}
	if got.Spec.Selector.MatchLabels["k8s-app"] != tenantDNSAppLabel {
		t.Errorf("selector k8s-app = %q, want %q", got.Spec.Selector.MatchLabels["k8s-app"], tenantDNSAppLabel)
	}
}
