/*
Copyright 2022 The KubeZoo Authors.

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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	tenantv1alpha1 "github.com/fivetime/kubezoo-contract/pkg/apis/tenant/v1alpha1"
	"github.com/fivetime/kubezoo-contract/pkg/common"
)

func namespaceOf(t *testing.T, client *fake.Clientset, name string) *corev1.Namespace {
	t.Helper()
	ns, err := client.CoreV1().Namespaces().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading namespace %s back: %v", name, err)
	}
	return ns
}

// TestFreezeLabelsTheTenantsNamespaces covers the half of a freeze that reaches
// the tenant's own workloads. Withdrawing the RoleBindings kubezoo issued stops
// the tenant's kubectl and nothing else -- a tenant that bound its own
// ServiceAccount keeps that binding, and its pods talk to the upstream API
// server without passing through kubezoo. Upstream cannot see the Tenant
// object, so this label is the only way it learns which namespaces are frozen.
func TestFreezeLabelsTheTenantsNamespaces(t *testing.T) {
	newNamespace := func(name string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{common.TenantNamespaceLabelKey: "111111"},
		}}
	}
	client := fake.NewSimpleClientset(newNamespace("111111-default"), newNamespace("111111-kube-system"))

	frozen := tenantv1alpha1.SuspensionFrozen
	if err := syncNamespaceRoleBindings(client.CoreV1(), client.RbacV1(), "111111", frozen); err != nil {
		t.Fatalf("freezing: %v", err)
	}
	for _, name := range []string{"111111-default", "111111-kube-system"} {
		if _, ok := namespaceOf(t, client, name).Labels[common.TenantFrozenLabelKey]; !ok {
			t.Errorf("namespace %s was not labelled frozen; upstream has no other way to "+
				"know, so the tenant's own ServiceAccount keeps working", name)
		}
	}

	// Lifting has to take the label off again, or the tenant stays frozen
	// upstream while the front door lets it back in -- the two layers
	// disagreeing, which is the failure this pair of tests exists to catch.
	if err := syncNamespaceRoleBindings(client.CoreV1(), client.RbacV1(), "111111", ""); err != nil {
		t.Fatalf("lifting: %v", err)
	}
	for _, name := range []string{"111111-default", "111111-kube-system"} {
		if _, ok := namespaceOf(t, client, name).Labels[common.TenantFrozenLabelKey]; ok {
			t.Errorf("namespace %s kept the frozen label after the suspension was lifted", name)
		}
	}
}

// TestReadOnlySuspensionDoesNotFreezeNamespaces -- a read-only tenant keeps its
// reads through the front door, and its workloads are not the thing being
// stopped. Labelling it would have upstream refuse writes that read-only is
// meant to refuse at the door with an explanation.
func TestReadOnlySuspensionDoesNotFreezeNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "111111-default",
		Labels: map[string]string{common.TenantNamespaceLabelKey: "111111"},
	}})
	if err := syncNamespaceRoleBindings(client.CoreV1(), client.RbacV1(), "111111",
		tenantv1alpha1.SuspensionReadOnly); err != nil {
		t.Fatalf("suspending read-only: %v", err)
	}
	if _, ok := namespaceOf(t, client, "111111-default").Labels[common.TenantFrozenLabelKey]; ok {
		t.Error("a read-only suspension labelled the namespace frozen")
	}
}
