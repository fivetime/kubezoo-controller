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

	"github.com/fivetime/kubezoo-contract/pkg/common"
)

// TestSyncNamespacesStampsPodSecurity covers the namespaces the CONTROLLER
// creates, which never pass through the gateway.
//
// ⭐ Pod Security Admission runs inside the apiserver -- no webhook, no single
// point -- so a namespace carrying this label refuses host namespaces,
// privileged containers and host paths with every webhook in the cluster gone.
// It used to be written only by a Kyverno mutate, which meant the second layer
// was installed by the first: a namespace created while that webhook was not
// registered got no label and no enforcement at all.
func TestSyncNamespacesStampsPodSecurity(t *testing.T) {
	client := fake.NewSimpleClientset()
	if err := syncNamespaces(client.CoreV1(), "111111"); err != nil {
		t.Fatalf("syncing a new tenant's namespaces: %v", err)
	}
	for _, name := range []string{"111111-default", "111111-kube-system",
		"111111-kube-public", "111111-kube-node-lease"} {
		labels := namespaceOf(t, client, name).Labels
		if labels[common.PodSecurityEnforceLabelKey] != common.PodSecurityLevel {
			t.Errorf("%s: enforce is %q, want %q -- without it the namespace has no "+
				"webhook-free protection at all",
				name, labels[common.PodSecurityEnforceLabelKey], common.PodSecurityLevel)
		}
		if labels[common.PodSecurityEnforceVersionLabelKey] != common.PodSecurityVersion {
			t.Errorf("%s: enforce-version is %q, want %q",
				name, labels[common.PodSecurityEnforceVersionLabelKey], common.PodSecurityVersion)
		}
		if labels[common.TenantNamespaceLabelKey] != "111111" {
			t.Errorf("%s: the tenant label was lost: %q", name, labels[common.TenantNamespaceLabelKey])
		}
	}
}

// TestSyncNamespacesRepairsAWeakenedLevel is the recovery path.
//
// ⚠️ A namespace CAN end up weaker -- a tenant labelling its own during the very
// outage this hardening is for. The sync loop has to put it back on its own; the
// alternative is a namespace that stays privileged until somebody notices, and
// nothing about it looks wrong from outside.
func TestSyncNamespacesRepairsAWeakenedLevel(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "111111-default",
			Labels: map[string]string{
				common.TenantNamespaceLabelKey:    "111111",
				common.PodSecurityEnforceLabelKey: "privileged",
			},
		},
	})
	if err := syncNamespaces(client.CoreV1(), "111111"); err != nil {
		t.Fatalf("syncing over a weakened namespace: %v", err)
	}
	labels := namespaceOf(t, client, "111111-default").Labels
	if labels[common.PodSecurityEnforceLabelKey] != common.PodSecurityLevel {
		t.Errorf("a namespace left at %q was not repaired to %q",
			labels[common.PodSecurityEnforceLabelKey], common.PodSecurityLevel)
	}
}

// TestSyncNamespacesWritesNothingWhenNothingDrifted -- the loop runs on every
// resync for every tenant, so it must not issue an Update per pass. That would
// be a write amplification proportional to tenants times namespaces times
// resyncs, against the same apiserver every tenant shares.
func TestSyncNamespacesWritesNothingWhenNothingDrifted(t *testing.T) {
	client := fake.NewSimpleClientset()
	if err := syncNamespaces(client.CoreV1(), "111111"); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	client.ClearActions()
	if err := syncNamespaces(client.CoreV1(), "111111"); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "update" || action.GetVerb() == "create" {
			t.Errorf("a steady-state sync issued a %s on %s; it should only read",
				action.GetVerb(), action.GetResource().Resource)
		}
	}
	_ = context.TODO
}
