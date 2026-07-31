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
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/workqueue"

	kubezoodynamic "github.com/fivetime/kubezoo-contract/pkg/dynamic"
)

// TestEnqueueReadsAFixedLengthTenantID guards the two informers that exist to
// make a reconcile event-driven.
//
// ⚠️ Both read the tenant id by cutting the string at the first dash, and a
// tenant name may contain one after position 0. For a tenant called ab-cde they
// enqueued "ab", onTenantUpdate got NotFound and dropped it, and the latency
// these informers were added to remove came straight back as the ten-minute
// resync -- silently, and only for tenants whose names carry a dash.
func TestEnqueueReadsAFixedLengthTenantID(t *testing.T) {
	drain := func(queue workqueue.RateLimitingInterface) []string {
		var got []string
		for queue.Len() > 0 {
			item, _ := queue.Get()
			got = append(got, item.(Event).tenantId)
			queue.Done(item)
		}
		return got
	}

	for _, tenantID := range []string{"111111", "ab-cde"} {
		t.Run(tenantID, func(t *testing.T) {
			tc := &TenantController{
				queue: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
			}

			// Separately: both produce the same Event, and the queue dedupes,
			// so one queue could not tell which of them was right.
			tc.enqueueProjectionOwner(&rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: tenantID + "-kube-system"},
			})
			if got := drain(tc.queue); len(got) != 1 || got[0] != tenantID {
				t.Errorf("a projection record in namespace %s-kube-system enqueued %v, want [%s]; "+
					"anything else is dropped as belonging to a tenant that does not exist",
					tenantID, got, tenantID)
			}

			tc.enqueueCRDOwner(&apiextensionsv1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "widgets." + tenantID + "-example.com"},
				Spec:       apiextensionsv1.CustomResourceDefinitionSpec{Group: tenantID + "-example.com"},
			})
			if got := drain(tc.queue); len(got) != 1 || got[0] != tenantID {
				t.Errorf("a CRD in group %s-example.com enqueued %v, want [%s]",
					tenantID, got, tenantID)
			}
		})
	}
}

// fakeClusterScoped serves one cluster-scoped resource and records what gets
// deleted. Only List and Delete are implemented; anything else this test reaches
// would be a test bug, and the embedded nil interface says so loudly.
type fakeClusterScoped struct {
	kubezoodynamic.Interface
	names   []string
	deleted []string
}

type fakeClusterScopedResource struct {
	kubezoodynamic.NamespaceableResourceInterface
	parent *fakeClusterScoped
}

func (f *fakeClusterScoped) Resource(schema.GroupVersionResource) kubezoodynamic.NamespaceableResourceInterface {
	return &fakeClusterScopedResource{parent: f}
}

func (f *fakeClusterScopedResource) List(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	list := &unstructured.UnstructuredList{}
	for _, name := range f.parent.names {
		item := unstructured.Unstructured{Object: map[string]interface{}{}}
		item.SetName(name)
		list.Items = append(list.Items, item)
	}
	return list, nil
}

func (f *fakeClusterScopedResource) Delete(_ context.Context, name string, _ metav1.DeleteOptions,
	_ ...string) (*unstructured.Unstructured, bool, error) {
	f.parent.deleted = append(f.parent.deleted, name)
	return nil, false, nil
}

// TestTeardownRequiresTheSeparator is the guard on the one defect in these
// repositories that can destroy the cluster rather than a tenant.
//
// ⚠️ deleteNonCRDClusterScopedResources matched the tenant id without the dash.
// ValidateTenantName checks length and RFC1123 characters and nothing else, so a
// tenant may be called "system" -- and deleting it then deleted every
// cluster-scoped object whose name merely starts with those six characters.
// Measured against a real 1.36 apiserver: 66 of the 70 bootstrap ClusterRoles,
// system:kube-controller-manager and system:kube-scheduler among them, with no
// reconciler to put them back.
func TestTeardownRequiresTheSeparator(t *testing.T) {
	resources := []metav1.APIResource{{
		Name: "clusterroles", Namespaced: false,
		Group: "rbac.authorization.k8s.io", Version: "v1",
		Verbs: metav1.Verbs{"list", "delete"},
	}}

	cases := []struct {
		tenantID string
		present  []string
		want     []string
	}{
		{
			tenantID: "system",
			present: []string{
				"system:kube-controller-manager", "system:kube-scheduler", "system:node",
				"system:controller:deployment-controller", "system-cluster-critical",
				"system-my-own-role",
			},
			// A tenant called system owns names under "system-", and nothing else.
			want: []string{"system-cluster-critical", "system-my-own-role"},
		},
		{
			tenantID: "111111",
			present:  []string{"111111-cluster-admin", "111111", "1111112-other", "unrelated"},
			want:     []string{"111111-cluster-admin"},
		},
		{
			tenantID: "kube-s",
			present:  []string{"kube-scheduler", "kube-system-thing", "kube-s-mine"},
			want:     []string{"kube-s-mine"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.tenantID, func(t *testing.T) {
			upstream := &fakeClusterScoped{names: tc.present}
			tc2 := &TenantController{upstreamDynamicClient: upstream}
			if err := tc2.deleteNonCRDClusterScopedResources(tc.tenantID, resources); err != nil {
				t.Fatalf("teardown: %v", err)
			}
			if !reflect.DeepEqual(upstream.deleted, tc.want) {
				t.Errorf("tearing down tenant %q deleted %v, want %v",
					tc.tenantID, upstream.deleted, tc.want)
			}
		})
	}
}
