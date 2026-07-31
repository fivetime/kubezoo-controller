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
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
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
