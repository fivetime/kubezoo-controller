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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tenantv1alpha1 "github.com/fivetime/kubezoo-contract/pkg/apis/tenant/v1alpha1"
	tenantfake "github.com/fivetime/kubezoo-contract/pkg/generated/clientset/versioned/fake"
)

// TestQuotaUnenforceableIsReportedOnlyWhenAsked pins the difference that made
// this bug invisible for so long.
//
// ⛔ The controller logged one Warning saying the quota sync was skipped, before
// looking at whether the tenant had asked for a quota at all. It read like "you
// did not turn on an optional feature" -- and it was printed on every resync in
// every deployment, because the upstream cluster only serves quota.kubezoo.io
// when a ClusterResourceQuota CRD is registered and nothing in any of the three
// repositories registers or generates one. A tenant with spec.quota set has
// never had it enforced, and that line was the only trace.
//
// ⚠️ Silence is correct when nothing was asked for: quota is genuinely optional.
// What is not correct is silence when a tenant DID ask.
func TestQuotaUnenforceableIsReportedOnlyWhenAsked(t *testing.T) {
	withQuota := &tenantv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "111111"},
		Spec: tenantv1alpha1.TenantSpec{
			Quota: tenantv1alpha1.TenantQuota{
				Hard: corev1.ResourceList{"count/configmaps": resource.MustParse("40")},
			},
		},
	}
	withoutQuota := &tenantv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "222222"},
	}

	client := tenantfake.NewSimpleClientset(withQuota, withoutQuota)
	// clusterquotaCli deliberately nil: this is the broken deployment.
	controller := &TenantController{tenantClient: client.TenantV1alpha1()}

	// ⭐ Asserted through the reporting bookkeeping rather than by capturing log
	// output: what matters is that the controller DECIDED this tenant is worth
	// reporting, and log scraping would pin the wording instead of the decision.
	controller.reportQuotaUnenforceable("111111")
	if _, told := controller.quotaUnenforceableReported.Load("111111"); !told {
		t.Error("a tenant that set spec.quota was not reported; its quota is silently unenforced")
	}

	controller.reportQuotaUnenforceable("222222")
	if _, told := controller.quotaUnenforceableReported.Load("222222"); told {
		t.Error("a tenant that asked for no quota was reported; optional means optional, and " +
			"nagging every cluster without quota is how the real message gets ignored")
	}
}

// TestQuotaUnenforceableIsReportedOnce -- this runs on every resync for every
// tenant. An unconditional error would bury the cluster in a line that says the
// same thing forever, and the one time it matters would be lost in it.
func TestQuotaUnenforceableIsReportedOnce(t *testing.T) {
	tenant := &tenantv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "111111"},
		Spec: tenantv1alpha1.TenantSpec{
			Quota: tenantv1alpha1.TenantQuota{
				Hard: corev1.ResourceList{"count/configmaps": resource.MustParse("40")},
			},
		},
	}
	client := tenantfake.NewSimpleClientset(tenant)
	controller := &TenantController{tenantClient: client.TenantV1alpha1()}

	controller.reportQuotaUnenforceable("111111")
	before := 0
	controller.quotaUnenforceableReported.Range(func(any, any) bool { before++; return true })

	for i := 0; i < 5; i++ {
		controller.reportQuotaUnenforceable("111111")
	}
	after := 0
	controller.quotaUnenforceableReported.Range(func(any, any) bool { after++; return true })

	if before != 1 || after != 1 {
		t.Errorf("the tenant was tracked %d times then %d; it must be remembered once so the "+
			"message is not repeated on every resync", before, after)
	}
}
