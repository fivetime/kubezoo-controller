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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tenantv1alpha1 "github.com/fivetime/kubezoo-contract/pkg/apis/tenant/v1alpha1"
	tenantfake "github.com/fivetime/kubezoo-contract/pkg/generated/clientset/versioned/fake"
	"github.com/fivetime/kubezoo-contract/pkg/util"
)

func tenantWithAnnotations(name string, annotations map[string]string) *tenantv1alpha1.Tenant {
	return &tenantv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: annotations},
	}
}

// TestWithdrawCollectedCredential pins when the platform stops holding a copy of
// a tenant's private key.
//
// ⛔ The kubeconfig annotation contains that key, and the platform kept it
// forever. One read of one cluster-scoped object was every tenant's credentials
// at once -- and it bought nothing, because a client certificate cannot be
// revoked, so the copy was never leverage over anything.
//
// ⚠️ Withdrawal is NOT revocation. What the tenant already holds keeps working;
// what stops is the platform's ability to hand the same credential out again.
// Cutting off a tenant that holds one is spec.suspension, a different mechanism
// with a different meaning.
func TestWithdrawCollectedCredential(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	issued := func(ago time.Duration) string {
		return now.Add(-ago).Format(time.RFC3339)
	}

	for _, tc := range []struct {
		name        string
		annotations map[string]string
		retention   time.Duration
		wantStored  bool
	}{
		{
			name: "still inside the window",
			annotations: map[string]string{
				util.AnnotationTenantKubeConfigBase64:   "a-kubeconfig",
				util.AnnotationTenantCredentialIssuedAt: issued(time.Hour),
			},
			retention:  24 * time.Hour,
			wantStored: true,
		},
		{
			name: "past the window",
			annotations: map[string]string{
				util.AnnotationTenantKubeConfigBase64:   "a-kubeconfig",
				util.AnnotationTenantCredentialIssuedAt: issued(48 * time.Hour),
			},
			retention: 24 * time.Hour,
		},
		{
			// Exactly at the boundary counts as elapsed, so a retention of zero
			// would mean "immediately" if zero did not already mean "never".
			name: "exactly at the window",
			annotations: map[string]string{
				util.AnnotationTenantKubeConfigBase64:   "a-kubeconfig",
				util.AnnotationTenantCredentialIssuedAt: issued(24 * time.Hour),
			},
			retention: 24 * time.Hour,
		},
		{
			// ⚠️ Opt-out, for a provisioning flow that collects the credential
			// later than any window would allow. Zero must not read as "expire
			// instantly" -- that would destroy every credential on a platform
			// that simply had not set the flag.
			name: "retention disabled",
			annotations: map[string]string{
				util.AnnotationTenantKubeConfigBase64:   "a-kubeconfig",
				util.AnnotationTenantCredentialIssuedAt: issued(10000 * time.Hour),
			},
			retention:  0,
			wantStored: true,
		},
		{
			// Not yet adopted. Withdrawing here would be withdrawing on a clock
			// nobody can see; genCertAndKubeconfig stamps the marker first and
			// the window starts from there.
			name: "no issue time recorded",
			annotations: map[string]string{
				util.AnnotationTenantKubeConfigBase64: "a-kubeconfig",
			},
			retention:  24 * time.Hour,
			wantStored: true,
		},
		{
			// ⚠️ A hand edit or a bug. Destroying a credential on the strength of
			// a timestamp that cannot be read is the worst available reading of
			// it.
			name: "unparseable issue time",
			annotations: map[string]string{
				util.AnnotationTenantKubeConfigBase64:   "a-kubeconfig",
				util.AnnotationTenantCredentialIssuedAt: "last tuesday",
			},
			retention:  24 * time.Hour,
			wantStored: true,
		},
		{
			name: "already withdrawn",
			annotations: map[string]string{
				util.AnnotationTenantCredentialIssuedAt: issued(48 * time.Hour),
			},
			retention: 24 * time.Hour,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant := tenantWithAnnotations("909090", tc.annotations)
			client := tenantfake.NewSimpleClientset(tenant)
			if err := withdrawCollectedCredential(client.TenantV1alpha1(), tenant, tc.retention, now); err != nil {
				t.Fatalf("withdrawCollectedCredential: %v", err)
			}
			got, err := client.TenantV1alpha1().Tenants().Get(context.TODO(), "909090", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("reading the tenant back: %v", err)
			}
			_, present := got.Annotations[util.AnnotationTenantKubeConfigBase64]
			if !tc.wantStored && present {
				t.Errorf("the stored credential is still there; the platform is still holding the tenant's private key")
			}
			if tc.wantStored && !present {
				t.Errorf("the stored credential was withdrawn when it should have been left alone")
			}
			// ⭐ The marker must survive in every case. Without it the next
			// reconcile reads "never issued" and signs a new credential, which
			// puts the key straight back and makes the whole thing a no-op that
			// churns certificates.
			if _, ok := tc.annotations[util.AnnotationTenantCredentialIssuedAt]; ok {
				if _, still := got.Annotations[util.AnnotationTenantCredentialIssuedAt]; !still {
					t.Errorf("the issued-at marker was removed; the next reconcile would reissue and restore the key")
				}
			}
		})
	}
}
