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

	rbacv1 "k8s.io/api/rbac/v1"
)

// TestOwnGroupRules covers which rules of a tenant's ClusterRole may be granted
// cluster-wide for real. Each case is a way a tenant could reach past itself, so
// the names say what goes wrong rather than what the input is.
func TestOwnGroupRules(t *testing.T) {
	rule := func(groups []string, resources []string, verbs ...string) rbacv1.PolicyRule {
		return rbacv1.PolicyRule{APIGroups: groups, Resources: resources, Verbs: verbs}
	}
	tests := []struct {
		what string
		in   []rbacv1.PolicyRule
		want int
	}{
		{
			what: "the tenant's own group is granted, which is the point",
			in:   []rbacv1.PolicyRule{rule([]string{"111111-cert-manager.io"}, []string{"clusterissuers"}, "list")},
			want: 1,
		},
		{
			what: "another tenant's group is not, even though it is prefixed",
			in:   []rbacv1.PolicyRule{rule([]string{"222222-cert-manager.io"}, []string{"clusterissuers"}, "list")},
			want: 0,
		},
		{
			what: "a wildcard group is not, or this would grant everything in the cluster",
			in:   []rbacv1.PolicyRule{rule([]string{"*"}, []string{"*"}, "*")},
			want: 0,
		},
		{
			what: "nor the core group, where every native resource lives",
			in:   []rbacv1.PolicyRule{rule([]string{""}, []string{"secrets"}, "list")},
			want: 0,
		},
		{
			what: "nor a native group such as the one holding CRDs",
			in:   []rbacv1.PolicyRule{rule([]string{"apiextensions.k8s.io"}, []string{"customresourcedefinitions"}, "list")},
			want: 0,
		},
		{
			what: "a rule mixing its own group with another is dropped whole, not partly kept",
			in:   []rbacv1.PolicyRule{rule([]string{"111111-cert-manager.io", ""}, []string{"secrets"}, "list")},
			want: 0,
		},
		{
			what: "a group merely beginning with the digits is not the tenant's",
			in:   []rbacv1.PolicyRule{rule([]string{"111111x.example.com"}, []string{"things"}, "list")},
			want: 0,
		},
		{
			what: "a rule naming no group at all, such as one over non-resource URLs",
			in:   []rbacv1.PolicyRule{{NonResourceURLs: []string{"/healthz"}, Verbs: []string{"get"}}},
			want: 0,
		},
		{
			what: "the ones that qualify are kept and the rest dropped, from the same role",
			in: []rbacv1.PolicyRule{
				rule([]string{"111111-cert-manager.io"}, []string{"clusterissuers"}, "list"),
				rule([]string{""}, []string{"secrets"}, "list"),
				rule([]string{"111111-acme.io"}, []string{"orders"}, "watch"),
			},
			want: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.what, func(t *testing.T) {
			got := ownGroupRules("111111", test.in)
			if len(got) != test.want {
				t.Errorf("kept %d rules, want %d: %+v", len(got), test.want, got)
			}
		})
	}
}
