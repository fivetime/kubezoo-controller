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
	"os"
	"path/filepath"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/fivetime/kubezoo-contract/pkg/common"
)

// TestShippedRBACCanTearDownWhatTenantsCanCreate ties the deployment manifest to
// the grant tenants actually hold.
//
// ⚠️ These two lists drifted, and the drift was invisible until a teardown ran.
// The manifest granted customresourcedefinitions get/list/watch under a comment
// reading "只读" and namespaces everything but delete, so deleteResources took a
// 403 on its first step, the finalizer was never removed and the Tenant stayed
// Terminating for good. The operator's natural remedy is to strip the finalizer
// by hand, after which the tenant's namespaces, secrets and custom resources are
// left behind -- waiting for the next holder of that six-character id, who is
// authorized for exactly the same <tid>- prefix.
//
// The rule is: every cluster-scoped resource a tenant may CREATE must be one the
// controller may LIST and DELETE, or teardown leaves it behind.
func TestShippedRBACCanTearDownWhatTenantsCanCreate(t *testing.T) {
	granted := readShippedClusterRole(t)

	for _, rule := range common.ClusterScopedRules() {
		if !containsVerb(rule.Verbs, "create") {
			continue
		}
		// A resource the tenant may create but not list is a request-and-answer
		// API -- TokenReview, SubjectAccessReview -- which stores nothing, so
		// there is nothing for teardown to find. Derived from the rule rather
		// than named in a skip list, so a resource that later becomes listable
		// is covered automatically.
		if !containsVerb(rule.Verbs, "list") {
			continue
		}
		for _, group := range rule.APIGroups {
			for _, resource := range rule.Resources {
				if strings.Contains(resource, "/") {
					continue // a subresource is deleted with its parent
				}
				for _, verb := range []string{"list", "delete"} {
					if !granted[key(group, resource, verb)] {
						t.Errorf("a tenant may create %s.%s, but config/setup/controller.yaml does not "+
							"let the controller %s it -- teardown will leave every one behind, and the "+
							"only sign will be a warning in the log",
							resource, group, verb)
					}
				}
			}
		}
	}
}

func key(group, resource, verb string) string { return group + "/" + resource + "/" + verb }

func containsVerb(verbs []string, want string) bool {
	for _, verb := range verbs {
		if verb == want || verb == "*" {
			return true
		}
	}
	return false
}

func readShippedClusterRole(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "config", "setup", "controller.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	granted := map[string]bool{}
	for _, doc := range strings.Split(string(raw), "\n---") {
		var role rbacv1.ClusterRole
		if err := yaml.Unmarshal([]byte(doc), &role); err != nil {
			continue
		}
		if role.Kind != "ClusterRole" {
			continue
		}
		for _, rule := range role.Rules {
			for _, group := range rule.APIGroups {
				for _, resource := range rule.Resources {
					for _, verb := range rule.Verbs {
						granted[key(group, resource, verb)] = true
					}
				}
			}
		}
	}
	if len(granted) == 0 {
		t.Fatalf("no ClusterRole rules found in %s; the test is measuring nothing", path)
	}
	return granted
}
