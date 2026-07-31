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
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/klog"

	"github.com/fivetime/kubezoo-contract/pkg/common"
	"github.com/fivetime/kubezoo-contract/pkg/util"
)

const verbPatch = "patch"

// stripFinalizersInTenantNamespaces clears finalizers left on objects in a
// tenant's namespaces so that the namespaces can finish terminating.
//
// Without this a departing tenant can strand its own namespaces for good, and it
// takes one line of YAML: a finalizer nothing will ever remove. Kubernetes then
// keeps the object, the namespace stays Terminating, and kubezoo has already
// dropped its own finalizer and forgotten the tenant, so nobody is left to clean
// up. Reusing that tenant id afterwards produces a half-provisioned tenant --
// the other namespaces come back, that one does not -- which fails on the
// tenant's first request.
//
// Ordering matters and is the reason this runs last in deleteResources. By the
// time it is called the namespaces are already terminating, which is what makes
// it race-free: a terminating namespace admits no new objects, so the tenant
// cannot put a finalizer back after it has been stripped. Its cluster-scoped
// bindings are gone by then too.
//
// Forcing this is the point. A tenant's own operator may have finalizers that
// mean something, but teardown is exactly when they stop mattering.
func (tc *TenantController) stripFinalizersInTenantNamespaces(tenantID string) error {
	namespaces, err := tc.upstreamCoreClient.Namespaces().List(context.TODO(), metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{common.TenantNamespaceLabelKey: tenantID}).String(),
	})
	if err != nil {
		return fmt.Errorf("listing namespaces of tenant %s: %w", tenantID, err)
	}
	if len(namespaces.Items) == 0 {
		return nil
	}

	resources, err := tc.namespacedResourcesForCleanup()
	if err != nil {
		return err
	}

	var stripped int
	for i := range namespaces.Items {
		for _, apiResource := range resources {
			n, err := tc.stripFinalizersForResource(namespaces.Items[i].Name, apiResource)
			if err != nil {
				return err
			}
			stripped += n
		}
	}
	if stripped > 0 {
		klog.Infof("stripped finalizers from %d objects in the namespaces of tenant %s so that "+
			"they can finish terminating", stripped, tenantID)
	}
	return nil
}

// namespacedResourcesForCleanup lists the namespaced resources that can be
// listed and patched. Anything that cannot be patched cannot have its finalizers
// cleared, and anything that cannot be listed cannot be found in the first
// place.
func (tc *TenantController) namespacedResourcesForCleanup() ([]metav1.APIResource, error) {
	_, apiResourceLists, err := tc.upstreamDiscoveryClient.ServerGroupsAndResources()
	if err != nil {
		// Discovery is partial when an aggregated API is unreachable. That says
		// nothing about the core groups a tenant's objects live in, and failing
		// teardown over it would strand the namespaces this exists to free.
		if apiResourceLists == nil {
			return nil, fmt.Errorf("discovering namespaced resources: %w", err)
		}
		klog.Warningf("partial discovery during tenant teardown, continuing: %v", err)
	}

	namespacedLists := discovery.FilteredBy(
		discovery.ResourcePredicateFunc(func(gv string, r *metav1.APIResource) bool {
			return r.Namespaced &&
				util.ContainString(r.Verbs, verbList) &&
				util.ContainString(r.Verbs, verbPatch)
		}), apiResourceLists)

	return util.FlattenResourceLists(namespacedLists), nil
}

// stripFinalizersForResource clears the finalizers on every object of one
// resource type in one namespace, and reports how many it touched.
func (tc *TenantController) stripFinalizersForResource(namespace string, apiResource metav1.APIResource) (int, error) {
	client := tc.upstreamDynamicClient.Resource(util.GetGVR(apiResource)).Namespace(namespace)

	list, err := client.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		// A resource can disappear underneath us mid-teardown -- a tenant CRD
		// removed a moment ago, an aggregated API that stopped answering. Neither
		// should stop the rest of the cleanup.
		if apierrors.IsNotFound(err) || apierrors.IsMethodNotSupported(err) || apierrors.IsServiceUnavailable(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("listing %s in %s: %w", apiResource.Name, namespace, err)
	}

	var stripped int
	for i := range list.Items {
		object := &list.Items[i]
		if len(object.GetFinalizers()) == 0 {
			continue
		}
		// A merge patch with a null finalizers field is the smallest thing that
		// removes them all, and it does not depend on the object's resourceVersion,
		// so it does not lose a race with whatever else is deleting it.
		_, _, err := client.Patch(context.TODO(), object.GetName(), types.MergePatchType,
			[]byte(`{"metadata":{"finalizers":null}}`), metav1.PatchOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return stripped, fmt.Errorf("clearing finalizers on %s %s/%s: %w",
				apiResource.Name, namespace, object.GetName(), err)
		}
		klog.V(2).Infof("cleared finalizers on %s %s/%s during tenant teardown",
			apiResource.Name, namespace, object.GetName())
		stripped++
	}
	return stripped, nil
}
