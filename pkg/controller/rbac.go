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
	"strconv"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	rbacclient "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/component-helpers/auth/rbac/reconciliation"
	"sort"
	"strings"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacv1helpers "k8s.io/kubernetes/pkg/apis/rbac/v1"

	"github.com/fivetime/kubezoo-contract/pkg/common"
	"github.com/fivetime/kubezoo-contract/pkg/util"
	tenantv1alpha1 "github.com/fivetime/kubezoo-contract/pkg/apis/tenant/v1alpha1"
)

// Names of the two shared RBAC objects. Unlike the per-tenant ClusterRole these
// are not tenant-specific: one ClusterRole is referenced from a RoleBinding
// inside each tenant namespace, and it is the binding's namespace -- not the
// role -- that confines what it grants.
const (
	tenantNamespaceAdminRole    = "kubezoo:tenant-namespace-admin"
	tenantNamespaceAdminBinding = "kubezoo:tenant-admin"
	// The read-only counterpart, bound in place of the admin role while a
	// tenant is suspended read-only. A separate role rather than a narrowed one,
	// because both are shared by every tenant and only the binding differs.
	tenantNamespaceReadOnlyRole = "kubezoo:tenant-namespace-readonly"
	// The role behind util.RoleAuthorGroup. Shared by every tenant, because what
	// it grants is not tenant-specific and it grants nothing on its own: escalate
	// is an exemption from a check, not a permission to write anything.
	tenantRoleAuthorRole    = "kubezoo:tenant-role-author"
	tenantRoleAuthorBinding = "kubezoo:tenant-role-author"
)

// readOnlyVerbs is what a read-only suspension leaves a tenant.
var readOnlyVerbs = []string{"get", "list", "watch"}

// namespaceRoleFor picks which shared ClusterRole the per-namespace binding
// should reference.
func namespaceRoleFor(mode tenantv1alpha1.TenantSuspensionMode) string {
	if mode == tenantv1alpha1.SuspensionReadOnly {
		return tenantNamespaceReadOnlyRole
	}
	return tenantNamespaceAdminRole
}

// isFreeze reports whether a mode withdraws the tenant's bindings outright.
//
// Anything set but unrecognised counts. Validation refuses unknown modes on the
// way in, so this only covers objects written before it existed, and a
// suspension that cannot be interpreted should hold rather than leave upstream
// RBAC at full admin while the front door refuses writes -- which is what the
// two layers used to do, disagreeing with each other.
func isFreeze(mode tenantv1alpha1.TenantSuspensionMode) bool {
	return mode != "" && mode != tenantv1alpha1.SuspensionReadOnly
}

// narrowToReadOnly strips every verb but the reading ones from a rule set, so
// that a read-only suspension covers the cluster-scoped half of a tenant's
// permissions as well as the namespaced half. Rules left with no verbs are
// dropped, since a rule granting nothing is noise.
func narrowToReadOnly(rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	narrowed := make([]rbacv1.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		kept := make([]string, 0, len(readOnlyVerbs))
		for _, verb := range rule.Verbs {
			for _, allowed := range readOnlyVerbs {
				if verb == allowed || verb == "*" {
					kept = append(kept, allowed)
					break
				}
			}
		}
		if len(kept) == 0 {
			continue
		}
		rule.Verbs = kept
		narrowed = append(narrowed, rule)
	}
	return narrowed
}

// tenantUser is the upstream identity kubezoo impersonates on behalf of a
// tenant. pkg/dynamic sets the impersonation headers on every request, so
// upstream RBAC is evaluated against this user and not against kubezoo's own
// credentials -- which is what makes any of this effective.
func tenantUser(tenantID string) string {
	return util.TenantAdminUser(tenantID)
}

// tenantClusterRole is the per-tenant ClusterRole holding the cluster-scoped
// half of a tenant's permissions.
//
// The name is historical: it used to grant "*" on "*" and deserved it. It is
// kept because renaming would leave the old ClusterRole and its binding behind,
// still granting cluster-admin, and the downgrade would silently not happen.
// Reconciling the same name with RemoveExtraPermissions narrows it in place.
func tenantClusterRole(tenantID string) string {
	return tenantID + "-cluster-admin"
}

// syncClusterRoles reconciles the two ClusterRoles a tenant needs.
//
// Before this, a tenant was bound to a ClusterRole granting "*" on "*" plus
// every non-resource URL, so upstream RBAC allowed a tenant to reach any object
// in the cluster and the rewriting layer was the only thing that stopped them.
// Now the cluster-scoped grants are enumerated, and everything namespaced is
// granted per namespace instead (see syncNamespaceRoleBindings).
//
// Non-resource URLs are no longer granted at all. Discovery still works because
// Kubernetes binds system:discovery to system:authenticated out of the box.
// ownCustomResourceRules grants the tenant, cluster-wide, everything in the API
// groups that are its own.
//
// Without this a tenant cannot create a ClusterRole mentioning its own custom
// resources. RBAC refuses to let anyone write a role carrying permissions they
// do not hold, and a tenant holds its rights per namespace, so the check fails
// even for a group only it can have anything in. That is what stops an operator
// chart from installing: measured with cert-manager, twenty-one refusals.
//
// Safe because the group name carries the tenant. A group called
// 111111-cert-manager.io can only ever contain tenant 111111's objects, since
// kubezoo prefixes a tenant's CRD groups on the way in, so cluster-wide here
// means "all of mine" rather than "everyone's".
//
// Enumerated rather than matched by prefix because RBAC has no prefix: an
// apiGroup is a literal or "*", and "111111-*" is neither. So the rules are
// rebuilt from the tenant's CRDs on every pass, and a CRD added or removed
// shows up on the next resync.
func ownCustomResourceRules(tenantID string, crdClient *apiextensions.Clientset) []rbacv1.PolicyRule {
	if crdClient == nil {
		return nil
	}
	crds, err := crdClient.ApiextensionsV1().CustomResourceDefinitions().List(
		context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		klog.Warningf("could not read tenant %s's CRDs, so its ClusterRoles naming its own "+
			"custom resources will be refused until the next resync: %v", tenantID, err)
		return nil
	}
	prefix := tenantID + "-"
	seen := map[string]bool{}
	groups := make([]string, 0, len(crds.Items))
	for i := range crds.Items {
		group := crds.Items[i].Spec.Group
		if !strings.HasPrefix(group, prefix) || seen[group] {
			continue
		}
		seen[group] = true
		groups = append(groups, group)
	}
	if len(groups) == 0 {
		return nil
	}
	sort.Strings(groups)
	return []rbacv1.PolicyRule{
		rbacv1helpers.NewRule("*").Groups(groups...).Resources("*").RuleOrDie(),
	}
}

func syncClusterRoles(coreClient v1.CoreV1Interface, rbacClient rbacclient.RbacV1Interface, tenantID string,
	mode tenantv1alpha1.TenantSuspensionMode,
	crdClient *apiextensions.Clientset) error {
	if _, err := rbacClient.ClusterRoles().List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"}); err != nil {
		klog.Warningf("Failed to list the clusterroles %s with error %v", tenantID, err)
		return err
	}

	// A read-only suspension narrows the cluster-scoped half too. Reconciling
	// with RemoveExtraPermissions rewrites the role in place, so lifting the
	// suspension restores it on the next pass.
	tenantRules := append(common.ClusterScopedRules(), ownCustomResourceRules(tenantID, crdClient)...)
	if mode == tenantv1alpha1.SuspensionReadOnly {
		tenantRules = narrowToReadOnly(tenantRules)
	}

	clusterRoles := []rbacv1.ClusterRole{
		{
			ObjectMeta: metav1.ObjectMeta{Name: tenantClusterRole(tenantID)},
			Rules:      tenantRules,
		},
		{
			// Lets a tenant create the ClusterRoles an operator chart ships.
			//
			// RBAC refuses to let anyone write a role granting permissions they
			// do not hold, and it asks that at cluster scope, while a tenant
			// holds its namespaced permissions per namespace. So a ClusterRole
			// over pods or secrets is refused even though the tenant has both in
			// every namespace it owns. escalate is the documented exemption.
			//
			// The write verbs are not here: they come from the tenant's own role,
			// so this grants nothing by itself and a suspended tenant gains
			// nothing. And it covers clusterroles only -- binding one
			// cluster-wide still faces the check, which is what keeps a role the
			// tenant could not otherwise have written from taking effect outside
			// its own namespaces. See util.RoleAuthorGroup.
			ObjectMeta: metav1.ObjectMeta{Name: tenantRoleAuthorRole},
			Rules: []rbacv1.PolicyRule{
				rbacv1helpers.NewRule("escalate").Groups("rbac.authorization.k8s.io").
					Resources("clusterroles").RuleOrDie(),
			},
		},
		{
			// The read-only counterpart of the namespace admin role below.
			// Always reconciled, whether or not anything is bound to it: a
			// suspension has to take effect immediately, not one resync after
			// the role is created.
			ObjectMeta: metav1.ObjectMeta{Name: tenantNamespaceReadOnlyRole},
			Rules: []rbacv1.PolicyRule{
				rbacv1helpers.NewRule(readOnlyVerbs...).Groups("*").Resources("*").RuleOrDie(),
			},
		},
		{
			// Shared by every tenant. Broad on purpose: a RoleBinding may only
			// grant inside its own namespace, so "*" on "*" here means "admin of
			// this one namespace" wherever it is bound. Keeping it broad also
			// means custom resources from tenant CRDs are covered, which an
			// aggregated role such as the built-in admin would miss.
			ObjectMeta: metav1.ObjectMeta{Name: tenantNamespaceAdminRole},
			Rules: []rbacv1.PolicyRule{
				rbacv1helpers.NewRule("*").Groups("*").Resources("*").RuleOrDie(),
			},
		},
		{
			// The tenant's copy of the built-in admin ClusterRole. Nothing here
			// binds it, which makes it look dead -- it is not. A tenant writing
			// a RoleBinding against ClusterRole "admin" has the reference
			// rewritten to "<id>-admin" by pkg/convert, so a role by that name
			// has to exist upstream or the binding dangles.
			//
			// Only admin is mirrored. A tenant referencing "edit" or "view" gets
			// a dangling "<id>-edit"; that gap predates this change.
			//
			// Reconciling an aggregated role is safe alongside
			// RemoveExtraPermissions: when both sides carry an AggregationRule,
			// reconciliation does not compute extra rules, so the aggregation
			// controller keeps ownership of the contents.
			ObjectMeta: metav1.ObjectMeta{Name: tenantID + "-admin"},
			AggregationRule: &rbacv1.AggregationRule{
				ClusterRoleSelectors: []metav1.LabelSelector{
					{MatchLabels: map[string]string{"rbac.authorization.k8s.io/aggregate-to-admin": "true"}},
				},
			},
		},
	}

	for i := range clusterRoles {
		clusterRole := clusterRoles[i]
		opts := reconciliation.ReconcileRoleOptions{
			Role:    reconciliation.ClusterRoleRuleOwner{ClusterRole: &clusterRole},
			Client:  reconciliation.ClusterRoleModifier{Client: rbacClient.ClusterRoles()},
			Confirm: true,
			// Reconciliation is additive by default. Without this, narrowing the
			// rules above would leave the "*" on "*" already present on an
			// existing cluster untouched, and the downgrade would apply to new
			// tenants only while looking like it had applied to all of them.
			RemoveExtraPermissions: true,
		}
		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			result, err := opts.Run()
			if err != nil {
				return err
			}
			switch {
			case result.Protected && result.Operation != reconciliation.ReconcileNone:
				klog.Warningf("skipped reconcile-protected clusterrole.%s/%s with missing permissions: %v", rbac.GroupName, clusterRole.Name, result.MissingRules)
			case result.Operation == reconciliation.ReconcileUpdate:
				klog.V(2).Infof("updated clusterrole.%s/%s", rbac.GroupName, clusterRole.Name)
			case result.Operation == reconciliation.ReconcileCreate:
				klog.V(2).Infof("created clusterrole.%s/%s", rbac.GroupName, clusterRole.Name)
			}
			return nil
		})
		if err != nil {
			klog.Warningf("unable to reconcile clusterrole.%s/%s: %v", rbac.GroupName, clusterRole.Name, err)
			return err
		}
	}
	return nil
}

// syncClusterRoleBindings binds the tenant's upstream user to its cluster-scoped
// role. The namespaced half is bound per namespace, not here.
func syncClusterRoleBindings(coreClient v1.CoreV1Interface, rbacClient rbacclient.RbacV1Interface, tenantId string,
	mode tenantv1alpha1.TenantSuspensionMode) error {
	if _, err := rbacClient.ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"}); err != nil {
		klog.Warningf("Failed to list the clusterrolebindings %s with error %v", tenantId, err)
		return err
	}

	// Freezing withdraws the binding rather than narrowing it. The tenant is
	// then not a subject of anything kubezoo created, and upstream refuses it
	// outright. Nothing is deleted but the binding itself, so lifting the
	// suspension puts it back on the next pass.
	if isFreeze(mode) {
		name := rbacv1helpers.NewClusterBinding(tenantClusterRole(tenantId)).
			Groups(util.ProxiedGroup(tenantId)).BindingOrDie().Name
		err := rbacClient.ClusterRoleBindings().Delete(context.TODO(), name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("withdrawing clusterrolebinding %s to freeze the tenant: %w", name, err)
		}
		return nil
	}

	// The subject is a group kubezoo asserts when it forwards a request, not the
	// tenant's user. Cluster-scoped grants cannot be bounded by name -- RBAC has
	// no prefix form -- so held by the user they were a grant over every
	// tenant's cluster-scoped objects, usable by anything holding that identity.
	// Held by a group they exist only on a forwarded request. See
	// util.ProxiedGroup.
	clusterRoleBindings := []rbacv1.ClusterRoleBinding{
		rbacv1helpers.NewClusterBinding(tenantClusterRole(tenantId)).
			Groups(util.ProxiedGroup(tenantId)).BindingOrDie(),
		// Shared by every tenant, like the role it names, and reconciled here so
		// that a cluster with tenants on it has it without a separate install
		// step. Its subject is a group no tenant can present.
		{
			ObjectMeta: metav1.ObjectMeta{Name: tenantRoleAuthorBinding},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     tenantRoleAuthorRole,
			},
			Subjects: []rbacv1.Subject{{
				APIGroup: rbacv1.GroupName,
				Kind:     rbacv1.GroupKind,
				Name:     util.RoleAuthorGroup,
			}},
		},
	}

	for i := range clusterRoleBindings {
		clusterRoleBinding := clusterRoleBindings[i]
		opts := reconciliation.ReconcileRoleBindingOptions{
			RoleBinding: reconciliation.ClusterRoleBindingAdapter{ClusterRoleBinding: &clusterRoleBinding},
			Client:      reconciliation.ClusterRoleBindingClientAdapter{Client: rbacClient.ClusterRoleBindings()},
			Confirm:     true,
			// Reconciliation only adds subjects by default. Without this an
			// existing cluster keeps the user subject alongside the new group,
			// so the permissions stay reachable without kubezoo and the change
			// applies to new tenants only while looking as though it applied to
			// all of them -- the same trap RemoveExtraPermissions covers for the
			// rules.
			RemoveExtraSubjects: true,
		}
		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			result, err := opts.Run()
			if err != nil {
				return err
			}
			switch {
			case result.Protected && result.Operation != reconciliation.ReconcileNone:
				klog.Warningf("skipped reconcile-protected clusterrolebinding.%s/%s with missing subjects: %v", rbac.GroupName, clusterRoleBinding.Name, result.MissingSubjects)
			case result.Operation == reconciliation.ReconcileUpdate:
				klog.V(2).Infof("updated clusterrolebinding.%s/%s with additional subjects: %v", rbac.GroupName, clusterRoleBinding.Name, result.MissingSubjects)
			case result.Operation == reconciliation.ReconcileCreate:
				klog.V(2).Infof("created clusterrolebinding.%s/%s", rbac.GroupName, clusterRoleBinding.Name)
			case result.Operation == reconciliation.ReconcileRecreate:
				klog.V(2).Infof("recreated clusterrolebinding.%s/%s", rbac.GroupName, clusterRoleBinding.Name)
			}
			return nil
		})
		if err != nil {
			klog.Warningf("unable to reconcile clusterrolebinding.%s/%s: %v", rbac.GroupName, clusterRoleBinding.Name, err)
			return err
		}
	}
	return nil
}

// markFrozen puts the frozen label on one of the tenant's namespaces, or takes
// it off again.
//
// This is the half of a freeze that reaches the tenant's own workloads.
// Withdrawing the RoleBindings kubezoo issued stops the tenant's kubectl, and
// nothing else: a tenant may bind its own ServiceAccount inside its namespace --
// RBAC permits it, since the tenant already holds those rights -- and the
// resulting pod talks to the upstream API server directly, never reaching
// kubezoo. A frozen tenant's pod was measured still listing and creating
// objects. The label lets a policy in the upstream API server refuse those
// credentials, which is the only place that sees both paths.
//
// Patched rather than updated so that a namespace changing underneath does not
// turn into a conflict, and skipped when already in the wanted state so a freeze
// does not rewrite every namespace on each resync.
func markFrozen(coreClient v1.CoreV1Interface, ns *corev1.Namespace, frozen bool) error {
	_, labelled := ns.Labels[common.TenantFrozenLabelKey]
	if labelled == frozen {
		return nil
	}
	value := "null"
	if frozen {
		value = strconv.Quote("true")
	}
	patch := fmt.Sprintf(`{"metadata":{"labels":{%s:%s}}}`,
		strconv.Quote(common.TenantFrozenLabelKey), value)
	_, err := coreClient.Namespaces().Patch(context.TODO(), ns.Name, types.MergePatchType,
		[]byte(patch), metav1.PatchOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("marking namespace %s frozen=%v: %w", ns.Name, frozen, err)
	}
	return nil
}

// syncNamespaceRoleBindings puts a RoleBinding in each of the tenant's
// namespaces, which is what actually bounds the tenant: upstream now refuses a
// namespaced request outside them rather than relying on the rewriting layer to
// have addressed it correctly.
//
// The namespaces are found by the kubezoo.io/tenant label. Every tenant
// namespace carries it -- the four system ones because the controller creates
// them that way, and tenant-created ones because pkg/convert stamps it on the
// way through and refuses to let a tenant set it to another tenant's id.
func syncNamespaceRoleBindings(coreClient v1.CoreV1Interface, rbacClient rbacclient.RbacV1Interface, tenantId string,
	mode tenantv1alpha1.TenantSuspensionMode) error {
	selector := labels.SelectorFromSet(labels.Set{common.TenantNamespaceLabelKey: tenantId})
	namespaces, err := coreClient.Namespaces().List(context.TODO(), metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return fmt.Errorf("listing namespaces of tenant %s: %w", tenantId, err)
	}

	for i := range namespaces.Items {
		ns := &namespaces.Items[i]
		if ns.DeletionTimestamp != nil {
			continue
		}
		if err := markFrozen(coreClient, ns, isFreeze(mode)); err != nil {
			return err
		}
		if isFreeze(mode) {
			err := rbacClient.RoleBindings(ns.Name).Delete(context.TODO(), tenantNamespaceAdminBinding, metav1.DeleteOptions{})
			if err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("withdrawing rolebinding in namespace %s to freeze the tenant: %w", ns.Name, err)
			}
			continue
		}
		// Built by hand rather than with rbacv1helpers.NewRoleBinding, which
		// hardwires RoleRef.Kind to Role and takes the binding's name from the
		// role's. This one has to reference a ClusterRole from inside a
		// namespace, which is the whole trick: the role is shared, the binding
		// is what confines it.
		roleBinding := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      tenantNamespaceAdminBinding,
				Namespace: ns.Name,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				// roleRef is immutable, so switching between the admin and
				// read-only roles cannot be an update. Reconciliation notices
				// and recreates the binding, which is the ReconcileRecreate
				// case handled below.
				Name: namespaceRoleFor(mode),
			},
			Subjects: []rbacv1.Subject{{
				APIGroup: rbacv1.GroupName,
				Kind:     rbacv1.UserKind,
				Name:     tenantUser(tenantId),
			}},
		}

		opts := reconciliation.ReconcileRoleBindingOptions{
			RoleBinding: reconciliation.RoleBindingAdapter{RoleBinding: &roleBinding},
			Client:      reconciliation.RoleBindingClientAdapter{Client: rbacClient, NamespaceClient: coreClient.Namespaces()},
			Confirm:     true,
		}
		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			result, err := opts.Run()
			if err != nil {
				return err
			}
			switch result.Operation {
			case reconciliation.ReconcileCreate:
				klog.V(2).Infof("created rolebinding.%s/%s in %s", rbac.GroupName, roleBinding.Name, ns.Name)
			case reconciliation.ReconcileUpdate, reconciliation.ReconcileRecreate:
				klog.V(2).Infof("reconciled rolebinding.%s/%s in %s", rbac.GroupName, roleBinding.Name, ns.Name)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("reconciling rolebinding in namespace %s: %w", ns.Name, err)
		}
	}

	if err := syncProjectedClusterRoleBindings(coreClient, rbacClient, tenantId, namespaces.Items); err != nil {
		return err
	}
	return syncOwnGroupClusterBindings(rbacClient, tenantId, mode)
}

// syncProjectedClusterRoleBindings keeps a tenant's ClusterRoleBindings present
// in every namespace it owns.
//
// A tenant's cluster is its namespaces, so its cluster-wide binding is one
// RoleBinding in each of them; see pkg/proxy/crbprojection.go. The request path
// writes the copies when the binding is created, because a chart expects its
// workload to be able to act immediately, but that write is not atomic across
// namespaces and cannot cover a namespace created later. This is what makes it
// true rather than nearly true.
//
// The record in the tenant's kube-system is the source. A copy elsewhere with no
// record is an orphan and is removed -- otherwise deleting a ClusterRoleBinding
// while a namespace was unreachable would leave a grant behind with nothing in
// the tenant's view to explain it.
func syncProjectedClusterRoleBindings(coreClient v1.CoreV1Interface, rbacClient rbacclient.RbacV1Interface,
	tenantId string, namespaces []corev1.Namespace) error {

	recordNamespace := tenantId + "-" + metav1.NamespaceSystem
	selector := labels.SelectorFromSet(labels.Set{common.ProjectedClusterRoleBindingLabelKey: "true"})
	records, err := rbacClient.RoleBindings(recordNamespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// The namespace is on its way back; syncNamespaces recreates it.
			return nil
		}
		return fmt.Errorf("listing tenant %s's projected clusterrolebindings: %w", tenantId, err)
	}
	wanted := make(map[string]*rbacv1.RoleBinding, len(records.Items))
	for i := range records.Items {
		wanted[records.Items[i].Name] = &records.Items[i]
	}

	for i := range namespaces {
		ns := &namespaces[i]
		if ns.Name == recordNamespace || ns.DeletionTimestamp != nil {
			continue
		}
		existing, err := rbacClient.RoleBindings(ns.Name).List(context.TODO(), metav1.ListOptions{
			LabelSelector: selector.String(),
		})
		if err != nil {
			return fmt.Errorf("listing projected clusterrolebindings in namespace %s: %w", ns.Name, err)
		}
		for j := range existing.Items {
			name := existing.Items[j].Name
			if _, keep := wanted[name]; !keep {
				if err := rbacClient.RoleBindings(ns.Name).Delete(context.TODO(), name,
					metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
					return fmt.Errorf("withdrawing orphaned projection %s from namespace %s: %w",
						name, ns.Name, err)
				}
			}
		}
		for name, record := range wanted {
			copied := record.DeepCopy()
			copied.Namespace = ns.Name
			copied.ResourceVersion = ""
			copied.UID = ""
			copied.CreationTimestamp = metav1.Time{}
			copied.ManagedFields = nil
			opts := reconciliation.ReconcileRoleBindingOptions{
				RoleBinding: reconciliation.RoleBindingAdapter{RoleBinding: copied},
				Client: reconciliation.RoleBindingClientAdapter{
					Client: rbacClient, NamespaceClient: coreClient.Namespaces()},
				Confirm: true,
				// The record is the whole truth, so a subject removed from it
				// has to disappear from the copies rather than linger.
				RemoveExtraSubjects: true,
			}
			if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				_, err := opts.Run()
				return err
			}); err != nil {
				return fmt.Errorf("projecting clusterrolebinding %s into namespace %s: %w",
					name, ns.Name, err)
			}
		}
	}
	return nil
}

// ownGroupBindingPrefix begins the names of the real cluster-scoped bindings
// kubezoo derives from a tenant's own projected ones.
//
// Under kubezoo:, which a tenant cannot address: names of cluster-scoped objects
// a tenant writes get the tenant prefix, so anything it asks for lands under
// <tid>-.
const ownGroupBindingPrefix = "kubezoo:crgroups:"

// ownGroupRules keeps the rules of a role that name nothing but the tenant's own
// API groups.
//
// A tenant's CRD groups are prefixed -- 111111-cert-manager.io -- so the group
// name itself carries the tenant, and a rule confined to those groups can only
// ever reach that tenant's objects. That is what makes this safe to grant for
// real, cluster-wide, rather than through the projection: there is nothing to
// filter, because there is nothing else in there. Measured: a ServiceAccount
// granted this lists clusterissuers in its own group and is refused in another
// tenant's.
//
// A rule survives only if every group it names is the tenant's. A wildcard is
// not the tenant's, and neither is the core group, and a rule mixing one of
// those with a tenant group would grant the lot. Rules over non-resource URLs
// have no groups at all and are dropped with everything else.
func ownGroupRules(tenantID string, rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	prefix := tenantID + "-"
	kept := make([]rbacv1.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.APIGroups) == 0 || len(rule.Resources) == 0 {
			continue
		}
		ownOnly := true
		for _, group := range rule.APIGroups {
			if !strings.HasPrefix(group, prefix) {
				ownOnly = false
				break
			}
		}
		if ownOnly {
			kept = append(kept, rule)
		}
	}
	return kept
}

// syncOwnGroupClusterBindings gives a tenant's ServiceAccounts the cluster-wide
// half of what it bound them to, for the part of it that is its own.
//
// The projection cannot carry this: it is a RoleBinding per namespace, and a
// RoleBinding never authorizes a cluster-scoped resource, so the cluster-scoped
// rules of a tenant's ClusterRole were silently dropped -- the tenant wrote the
// binding, saw no error, and its operator failed at runtime. This is the part of
// that gap which can be closed without widening anything: rules confined to the
// tenant's own API groups.
//
// What is deliberately not here is the rest of it -- list and watch on native
// cluster-scoped resources such as customresourcedefinitions. RBAC cannot bound
// those by name, since a list request names nothing, so granting them would rest
// on kubezoo's filtering rather than on RBAC, and would have to be withheld from
// anything not coming through kubezoo. That is a separate decision; see the
// audit.
func syncOwnGroupClusterBindings(rbacClient rbacclient.RbacV1Interface, tenantID string,
	mode tenantv1alpha1.TenantSuspensionMode) error {

	recordNamespace := tenantID + "-" + metav1.NamespaceSystem
	selector := labels.SelectorFromSet(labels.Set{common.ProjectedClusterRoleBindingLabelKey: "true"})
	records, err := rbacClient.RoleBindings(recordNamespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("listing tenant %s's projected clusterrolebindings: %w", tenantID, err)
	}

	wanted := map[string]*rbacv1.ClusterRoleBinding{}
	roles := map[string]*rbacv1.ClusterRole{}
	// A frozen tenant keeps nothing: its workloads reach upstream directly, so
	// leaving these would let a suspended tenant carry on reading.
	if !isFreeze(mode) {
		for i := range records.Items {
			record := &records.Items[i]
			if record.RoleRef.Kind != "ClusterRole" {
				continue
			}
			role, err := rbacClient.ClusterRoles().Get(context.TODO(), record.RoleRef.Name, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					// A binding pointing at nothing. The tenant can see that for
					// itself, and it grants nothing meanwhile.
					continue
				}
				return fmt.Errorf("reading clusterrole %s for tenant %s: %w", record.RoleRef.Name, tenantID, err)
			}
			rules := ownGroupRules(tenantID, role.Rules)
			if mode == tenantv1alpha1.SuspensionReadOnly {
				rules = narrowToReadOnly(rules)
			}
			if len(rules) == 0 {
				continue
			}
			name := ownGroupBindingPrefix + tenantID + ":" + util.TrimProjectedBindingName(record.Name)
			roles[name] = &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:   name,
					Labels: map[string]string{common.TenantNamespaceLabelKey: tenantID},
				},
				Rules: rules,
			}
			wanted[name] = &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:   name,
					Labels: map[string]string{common.TenantNamespaceLabelKey: tenantID},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     name,
				},
				Subjects: record.Subjects,
			}
		}
	}

	// Withdraw first: a binding whose record is gone still grants, and the
	// tenant has nothing in its own view that would explain it.
	existing, err := rbacClient.ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{common.TenantNamespaceLabelKey: tenantID}).String(),
	})
	if err != nil {
		return fmt.Errorf("listing tenant %s's derived cluster bindings: %w", tenantID, err)
	}
	for i := range existing.Items {
		name := existing.Items[i].Name
		if !strings.HasPrefix(name, ownGroupBindingPrefix) {
			continue
		}
		if _, keep := wanted[name]; keep {
			continue
		}
		if err := rbacClient.ClusterRoleBindings().Delete(context.TODO(), name,
			metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("withdrawing derived cluster binding %s: %w", name, err)
		}
		if err := rbacClient.ClusterRoles().Delete(context.TODO(), name,
			metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("withdrawing derived cluster role %s: %w", name, err)
		}
	}

	for name, role := range roles {
		roleOpts := reconciliation.ReconcileRoleOptions{
			Role:                   reconciliation.ClusterRoleRuleOwner{ClusterRole: role},
			Client:                 reconciliation.ClusterRoleModifier{Client: rbacClient.ClusterRoles()},
			Confirm:                true,
			RemoveExtraPermissions: true,
		}
		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			_, err := roleOpts.Run()
			return err
		}); err != nil {
			return fmt.Errorf("reconciling derived cluster role %s: %w", name, err)
		}
		bindingOpts := reconciliation.ReconcileRoleBindingOptions{
			RoleBinding:         reconciliation.ClusterRoleBindingAdapter{ClusterRoleBinding: wanted[name]},
			Client:              reconciliation.ClusterRoleBindingClientAdapter{Client: rbacClient.ClusterRoleBindings()},
			Confirm:             true,
			RemoveExtraSubjects: true,
		}
		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			_, err := bindingOpts.Run()
			return err
		}); err != nil {
			return fmt.Errorf("reconciling derived cluster binding %s: %w", name, err)
		}
	}
	return nil
}


