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
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	rbacclient "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/klog"

	"github.com/fivetime/kubezoo-contract/pkg/common"
	"github.com/fivetime/kubezoo-contract/pkg/util"
)

const (
	// derivedLabelKey marks the pair this file owns, so that they can be found
	// again and told apart from anything a tenant made.
	derivedLabelKey = "kubezoo.io/clusterscoped"
	// derivedPrefix is the name space kubezoo owns. A tenant's own cluster-scoped
	// objects are prefixed with its id, and `kubezoo:` is refused to tenants, so
	// nothing a tenant can name collides with these.
	//
	// ⛔ The TENANT ID goes into the name after this, and leaving it out is a
	// cross-tenant collision rather than an untidiness. A projection record is
	// called `kubezoo:clusterrolebinding:<name>` and carries no tenant id -- it
	// does not need one, because it is told apart by the namespace it sits in.
	// These are cluster-scoped and have no namespace to be told apart by, so two
	// tenants that each create a ClusterRoleBinding called `cs-op` would derive
	// the same object and the second would silently take the first's subjects.
	derivedPrefix = "kubezoo:clusterscoped:"
)

// syncClusterWideBindings gives a tenant's ClusterRoleBindings the part of their
// effect that a projected RoleBinding structurally cannot carry.
//
// ⛔ WHY THIS IS IN THE CONTROLLER AND NOT THE GATEWAY, which is where the rest
// of the projection is written. Binding a role cluster-wide is precisely what
// the tenant is not allowed to do, and upstream enforces it: a tenant writing
// this pair is refused with "attempting to grant RBAC permissions not currently
// held". The escalate exemption kubezoo asserts for ClusterRoles is deliberately
// not extended to ClusterRoleBindings -- see util.RoleAuthorGroup, where that is
// named as the thing keeping the exemption contained.
//
// So this write needs platform privilege, and it belongs where the platform's
// other privileged reconciliation lives rather than on the path that serves
// tenant requests. It also has to be reconciled rather than written inline: a
// chart writes a ClusterRole and a ClusterRoleBinding in no guaranteed order, so
// the role may not exist at the moment the binding arrives.
//
// ⭐ WHAT MAKES IT SAFE is not this function, it is
// util.RulesSafeForClusterWideBinding: only rules whose every API group carries
// the tenant's id survive, and such a group can only contain that tenant's
// objects. This function must never widen that set.
func (tc *TenantController) syncClusterWideBindings(tenantID string,
	coreClient v1.CoreV1Interface, rbacClient rbacclient.RbacV1Interface) error {

	ctx := context.TODO()
	recordNamespace := util.AddTenantIDPrefix(tenantID, metav1.NamespaceSystem)
	records, err := rbacClient.RoleBindings(recordNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: common.ProjectedClusterRoleBindingLabelKey + "=true",
	})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	wanted := map[string]bool{}
	for i := range records.Items {
		record := &records.Items[i]
		name := derivedNameFor(tenantID, record.Name)
		rules, err := tc.safeRulesFor(ctx, rbacClient, tenantID, record)
		if err != nil {
			klog.V(4).Infof("tenant %s: cannot derive the cluster-wide half of %s yet: %v",
				tenantID, record.Name, err)
			continue
		}
		if len(rules) == 0 || len(record.Subjects) == 0 {
			// ⚠️ Not "leave it alone". A tenant that narrows its ClusterRole must
			// lose the cluster-wide grant derived from the wider one, or the only
			// way to take a grant back would be to delete the binding entirely.
			continue
		}
		wanted[name] = true
		if err := applyDerivedPair(ctx, rbacClient, name, rules, record.Subjects); err != nil {
			klog.Warningf("tenant %s: could not write the derived cluster-wide binding %s: %v",
				tenantID, name, err)
		}
	}
	// ⭐ The other half, and a different rule set entirely. Above is what a
	// tenant may hold over its OWN api groups, safe because those groups contain
	// nothing of anybody else's. This is what it may READ of the NATIVE
	// cluster-scoped resources -- webhook configurations, CRDs -- where there is
	// no such guarantee and confinement comes from kubezoo filtering every
	// cluster-scoped read by name prefix.
	//
	// ⛔ Which is why it is granted to a group naming ONE ServiceAccount, and to
	// a group kubezoo asserts rather than to the account itself: reaching
	// upstream by any other route carries nothing at all.
	for i := range records.Items {
		record := &records.Items[i]
		if err := tc.deriveServiceAccountReads(ctx, rbacClient, tenantID, record, wanted); err != nil {
			klog.Warningf("tenant %s: could not derive the ServiceAccount reads of %s: %v",
				tenantID, record.Name, err)
		}
	}
	return tc.withdrawUnwantedPairs(ctx, rbacClient, tenantID, wanted)
}

// derivedNameFor names the pair derived from one tenant's record.
func derivedNameFor(tenantID, recordName string) string {
	return derivedPrefix + tenantID + ":" + recordName
}

// safeRulesFor reads the ClusterRole a record points at and keeps only the rules
// that may be granted across the cluster.
func (tc *TenantController) safeRulesFor(ctx context.Context, rbacClient rbacclient.RbacV1Interface,
	tenantID string, record *rbacv1.RoleBinding) ([]rbacv1.PolicyRule, error) {

	// ⛔ Only a ClusterRole can hold cluster-scoped rules. A roleRef to a
	// namespaced Role means the tenant asked for something that cannot have a
	// cluster-wide half at all.
	if record.RoleRef.Kind != "ClusterRole" {
		return nil, nil
	}
	role, err := rbacClient.ClusterRoles().Get(ctx, record.RoleRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return util.RulesSafeForClusterWideBinding(role.Rules, tenantID), nil
}

// deriveServiceAccountReads gives each ServiceAccount a record binds the
// cluster-scoped READS its role asks for, as much of them as the tenant may have.
//
// ⚠️ One pair per ServiceAccount, not one per record. A record can name several
// subjects, and they are not interchangeable -- a tenant splits work across
// ServiceAccounts precisely to give them different reach.
//
// ⚠️ Users and Groups among the subjects are skipped. A tenant's only upstream
// identities are its ServiceAccounts and its own credential; the credential
// already holds these reads, and a bare user or group name would be a request
// for an identity kubezoo does not mint.
func (tc *TenantController) deriveServiceAccountReads(ctx context.Context,
	rbacClient rbacclient.RbacV1Interface, tenantID string, record *rbacv1.RoleBinding,
	wanted map[string]bool) error {

	if record.RoleRef.Kind != "ClusterRole" {
		return nil
	}
	role, err := rbacClient.ClusterRoles().Get(ctx, record.RoleRef.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	// What this tenant is allowed to hold at cluster scope at all. The
	// intersection with it is the half that stops a tenant writing itself a
	// wider ClusterRole and collecting the difference through a workload.
	allowed := common.ClusterScopedRules()
	for i := range record.Subjects {
		subject := &record.Subjects[i]
		if subject.Kind != rbacv1.ServiceAccountKind {
			continue
		}
		// ⚠️ The subject's namespace is the tenant's own name for it; the group
		// kubezoo asserts is built from the same, so the two must agree.
		rules := util.ClusterScopedRulesForSA(role.Rules, allowed)
		if len(rules) == 0 {
			continue
		}
		name := derivedSAName(tenantID, subject.Namespace, subject.Name)
		wanted[name] = true
		group := util.TenantSAGroup(tenantID, subject.Namespace, subject.Name)
		if err := applyDerivedPair(ctx, rbacClient, name, rules, []rbacv1.Subject{{
			Kind:     rbacv1.GroupKind,
			APIGroup: rbacv1.GroupName,
			Name:     group,
		}}); err != nil {
			return err
		}
	}
	return nil
}

// derivedSAName names the pair derived for one ServiceAccount.
//
// ⚠️ Under the same prefix as the record-derived pairs, so that
// withdrawUnwantedPairs finds and removes both by the same rule -- and so that
// a ServiceAccount no longer named by any record loses its grant.
func derivedSAName(tenantID, namespace, name string) string {
	return derivedPrefix + tenantID + ":sa:" + namespace + ":" + name
}

// applyDerivedPair writes the restricted ClusterRole and the binding to it.
func applyDerivedPair(ctx context.Context, rbacClient rbacclient.RbacV1Interface, name string,
	rules []rbacv1.PolicyRule, subjects []rbacv1.Subject) error {

	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{derivedLabelKey: "true"}},
		Rules:      rules,
	}
	if _, err := rbacClient.ClusterRoles().Create(ctx, role, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		if _, err := rbacClient.ClusterRoles().Update(ctx, role, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{derivedLabelKey: "true"}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name,
		},
		Subjects: subjects,
	}
	if _, err := rbacClient.ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		// ⚠️ roleRef is immutable, so an update can only carry the subjects --
		// and it never needs to carry anything else, because the derived binding
		// always points at the derived role of the same name.
		existing, getErr := rbacClient.ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		existing.Subjects = subjects
		if _, err := rbacClient.ClusterRoleBindings().Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}
	return nil
}

// withdrawUnwantedPairs removes derived pairs that no record calls for any more.
//
// ⛔ This is how a grant is taken back, and it has to work from the derived side
// rather than from the records: a record that was deleted leaves nothing behind
// to iterate over, so a loop over records alone would never notice.
func (tc *TenantController) withdrawUnwantedPairs(ctx context.Context,
	rbacClient rbacclient.RbacV1Interface, tenantID string, wanted map[string]bool) error {

	existing, err := rbacClient.ClusterRoleBindings().List(ctx, metav1.ListOptions{
		LabelSelector: derivedLabelKey + "=true",
	})
	if err != nil {
		return err
	}
	// ⚠️ Only this tenant's. The label finds every tenant's derived bindings, and
	// deleting another tenant's because this pass did not ask for it would be a
	// cross-tenant outage produced by a reconcile loop.
	mine := derivedPrefix + tenantID + ":"
	for i := range existing.Items {
		name := existing.Items[i].Name
		if wanted[name] || !strings.HasPrefix(name, mine) {
			continue
		}
		// The binding first: a role deleted first leaves a binding pointing at
		// nothing, which upstream keeps and which reads as a grant whose contents
		// cannot be seen.
		if err := rbacClient.ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{}); err != nil &&
			!apierrors.IsNotFound(err) {
			klog.Warningf("tenant %s: withdrawing derived binding %s: %v", tenantID, name, err)
		}
		if err := rbacClient.ClusterRoles().Delete(ctx, name, metav1.DeleteOptions{}); err != nil &&
			!apierrors.IsNotFound(err) {
			klog.Warningf("tenant %s: withdrawing derived role %s: %v", tenantID, name, err)
		}
	}
	return nil
}
