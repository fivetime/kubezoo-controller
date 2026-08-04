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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"

	rbacv1 "k8s.io/api/rbac/v1"

	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	externalinformer "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	rbacclient "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	quotav1alpha1 "github.com/fivetime/kubezoo-contract/pkg/apis/quota/v1alpha1"
	tenantv1alpha1 "github.com/fivetime/kubezoo-contract/pkg/apis/tenant/v1alpha1"
	"github.com/fivetime/kubezoo-contract/pkg/common"
	"github.com/fivetime/kubezoo-contract/pkg/dynamic"
	quotaclient "github.com/fivetime/kubezoo-contract/pkg/generated/clientset/versioned/typed/quota/v1alpha1"
	tenantclient "github.com/fivetime/kubezoo-contract/pkg/generated/clientset/versioned/typed/tenant/v1alpha1"
	tenantlister "github.com/fivetime/kubezoo-contract/pkg/generated/listers/tenant/v1alpha1"
	"github.com/fivetime/kubezoo-contract/pkg/util"
)

type EventType int

const (
	Create = iota
	Update
	Delete
)

const (
	maxRetries         = 10
	tenantFinalizerKey = "kubezoo.io/tenant"
	verbList           = "list"
	verbDelete         = "delete"
)

// namespaceResyncPeriod is the repair interval for the per-namespace
// RoleBindings. Creation is event-driven; this only catches a binding that was
// deleted out from under us.
const namespaceResyncPeriod = 10 * time.Minute

// Event indicate the informerEvent
type Event struct {
	tenantId  string
	eventType EventType
}

// TenantController take responsibility for tenant management including
// the tenant object, tenant certificate and the tenant's k8s resources.
type TenantController struct {
	queue             workqueue.RateLimitingInterface
	tenantInformer    cache.SharedIndexInformer
	namespaceInformer cache.SharedIndexInformer
	tenantLister      tenantlister.TenantLister
	tenantClient      tenantclient.TenantV1alpha1Interface
	clusterquotaCli   quotaclient.QuotaV1alpha1Interface
	// quotaUnenforceableReported remembers which tenants have already been told
	// about, so a permanent misconfiguration is reported once per tenant rather
	// than once per resync.
	quotaUnenforceableReported sync.Map
	upstreamDiscoveryClient    *discovery.DiscoveryClient
	upstreamDynamicClient      dynamic.Interface
	// The generated interface rather than the concrete Clientset, so that the
	// teardown predicates can be driven in a test. Nothing else changes.
	upstreamCRDClient  apiextensions.Interface
	upstreamCoreClient v1.CoreV1Interface
	upstreamRbacClient rbacclient.RbacV1Interface
	clientCAFile       string
	clientCAKeyFile    string
	kubeZooHostAddress string
	// credentialRetention is how long the platform keeps its copy of a tenant's
	// kubeconfig -- and so of the tenant's private key -- after issuing it.
	credentialRetention time.Duration
	// credentialValidity is the validity issued to a tenant that asks for none,
	// and credentialValidityCeiling is the longest one that will be honoured.
	credentialValidity        time.Duration
	credentialValidityCeiling time.Duration
}

// newTenantController create a controller to handler the events of tenant.
func newTenantController(ti cache.SharedIndexInformer, tenantCli tenantclient.TenantV1alpha1Interface, coreCli v1.CoreV1Interface, rbacCli rbacclient.RbacV1Interface, quotaClient quotaclient.QuotaV1alpha1Interface, discoveryCli *discovery.DiscoveryClient, dynamicCli dynamic.Interface, crdClient apiextensions.Interface, clientCAFile, clientCAKeyFile, kubeZooBindAddress string, kubeZooSecurePort int, credentialRetention, credentialValidity, credentialValidityCeiling time.Duration) *TenantController {
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	// Each handler builds its own event. They used to share one Event value and
	// one err declared out here, mutating it field by field before queueing it:
	// two handlers running at once could interleave between setting tenantId and
	// setting eventType, and queue an event with one tenant's id and another
	// event's type -- a create processed as a delete, or the reverse. The
	// informer calls handlers from its own goroutines, so nothing prevented it.
	enqueue := func(obj interface{}, eventType EventType, keyFunc cache.KeyFunc) {
		tenantId, err := keyFunc(obj)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("deriving the key of a tenant event: %w", err))
			return
		}
		queue.Add(Event{tenantId: tenantId, eventType: eventType})
	}
	// Checked, like every other AddEventHandler in this file. This is the one
	// that watches Tenants themselves, so a registration that failed would leave
	// the controller running and reconciling nothing at all -- no namespaces, no
	// RBAC, no certificates -- with no error anywhere.
	if _, err := ti.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			enqueue(obj, Create, cache.MetaNamespaceKeyFunc)
		},
		UpdateFunc: func(_, new interface{}) {
			enqueue(new, Update, cache.MetaNamespaceKeyFunc)
		},
		DeleteFunc: func(obj interface{}) {
			enqueue(obj, Delete, cache.DeletionHandlingMetaNamespaceKeyFunc)
		},
	}); err != nil {
		utilruntime.HandleError(fmt.Errorf("watching tenants: %w", err))
	}

	return &TenantController{
		queue:                     queue,
		tenantInformer:            ti,
		tenantLister:              tenantlister.NewTenantLister(ti.GetIndexer()),
		tenantClient:              tenantCli,
		upstreamCoreClient:        coreCli,
		upstreamRbacClient:        rbacCli,
		clusterquotaCli:           quotaClient,
		upstreamDiscoveryClient:   discoveryCli,
		upstreamDynamicClient:     dynamicCli,
		upstreamCRDClient:         crdClient,
		clientCAFile:              clientCAFile,
		clientCAKeyFile:           clientCAKeyFile,
		kubeZooHostAddress:        net.JoinHostPort(kubeZooBindAddress, strconv.Itoa(kubeZooSecurePort)),
		credentialRetention:       credentialRetention,
		credentialValidity:        credentialValidity,
		credentialValidityCeiling: credentialValidityCeiling,
	}
}

// Run starts the tenant controller
func Run(stopCh <-chan struct{}, ti cache.SharedIndexInformer, tenantCli tenantclient.TenantV1alpha1Interface, typedCli kubernetes.Interface, discoveryCli *discovery.DiscoveryClient, dynamicCli dynamic.Interface, crdClient apiextensions.Interface, quotaClient quotaclient.QuotaV1alpha1Interface, clientCAFile, clientCAKeyFile, kubeZooBindAddress string, kubeZooSecurePort int, credentialRetention, credentialValidity, credentialValidityCeiling time.Duration) {
	tc := newTenantController(ti, tenantCli, typedCli.CoreV1(), typedCli.RbacV1(), quotaClient, discoveryCli, dynamicCli, crdClient, clientCAFile, clientCAKeyFile, kubeZooBindAddress, kubeZooSecurePort, credentialRetention, credentialValidity, credentialValidityCeiling)
	defer utilruntime.HandleCrash()
	defer tc.queue.ShutDown()

	klog.V(4).Info("Starting Tenant Controller")

	go tc.tenantInformer.Run(stopCh)

	// A tenant's namespaces are not a fixed set: it creates more at any time,
	// and each one needs its own RoleBinding before the tenant can use it.
	// Waiting for the tenant resync would leave a tenant Forbidden in a
	// namespace it just created, for as long as the resync period.
	//
	// The selector is the label's presence, not a particular tenant, so one
	// informer serves all of them. pkg/convert stamps it on every namespace on
	// the way through and refuses to let a tenant claim another tenant's id.
	nsFactory := informers.NewSharedInformerFactoryWithOptions(typedCli, namespaceResyncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.LabelSelector = common.TenantNamespaceLabelKey
		}))
	tc.namespaceInformer = nsFactory.Core().V1().Namespaces().Informer()
	if _, err := tc.namespaceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { tc.enqueueNamespaceOwner(obj) },
		UpdateFunc: func(_, obj interface{}) { tc.enqueueNamespaceOwner(obj) },
	}); err != nil {
		utilruntime.HandleError(fmt.Errorf("adding the namespace event handler: %w", err))
		return
	}
	nsFactory.Start(stopCh)

	// The tenant's cluster-scoped role lists the API groups of its own CRDs, so
	// that it can write a ClusterRole naming its own custom resources. Those
	// groups change when the tenant adds or removes a CRD, and waiting for the
	// tenant resync leaves it unable to grant rights over a CRD it has just
	// created -- measured: the create is Forbidden until the tenant is touched.
	// A tenant's ClusterRoleBinding becomes a RoleBinding in each of its
	// namespaces, and the cluster-scoped half of what it grants -- the part
	// confined to the tenant's own API groups -- is derived from that record
	// here. The tenant writes the binding through the proxy, which cannot create
	// the derived objects itself because they are cluster-scoped and the tenant
	// holds nothing at cluster scope. So the controller has to notice, and
	// waiting for the tenant resync would leave a chart's operator unable to read
	// its own custom resources for as long as that takes -- measured at over
	// thirty seconds and bounded only by the resync period.
	//
	// The selector is the label the records carry, so this watches those and
	// nothing else.
	rbFactory := informers.NewSharedInformerFactoryWithOptions(typedCli, namespaceResyncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.LabelSelector = common.ProjectedClusterRoleBindingLabelKey
		}))
	rbInformer := rbFactory.Rbac().V1().RoleBindings().Informer()
	if _, err := rbInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { tc.enqueueProjectionOwner(obj) },
		UpdateFunc: func(_, obj interface{}) { tc.enqueueProjectionOwner(obj) },
		DeleteFunc: func(obj interface{}) { tc.enqueueProjectionOwner(obj) },
	}); err != nil {
		utilruntime.HandleError(fmt.Errorf("adding the projected binding event handler: %w", err))
		return
	}
	rbFactory.Start(stopCh)

	crdFactory := externalinformer.NewSharedInformerFactory(tc.upstreamCRDClient, namespaceResyncPeriod)
	crdInformer := crdFactory.Apiextensions().V1().CustomResourceDefinitions().Informer()
	if _, err := crdInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { tc.enqueueCRDOwner(obj) },
		DeleteFunc: func(obj interface{}) { tc.enqueueCRDOwner(obj) },
	}); err != nil {
		utilruntime.HandleError(fmt.Errorf("adding the CRD event handler: %w", err))
		return
	}
	crdFactory.Start(stopCh)

	if !cache.WaitForCacheSync(stopCh, tc.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		return
	}

	klog.V(4).Info("Tenant controller synced and ready")
	wait.Until(tc.runWorker, time.Second, stopCh)
}

// enqueueNamespaceOwner queues the tenant that owns a namespace, so that its
// RoleBindings are reconciled as soon as the namespace exists rather than at the
// next tenant resync.
func (tc *TenantController) enqueueNamespaceOwner(obj interface{}) {
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		return
	}
	tenantID := ns.Labels[common.TenantNamespaceLabelKey]
	if tenantID == "" {
		return
	}
	// A terminating namespace needs no RoleBinding, and if it is stuck -- a
	// tenant can leave a finalizer behind that nothing removes -- it keeps
	// emitting updates for as long as it is stuck. Queueing those drove a
	// permanent retry loop against a tenant that no longer exists.
	if ns.DeletionTimestamp != nil {
		return
	}
	tc.queue.Add(Event{tenantId: tenantID, eventType: Update})
}

// enqueueCRDOwner queues the tenant whose CRD this is.
//
// The tenant is read off the group rather than any label: kubezoo prefixes a
// tenant's CRD groups on the way in, so 111111-cert-manager.io belongs to
// 111111 by construction, and a CRD the platform installed has no prefix and is
// nobody's.
// enqueueProjectionOwner queues the tenant a projected ClusterRoleBinding
// belongs to, so that the cluster-scoped half it implies is derived as soon as
// the tenant writes it.
func (tc *TenantController) enqueueProjectionOwner(obj interface{}) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	binding, ok := obj.(*rbacv1.RoleBinding)
	if !ok {
		return
	}
	// ⚠️ Not strings.Cut on the first dash. A tenant id is a fixed six characters
	// and ValidateTenantName permits a dash at any position after the first, so
	// for a tenant like ab-cde the first-dash reading enqueued tenant "ab",
	// onTenantUpdate got NotFound and dropped it, and the event-driven reconcile
	// this informer exists to provide degraded to the ten-minute resync -- for
	// exactly the tenants whose names carry a dash, and in silence.
	tenantID, err := util.TenantIDFromPrefixed(binding.Namespace)
	if err != nil {
		return
	}
	tc.queue.Add(Event{tenantId: tenantID, eventType: Update})
}

func (tc *TenantController) enqueueCRDOwner(obj interface{}) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	crd, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		return
	}
	// Fixed-length prefix, for the same reason as enqueueProjectionOwner: a
	// tenant whose name contains a dash was enqueued under a truncated id and
	// its CRD events were dropped.
	tenantID, err := util.TenantIDFromPrefixed(crd.Spec.Group)
	if err != nil {
		return
	}
	tc.queue.Add(Event{tenantId: tenantID, eventType: Update})
}

// HasSynced returns true if the shared informers' stores have been
// informed by at least one full LIST of the authoritative state
// of their object collections.
func (tc *TenantController) HasSynced() bool {
	if tc.namespaceInformer != nil && !tc.namespaceInformer.HasSynced() {
		return false
	}
	return tc.tenantInformer.HasSynced()
}

// runWorker start to process the events.
func (tc *TenantController) runWorker() {
	for tc.processNextItem() {
	}
}

// processNextItem gets event from queue and process it.
func (tc *TenantController) processNextItem() bool {
	newEvent, quit := tc.queue.Get()

	if quit {
		return false
	}
	defer tc.queue.Done(newEvent)
	err := tc.processItem(newEvent.(Event))
	if err == nil {
		// No error, reset the ratelimit counters
		tc.queue.Forget(newEvent)
	} else if tc.queue.NumRequeues(newEvent) < maxRetries {
		klog.Errorf("Error processing %s (will retry): %v", newEvent.(Event).tenantId, err)
		tc.queue.AddRateLimited(newEvent)
	} else {
		// err != nil and too many retries
		klog.Errorf("Error processing %s (giving up): %v", newEvent.(Event).tenantId, err)
		tc.queue.Forget(newEvent)
		utilruntime.HandleError(err)
	}

	return true
}

// processItem processes the event according the event type.
func (tc *TenantController) processItem(e Event) error {
	// process events based on its type
	switch e.eventType {
	case Create:
		return tc.onTenantCreate(e.tenantId)
	case Update:
		return tc.onTenantUpdate(e.tenantId)
	case Delete:
		klog.Warningf("deleting tenant %v", e.tenantId)
		return nil
	}
	return nil
}

func (tc *TenantController) onTenantCreate(tenantID string) error {
	if err := tc.onTenantAddOrUpdate(tenantID); err != nil {
		return err
	}

	if err := tc.syncResources(tenantID); err != nil {
		return err
	}

	if err := tc.syncClusterResourceQuota(tenantID); err != nil {
		return err
	}
	return nil
}

func (tc *TenantController) onTenantUpdate(tenantID string) error {
	if err := tc.onTenantAddOrUpdate(tenantID); err != nil {
		return err
	}

	// Update used to skip syncResources, so nothing converged a tenant's
	// upstream namespaces and RBAC after they were first created: a resync
	// produces Update, not Create, and so does every subsequent event. Deleting
	// one of those objects left it deleted until kubezoo restarted and the
	// informer's initial LIST replayed it as an Add.
	//
	// It matters more now that a namespace appearing is what triggers its
	// RoleBinding. syncResources is idempotent -- the namespaces are gets, the
	// certificate returns early once issued -- so converging here is cheap.
	//
	// Not while the tenant is going away, though: deletion arrives as an update
	// that sets deletionTimestamp, and converging then puts back the namespaces
	// and roles that onTenantAddOrUpdate has just torn down.
	tenant, err := tc.tenantClient.Tenants().Get(context.TODO(), tenantID, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if !tenant.ObjectMeta.DeletionTimestamp.IsZero() {
		return nil
	}

	if err := tc.syncResources(tenantID); err != nil {
		return err
	}

	if err := tc.syncClusterResourceQuota(tenantID); err != nil {
		return err
	}
	return nil
}

// onTenantAddOrUpdate handles the Create or UPDATE event of a Tenant.
func (tc *TenantController) onTenantAddOrUpdate(tenantId string) error {
	tenant, err := tc.tenantClient.Tenants().Get(context.TODO(), tenantId, metav1.GetOptions{})
	if err != nil {
		// The tenant is gone. Anything still referring to it -- a namespace that
		// has not finished terminating, say -- has nothing left to converge
		// towards, and retrying only produces noise.
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	if tenant.ObjectMeta.DeletionTimestamp.IsZero() {
		if !util.ContainString(tenant.ObjectMeta.Finalizers, tenantFinalizerKey) {
			tenant.ObjectMeta.Finalizers = append(tenant.ObjectMeta.Finalizers, tenantFinalizerKey)
			if _, err := tc.tenantClient.Tenants().Update(context.TODO(), tenant, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	} else {
		if util.ContainString(tenant.ObjectMeta.Finalizers, tenantFinalizerKey) {
			if err = tc.deleteResources(tenantId); err != nil {
				return err
			}
			tenant.ObjectMeta.Finalizers = util.RemoveString(tenant.ObjectMeta.Finalizers, tenantFinalizerKey)
			if _, err = tc.tenantClient.Tenants().Update(context.TODO(), tenant, metav1.UpdateOptions{}); err != nil {
				if apierrors.IsNotFound(err) {
					return nil
				}
				return err
			}
		}
		return nil
	}

	return nil
}

// deleteResources deletes resources belonging to the tenant from the upstream cluster.
func (tc *TenantController) deleteResources(tenantId string) error {
	klog.V(4).Infof("delete resources for tenant %s", tenantId)

	clusterScopedResources, err := tc.getClusterScopedResources()
	if err != nil {
		return err
	}
	if err := tc.deleteCRDs(tenantId); err != nil {
		return err
	}
	nonCRDResources := tc.filterCRDs(clusterScopedResources)
	if err := tc.deleteNonCRDClusterScopedResources(tenantId, nonCRDResources); err != nil {
		return err
	}

	// ⚠️ The sweep above finds objects by the tenant's name prefix, and the
	// cluster-scoped bindings derived from a tenant's ClusterRoleBindings are not
	// named that way -- they are kubezoo:crgroups:<tid>:<binding>. Nothing else
	// deleted them, so every tenant lifecycle left a ClusterRole and a
	// ClusterRoleBinding behind for good, granting rights over that tenant's own
	// API groups to a subject in that tenant's own namespaces. Not reachable by
	// anyone once the tenant is gone, but RBAC is loaded into every apiserver's
	// authorizer and this accumulated without bound.
	if err := withdrawOwnGroupClusterBindings(tc.upstreamRbacClient, tenantId, nil); err != nil {
		return errors.Errorf("fail to withdraw derived cluster bindings for tenant %s: %v", tenantId, err)
	}

	// Last, and deliberately so. The namespaces are terminating by now, which
	// admits no new objects, and the tenant's cluster-scoped bindings are gone --
	// so a finalizer cleared here cannot be put back.
	if err := tc.stripFinalizersInTenantNamespaces(tenantId); err != nil {
		return errors.Errorf("fail to clear finalizers for tenant %s: %v", tenantId, err)
	}

	if err := tc.deleteClusterResourceQuota(tenantId); err != nil {
		return errors.Errorf("fail to delete clusterResourceQuota for tenant %s: %v", tenantId, err)
	}

	klog.Infof("deleted resources for tenant %s", tenantId)
	return nil
}

// genClusterScopedResourceList generates the list of the cluster-scoped resources.
func (tc *TenantController) getClusterScopedResources() ([]metav1.APIResource, error) {
	_, apiResourceLists, err := tc.upstreamDiscoveryClient.ServerGroupsAndResources()
	if err != nil {
		return nil, err
	}

	clusterScopedLists := discovery.FilteredBy(
		discovery.ResourcePredicateFunc(
			func(gv string, r *metav1.APIResource) bool {
				return !r.Namespaced
			},
		), apiResourceLists)

	return util.FlattenResourceLists(clusterScopedLists), nil
}

// deleteCRDs delete all crds belong to the tenant.
// NOTE: when a CRD is deleted, all its associated CRs will be removed automatically.
func (tc *TenantController) deleteCRDs(tenantId string) error {
	crdList, err := tc.upstreamCRDClient.ApiextensionsV1().CustomResourceDefinitions().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	for _, crd := range crdList.Items {
		if strings.HasPrefix(crd.Spec.Group, tenantId+util.TenantIDSeparator) {
			if err = tc.upstreamCRDClient.ApiextensionsV1().CustomResourceDefinitions().Delete(context.TODO(), crd.GetName(), metav1.DeleteOptions{}); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return err
			}
			klog.Infof("delete crd(%s) for tenant %s", crd.GetName(), tenantId)
			continue
		}
		klog.V(4).Infof("crd(%s) does not belong to tenant %s", crd.GetName(), tenantId)
	}

	return nil
}

// deleteNonCRDClusterScopedResources delete all non-crd resources belong to the tenant.
func (tc *TenantController) deleteNonCRDClusterScopedResources(tenantId string, nonCRDAPIResources []metav1.APIResource) error {
	for _, apiResource := range nonCRDAPIResources {
		if !util.ContainString(apiResource.Verbs, verbList) || !util.ContainString(apiResource.Verbs, verbDelete) {
			continue
		}

		gvr := util.GetGVR(apiResource)
		rClient := tc.upstreamDynamicClient.Resource(gvr)

		resourceList, err := rClient.List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			// ⚠️ Forbidden is expected here and must not stop the sweep. This
			// loop walks *every* cluster-scoped resource upstream advertises with
			// list and delete -- nodes, apiservices, storageclasses, csidrivers,
			// priorityclasses -- almost none of which a tenant could ever have
			// created, and the controller is deliberately not cluster-admin. A
			// SubjectAccessReview census under the shipped manifest found only 2
			// of 26 both listable and deletable, so returning here aborted every
			// teardown at the first one: the finalizer was never removed, the
			// Tenant stayed Terminating for good, and the operator's natural
			// remedy -- stripping the finalizer by hand -- left the tenant's
			// namespaces, secrets and custom resources behind for the next holder
			// of that six-character id.
			if apierrors.IsForbidden(err) {
				klog.V(4).Infof("not listing %s while tearing down tenant %s, which is fine "+
					"unless a tenant can create one: %v", gvr.String(), tenantId, err)
				continue
			}
			return err
		}

		for _, resource := range resourceList.Items {
			// ⚠️ The separator is load-bearing, and these two sites were the only
			// ones in either repository that dropped it. Everything kubezoo names
			// for a tenant comes from AddTenantIDPrefix, which is literally
			// tenantID + "-" + input, and the contract's own ownership predicate
			// (util.UpstreamObjectBelongsToTenant) has always required the dash.
			//
			// Without it, deleting a tenant deletes every cluster-scoped object
			// whose name merely begins with the six characters of its id.
			// ValidateTenantName checks length and RFC1123 and nothing else, so a
			// tenant may be called "system" -- and tearing that one down was
			// measured against a real 1.36 apiserver to delete 66 of the 70
			// bootstrap ClusterRoles, including system:kube-controller-manager and
			// system:kube-scheduler. The shipped controller RBAC does not save
			// you: clusterroles and clusterrolebindings are exactly what it grants
			// delete on. Nothing puts them back either -- rbac/bootstrap-roles is
			// a post-start hook, not a running reconciler -- so the cluster stays
			// broken until every apiserver restarts.
			if strings.HasPrefix(resource.GetName(), tenantId+util.TenantIDSeparator) {
				if _, _, err = rClient.Delete(context.TODO(), resource.GetName(), metav1.DeleteOptions{}); err != nil {
					if apierrors.IsNotFound(err) {
						continue
					}
					if apierrors.IsForbidden(err) {
						// Different from the list above: this object really is the
						// tenant's and really is being left behind, so it is a
						// warning rather than a V(4) -- but it still must not wedge
						// the teardown, or nothing else gets cleaned up either.
						klog.Warningf("cannot delete %s %s belonging to tenant %s, leaving it behind; "+
							"grant the controller delete on %s: %v",
							gvr.String(), resource.GetName(), tenantId, gvr.Resource, err)
						continue
					}
					return err
				}
				klog.Infof("delete cluster-scoped resource (%s) for tenant %s", resource.GetName(), tenantId)
			} else {
				klog.V(4).Infof("cluster-scoped resource (%s) does not belong to tenant %s", resource.GetName(), tenantId)
			}
		}
	}

	return nil
}

// filterCRDs split cluster-scoped resources to CRDs and non-CRDs.
func (tc *TenantController) filterCRDs(clusterScopedAPIResources []metav1.APIResource) []metav1.APIResource {
	nonCRDs := make([]metav1.APIResource, 0, len(clusterScopedAPIResources))
	for _, resource := range clusterScopedAPIResources {
		if !util.IsCRD(resource) {
			nonCRDs = append(nonCRDs, resource)
		}
	}

	return nonCRDs
}

// suspensionModeOf reports the suspension in force for a tenant, or the empty
// mode if it is operating normally.
func (tc *TenantController) suspensionModeOf(tenantId string) tenantv1alpha1.TenantSuspensionMode {
	tenant, err := tc.tenantLister.Get(tenantId)
	if err != nil {
		// Treated as not suspended. The alternative -- assuming the strictest
		// mode when the cache cannot answer -- would freeze every tenant on a
		// transient fault, which is a far worse failure than briefly leaving a
		// suspension unapplied.
		klog.Warningf("cannot read tenant %s to determine its suspension, reconciling it as "+
			"operating normally: %v", tenantId, err)
		return ""
	}
	if tenant.Spec.Suspension == nil {
		return ""
	}
	return tenant.Spec.Suspension.Mode
}

// reportBindingsFreezingDoesNotReach names what a revocation leaves standing.
//
// Freezing a tenant withdraws the bindings kubezoo created, which stops the
// tenant's own credentials. It does not stop the tenant's workloads: a tenant
// may bind its own service accounts, those bindings are the tenant's objects
// rather than kubezoo's, and a controller the tenant deployed keeps its
// permissions and its token. For the billing case that is correct -- the
// applications are supposed to keep working. For an investigation it is a hole,
// because the tenant's own automation can still change or delete the evidence --
// so a freeze is not on its own a forensic hold.
//
// This is deliberately not closed, and the reason is where the boundary of this
// component lies. KubeZoo freezes the control plane; that is the primitive it
// offers. Whatever an investigation additionally requires -- capturing the
// object state, stopping the workloads themselves -- happens outside it, and
// deciding on that is the job of whatever drives KubeZoo, not of KubeZoo.
//
// So this reports rather than fixes, and reports only what it knows: which of
// the tenant's own bindings a freeze does not reach. What to do about them is
// the caller's call.
func (tc *TenantController) reportBindingsFreezingDoesNotReach(tenantId string) {
	namespaces, err := tc.upstreamCoreClient.Namespaces().List(context.TODO(), metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{common.TenantNamespaceLabelKey: tenantId}).String(),
	})
	if err != nil {
		klog.Warningf("tenant %s is frozen, but its own role bindings could not be listed to "+
			"report what the freeze does not reach: %v", tenantId, err)
		return
	}
	var remaining []string
	for i := range namespaces.Items {
		bindings, err := tc.upstreamRbacClient.RoleBindings(namespaces.Items[i].Name).List(
			context.TODO(), metav1.ListOptions{})
		if err != nil {
			continue
		}
		for j := range bindings.Items {
			if bindings.Items[j].Name == tenantNamespaceAdminBinding {
				continue
			}
			remaining = append(remaining, namespaces.Items[i].Name+"/"+bindings.Items[j].Name)
		}
	}
	if len(remaining) == 0 {
		return
	}
	klog.Warningf("tenant %s is frozen; %d role bindings it created are still in force and still "+
		"grant its service accounts: %v. A freeze withdraws the tenant's own access, not the "+
		"permissions its workloads hold, so anything it deployed keeps running with them",
		tenantId, len(remaining), remaining)
}

// syncResources sync system resources to the upstream cluster when new tenant is being created.
func (tc *TenantController) syncResources(tenantId string) error {
	if tc.tenantClient == nil || tc.upstreamCoreClient == nil || tc.upstreamRbacClient == nil {
		return errors.New("Skip synchronize namespaces or RBAC resources since nil client.")
	}

	klog.V(4).Infof("Sync system resources for tenant %s", tenantId)

	// The suspension decides how much of a tenant's upstream permission is
	// reconciled back. It is read here, from the tenant object, rather than
	// left to an operator editing RBAC by hand: this controller converges, so a
	// hand-deleted binding is simply recreated on the next pass.
	mode := tc.suspensionModeOf(tenantId)

	if err := syncNamespaces(tc.upstreamCoreClient, tenantId); err != nil {
		return err
	}
	if err := syncClusterRoles(tc.upstreamCoreClient, tc.upstreamRbacClient, tenantId, mode, tc.upstreamCRDClient); err != nil {
		return err
	}
	if err := syncClusterRoleBindings(tc.upstreamCoreClient, tc.upstreamRbacClient, tenantId, mode); err != nil {
		return err
	}
	if err := syncNamespaceRoleBindings(tc.upstreamCoreClient, tc.upstreamRbacClient, tenantId, mode); err != nil {
		return err
	}
	// ⚠️ Skipped entirely while a tenant is suspended. A suspension withdraws
	// upstream permission; deriving a cluster-wide grant during one would hand
	// back, through another door, exactly what the suspension took away.
	if mode == "" {
		if err := tc.syncClusterWideBindings(tenantId, tc.upstreamCoreClient, tc.upstreamRbacClient); err != nil {
			klog.Warningf("tenant %s: could not reconcile its cluster-wide bindings: %v", tenantId, err)
		}
	} else if err := tc.withdrawUnwantedPairs(context.TODO(), tc.upstreamRbacClient, tenantId,
		map[string]bool{}); err != nil {
		klog.Warningf("tenant %s: could not withdraw its cluster-wide bindings for the suspension: %v",
			tenantId, err)
	}
	if isFreeze(mode) {
		tc.reportBindingsFreezingDoesNotReach(tenantId)
	}
	if err := genCertAndKubeconfig(tc.tenantClient, tenantId, tc.tenantLister, tc.clientCAFile, tc.clientCAKeyFile, tc.kubeZooHostAddress, tc.credentialValidity, tc.credentialValidityCeiling); err != nil {
		return err
	}
	// ⚠️ After issuing, not instead of it, and on every reconcile rather than on a
	// timer of its own. The resync is what makes the retention window take effect
	// at all: nothing else revisits a tenant that has stopped changing, and a
	// tenant that has stopped changing is exactly the one whose credential has
	// been sitting there longest.
	//
	// ⛔ And it can NEVER fail this reconcile. Dropping a stored copy of an
	// already-delivered credential is housekeeping; namespaces, RBAC and quota
	// are not. The first version returned both errors from here, which meant a
	// lister miss or a conflicting write turned a tenant's whole reconcile into a
	// failure and a backoff -- and a tenant whose RBAC converges late shows up as
	// a ServiceAccount refused a grant it demonstrably has, which is nothing like
	// a credential problem to look at.
	if current, err := tc.tenantLister.Get(tenantId); err != nil {
		klog.V(4).Infof("skipping the credential retention check for tenant(%s): %v", tenantId, err)
	} else if err := withdrawCollectedCredential(tc.tenantClient, current, tc.credentialRetention, time.Now()); err != nil {
		klog.Warningf("could not withdraw the stored credential of tenant(%s), will retry next resync: %v", tenantId, err)
	}
	return nil
}

// deleteClusterResourceQuota removes the tenant's quota during teardown.
//
// ⚠️ Teardown used to call syncClusterResourceQuota, which deletes the quota only
// on the branch where the Tenant is already NotFound -- and during teardown it is
// not: the finalizer is still on it, which is the whole reason this code is
// running. Worse, the function returns early whenever a deletionTimestamp is set,
// so it did nothing at all and reported success. The finalizer was then removed,
// the Tenant vanished, and no later event reached the delete branch: the
// finalizer-removal update returns on NotFound, and the informer's Delete event
// only logs. The cluster-scoped quota was orphaned for good, and a reused tenant
// id inherited the previous tenant's limits.
func (tc *TenantController) deleteClusterResourceQuota(tenantID string) error {
	if tc.clusterquotaCli == nil {
		return nil
	}
	name := fmt.Sprintf("%s-%s", common.TenantQuotaNamePrefix, tenantID)
	if err := tc.clusterquotaCli.ClusterResourceQuotas().Delete(
		context.TODO(), name, metav1.DeleteOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	klog.Infof("delete cluster resource quota (%s) for tenant %s", name, tenantID)
	return nil
}

// reportQuotaUnenforceable says out loud that a tenant's quota is not being
// enforced, but only when the tenant actually asked for one.
//
// ⛔ This used to be a single klog.Warning saying the sync was skipped, which
// read like "you did not enable an optional feature" -- and that is exactly how
// it was missed. The upstream cluster only serves quota.kubezoo.io if a
// ClusterResourceQuota CRD is registered, no manifest in any of the three
// repositories contains one, and nothing generates one, so clusterQuotaClient
// returns nil in EVERY deployment path. A tenant with spec.quota set has simply
// never had it enforced, and the only trace was that one line.
//
// ⚠️ Silence is right when the tenant asked for nothing: quota really is
// optional and a cluster without it should not be nagged. What is not right is
// being quiet when a tenant DID ask. That difference is the whole point of this
// function, and it is why the check reads the tenant rather than logging up
// front.
//
// Reported once per tenant per process. This runs on every resync for every
// tenant, so an unconditional error would bury the cluster in a line that says
// the same thing forever.
func (tc *TenantController) reportQuotaUnenforceable(tenantID string) {
	if tc.tenantClient == nil {
		// Nothing to read the tenant with; the old message is all that can be said.
		klog.Warning("Skip synchronize cluster resource quota since nil tenant client.")
		return
	}
	tenant, err := tc.tenantClient.Tenants().Get(context.TODO(), tenantID, metav1.GetOptions{})
	if err != nil || len(tenant.Spec.Quota.Hard) == 0 {
		// No quota asked for, or the tenant is gone. Optional means optional.
		return
	}
	if _, told := tc.quotaUnenforceableReported.LoadOrStore(tenantID, true); told {
		return
	}
	klog.Errorf("tenant %s sets spec.quota but NO QUOTA IS BEING ENFORCED for it: the upstream "+
		"cluster does not serve quota.kubezoo.io clusterresourcequotas, so the cluster resource "+
		"quota client could not be built. Register the ClusterResourceQuota CRD upstream before "+
		"relying on tenant quotas -- until then this tenant can consume the cluster without limit",
		tenantID)
}

func (tc *TenantController) syncClusterResourceQuota(tenantID string) error {
	if tc.tenantClient == nil || tc.clusterquotaCli == nil {
		tc.reportQuotaUnenforceable(tenantID)
		return nil
	}
	tenantQuotaName := fmt.Sprintf("%s-%s", common.TenantQuotaNamePrefix, tenantID)

	tenant, err := tc.tenantClient.Tenants().Get(context.TODO(), tenantID, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			nerr := tc.clusterquotaCli.ClusterResourceQuotas().Delete(context.TODO(), tenantQuotaName, metav1.DeleteOptions{})
			if apierrors.IsNotFound(nerr) {
				// ignore notFound
				nerr = nil
			}
			if nerr == nil {
				klog.Infof("delete cluster resource quota (%v) successfully", tenantQuotaName)
			}
			return nerr
		}
		return err
	}

	if tenant.DeletionTimestamp != nil {
		// skip sync, wait for cleanup
		return nil
	}

	clusterquota, err := tc.clusterquotaCli.ClusterResourceQuotas().Get(context.TODO(), tenantQuotaName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	expectedQuota := &quotav1alpha1.ClusterResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: tenantQuotaName,
		},
		Spec: quotav1alpha1.ClusterResourceQuotaSpec{
			ResourceQuotaSpec: corev1.ResourceQuotaSpec{
				Hard: tenant.Spec.Quota.Hard,
			},
			NamepsaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					common.TenantNamespaceLabelKey: tenantID,
				},
			},
		},
	}
	if apierrors.IsNotFound(err) {
		// create
		_, err := tc.clusterquotaCli.ClusterResourceQuotas().Create(context.TODO(), expectedQuota, metav1.CreateOptions{})
		return err
	}

	// update
	if !reflect.DeepEqual(clusterquota.Spec.Hard, tenant.Spec.Quota.Hard) ||
		!reflect.DeepEqual(clusterquota.Spec.NamepsaceSelector, expectedQuota.Spec.NamepsaceSelector) {
		mutator := func(quota *quotav1alpha1.ClusterResourceQuota) error {
			quota.Spec.Hard = tenant.Spec.Quota.Hard
			quota.Spec.NamepsaceSelector = expectedQuota.Spec.NamepsaceSelector
			return nil
		}
		//TODO: retry
		return retry.RetryOnConflict(wait.Backoff{
			Steps:    20,
			Duration: 500 * time.Millisecond,
			Factor:   1.0,
			Jitter:   0.1},
			func() error {
				quota, err := tc.clusterquotaCli.ClusterResourceQuotas().Get(context.TODO(), tenantQuotaName, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if err = mutator(quota); err != nil {
					return errors.Wrap(err, "unable to mutate ClusterResourceQuotas")
				}
				_, err = tc.clusterquotaCli.ClusterResourceQuotas().Update(context.TODO(), quota, metav1.UpdateOptions{})
				return err
			},
		)
	}

	// do nothing
	return nil
}

// syncNamespaces synchronize the system namespaces to upstream cluster.
func syncNamespaces(coreClient v1.CoreV1Interface, tenantId string) error {
	systemNamespaces := []string{metav1.NamespaceSystem, metav1.NamespacePublic, corev1.NamespaceNodeLease, corev1.NamespaceDefault}

	for _, systemNamespace := range systemNamespaces {
		expectNamespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:      tenantId + "-" + systemNamespace,
				Namespace: "",
				Labels:    tenantNamespaceLabels(tenantId),
			},
		}
		ns, err := coreClient.Namespaces().Get(context.TODO(), expectNamespace.Name, metav1.GetOptions{})
		if err != nil {
			_, err = coreClient.Namespaces().Create(context.TODO(), expectNamespace, metav1.CreateOptions{})
			if err == nil {
				continue
			}
			if !apierrors.IsAlreadyExists(err) {
				klog.Warningf("Failed to create the tenant namespace %s with error %v", expectNamespace.Name, err)
				return err
			}
			// check namespaces's labels if it already exists
			ns, err = coreClient.Namespaces().Get(context.TODO(), expectNamespace.Name, metav1.GetOptions{})
			if err != nil {
				klog.Warningf("Failed to get the tenant namespace %s with error %v", expectNamespace.Name, err)
				return err
			}
		}

		if ns.Labels == nil {
			ns.Labels = make(map[string]string)
		}
		drifted := false
		for key, want := range tenantNamespaceLabels(tenantId) {
			if ns.Labels[key] != want {
				ns.Labels[key] = want
				drifted = true
			}
		}
		if drifted {
			// TODO: retry on conflict
			_, err := coreClient.Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
			if err != nil {
				klog.Warningf("Failed to update the tenant namespace %s with error %v", expectNamespace.Name, err)
				return err
			}
		}
	}
	return nil
}

// tenantNamespaceLabels are the labels every tenant namespace must carry.
//
// ⭐ The Pod Security ones are here, and not left to the Kyverno policy that also
// writes them, because Pod Security Admission runs INSIDE the apiserver -- no
// webhook, no single point. A namespace carrying the label refuses host
// namespaces, privileged containers and host paths with every webhook in the
// cluster gone, which makes it the one piece of real depth in the pod surface.
//
// ⛔ Until this, the label was written only by a Kyverno mutate, so the second
// layer was installed by the first: a namespace created while that webhook was
// not registered carried no label and got no enforcement at all. failurePolicy:
// Fail does not cover it -- that covers a webhook which fails, not one which was
// never registered, and the latter is the failure that actually happened.
//
// Written on create and repaired by the loop above, so a namespace that drifted
// -- or that a tenant weakened -- is put back on the next sync rather than
// needing an administrator.
func tenantNamespaceLabels(tenantId string) map[string]string {
	return map[string]string{
		common.TenantNamespaceLabelKey:           tenantId,
		common.PodSecurityEnforceLabelKey:        common.PodSecurityLevel,
		common.PodSecurityEnforceVersionLabelKey: common.PodSecurityVersion,
	}
}

// genCertAndKubeconfig signs the certificate/key and generates the kubeconfig for the tenant;
// the generated kubeconfig will be attached in the tenant's annotation.
func genCertAndKubeconfig(tenantCli tenantclient.TenantV1alpha1Interface, tenantId string, tenantlister tenantlister.TenantLister, clientCAFile, clientCAKeyFile, kubeZooHostAddress string, validity, validityCeiling time.Duration) error {
	cached, err := tenantlister.Get(tenantId)
	if err != nil {
		return errors.Errorf("Error fetching object with key %s from store: %v", tenantId, err)
	}
	// ⚠️ Copied. The lister hands back the informer's own object, and this
	// function writes the kubeconfig annotation into it before calling Update.
	// When that Update failed -- a webhook, a 500, a missing permission -- the
	// error was returned and the item requeued, but the cache now carried the
	// annotation, so the retry took the "already generated" early return and
	// reported success. The tenant ended up fully provisioned and never handed
	// credentials, with one klog.Warningf as the only trace, until a full re-LIST
	// or a controller restart cleared the poisoned entry. A persistent rejection
	// turned into a permanently green reconcile.
	tenant := cached.DeepCopy()

	// 1. Decide from the two annotations which of the three states this is.
	//
	// ⭐ "Does it already have a kubeconfig" is no longer the question, because
	// the kubeconfig is meant to go away: the platform hands it over once and
	// then stops holding the tenant's private key. The question is whether a
	// credential has ever been issued, and the issued-at marker is what answers
	// it.
	kubeconfig := tenant.Annotations[util.AnnotationTenantKubeConfigBase64]
	issuedAt := tenant.Annotations[util.AnnotationTenantCredentialIssuedAt]
	switch {
	case issuedAt != "":
		// Issued: either still being collected, or already withdrawn. Neither is
		// a reason to sign something new. Asking for a new credential means
		// removing this annotation.
		return nil
	case kubeconfig != "":
		// ⚠️ Adoption, not reissue. A tenant provisioned before this marker
		// existed has a kubeconfig and no marker, which reads as "never issued"
		// -- and signing a second credential for every existing tenant would be
		// a surprising thing for an upgrade to do on its own. Stamp the marker
		// on what is already there and leave the credential alone. The retention
		// clock then starts at the upgrade, which is the earliest moment the
		// platform can honestly claim to know anything about it.
		return stampCredentialIssued(tenantCli, tenant, time.Now())
	}

	// 2. Generate the certificate and the key
	cert, key, err := util.NewTenantCertAndKey(clientCAFile, clientCAKeyFile, tenantId,
		credentialValidityFor(tenant, validity, validityCeiling))
	if err != nil {
		klog.Warningf("fail to generate the certificate for the tenant(%s): %v", tenantId, err)
		return err
	}

	// 3. Generate the kubeconfig
	caCertByts, err := ioutil.ReadFile(clientCAFile)
	if err != nil {
		klog.Warningf("fail to read CA from file(%s): %v", clientCAFile, err)
		return err
	}
	kbcfgByts, err := util.GenKubeconfig("https://"+kubeZooHostAddress, tenantId, caCertByts, util.EncodePrivateKeyPEM(key), util.EncodeCertPEM(cert))
	if err != nil {
		klog.Warningf("fail to generate the kubeconfig for tenant(%s): %v", tenantId, err)
		return err
	}
	kbcfgB64Str := base64.StdEncoding.EncodeToString(kbcfgByts)

	// 4. Attach the kubeconfig to the annotation
	if tenant.Annotations == nil {
		tenant.Annotations = make(map[string]string)
	}
	tenant.Annotations[util.AnnotationTenantKubeConfigBase64] = kbcfgB64Str
	// ⚠️ Written in the SAME update as the kubeconfig, deliberately. Two updates
	// would leave a window where a credential exists with no record that it was
	// issued -- and a controller restart inside that window reads it as "never
	// issued" and signs another one.
	tenant.Annotations[util.AnnotationTenantCredentialIssuedAt] = time.Now().UTC().Format(time.RFC3339)
	// ⭐ Expiry is written down because otherwise nobody can see it. The
	// certificate carries it, but reading it means base64-decoding an annotation
	// and running openssl on the result -- so in practice the first anyone learns
	// of an expired credential is a 401 from CI on a morning nobody chose. The
	// whole point of a shorter validity is that expiry becomes a routine event,
	// and a routine event has to be visible before it happens.
	tenant.Annotations[util.AnnotationTenantCredentialExpiresAt] = cert.NotAfter.UTC().Format(time.RFC3339)
	if _, err := tenantCli.Tenants().Update(context.TODO(), tenant, metav1.UpdateOptions{}); err != nil {
		klog.Warningf("fail to update the tenant with new annotation(%s): %v", util.AnnotationTenantKubeConfigBase64, err)
		return err
	}
	klog.V(4).Infof("kubeconfig of tenant(%s) is created", tenantId)
	return nil
}

// credentialValidityFor resolves how long this tenant's next credential lives:
// the tenant's own choice, bounded by the platform's ceiling.
//
// ⭐ Both halves are decisions by different parties and neither can be dropped.
// How often a tenant wants to come back for a credential depends on how its CI
// is wired and how many people hold a kubeconfig -- the platform cannot answer
// that. How long the platform is willing to be unable to cut that tenant off is
// not the tenant's to answer either, because a client certificate cannot be
// revoked and the validity is the whole bound.
//
// ⚠️ A request over the ceiling is CLAMPED, not refused. Refusing would put a
// tenant into a state where it has no working credential and cannot get one
// without an operator noticing an error it never sees, over a field it is
// allowed to set. The clamp is logged so the operator can see the disagreement.
func credentialValidityFor(tenant *tenantv1alpha1.Tenant, platformDefault, ceiling time.Duration) time.Duration {
	validity := platformDefault
	if tenant.Spec.CredentialValidity != nil && tenant.Spec.CredentialValidity.Duration > 0 {
		validity = tenant.Spec.CredentialValidity.Duration
	}
	if ceiling > 0 && validity > ceiling {
		klog.Infof("tenant(%s) asked for a credential valid %s, which is beyond the platform ceiling of %s; issuing %s",
			tenant.Name, validity, ceiling, ceiling)
		validity = ceiling
	}
	return validity
}

// stampCredentialIssued records an issue time against a credential that already
// exists, without touching the credential.
func stampCredentialIssued(tenantCli tenantclient.TenantV1alpha1Interface, tenant *tenantv1alpha1.Tenant, at time.Time) error {
	if tenant.Annotations == nil {
		tenant.Annotations = make(map[string]string)
	}
	tenant.Annotations[util.AnnotationTenantCredentialIssuedAt] = at.UTC().Format(time.RFC3339)
	if _, err := tenantCli.Tenants().Update(context.TODO(), tenant, metav1.UpdateOptions{}); err != nil {
		klog.Warningf("fail to record the credential issue time for tenant(%s): %v", tenant.Name, err)
		return err
	}
	klog.V(4).Infof("adopted the pre-existing credential of tenant(%s); its retention starts now", tenant.Name)
	return nil
}

// withdrawCollectedCredential drops the tenant's kubeconfig -- and with it the
// tenant's private key -- once it has had long enough to be collected.
//
// ⛔ The platform was never asked to keep it. A tenant wants a credential handed
// over; it does not want a copy of its private key stored indefinitely on a
// cluster-scoped object, where a single read is every tenant at once. Holding it
// buys the platform nothing it can use: there is no revocation for a client
// certificate, so the copy is not leverage, only exposure.
//
// ⚠️ Withdrawal is not revocation and must not be mistaken for it. The
// certificate that was handed over stays valid until it expires; what stops
// working here is the platform's ability to hand out that same credential again.
// Cutting off a tenant that already holds one is a suspension (spec.suspension),
// not this.
//
// retention <= 0 turns this off, for a platform whose provisioning flow collects
// the credential later than any window would allow.
func withdrawCollectedCredential(tenantCli tenantclient.TenantV1alpha1Interface, tenant *tenantv1alpha1.Tenant, retention time.Duration, now time.Time) error {
	if retention <= 0 {
		return nil
	}
	if tenant.Annotations[util.AnnotationTenantKubeConfigBase64] == "" {
		return nil
	}
	issuedAt := tenant.Annotations[util.AnnotationTenantCredentialIssuedAt]
	if issuedAt == "" {
		// Not yet adopted; genCertAndKubeconfig stamps it and the clock starts
		// there. Withdrawing without a recorded issue time would mean withdrawing
		// on a clock nobody can see.
		return nil
	}
	at, err := time.Parse(time.RFC3339, issuedAt)
	if err != nil {
		// ⚠️ Left alone rather than treated as expired. An unparseable timestamp
		// is a bug or a hand edit, and destroying a credential on the strength of
		// one would be the worst available reading of it.
		klog.Warningf("tenant(%s) has an unparseable %s (%q); leaving its credential in place",
			tenant.Name, util.AnnotationTenantCredentialIssuedAt, issuedAt)
		return nil
	}
	if now.Before(at.Add(retention)) {
		return nil
	}
	updated := tenant.DeepCopy()
	delete(updated.Annotations, util.AnnotationTenantKubeConfigBase64)
	if _, err := tenantCli.Tenants().Update(context.TODO(), updated, metav1.UpdateOptions{}); err != nil {
		klog.Warningf("fail to withdraw the stored credential of tenant(%s): %v", tenant.Name, err)
		return err
	}
	// Info, not V(4): an operator who goes looking for a kubeconfig that is no
	// longer there needs to find out why without turning verbosity up.
	klog.Infof("tenant(%s) credential issued at %s has been held for %s; dropping the stored copy. "+
		"To be issued a new one, remove the %s annotation",
		tenant.Name, issuedAt, retention, util.AnnotationTenantCredentialIssuedAt)
	return nil
}
