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

// Command kubezoo-controller reconciles the upstream cluster against the Tenant
// objects kubezoo serves.
//
// It used to run inside the kubezoo process, started from a post-start hook.
// That made every kubezoo replica run a controller, which is wrong for the same
// reason kube-controller-manager is not part of kube-apiserver: an apiserver is
// all-active and a controller is not. Splitting it out is what makes it possible
// to say how many of each there should be.
package main

import (
	"flag"
	"time"

	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	clidiscovery "k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"

	quotav1alpha1 "github.com/fivetime/kubezoo-contract/pkg/apis/quota/v1alpha1"
	kubezoodynamic "github.com/fivetime/kubezoo-contract/pkg/dynamic"
	"github.com/fivetime/kubezoo-contract/pkg/generated/clientset/versioned"
	quotaclient "github.com/fivetime/kubezoo-contract/pkg/generated/clientset/versioned/typed/quota/v1alpha1"
	"github.com/fivetime/kubezoo-contract/pkg/generated/informers/externalversions"

	"github.com/fivetime/kubezoo-controller/pkg/controller"
)

type options struct {
	// kubezooKubeconfig reaches kubezoo itself, which is where the Tenant
	// objects live. In-process this was the loopback config; standalone it has
	// to be spelled out.
	kubezooKubeconfig string
	// upstreamKubeconfig reaches the cluster being reconciled. Everything the
	// controller writes -- namespaces, bindings, projections -- goes here.
	upstreamKubeconfig string

	// The CA the tenant client certificates are signed with, and the address
	// they are pointed at. The controller mints a kubeconfig per tenant, so it
	// needs the signing key, not just the certificate.
	clientCAFile    string
	clientCAKeyFile string
	kubezooAddress  string
	kubezooPort     int

	resyncPeriod time.Duration
	// credentialRetention is how long the platform keeps its copy of a tenant's
	// kubeconfig -- and therefore of the tenant's private key -- after issuing it.
	credentialRetention time.Duration
	// credentialValidity is what a tenant gets when it asks for nothing;
	// credentialValidityCeiling is the longest request that will be honoured.
	credentialValidity        time.Duration
	credentialValidityCeiling time.Duration
}

func (o *options) addFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.kubezooKubeconfig, "kubezoo-kubeconfig", "",
		"Path to a kubeconfig reaching kubezoo, where the Tenant objects live. Required.")
	fs.StringVar(&o.upstreamKubeconfig, "upstream-kubeconfig", "",
		"Path to a kubeconfig reaching the upstream cluster. Empty means the in-cluster config.")
	fs.StringVar(&o.clientCAFile, "client-ca-file", "",
		"Certificate of the CA that tenant client certificates are signed with.")
	fs.StringVar(&o.clientCAKeyFile, "client-ca-key-file", "",
		"Private key of that CA. The controller signs with it, so this is not the same as --client-ca-file.")
	fs.StringVar(&o.kubezooAddress, "kubezoo-address", "",
		"Address to write into the kubeconfig handed to each tenant.")
	fs.IntVar(&o.kubezooPort, "kubezoo-port", 6443,
		"Port to write into the kubeconfig handed to each tenant.")
	fs.DurationVar(&o.resyncPeriod, "resync-period", 5*time.Minute,
		"How often to reconcile every tenant regardless of events. This is the repair path; "+
			"ordinary changes are picked up by informers within seconds.")
	fs.DurationVar(&o.credentialRetention, "credential-retention", 24*time.Hour,
		"How long a freshly issued tenant kubeconfig is kept on the Tenant object before the "+
			"stored copy is dropped. That copy contains the tenant's PRIVATE KEY, so keeping it "+
			"forever makes one read of one object worth every tenant's credentials -- and it buys "+
			"nothing, since a client certificate cannot be revoked and the copy is therefore not "+
			"leverage. Removing the credential-issued-at annotation asks for a new credential. "+
			"Zero or less keeps the copy indefinitely, for a provisioning flow that collects it "+
			"later than any window would allow.")
	fs.DurationVar(&o.credentialValidity, "tenant-credential-validity", 90*24*time.Hour,
		"How long a tenant credential is valid when the tenant asks for nothing. A tenant can "+
			"choose its own with spec.credentialValidity. This number is the platform's only "+
			"bound on how long a credential keeps working after the platform would rather it "+
			"stopped, because a client certificate cannot be revoked -- so it is also how long "+
			"cutting off a single tenant takes.")
	fs.DurationVar(&o.credentialValidityCeiling, "max-tenant-credential-validity", 365*24*time.Hour,
		"Longest spec.credentialValidity that will be honoured. A longer request is clamped to "+
			"this and logged, rather than refused: refusing would leave a tenant with no working "+
			"credential over a field it is allowed to set. Zero or less means no ceiling.")
}

func main() {
	klog.InitFlags(nil)
	o := &options{}
	o.addFlags(flag.CommandLine)
	flag.Parse()

	if o.kubezooKubeconfig == "" {
		klog.Exit("--kubezoo-kubeconfig is required: the controller reads Tenant objects from kubezoo, not from the upstream cluster")
	}

	loopConfig, err := clientcmd.BuildConfigFromFlags("", o.kubezooKubeconfig)
	if err != nil {
		klog.Exitf("reading --kubezoo-kubeconfig: %v", err)
	}
	upstreamConfig, err := upstreamRestConfig(o.upstreamKubeconfig)
	if err != nil {
		klog.Exitf("reading --upstream-kubeconfig: %v", err)
	}

	tenantClient, err := versioned.NewForConfig(loopConfig)
	if err != nil {
		klog.Exitf("building the tenant client: %v", err)
	}
	tenantInformers := externalversions.NewSharedInformerFactory(tenantClient, o.resyncPeriod)

	typedClientSet, err := kubernetes.NewForConfig(upstreamConfig)
	if err != nil {
		klog.Exitf("building the upstream client: %v", err)
	}
	discoveryClient, err := clidiscovery.NewDiscoveryClientForConfig(upstreamConfig)
	if err != nil {
		klog.Exitf("building the upstream discovery client: %v", err)
	}
	dynamicClient, err := kubezoodynamic.NewForConfig(upstreamConfig)
	if err != nil {
		klog.Exitf("building the upstream dynamic client: %v", err)
	}
	crdClient, err := clientset.NewForConfig(upstreamConfig)
	if err != nil {
		klog.Exitf("building the upstream CRD client: %v", err)
	}

	stopCh := make(chan struct{})
	go controller.Run(stopCh,
		tenantInformers.Tenant().V1alpha1().Tenants().Informer(),
		tenantClient.TenantV1alpha1(),
		typedClientSet,
		discoveryClient,
		dynamicClient,
		crdClient,
		clusterQuotaClient(discoveryClient, upstreamConfig),
		o.clientCAFile,
		o.clientCAKeyFile,
		o.kubezooAddress,
		o.kubezooPort,
		o.credentialRetention,
		o.credentialValidity,
		o.credentialValidityCeiling)

	// No Start here. controller.Run runs the informer it is handed -- that is its
	// contract -- and calling Start as well produced client-go's "the
	// sharedIndexInformer has started, run more than once is not allowed" on
	// every boot.
	//
	// ⚠️ That side effect is worth being wary of rather than relying on: the
	// gateway used to get its own tenant informer started the same way, by
	// passing it to controller.Run, and taking the controller out of that process
	// stopped the informer with nothing to say so. Here the informer and the
	// thing that runs it are one line apart, which is the only reason this is
	// safe to leave implicit.
	klog.Info("kubezoo-controller running")
	select {}
}

func upstreamRestConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		return rest.InClusterConfig()
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

// clusterQuotaClient returns a quota client only if the upstream cluster serves
// that API.
//
// Nil is a supported answer, and the controller handles it: cluster resource
// quota is an optional component, and a cluster without it should not stop
// tenants being reconciled. Returning an error here instead would make the
// optional part mandatory.
func clusterQuotaClient(discoveryClient *clidiscovery.DiscoveryClient, upstreamConfig *rest.Config) quotaclient.QuotaV1alpha1Interface {
	resources, err := discoveryClient.ServerResourcesForGroupVersion(quotav1alpha1.GroupVersion.String())
	if err != nil {
		if !errors.IsNotFound(err) {
			klog.Warningf("could not ask the upstream cluster whether it serves cluster resource quotas: %v", err)
		}
		return nil
	}
	for _, resource := range resources.APIResources {
		if resource.Name != "clusterresourcequotas" {
			continue
		}
		client, err := quotaclient.NewForConfig(upstreamConfig)
		if err != nil {
			klog.Warningf("the upstream cluster serves cluster resource quotas but the client would not build: %v", err)
			return nil
		}
		return client
	}
	klog.Info("the upstream cluster does not serve clusterresourcequotas; tenant quota will not be reconciled")
	return nil
}
