//! The watched-resource kind registry.

use serde::{Deserialize, Serialize};

/// The twelve resource kinds the app watches. Serializes to the same lowercase
/// ids the frontend uses (see src/lib/kinds.ts).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ResourceKind {
    Pods,
    Deployments,
    /// The generation a Deployment actually runs; also a pod's immediate owner.
    Replicasets,
    Statefulsets,
    Daemonsets,
    Jobs,
    Cronjobs,
    Services,
    Ingresses,
    /// The controller an Ingress is handled by (cluster-scoped).
    Ingressclasses,
    Configmaps,
    Secrets,
    /// The identity a pod runs as.
    Serviceaccounts,
    /// Storage claims (namespaced) and the volumes that back them (cluster-scoped).
    Persistentvolumeclaims,
    Persistentvolumes,
    /// The classes claims are provisioned from (cluster-scoped).
    Storageclasses,
    /// NetworkPolicy — namespaced; selects which pods can talk to which.
    Networkpolicies,
    /// HorizontalPodAutoscaler — namespaced; scales a workload on metrics.
    Horizontalpodautoscalers,
    /// ResourceQuota — namespaced; caps the total resource use in an ns.
    Resourcequotas,
    /// LimitRange — namespaced; caps per-Pod / per-Container resources.
    Limitranges,
    Nodes,
    Namespaces,
    /// Cluster-wide event feed (B14) — a read-only view, not a managed resource.
    Events,
    /// Helm releases (B26) — decoded from Helm's release Secrets; read-only.
    Helm,
    /// RBAC: namespaced permission rules.
    Roles,
    /// RBAC: cluster-scoped permission rules.
    Clusterroles,
    /// RBAC: bind roles to subjects (namespaced).
    Rolebindings,
    /// RBAC: bind cluster roles to subjects (cluster-scoped).
    Clusterrolebindings,
    /// PodDisruptionBudget — namespaced; limits voluntary disruptions.
    Poddisruptionbudgets,
    /// MutatingWebhookConfiguration — cluster-scoped; admission webhooks.
    Mutatingwebhookconfigurations,
    /// ValidatingWebhookConfiguration — cluster-scoped; admission webhooks.
    Validatingwebhookconfigurations,
    /// APIService — cluster-scoped; registers aggregated API servers.
    Apiservices,
}

impl ResourceKind {
    /// The lowercase id string (matches the frontend and serde rename).
    pub fn id(&self) -> &'static str {
        match self {
            ResourceKind::Pods => "pods",
            ResourceKind::Deployments => "deployments",
            ResourceKind::Replicasets => "replicasets",
            ResourceKind::Statefulsets => "statefulsets",
            ResourceKind::Daemonsets => "daemonsets",
            ResourceKind::Jobs => "jobs",
            ResourceKind::Cronjobs => "cronjobs",
            ResourceKind::Services => "services",
            ResourceKind::Ingresses => "ingresses",
            ResourceKind::Ingressclasses => "ingressclasses",
            ResourceKind::Configmaps => "configmaps",
            ResourceKind::Secrets => "secrets",
            ResourceKind::Serviceaccounts => "serviceaccounts",
            ResourceKind::Persistentvolumeclaims => "persistentvolumeclaims",
            ResourceKind::Persistentvolumes => "persistentvolumes",
            ResourceKind::Storageclasses => "storageclasses",
            ResourceKind::Networkpolicies => "networkpolicies",
            ResourceKind::Horizontalpodautoscalers => "horizontalpodautoscalers",
            ResourceKind::Resourcequotas => "resourcequotas",
            ResourceKind::Limitranges => "limitranges",
            ResourceKind::Nodes => "nodes",
            ResourceKind::Namespaces => "namespaces",
            ResourceKind::Events => "events",
            ResourceKind::Helm => "helm",
            ResourceKind::Roles => "roles",
            ResourceKind::Clusterroles => "clusterroles",
            ResourceKind::Rolebindings => "rolebindings",
            ResourceKind::Clusterrolebindings => "clusterrolebindings",
            ResourceKind::Poddisruptionbudgets => "poddisruptionbudgets",
            ResourceKind::Mutatingwebhookconfigurations => "mutatingwebhookconfigurations",
            ResourceKind::Validatingwebhookconfigurations => "validatingwebhookconfigurations",
            ResourceKind::Apiservices => "apiservices",
        }
    }

    /// The API group (e.g. "apps", "autoscaling", "" for core/v1).
    pub fn group(&self) -> &'static str {
        match self {
            ResourceKind::Pods
            | ResourceKind::Services
            | ResourceKind::Configmaps
            | ResourceKind::Secrets
            | ResourceKind::Serviceaccounts
            | ResourceKind::Persistentvolumeclaims
            | ResourceKind::Persistentvolumes
            | ResourceKind::Nodes
            | ResourceKind::Namespaces
            | ResourceKind::Events
            | ResourceKind::Resourcequotas
            | ResourceKind::Limitranges => "",
            ResourceKind::Deployments
            | ResourceKind::Replicasets
            | ResourceKind::Statefulsets
            | ResourceKind::Daemonsets => "apps",
            ResourceKind::Jobs | ResourceKind::Cronjobs => "batch",
            ResourceKind::Ingresses
            | ResourceKind::Ingressclasses
            | ResourceKind::Networkpolicies => "networking.k8s.io",
            ResourceKind::Storageclasses => "storage.k8s.io",
            ResourceKind::Horizontalpodautoscalers => "autoscaling",
            ResourceKind::Roles
            | ResourceKind::Clusterroles
            | ResourceKind::Rolebindings
            | ResourceKind::Clusterrolebindings => "rbac.authorization.k8s.io",
            ResourceKind::Helm => "",
            ResourceKind::Poddisruptionbudgets => "policy",
            ResourceKind::Mutatingwebhookconfigurations
            | ResourceKind::Validatingwebhookconfigurations => "admissionregistration.k8s.io",
            ResourceKind::Apiservices => "apiregistration.k8s.io",
        }
    }

    /// The API version (e.g. "v1", "v2").
    pub fn version(&self) -> &'static str {
        match self {
            ResourceKind::Horizontalpodautoscalers => "v2",
            _ => "v1",
        }
    }

    /// The plural lowercase name (e.g. "horizontalpodautoscalers").
    pub fn plural(&self) -> &'static str {
        self.id()
    }

    /// The PascalCase kind name (e.g. "HorizontalPodAutoscaler").
    pub fn kind_name(&self) -> &'static str {
        match self {
            ResourceKind::Pods => "Pod",
            ResourceKind::Deployments => "Deployment",
            ResourceKind::Replicasets => "ReplicaSet",
            ResourceKind::Statefulsets => "StatefulSet",
            ResourceKind::Daemonsets => "DaemonSet",
            ResourceKind::Jobs => "Job",
            ResourceKind::Cronjobs => "CronJob",
            ResourceKind::Services => "Service",
            ResourceKind::Ingresses => "Ingress",
            ResourceKind::Ingressclasses => "IngressClass",
            ResourceKind::Configmaps => "ConfigMap",
            ResourceKind::Secrets => "Secret",
            ResourceKind::Serviceaccounts => "ServiceAccount",
            ResourceKind::Persistentvolumeclaims => "PersistentVolumeClaim",
            ResourceKind::Persistentvolumes => "PersistentVolume",
            ResourceKind::Storageclasses => "StorageClass",
            ResourceKind::Networkpolicies => "NetworkPolicy",
            ResourceKind::Horizontalpodautoscalers => "HorizontalPodAutoscaler",
            ResourceKind::Resourcequotas => "ResourceQuota",
            ResourceKind::Limitranges => "LimitRange",
            ResourceKind::Nodes => "Node",
            ResourceKind::Namespaces => "Namespace",
            ResourceKind::Events => "Event",
            ResourceKind::Helm => "HelmRelease",
            ResourceKind::Roles => "Role",
            ResourceKind::Clusterroles => "ClusterRole",
            ResourceKind::Rolebindings => "RoleBinding",
            ResourceKind::Clusterrolebindings => "ClusterRoleBinding",
            ResourceKind::Poddisruptionbudgets => "PodDisruptionBudget",
            ResourceKind::Mutatingwebhookconfigurations => "MutatingWebhookConfiguration",
            ResourceKind::Validatingwebhookconfigurations => "ValidatingWebhookConfiguration",
            ResourceKind::Apiservices => "APIService",
        }
    }

    /// Whether this kind is namespaced.
    pub fn is_namespaced(&self) -> bool {
        !matches!(
            self,
            ResourceKind::Nodes
                | ResourceKind::Persistentvolumes
                | ResourceKind::Storageclasses
                | ResourceKind::Namespaces
                | ResourceKind::Events
                | ResourceKind::Helm
                | ResourceKind::Clusterroles
                | ResourceKind::Clusterrolebindings
                | ResourceKind::Mutatingwebhookconfigurations
                | ResourceKind::Validatingwebhookconfigurations
                | ResourceKind::Apiservices
        )
    }

    /// Parse a lowercase kind id (e.g. "deployments") into a `ResourceKind`.
    ///
    /// Returns `None` for unknown ids, custom CRD kinds (contain `/`),
    /// and the special "endpoints" id (not watched, no enum variant).
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "pods" => Some(Self::Pods),
            "deployments" => Some(Self::Deployments),
            "replicasets" => Some(Self::Replicasets),
            "statefulsets" => Some(Self::Statefulsets),
            "daemonsets" => Some(Self::Daemonsets),
            "jobs" => Some(Self::Jobs),
            "cronjobs" => Some(Self::Cronjobs),
            "services" => Some(Self::Services),
            "ingresses" => Some(Self::Ingresses),
            "ingressclasses" => Some(Self::Ingressclasses),
            "configmaps" => Some(Self::Configmaps),
            "secrets" => Some(Self::Secrets),
            "serviceaccounts" => Some(Self::Serviceaccounts),
            "persistentvolumeclaims" => Some(Self::Persistentvolumeclaims),
            "persistentvolumes" => Some(Self::Persistentvolumes),
            "storageclasses" => Some(Self::Storageclasses),
            "networkpolicies" => Some(Self::Networkpolicies),
            "horizontalpodautoscalers" => Some(Self::Horizontalpodautoscalers),
            "resourcequotas" => Some(Self::Resourcequotas),
            "limitranges" => Some(Self::Limitranges),
            "nodes" => Some(Self::Nodes),
            "namespaces" => Some(Self::Namespaces),
            "events" => Some(Self::Events),
            "helm" => Some(Self::Helm),
            "roles" => Some(Self::Roles),
            "clusterroles" => Some(Self::Clusterroles),
            "rolebindings" => Some(Self::Rolebindings),
            "clusterrolebindings" => Some(Self::Clusterrolebindings),
            "poddisruptionbudgets" => Some(Self::Poddisruptionbudgets),
            "mutatingwebhookconfigurations" => Some(Self::Mutatingwebhookconfigurations),
            "validatingwebhookconfigurations" => Some(Self::Validatingwebhookconfigurations),
            "apiservices" => Some(Self::Apiservices),
            _ => None,
        }
    }

    /// Parse a PascalCase kind name (e.g. "Deployment") into a `ResourceKind`.
    ///
    /// Returns `None` for unknown kinds, "Endpoints" (not in the enum),
    /// and custom CRD kinds.
    pub fn from_kind_name(name: &str) -> Option<Self> {
        match name {
            "Pod" => Some(Self::Pods),
            "Deployment" => Some(Self::Deployments),
            "ReplicaSet" => Some(Self::Replicasets),
            "StatefulSet" => Some(Self::Statefulsets),
            "DaemonSet" => Some(Self::Daemonsets),
            "Job" => Some(Self::Jobs),
            "CronJob" => Some(Self::Cronjobs),
            "Service" => Some(Self::Services),
            "Ingress" => Some(Self::Ingresses),
            "IngressClass" => Some(Self::Ingressclasses),
            "ConfigMap" => Some(Self::Configmaps),
            "Secret" => Some(Self::Secrets),
            "ServiceAccount" => Some(Self::Serviceaccounts),
            "PersistentVolumeClaim" => Some(Self::Persistentvolumeclaims),
            "PersistentVolume" => Some(Self::Persistentvolumes),
            "StorageClass" => Some(Self::Storageclasses),
            "NetworkPolicy" => Some(Self::Networkpolicies),
            "HorizontalPodAutoscaler" => Some(Self::Horizontalpodautoscalers),
            "ResourceQuota" => Some(Self::Resourcequotas),
            "LimitRange" => Some(Self::Limitranges),
            "Node" => Some(Self::Nodes),
            "Namespace" => Some(Self::Namespaces),
            "Event" => Some(Self::Events),
            "HelmRelease" => Some(Self::Helm),
            "Role" => Some(Self::Roles),
            "ClusterRole" => Some(Self::Clusterroles),
            "RoleBinding" => Some(Self::Rolebindings),
            "ClusterRoleBinding" => Some(Self::Clusterrolebindings),
            "PodDisruptionBudget" => Some(Self::Poddisruptionbudgets),
            "MutatingWebhookConfiguration" => Some(Self::Mutatingwebhookconfigurations),
            "ValidatingWebhookConfiguration" => Some(Self::Validatingwebhookconfigurations),
            "APIService" => Some(Self::Apiservices),
            _ => None,
        }
    }

    /// Create an ApiResource for DynamicObject-based watchers.
    pub fn api_resource(&self) -> k7s_deps::kube::core::ApiResource {
        let gvk = k7s_deps::kube::core::GroupVersionKind::gvk(self.group(), self.version(), self.kind_name());
        k7s_deps::kube::core::ApiResource::from_gvk_with_plural(&gvk, self.plural())
    }
}
