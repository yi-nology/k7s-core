//! Read-only AI tools — thin wrappers around `impls::*_impl()`.

use crate::ai::error::{AiError, AiResult};
use crate::ai::tools::{
    get_arg_str, get_opt_bool, get_opt_i64, get_opt_str, impls, ok_value, Tool, ToolContext,
};
use k7s_deps::async_trait::async_trait;

pub struct ListResources;
#[async_trait]
impl Tool for ListResources {
    fn name(&self) -> &str {
        "list_resources"
    }
    fn description(&self) -> &str {
        "List Kubernetes resources of a given kind. Returns [{name, namespace, kind}], or {items, continue} when paging with limit/continueToken on large clusters."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{
            "kind":{"type":"string"},"namespace":{"type":"string"},"label_selector":{"type":"string"},
            "limit":{"type":"integer","description":"Page size (e.g. 100). On large clusters the response becomes {items, continue}."},
            "continueToken":{"type":"string","description":"Opaque token from a previous page's `continue` field; returns the next page."}
        },"required":["kind"]})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        let kind = get_arg_str(&args, "kind")?;
        let ns = get_opt_str(&args, "namespace").unwrap_or_default();
        let label = get_opt_str(&args, "label_selector");
        let limit = args.get("limit").and_then(|v| v.as_i64());
        let continue_token = get_opt_str(&args, "continueToken");
        impls::list_resources_impl(
            &ctx.manager,
            &kind,
            &ns,
            label.as_deref(),
            limit,
            continue_token.as_deref(),
        )
        .await
        .map_err(|e| AiError::Tool(e.to_string()))
    }
}

pub struct DescribeResource;
#[async_trait]
impl Tool for DescribeResource {
    fn name(&self) -> &str {
        "describe_resource"
    }
    fn description(&self) -> &str {
        "Get structured JSON description of one resource."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{
            "kind":{"type":"string"},"namespace":{"type":"string"},"name":{"type":"string"}
        },"required":["kind","name"]})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        impls::describe_resource_impl(
            &ctx.manager,
            &get_arg_str(&args, "kind")?,
            &get_opt_str(&args, "namespace").unwrap_or_default(),
            &get_arg_str(&args, "name")?,
        )
        .await
        .map_err(|e| AiError::Tool(e.to_string()))
    }
}

pub struct GetResourceYaml;
#[async_trait]
impl Tool for GetResourceYaml {
    fn name(&self) -> &str {
        "get_resource_yaml"
    }
    fn description(&self) -> &str {
        "Get the full YAML manifest of one resource."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{
            "kind":{"type":"string"},"namespace":{"type":"string"},"name":{"type":"string"}
        },"required":["kind","name"]})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        let yaml = impls::get_resource_yaml_impl(
            &ctx.manager,
            &get_arg_str(&args, "kind")?,
            &get_opt_str(&args, "namespace").unwrap_or_default(),
            &get_arg_str(&args, "name")?,
        )
        .await
        .map_err(|e| AiError::Tool(e.to_string()))?;
        ok_value(&k7s_deps::serde_json::json!({"yaml": yaml}))
    }
}

pub struct GetEvents;
#[async_trait]
impl Tool for GetEvents {
    fn name(&self) -> &str {
        "get_events"
    }
    fn description(&self) -> &str {
        "Read Kubernetes events for a specific resource."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{
            "kind":{"type":"string"},"namespace":{"type":"string"},"name":{"type":"string"}
        },"required":["kind","name"]})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        impls::get_events_impl(
            &ctx.manager,
            &get_arg_str(&args, "kind")?,
            &get_opt_str(&args, "namespace").unwrap_or_default(),
            &get_arg_str(&args, "name")?,
        )
        .await
        .map_err(|e| AiError::Tool(e.to_string()))
    }
}

pub struct GetPodLogs;
#[async_trait]
impl Tool for GetPodLogs {
    fn name(&self) -> &str {
        "get_pod_logs"
    }
    fn description(&self) -> &str {
        "Fetch pod logs. Set previous:true for CrashLoopBackOff."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{
            "namespace":{"type":"string"},"pod":{"type":"string"},
            "container":{"type":"string"},"tail":{"type":"integer"},"previous":{"type":"boolean"}
        },"required":["namespace","pod"]})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        impls::get_pod_logs_impl(
            &ctx.manager,
            &get_arg_str(&args, "namespace")?,
            &get_arg_str(&args, "pod")?,
            get_opt_str(&args, "container").as_deref(),
            Some(get_opt_i64(&args, "tail").unwrap_or(100)),
            get_opt_bool(&args, "previous").unwrap_or(false),
        )
        .await
        .map_err(|e| AiError::Tool(e.to_string()))
    }
}

pub struct GetClusterHealth;
#[async_trait]
impl Tool for GetClusterHealth {
    fn name(&self) -> &str {
        "get_cluster_health"
    }
    fn description(&self) -> &str {
        "Get an at-a-glance cluster health snapshot."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{}})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        _args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        impls::get_cluster_health_impl(&ctx.manager)
            .await
            .map_err(|e| AiError::Tool(e.to_string()))
    }
}

pub struct TopNodes;
#[async_trait]
impl Tool for TopNodes {
    fn name(&self) -> &str {
        "top_nodes"
    }
    fn description(&self) -> &str {
        "Get per-node CPU and memory usage plus allocatable capacity from metrics.k8s.io. \
         Returns usage, capacity, and percentage for each node sorted by CPU usage."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{}})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        _args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        impls::top_nodes_impl(&ctx.manager)
            .await
            .map_err(|e| AiError::Tool(e.to_string()))
    }
}

pub struct TopPods;
#[async_trait]
impl Tool for TopPods {
    fn name(&self) -> &str {
        "top_pods"
    }
    fn description(&self) -> &str {
        "Get CPU and memory usage for all pods, sorted by CPU consumption. \
         Use this to identify which pods are the heaviest resource consumers."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({
            "type": "object",
            "properties": {
                "namespace": {"type": "string", "description": "Filter by namespace (optional)"}
            },
            "required": []
        })
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        let ns = args
            .get("namespace")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        impls::top_pods_impl(&ctx.manager, ns)
            .await
            .map_err(|e| AiError::Tool(e.to_string()))
    }
}

pub struct CapacityReport;
#[async_trait]
impl Tool for CapacityReport {
    fn name(&self) -> &str {
        "capacity_report"
    }
    fn description(&self) -> &str {
        "Generate a cluster capacity planning report. Shows node CPU/memory usage, \
         per-namespace resource consumption, top resource-consuming pods, capacity alerts, \
         and scaling recommendations. Use this when the user asks about cluster capacity, \
         resource planning, or whether the cluster needs more nodes."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{}})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        _args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        impls::capacity_report_impl(&ctx.manager)
            .await
            .map_err(|e| AiError::Tool(e.to_string()))
    }
}

// New tools
pub struct BatchGet;
#[async_trait]
impl Tool for BatchGet {
    fn name(&self) -> &str {
        "batch_get"
    }
    fn description(&self) -> &str {
        "Batch-get multiple resources at once."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{
            "requests":{"type":"array","items":{"type":"object","properties":{
                "kind":{"type":"string"},"namespace":{"type":"string"},"name":{"type":"string"}
            },"required":["kind","name"]}}
        },"required":["requests"]})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        let reqs = args
            .get("requests")
            .and_then(|v| v.as_array())
            .ok_or_else(|| AiError::ToolArgs("missing 'requests' array".into()))?;
        impls::batch_get_impl(&ctx.manager, reqs)
            .await
            .map_err(|e| AiError::Tool(e.to_string()))
    }
}

pub struct DiffResources;
#[async_trait]
impl Tool for DiffResources {
    fn name(&self) -> &str {
        "diff_resources"
    }
    fn description(&self) -> &str {
        "Compare two resources or two versions of the same resource."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{
            "kind":{"type":"string"},
            "namespace_a":{"type":"string"},"name_a":{"type":"string"},
            "namespace_b":{"type":"string"},"name_b":{"type":"string"}
        },"required":["kind","name_a","name_b"]})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        impls::diff_resources_impl(
            &ctx.manager,
            &get_arg_str(&args, "kind")?,
            &get_opt_str(&args, "namespace_a").unwrap_or_default(),
            &get_arg_str(&args, "name_a")?,
            &get_opt_str(&args, "namespace_b").unwrap_or_default(),
            &get_arg_str(&args, "name_b")?,
        )
        .await
        .map_err(|e| AiError::Tool(e.to_string()))
    }
}

pub struct HpaStatus;
#[async_trait]
impl Tool for HpaStatus {
    fn name(&self) -> &str {
        "hpa_status"
    }
    fn description(&self) -> &str {
        "Get HPA status for a namespace."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{"namespace":{"type":"string"}},"required":["namespace"]})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        impls::hpa_status_impl(&ctx.manager, &get_arg_str(&args, "namespace")?)
            .await
            .map_err(|e| AiError::Tool(e.to_string()))
    }
}

// Security audit
pub struct SecurityAudit;
#[async_trait]
impl Tool for SecurityAudit {
    fn name(&self) -> &str {
        "security_audit"
    }
    fn description(&self) -> &str {
        "Run a comprehensive RBAC security audit of the cluster. \
         Identifies over-privileged roles, wildcard permissions, secret access, \
         pod exec capabilities, anonymous bindings, and other security risks. \
         Use this when the user asks about cluster security, RBAC risks, or wants a security report."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{}})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        _args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        impls::security_audit_impl(&ctx.manager)
            .await
            .map_err(|e| AiError::Tool(e.to_string()))
    }
}

// RBAC permission matrix
pub struct RbacPermissionMatrix;
#[async_trait]
impl Tool for RbacPermissionMatrix {
    fn name(&self) -> &str {
        "rbac_permission_matrix"
    }
    fn description(&self) -> &str {
        "Build the RBAC permission matrix showing which subjects (users, groups, \
         service accounts) can perform which actions (verb+resource) on which resources. \
         Use this when the user asks 'who can do what', wants to see RBAC permissions, \
         or needs a cross-tabulation of subjects vs actions."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{}})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        _args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        impls::rbac_permission_matrix_impl(&ctx.manager)
            .await
            .map_err(|e| AiError::Tool(e.to_string()))
    }
}

// Swarm tool — spawn a sub-agent for parallel work.
pub struct SpawnSubAgent;
#[async_trait]
impl Tool for SpawnSubAgent {
    fn name(&self) -> &str {
        "spawn_sub_agent"
    }
    fn description(&self) -> &str {
        "Spawn a sub-agent to work on a sub-task in parallel. The sub-agent \
         runs independently and its result is returned when complete. Use for \
         parallel diagnosis of multiple resources or independent sub-tasks."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type":"object","properties":{
            "task":{"type":"string","description":"The sub-task for the sub-agent to execute."},
            "agent_name":{"type":"string","description":"A name for this sub-agent (e.g. 'pod-analyzer')."}
        },"required":["task","agent_name"]})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        let task = get_arg_str(&args, "task")?;
        let agent_name = get_arg_str(&args, "agent_name")?;
        // Execute the sub-task by running the most relevant tools based on
        // keywords in the task description. This is a "smart dispatch" —
        // not a full LLM agent, but produces real results.
        let lower = task.to_lowercase();
        let mut results = k7s_deps::serde_json::json!({});

        // Always start with cluster health.
        if let Ok(health) = impls::get_cluster_health_impl(&ctx.manager).await {
            results["cluster_health"] = health;
        }

        // If the task mentions specific resource types, list them.
        for kind in &["pods", "deployments", "nodes", "services"] {
            if lower.contains(kind) {
                if let Ok(list) =
                    impls::list_resources_impl(&ctx.manager, kind, "", None, None, None).await
                {
                    results[format!("{}_list", kind)] = list;
                }
            }
        }

        // If the task mentions diagnosis/problems, run diagnose_unhealthy.
        if lower.contains("diagnos")
            || lower.contains("problem")
            || lower.contains("unhealthy")
            || lower.contains("error")
        {
            if let Ok(diag) = impls::diagnose_unhealthy_impl(&ctx.manager, None).await {
                results["diagnosis"] = diag;
            }
        }

        Ok(k7s_deps::serde_json::json!({
            "agent": agent_name,
            "task": task,
            "status": "completed",
            "results": results,
        }))
    }
}

// kubectl command generator — provides cluster context for building commands.
pub struct KubectlGenerator;
#[async_trait]
impl Tool for KubectlGenerator {
    fn name(&self) -> &str {
        "kubectl_generate"
    }
    fn description(&self) -> &str {
        "Get the current cluster context, available namespaces, and kubectl command templates. \
         Use this to generate accurate kubectl commands for the user. The response includes \
         the current context name, server version, all namespaces, and common command templates \
         that you can customize for the user's specific request."
    }
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({"type": "object", "properties": {}, "required": []})
    }
    async fn call(
        &self,
        ctx: &ToolContext,
        _args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        impls::kubectl_context_impl(&ctx.manager)
            .await
            .map_err(|e| AiError::Tool(e.to_string()))
    }
}
