//! Cluster properties: Nodes, StorageClasses, ServiceAccounts, PVCs, PVs.

use super::*;
use crate::error::AppResult;
use k7s_deps::k8s_openapi::api::core::v1::Node;
use k7s_deps::k8s_openapi::api::core::v1::{
    PersistentVolume, PersistentVolumeClaim, ServiceAccount,
};
use k7s_deps::k8s_openapi::api::storage::v1::StorageClass;
use k7s_deps::kube::api::Api;
use k7s_deps::kube::Client;

pub(super) async fn gather_node(client: Client, name: &str) -> AppResult<Properties> {
    let api: Api<Node> = Api::all(client);
    let node = api
        .get(name)
        .await
        .map_err(|e| AppError::Kube(e.to_string()))?;
    let spec = node.spec.clone().unwrap_or_default();
    let status = node.status.clone().unwrap_or_default();
    let info = status.node_info.clone();
    let mut props = Properties::default();

    // ---- Health: pressure conditions at a glance ----
    let conditions = status.conditions.as_deref().unwrap_or(&[]);
    let mut health_fields = Vec::new();
    for cond in conditions {
        let (label, is_bad) = match cond.type_.as_str() {
            "Ready" => ("Ready", cond.status.as_str() != "True"),
            "MemoryPressure" => ("Memory Pressure", cond.status.as_str() == "True"),
            "DiskPressure" => ("Disk Pressure", cond.status.as_str() == "True"),
            "PIDPressure" => ("PID Pressure", cond.status.as_str() == "True"),
            "NetworkUnavailable" => ("Network", cond.status.as_str() == "True"),
            _ => continue,
        };
        let tone = if is_bad { Tone::Bad } else { Tone::Good };
        let status_text = if is_bad { "Alert" } else { "OK" };
        health_fields.push(field_toned(label, status_text, tone));
    }
    if !health_fields.is_empty() {
        props.fields("Health", health_fields);
    }

    let unschedulable = spec.unschedulable.unwrap_or(false);
    props.fields(
        "Overview",
        vec![
            field_toned(
                "schedulable",
                if unschedulable {
                    "no (cordoned)"
                } else {
                    "yes"
                },
                if unschedulable {
                    Tone::Warn
                } else {
                    Tone::Good
                },
            ),
            field(
                "kubelet",
                info.as_ref()
                    .map(|i| i.kubelet_version.clone())
                    .unwrap_or_else(|| DASH.into()),
            ),
            field(
                "runtime",
                info.as_ref()
                    .map(|i| i.container_runtime_version.clone())
                    .unwrap_or_else(|| DASH.into()),
            ),
            field(
                "OS image",
                info.as_ref()
                    .map(|i| i.os_image.clone())
                    .unwrap_or_else(|| DASH.into()),
            ),
            field(
                "kernel",
                info.as_ref()
                    .map(|i| i.kernel_version.clone())
                    .unwrap_or_else(|| DASH.into()),
            ),
            field(
                "architecture",
                info.as_ref()
                    .map(|i| i.architecture.clone())
                    .unwrap_or_else(|| DASH.into()),
            ),
            field("pod CIDR", or_dash(spec.pod_cidr.clone())),
            field("provider", or_dash(spec.provider_id.clone())),
        ],
    );

    // ---- capacity vs allocatable ----
    // Allocatable is capacity minus what the kubelet reserves for the system, so
    // it — not capacity — is what pods can actually request.
    let capacity = status.capacity.clone().unwrap_or_default();
    let allocatable = status.allocatable.clone().unwrap_or_default();
    // Union of both maps: extended resources (GPUs) may appear in only one.
    let mut resource_names: Vec<&String> = capacity.keys().chain(allocatable.keys()).collect();
    resource_names.sort();
    resource_names.dedup();
    props.push_table(
        "Capacity",
        Some("not reported"),
        &["RESOURCE", "CAPACITY", "ALLOCATABLE"],
        resource_names
            .iter()
            .map(|r| {
                vec![
                    name_cell((*r).clone()),
                    c(qty(capacity.get(*r))),
                    c(qty(allocatable.get(*r))),
                ]
            })
            .collect(),
    );

    conditions_section(
        &mut props,
        status
            .conditions
            .unwrap_or_default()
            .into_iter()
            .map(|cd| Condition {
                type_: cd.type_,
                status: cd.status,
                reason: or_dash(cd.reason),
                message: or_dash(cd.message),
                since: cd.last_transition_time.map(|t| t.0.to_string()),
            })
            .collect(),
    );

    // ---- taints ----
    props.push_table(
        "Taints",
        Some("no taints"),
        &["KEY", "VALUE", "EFFECT"],
        spec.taints
            .iter()
            .flatten()
            .map(|t| {
                vec![
                    name_cell(t.key.clone()),
                    c(or_dash(t.value.clone())),
                    // NoSchedule/NoExecute actively keep pods off; worth the amber.
                    Cell::new(t.effect.clone(), Tone::Warn),
                ]
            })
            .collect(),
    );

    // ---- addresses ----
    props.push_table(
        "Addresses",
        Some("no addresses"),
        &["TYPE", "ADDRESS"],
        status
            .addresses
            .iter()
            .flatten()
            .map(|a| vec![name_cell(a.type_.clone()), c(a.address.clone())])
            .collect(),
    );

    meta_sections(&mut props, &node);
    Ok(props)
}

pub(super) async fn gather_storageclass(client: Client, name: &str) -> AppResult<Properties> {
    let api: Api<StorageClass> = Api::all(client);
    let sc = api
        .get(name)
        .await
        .map_err(|e| AppError::Kube(e.to_string()))?;
    let mut props = Properties::default();

    let allow_expand = sc.allow_volume_expansion.unwrap_or(false);
    props.fields(
        "Overview",
        vec![
            field("provisioner", sc.provisioner.clone()),
            field(
                "reclaim policy",
                sc.reclaim_policy.clone().unwrap_or_else(|| DASH.into()),
            ),
            field(
                "volume binding",
                sc.volume_binding_mode
                    .clone()
                    .unwrap_or_else(|| "Immediate".into()),
            ),
            field_toned(
                "allow expansion",
                if allow_expand { "yes" } else { "no" },
                if allow_expand {
                    Tone::Good
                } else {
                    Tone::Secondary
                },
            ),
        ],
    );

    // ---- parameters ----
    props.push_table(
        "Parameters",
        Some("no parameters"),
        &["KEY", "VALUE"],
        sc.parameters
            .iter()
            .flatten()
            .map(|(k, v)| vec![name_cell(k.clone()), c(v.clone())])
            .collect(),
    );

    // ---- mount options ----
    props.push_table(
        "Mount options",
        Some("no mount options"),
        &["OPTION"],
        sc.mount_options
            .iter()
            .flatten()
            .map(|m| vec![c(m.clone())])
            .collect(),
    );

    meta_sections(&mut props, &sc);
    Ok(props)
}

pub(super) async fn gather_serviceaccount(
    client: Client,
    namespace: &str,
    name: &str,
) -> AppResult<Properties> {
    let api: Api<ServiceAccount> = Api::namespaced(client, namespace);
    let sa = api
        .get(name)
        .await
        .map_err(|e| AppError::Kube(e.to_string()))?;
    let mut props = Properties::default();

    let ips_count = sa.image_pull_secrets.as_ref().map(|v| v.len()).unwrap_or(0);
    let sec_count = sa.secrets.as_ref().map(|v| v.len()).unwrap_or(0);
    // `automountServiceAccountToken` is a tri-state: unset means "default"
    // (which is true unless the pod opts out). Showing the literal field
    // is the honest answer — kubectl does the same.
    let automount = match sa.automount_service_account_token {
        Some(true) => "true",
        Some(false) => "false",
        None => "(default)",
    };
    props.fields(
        "Overview",
        vec![
            field("automount token", automount),
            field("image pull secrets", ips_count.to_string()),
            field("secrets", sec_count.to_string()),
        ],
    );

    // ---- image pull secrets ----
    props.push_table(
        "Image pull secrets",
        Some("no image pull secrets"),
        &["NAME"],
        sa.image_pull_secrets
            .iter()
            .flat_map(|v| v.iter())
            // `LocalObjectReference.name` is a bare String (not Option), but
            // the apiserver allows empty values for backwards-compat — show
            // a dash so the row isn't blank.
            .map(|r| {
                vec![name_cell(if r.name.is_empty() {
                    DASH.into()
                } else {
                    r.name.clone()
                })]
            })
            .collect(),
    );

    // ---- secrets ----
    props.push_table(
        "Secrets",
        Some("no secrets"),
        &["NAME"],
        sa.secrets
            .iter()
            .flat_map(|v| v.iter())
            .map(|r| vec![name_cell(r.name.clone().unwrap_or_else(|| DASH.into()))])
            .collect(),
    );

    meta_sections(&mut props, &sa);
    Ok(props)
}

pub(super) async fn gather_pvc(
    client: Client,
    namespace: &str,
    name: &str,
) -> AppResult<Properties> {
    let api: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), namespace);
    let pvc = api
        .get(name)
        .await
        .map_err(|e| AppError::Kube(e.to_string()))?;
    let spec = pvc.spec.clone().unwrap_or_default();
    let status = pvc.status.clone().unwrap_or_default();
    let mut props = Properties::default();

    let phase = or_dash(status.phase.clone());
    let phase_tone = match phase.as_str() {
        "Bound" => Tone::Good,
        "Pending" => Tone::Warn,
        "Lost" => Tone::Bad,
        _ => Tone::Secondary,
    };
    let volume = or_dash(spec.volume_name.clone());
    let class = or_dash(spec.storage_class_name.clone());
    let access_modes = spec
        .access_modes
        .as_ref()
        .map(|a| a.join(", "))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DASH.into());
    let capacity = status
        .capacity
        .as_ref()
        .and_then(|cap| cap.get("storage"))
        .map(|q| q.0.clone())
        .or_else(|| {
            spec.resources
                .as_ref()
                .and_then(|r| r.requests.as_ref())
                .and_then(|r| r.get("storage"))
                .map(|q| q.0.clone())
        })
        .unwrap_or_else(|| DASH.into());

    props.fields(
        "Overview",
        vec![
            field_toned("phase", phase, phase_tone),
            nav_field(
                "volume",
                volume.clone(),
                (volume != DASH).then(|| NavTarget::cluster("persistentvolumes", volume)),
            ),
            nav_field(
                "storage class",
                class.clone(),
                (class != DASH).then(|| NavTarget::cluster("storageclasses", class)),
            ),
            field("access modes", access_modes),
            field("capacity", capacity),
            field("volume mode", or_dash(spec.volume_mode.clone())),
        ],
    );

    // ---- conditions ----
    conditions_section(
        &mut props,
        status
            .conditions
            .unwrap_or_default()
            .into_iter()
            .map(|cd| Condition {
                type_: cd.type_,
                status: cd.status,
                reason: or_dash(cd.reason),
                message: or_dash(cd.message),
                since: cd.last_transition_time.map(|t| t.0.to_string()),
            })
            .collect(),
    );

    meta_sections(&mut props, &pvc);
    Ok(props)
}

pub(super) async fn gather_pv(client: Client, name: &str) -> AppResult<Properties> {
    let api: Api<PersistentVolume> = Api::all(client);
    let pv = api
        .get(name)
        .await
        .map_err(|e| AppError::Kube(e.to_string()))?;
    let spec = pv.spec.clone().unwrap_or_default();
    let status = pv.status.clone().unwrap_or_default();
    let mut props = Properties::default();

    let phase = or_dash(status.phase.clone());
    let phase_tone = match phase.as_str() {
        "Bound" => Tone::Good,
        "Available" => Tone::Good,
        "Pending" => Tone::Warn,
        "Released" => Tone::Warn,
        "Failed" => Tone::Bad,
        _ => Tone::Secondary,
    };
    let class = or_dash(spec.storage_class_name.clone());
    let capacity = spec
        .capacity
        .as_ref()
        .and_then(|cap| cap.get("storage"))
        .map(|q| q.0.clone())
        .unwrap_or_else(|| DASH.into());
    let access_modes = spec
        .access_modes
        .as_ref()
        .map(|a| {
            a.iter()
                .map(|m| format!("{m:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DASH.into());
    let reclaim = spec
        .persistent_volume_reclaim_policy
        .clone()
        .unwrap_or_else(|| DASH.into());
    let claim_ref = spec.claim_ref.as_ref();
    let claim_ns = claim_ref.and_then(|c| c.namespace.clone());
    let claim_name = claim_ref
        .map(|c| c.name.clone().unwrap_or_default())
        .unwrap_or_default();

    props.fields(
        "Overview",
        vec![
            field_toned("phase", phase, phase_tone),
            nav_field(
                "storage class",
                class.clone(),
                (class != DASH).then(|| NavTarget::cluster("storageclasses", class)),
            ),
            field("capacity", capacity),
            field("access modes", access_modes),
            field("reclaim policy", reclaim),
            field("volume mode", or_dash(spec.volume_mode.clone())),
            nav_field(
                "claim",
                if claim_name.is_empty() {
                    DASH.into()
                } else {
                    format!("{}/{}", claim_ns.as_deref().unwrap_or(""), claim_name)
                },
                if claim_name.is_empty() {
                    None
                } else {
                    Some(NavTarget::namespaced(
                        "persistentvolumeclaims",
                        claim_ns.as_deref().unwrap_or(""),
                        claim_name,
                    ))
                },
            ),
        ],
    );

    // ---- source ----
    let source_text = if let Some(local) = &spec.local {
        format!("local: {}", local.path)
    } else if let Some(host) = &spec.host_path {
        format!("hostPath: {}", host.path)
    } else if let Some(nfs) = &spec.nfs {
        format!("nfs: {}:{}", nfs.server, nfs.path)
    } else if spec.csi.is_some() {
        "CSI".into()
    } else {
        DASH.into()
    };
    props.fields("Source", vec![field("type", source_text)]);

    meta_sections(&mut props, &pv);
    Ok(props)
}
