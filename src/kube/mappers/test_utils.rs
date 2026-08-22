//! Shared property-test strategies for mapper tests.

use k7s_deps::kube::core::DynamicObject;
use proptest::prelude::*;

/// Generate an arbitrary DynamicObject with valid metadata.
#[allow(dead_code)] // shared proptest strategy for mapper property tests
pub fn arb_dynamic_object(namespaced: bool) -> impl Strategy<Value = DynamicObject> {
    (
        "[a-z][a-z0-9-]{0,20}",
        if namespaced {
            "[a-z][a-z0-9-]{0,20}".boxed()
        } else {
            Just(String::new()).boxed()
        },
        "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    )
        .prop_map(move |(name, namespace, uid)| {
            let mut metadata = k7s_deps::serde_json::json!({
                "name": name,
                "uid": uid,
                "creationTimestamp": "2025-01-15T10:30:00Z"
            });
            if namespaced && !namespace.is_empty() {
                metadata["namespace"] = k7s_deps::serde_json::json!(namespace);
            }
            k7s_deps::serde_json::from_value(k7s_deps::serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": metadata,
                "data": {}
            }))
            .unwrap()
        })
}

/// Generate an arbitrary non-empty string for cell text.
#[allow(dead_code)] // shared proptest strategy for mapper property tests
pub fn arb_cell_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 .:_/-]{1,50}"
}
