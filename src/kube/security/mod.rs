//! Security domain: SBOM generation/history ([`sbom`], [`sbom_storage`]),
//! RBAC audit ([`rbac_matrix`], [`security_audit`]), and NetworkPolicy
//! simulation ([`netpol_sim`]).

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod sbom;

// sbom_storage persists what sbom generates; its only consumer
// (k7s-commands/sbom) is also mobile-excluded.
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod sbom_storage;

#[cfg(not(target_os = "ios"))]
pub mod security_audit;

#[cfg(not(target_os = "ios"))]
pub mod rbac_matrix;

pub mod netpol_sim;
