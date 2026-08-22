//! Image domain: registry management ([`repo`]), scanning ([`scan`]),
//! sync/transfer ([`sync`]), archive handling ([`archive`]), and
//! import/export for air-gapped clusters ([`import`], [`export`]).

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod archive;

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod scan;

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod sync;

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod export;

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod import;

#[cfg(not(target_os = "ios"))]
pub mod repo;
