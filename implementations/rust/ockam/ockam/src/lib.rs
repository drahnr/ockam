// ---
// #![no_std] if the standard library is not present.

#![cfg_attr(not(feature = "std"), no_std)]

// ---
// Export the #[node] attribute macro.

pub use ockam_node_attribute::*;

// ---
// Export node implementation

#[cfg(all(feature = "std", feature = "ockam_node"))]
pub use ockam_node::*;

#[cfg(all(not(feature = "std"), feature = "ockam_node_no_std"))]
pub use ockam_node_no_std::*;

// ---

mod entity;
pub use entity::*;

mod error;
pub use error::OckamError;

pub use ockam_core::Error;
