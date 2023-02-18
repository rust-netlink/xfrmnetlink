// SPDX-License-Identifier: MIT

//! This crate provides methods to manipulate IPsec tunnel resources (policies, SAs)
//! via the netlink protocol.

#![allow(clippy::module_inception)]

mod connection;
pub use crate::connection::*;

pub mod constants;
pub use crate::constants::*;

mod errors;
pub use crate::errors::*;

mod handle;
pub use crate::handle::*;

mod macros;

mod policy;
pub use crate::policy::*;

mod state;
pub use crate::state::*;
