mod app;
mod auth;
pub(crate) mod dependencies;
pub mod domain;
#[cfg(test)]
mod evaluation;
mod legacy_evidence;
pub mod model;
pub(crate) mod scope;
mod storage;
mod ui;
pub(crate) mod web;

pub use app::run;
