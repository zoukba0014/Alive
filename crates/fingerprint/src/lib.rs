//! Service fingerprinting and tag routing.
//!
//! Two jobs:
//! - [`favicon_hash`] — the Shodan/mmh3 favicon hash, so a favicon can be
//!   matched against a known-product map ([`product_for_favicon`]).
//! - [`tags_for`] — map a detected service (+ optional banner) to nuclei
//!   `info.tags`. This is the "fingerprint-first" routing: identify what is
//!   listening, then only run POCs whose tags match.

mod favicon;
mod tags;

pub use favicon::{favicon_hash, product_for_favicon};
pub use tags::tags_for;
