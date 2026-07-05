//! nuclei-compatible YAML template model + loader + compatibility checker.
//!
//! We intentionally parse a *subset* of the nuclei schema and grow coverage
//! over milestones (M1: http + status/word/regex/size matchers, regex
//! extractor; M3: tcp/dns/tls + dsl). Unknown matcher/extractor types and
//! unknown protocol blocks are captured rather than rejected, so
//! [`check`] can report a template's compatibility instead of failing opaquely.

mod check;
mod load;
mod model;

pub use check::{check_template, Compatibility};
pub use load::{load_dir, load_file, LoadError};
pub use model::{Condition, Extractor, HttpRequest, Info, Matcher, Part, Template};
