//! nuclei-compatible DSL expression evaluator.
//!
//! Templates use `dsl:` expressions such as `status_code == 200`,
//! `contains(body, "root:")`, or `len(body) > 0`. We evaluate these on top of
//! [`evalexpr`], injecting response variables (via [`VarMap`]) and registering
//! the subset of nuclei helper functions we support.
//!
//! The evaluator is deliberately total: a malformed or unsupported expression
//! evaluates to `false` / `None` rather than erroring, so one bad template does
//! not abort a scan. Coverage of helper functions grows over time — see
//! [`functions`].

mod functions;

use std::collections::HashMap;

use evalexpr::{ContextWithMutableVariables, HashMapContext, Value as EvalValue};

/// A value that can be bound into the DSL context.
#[derive(Debug, Clone)]
pub enum DslValue {
    Str(String),
    Int(i64),
}

/// Named variables exposed to a DSL expression (e.g. `body`, `status_code`).
pub type VarMap = HashMap<String, DslValue>;

/// Build an evalexpr context: response variables + registered helper functions.
fn build_context(vars: &VarMap) -> HashMapContext {
    let mut ctx = HashMapContext::new();
    for (k, v) in vars {
        let value = match v {
            DslValue::Str(s) => EvalValue::from(s.clone()),
            DslValue::Int(i) => EvalValue::from(*i),
        };
        // Ignore bind failures for reserved identifiers; they simply stay unset.
        let _ = ctx.set_value(k.clone(), value);
    }
    functions::register(&mut ctx);
    ctx
}

/// Evaluate an expression to a boolean. Any error yields `false`.
pub fn eval_bool(expr: &str, vars: &VarMap) -> bool {
    let ctx = build_context(vars);
    evalexpr::eval_boolean_with_context(expr, &ctx).unwrap_or(false)
}

/// Evaluate an expression to a string. Non-string / error results yield `None`.
pub fn eval_string(expr: &str, vars: &VarMap) -> Option<String> {
    let ctx = build_context(vars);
    match evalexpr::eval_with_context(expr, &ctx) {
        Ok(EvalValue::String(s)) => Some(s),
        Ok(other) => Some(other.to_string()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> VarMap {
        let mut m = VarMap::new();
        m.insert("status_code".into(), DslValue::Int(200));
        m.insert("body".into(), DslValue::Str("hello root:x:0:0".into()));
        m
    }

    #[test]
    fn status_and_contains() {
        assert!(eval_bool("status_code == 200", &vars()));
        assert!(!eval_bool("status_code == 404", &vars()));
        assert!(eval_bool("contains(body, \"root:\")", &vars()));
        assert!(!eval_bool("contains(body, \"absent\")", &vars()));
    }

    #[test]
    fn len_and_logic() {
        assert!(eval_bool("len(body) > 0", &vars()));
        assert!(eval_bool(
            "status_code == 200 && contains(body, \"hello\")",
            &vars()
        ));
    }

    #[test]
    fn md5_equality() {
        // md5("a") = 0cc175b9c0f1b6a831c399e269772661
        let m = VarMap::new();
        assert!(eval_bool(
            "md5(\"a\") == \"0cc175b9c0f1b6a831c399e269772661\"",
            &m
        ));
    }

    #[test]
    fn base64_roundtrip_and_string_eval() {
        let m = VarMap::new();
        assert_eq!(eval_string("base64(\"abc\")", &m).as_deref(), Some("YWJj"));
        assert_eq!(
            eval_string("base64_decode(\"YWJj\")", &m).as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn malformed_is_false_not_error() {
        assert!(!eval_bool("this is not valid )(", &vars()));
    }
}
