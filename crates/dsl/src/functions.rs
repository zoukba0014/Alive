//! nuclei DSL helper functions registered into the evalexpr context.
//!
//! This is the subset we currently support; extend `register` to grow coverage.
//! Every function is total — bad arguments produce an `EvalexprError` that the
//! top-level evaluator turns into `false`/`None`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use evalexpr::{
    ContextWithMutableFunctions, EvalexprError, EvalexprResult, Function, HashMapContext, Value,
};
use md5::{Digest, Md5};
use regex::Regex;
use sha1::Sha1;
use sha2::Sha256;

/// Flatten a call argument into a positional list (`Tuple` → its elements).
fn args(v: &Value) -> Vec<Value> {
    match v {
        Value::Tuple(t) => t.clone(),
        other => vec![other.clone()],
    }
}

fn as_str(v: &Value) -> EvalexprResult<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Int(i) => Ok(i.to_string()),
        Value::Float(f) => Ok(f.to_string()),
        Value::Boolean(b) => Ok(b.to_string()),
        _ => Err(EvalexprError::CustomMessage("expected string".into())),
    }
}

fn arg_str(v: &Value, idx: usize) -> EvalexprResult<String> {
    let a = args(v);
    a.get(idx)
        .ok_or_else(|| EvalexprError::CustomMessage(format!("missing argument {idx}")))
        .and_then(as_str)
}

fn hex_digest<D: Digest>(input: &str) -> String {
    let mut h = D::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

/// Register all supported helper functions on `ctx`.
pub(crate) fn register(ctx: &mut HashMapContext) {
    let unary = |f: fn(String) -> EvalexprResult<Value>| {
        Function::new(move |v| f(as_str(&args(v)[0].clone())?))
    };

    let mut set = |name: &str, func: Function| {
        let _ = ctx.set_function(name.into(), func);
    };

    // Length (byte length, matching Go's len over strings).
    set(
        "len",
        Function::new(|v| Ok(Value::Int(as_str(&args(v)[0])?.len() as i64))),
    );

    // Substring / prefix / suffix predicates.
    set(
        "contains",
        Function::new(|v| Ok(Value::Boolean(arg_str(v, 0)?.contains(&arg_str(v, 1)?)))),
    );
    set(
        "startswith",
        Function::new(|v| Ok(Value::Boolean(arg_str(v, 0)?.starts_with(&arg_str(v, 1)?)))),
    );
    set(
        "endswith",
        Function::new(|v| Ok(Value::Boolean(arg_str(v, 0)?.ends_with(&arg_str(v, 1)?)))),
    );

    // Case / whitespace.
    set("tolower", unary(|s| Ok(Value::from(s.to_lowercase()))));
    set("toupper", unary(|s| Ok(Value::from(s.to_uppercase()))));
    set("trim", unary(|s| Ok(Value::from(s.trim().to_string()))));

    // Hashes.
    set("md5", unary(|s| Ok(Value::from(hex_digest::<Md5>(&s)))));
    set("sha1", unary(|s| Ok(Value::from(hex_digest::<Sha1>(&s)))));
    set(
        "sha256",
        unary(|s| Ok(Value::from(hex_digest::<Sha256>(&s)))),
    );

    // Encodings.
    set(
        "hex_encode",
        unary(|s| Ok(Value::from(hex::encode(s.as_bytes())))),
    );
    set(
        "hex_decode",
        unary(|s| {
            let bytes = hex::decode(s).map_err(|e| EvalexprError::CustomMessage(e.to_string()))?;
            Ok(Value::from(String::from_utf8_lossy(&bytes).to_string()))
        }),
    );
    set(
        "base64",
        unary(|s| Ok(Value::from(STANDARD.encode(s.as_bytes())))),
    );
    set(
        "base64_decode",
        unary(|s| {
            let bytes = STANDARD
                .decode(s)
                .map_err(|e| EvalexprError::CustomMessage(e.to_string()))?;
            Ok(Value::from(String::from_utf8_lossy(&bytes).to_string()))
        }),
    );
    set(
        "url_encode",
        unary(|s| Ok(Value::from(urlencoding::encode(&s).into_owned()))),
    );
    set(
        "url_decode",
        unary(|s| {
            Ok(Value::from(
                urlencoding::decode(&s).map(|c| c.into_owned()).unwrap_or(s),
            ))
        }),
    );

    // Regex match test: regex(pattern, input) -> bool.
    set(
        "regex",
        Function::new(|v| {
            let pattern = arg_str(v, 0)?;
            let input = arg_str(v, 1)?;
            let re =
                Regex::new(&pattern).map_err(|e| EvalexprError::CustomMessage(e.to_string()))?;
            Ok(Value::Boolean(re.is_match(&input)))
        }),
    );

    // Numeric coercion.
    set(
        "to_number",
        unary(|s| {
            if let Ok(i) = s.parse::<i64>() {
                Ok(Value::Int(i))
            } else if let Ok(f) = s.parse::<f64>() {
                Ok(Value::Float(f))
            } else {
                Err(EvalexprError::CustomMessage(format!("not a number: {s}")))
            }
        }),
    );
}
