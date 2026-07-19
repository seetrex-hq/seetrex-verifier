// SPDX-License-Identifier: Apache-2.0
// src/types.rs — the serializable types that define the public verdict
// package format: facts and their values (working memory), rules and
// conditions (ruleset shape), and audit log entries. This crate defines
// only the wire format; rule evaluation lives in the consuming engine.
use serde::{Deserialize, Serialize, Deserializer, Serializer};
use serde::de::Error as DeError;
use rust_decimal::Decimal;
use chrono::{DateTime, NaiveDate, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Fact {
    pub id: String,
    /// Value carried by this fact (boolean, number, string, list, …).
    /// Rendered as a generic JSON value in the spec because `FactValue`
    /// is an untagged enum with custom serde — not representable as a
    /// single static OpenAPI schema.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub value: FactValue,
    pub confidence: f64,
}

/// Value carried by a [`Fact`] or used as the operand of a
/// [`Condition`]. Variants are tried in order during `#[serde(untagged)]`
/// deserialization, so ORDER MATTERS — the most specific variants come
/// first.
///
/// Serialization shape:
/// - `Date`     → JSON string in ISO 8601 date format, e.g. `"2026-05-13"`.
/// - `DateTime` → JSON string in ISO 8601 UTC datetime, e.g.
///                `"2026-05-13T14:30:00Z"`. UTC ONLY at the format
///                boundary; timezone normalization is the caller's
///                responsibility.
/// - `Duration` → JSON string in humantime-like format:
///                `"30d"`, `"48h"`, `"10m"`, `"5s"`, or combinations
///                like `"1h30m"`. Stored internally as
///                `chrono::Duration` (signed seconds-level). A JSON
///                integer would collide with `Number(f64)` under
///                `#[serde(untagged)]` — the string form is the
///                disambiguator.
///
/// Untagged-deserialization order is: `Boolean → Number → Money →
/// DateTime → Date → Duration → String → List`. `Money` precedes
/// temporals because a numeric-looking string like `"100.50"`
/// must parse as `Money` first; that string cannot collide with the
/// temporal formats (which all require non-numeric separators
/// `-`/`T`/`Z` or unit suffixes `s|m|h|d`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum FactValue {
    Boolean(bool),
    Number(f64),
    Money(Decimal),
    DateTime(DateTime<Utc>),
    Date(NaiveDate),
    Duration(
        #[serde(serialize_with = "serialize_duration_humantime",
                deserialize_with = "deserialize_duration_humantime")]
        chrono::Duration
    ),
    String(String),
    List(Vec<FactValue>),  // operand for the `In` operator
}

/// Parse a humantime-like duration string into a signed
/// `chrono::Duration`. Accepts `<N><unit>` where unit ∈ {s, m, h, d},
/// optionally chained (e.g. `"1h30m"`, `"2d12h"`). Negative sign is
/// accepted as the FIRST character to denote negative (past-pointing)
/// durations. Rejects unknown units, missing unit, multiple signs, and
/// arithmetic overflow.
///
/// Intentional non-features: no fractional units (`"1.5h"` rejected —
/// write `"90m"`), no week unit `w` (write `"7d"`), no microseconds
/// or sub-second precision (Duration is seconds-level for rule
/// authoring clarity).
pub fn parse_humantime_duration(s: &str) -> Result<chrono::Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".into());
    }
    let (sign, rest) = if let Some(stripped) = s.strip_prefix('-') {
        (-1_i64, stripped)
    } else {
        (1_i64, s)
    };
    if rest.is_empty() {
        return Err("duration string has sign but no value".into());
    }
    let mut total_seconds: i64 = 0;
    let mut current_num: Option<i64> = None;
    let mut saw_unit = false;
    for ch in rest.chars() {
        if let Some(digit) = ch.to_digit(10) {
            current_num = Some(
                current_num
                    .unwrap_or(0)
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(digit as i64))
                    .ok_or_else(|| format!("duration overflow in '{s}'"))?,
            );
        } else {
            let n = current_num.ok_or_else(|| {
                format!("duration '{s}' has unit '{ch}' without preceding number")
            })?;
            let unit_seconds: i64 = match ch {
                's' => 1,
                'm' => 60,
                'h' => 3_600,
                'd' => 86_400,
                _ => return Err(format!("duration '{s}' has unknown unit '{ch}' (allowed: s/m/h/d)")),
            };
            let chunk = n
                .checked_mul(unit_seconds)
                .ok_or_else(|| format!("duration overflow in '{s}'"))?;
            total_seconds = total_seconds
                .checked_add(chunk)
                .ok_or_else(|| format!("duration overflow in '{s}'"))?;
            current_num = None;
            saw_unit = true;
        }
    }
    if current_num.is_some() {
        return Err(format!("duration '{s}' has trailing number without unit"));
    }
    if !saw_unit {
        return Err(format!("duration '{s}' has no unit (expected s/m/h/d)"));
    }
    let signed = total_seconds
        .checked_mul(sign)
        .ok_or_else(|| format!("duration overflow applying sign in '{s}'"))?;
    Ok(chrono::Duration::seconds(signed))
}

/// Render a `chrono::Duration` as the humantime-like form parsed by
/// `parse_humantime_duration`. Output is the canonical greedy form:
/// largest units first (d, h, m, s), zero components omitted, sign
/// preserved. `chrono::Duration::zero()` renders as `"0s"` (the unit
/// is mandatory in the grammar).
pub fn format_humantime_duration(d: chrono::Duration) -> String {
    let total = d.num_seconds();
    if total == 0 {
        return "0s".into();
    }
    let (sign, mut remaining) = if total < 0 { ("-", -total) } else { ("", total) };
    let mut out = String::from(sign);
    let days = remaining / 86_400;
    remaining %= 86_400;
    let hours = remaining / 3_600;
    remaining %= 3_600;
    let minutes = remaining / 60;
    let seconds = remaining % 60;
    if days > 0 { out.push_str(&format!("{days}d")); }
    if hours > 0 { out.push_str(&format!("{hours}h")); }
    if minutes > 0 { out.push_str(&format!("{minutes}m")); }
    if seconds > 0 { out.push_str(&format!("{seconds}s")); }
    out
}

fn serialize_duration_humantime<S: Serializer>(
    d: &chrono::Duration,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format_humantime_duration(*d))
}

fn deserialize_duration_humantime<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<chrono::Duration, D::Error> {
    let s = String::deserialize(d)?;
    parse_humantime_duration(&s).map_err(D::Error::custom)
}

// `Default` is not derivable (`#[default]` needs a unit variant;
// FactValue's variants all carry data). The manual impl gives
// `..Default::default()` ergonomics to tests and programmatic
// callers. `Boolean(false)` is the marker value — never meaningful;
// callers always specify the variant they want explicitly.
impl Default for FactValue {
    fn default() -> Self {
        FactValue::Boolean(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Condition {
    pub fact_id: String,
    pub operator: Operator,
    pub value: FactValue,
    /// Negates the result of the operator; composes with any operator
    /// ("NOT eq", "NOT exists", "NOT in", "NOT matches").
    /// Backward-compat: `#[serde(default)]` so existing JSON without
    /// the field parses as `false` (i.e. no negation).
    #[serde(default)]
    pub negated: bool,
}

/// Comparison operator of a [`Condition`]. Serializes as the bare
/// variant name (a JSON string, e.g. `"Eq"`, `"StartsWith"`) — this
/// string IS the wire form that appears in every serialized ruleset.
/// Evaluation semantics are defined by the consuming engine; the
/// comments below only gloss each variant's intended meaning.
///
/// There are no separate `Before`/`After` operators: `Lt`/`Gt` against
/// a temporal value express temporal ordering, keeping the operator
/// surface minimal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum Operator {
    // `Default` for tests / `..Default::default()` ergonomics. Eq is
    // the most common case and the cheapest; callers in production
    // ALWAYS specify the operator explicitly.
    #[default]
    Eq,     // ==
    Ne,     // !=
    Lt,     // strict less than ("before" on temporal values)
    Le,     // less than or equal
    Gt,     // strict greater than ("after" on temporal values)
    Ge,     // greater than or equal
    In,     // value in list
    Range,  // value between min,max
    Exists, // fact exists
    // Pattern operators; the operand is a String value.
    Matches,    // regex match: value is treated as a regex pattern
    Contains,   // substring contains
    StartsWith, // prefix match
    EndsWith,   // suffix match
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub conditions: Vec<Condition>,    // AND-joined condition list
    #[serde(default)]
    pub antecedents: Vec<String>,      // legacy compatibility
    pub consequent: String,
    #[serde(default)]
    pub consequent_value: Option<FactValue>,
    pub priority: i32,
    /// Disjunctive rule form (DNF): each inner `Vec<Condition>` is one
    /// alternative group — outer OR over inner AND. Precise evaluation
    /// semantics, including how groups interact with `conditions` and
    /// `antecedents`, are defined by the consuming engine.
    /// Backward-compat: `#[serde(default)]` so JSON without the field
    /// parses as empty.
    #[serde(default)]
    pub condition_groups: Vec<Vec<Condition>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub rule_id: String,
    pub rule_name: String,
    pub triggered_by: Vec<String>,
    pub produced: String,
}
