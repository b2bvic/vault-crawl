use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

pub const SCHEMA_NAMES: &[&str] = &["artifact", "capability", "policy", "receipt", "registry"];

pub const COMMON_ENVELOPE_FIELDS: &[&str] = &[
    "schema_version",
    "producer_version",
    "lane",
    "host_id",
    "source_hashes",
];

const SUPPORTED_SCHEMA_KEYWORDS: &[&str] = &[
    "$schema",
    "$id",
    "title",
    "description",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "minimum",
    "minLength",
    "minItems",
];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SchemaValidation {
    pub schema: String,
    pub example: String,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[must_use]
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Validates the canonical example paired with each Phase 0 schema.
///
/// # Errors
///
/// Returns an error when a file cannot be read, JSON cannot be parsed, or a
/// schema uses an invalid root shape.
pub fn validate_repository_examples() -> Result<Vec<SchemaValidation>, String> {
    let root = repository_root();
    SCHEMA_NAMES
        .iter()
        .map(|name| {
            let schema_path = root.join(format!("schemas/v1/{name}.schema.json"));
            let example_path = root.join(format!("schemas/v1/examples/{name}.example.json"));
            let schema = read_json(&schema_path)?;
            let instance = read_json(&example_path)?;
            validate_schema_document(&schema, &schema_path)?;
            let mut errors = Vec::new();
            validate_value(&schema, &instance, "$", &mut errors);
            Ok(SchemaValidation {
                schema: schema_path.display().to_string(),
                example: example_path.display().to_string(),
                valid: errors.is_empty(),
                errors,
            })
        })
        .collect()
}

/// Validates one instance against a named Phase 0 schema.
///
/// # Errors
///
/// Returns an error for an unknown schema, unreadable file, invalid JSON, or
/// invalid schema root.
pub fn validate_named_instance(
    name: &str,
    instance_path: &Path,
) -> Result<SchemaValidation, String> {
    if !SCHEMA_NAMES.contains(&name) {
        return Err(format!("unknown Phase 0 schema {name}"));
    }
    let schema_path = repository_root().join(format!("schemas/v1/{name}.schema.json"));
    let schema = read_json(&schema_path)?;
    let instance = read_json(instance_path)?;
    validate_schema_document(&schema, &schema_path)?;
    let mut errors = Vec::new();
    validate_value(&schema, &instance, "$", &mut errors);
    Ok(SchemaValidation {
        schema: schema_path.display().to_string(),
        example: instance_path.display().to_string(),
        valid: errors.is_empty(),
        errors,
    })
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn validate_schema_document(schema: &Value, path: &Path) -> Result<(), String> {
    let object = schema
        .as_object()
        .ok_or_else(|| format!("{}: schema root is not an object", path.display()))?;
    for key in ["$schema", "$id", "title", "type", "properties"] {
        if !object.contains_key(key) {
            return Err(format!("{}: schema lacks {key}", path.display()));
        }
    }
    if object.get("type").and_then(Value::as_str) != Some("object") {
        return Err(format!("{}: root type must be object", path.display()));
    }

    let required = object
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{}: root required must be an array", path.display()))?;
    let properties = object
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{}: root properties must be an object", path.display()))?;
    for field in COMMON_ENVELOPE_FIELDS {
        if !required.iter().any(|value| value.as_str() == Some(field)) {
            return Err(format!(
                "{}: common envelope field {field} is not required",
                path.display()
            ));
        }
        if !properties.contains_key(*field) {
            return Err(format!(
                "{}: common envelope field {field} lacks a schema",
                path.display()
            ));
        }
    }

    let mut errors = Vec::new();
    validate_schema_tree(schema, "$", &mut errors);
    if !errors.is_empty() {
        return Err(format!("{}: {}", path.display(), errors.join("; ")));
    }
    Ok(())
}

/// Recursively validates every node in the supported Phase 0 schema subset,
/// including optional properties and array branches an example does not visit.
fn validate_schema_tree(schema: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(schema_object) = schema.as_object() else {
        errors.push(format!("{path}: schema node is not an object"));
        return;
    };

    for key in schema_object.keys() {
        if !SUPPORTED_SCHEMA_KEYWORDS.contains(&key.as_str()) {
            errors.push(format!("{path}: unsupported Phase 0 schema keyword {key}"));
        }
    }

    if let Some(kind) = schema_object.get("type") {
        match kind.as_str() {
            Some("object" | "array" | "string" | "integer" | "number" | "boolean" | "null") => {}
            Some(kind) => errors.push(format!("{path}: unsupported type {kind}")),
            None => errors.push(format!("{path}.type: expected string")),
        }
    }

    if let Some(properties) = schema_object.get("properties") {
        let Some(properties) = properties.as_object() else {
            errors.push(format!("{path}.properties: expected object"));
            return;
        };
        for (name, child) in properties {
            validate_schema_tree(child, &format!("{path}.properties.{name}"), errors);
        }
    }

    if let Some(items) = schema_object.get("items") {
        validate_schema_tree(items, &format!("{path}.items"), errors);
    }

    if let Some(required) = schema_object.get("required") {
        let Some(required) = required.as_array() else {
            errors.push(format!("{path}.required: expected array"));
            return;
        };
        let mut unique = std::collections::BTreeSet::new();
        for (index, field) in required.iter().enumerate() {
            let Some(field) = field.as_str() else {
                errors.push(format!("{path}.required[{index}]: expected string"));
                continue;
            };
            if !unique.insert(field) {
                errors.push(format!("{path}.required: duplicate field {field}"));
            }
            if schema_object
                .get("properties")
                .and_then(Value::as_object)
                .is_none_or(|properties| !properties.contains_key(field))
            {
                errors.push(format!(
                    "{path}.required: field {field} has no property schema"
                ));
            }
        }
    }

    if schema_object
        .get("additionalProperties")
        .is_some_and(|value| !value.is_boolean())
    {
        errors.push(format!("{path}.additionalProperties: expected boolean"));
    }
    if schema_object
        .get("enum")
        .is_some_and(|value| value.as_array().is_none_or(Vec::is_empty))
    {
        errors.push(format!("{path}.enum: expected non-empty array"));
    }
    for keyword in ["minimum", "minLength", "minItems"] {
        if schema_object
            .get(keyword)
            .is_some_and(|value| value.as_u64().is_none())
        {
            errors.push(format!("{path}.{keyword}: expected non-negative integer"));
        }
    }
}

/// Validates the deliberately small JSON Schema subset used by Phase 0.
///
/// Phase 0 schemas avoid `$ref`, dynamic anchors, conditionals, and coercion.
/// A standards-complete validator may replace this module later without
/// changing the published schemas. The whole schema tree is checked before
/// this instance walk, so unsupported keywords in unvisited branches fail.
#[allow(clippy::too_many_lines)]
fn validate_value(schema: &Value, instance: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(schema_object) = schema.as_object() else {
        errors.push(format!("{path}: schema node is not an object"));
        return;
    };

    if let Some(expected) = schema_object.get("type").and_then(Value::as_str) {
        let type_matches = match expected {
            "object" => instance.is_object(),
            "array" => instance.is_array(),
            "string" => instance.is_string(),
            "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
            "number" => instance.is_number(),
            "boolean" => instance.is_boolean(),
            "null" => instance.is_null(),
            unsupported => {
                errors.push(format!("{path}: unsupported type {unsupported}"));
                false
            }
        };
        if !type_matches {
            errors.push(format!("{path}: expected {expected}"));
            return;
        }
    }

    if let Some(constant) = schema_object.get("const")
        && instance != constant
    {
        errors.push(format!("{path}: does not equal const value"));
    }
    if let Some(values) = schema_object.get("enum").and_then(Value::as_array)
        && !values.contains(instance)
    {
        errors.push(format!("{path}: value is outside enum"));
    }
    if let Some(minimum) = schema_object.get("minimum").and_then(Value::as_f64)
        && instance.as_f64().is_some_and(|value| value < minimum)
    {
        errors.push(format!("{path}: number is below minimum {minimum}"));
    }
    if let Some(minimum) = schema_object.get("minLength").and_then(Value::as_u64)
        && instance.as_str().is_some_and(|value| {
            value.chars().count() < usize::try_from(minimum).unwrap_or(usize::MAX)
        })
    {
        errors.push(format!("{path}: string is shorter than {minimum}"));
    }
    if let Some(minimum) = schema_object.get("minItems").and_then(Value::as_u64)
        && instance
            .as_array()
            .is_some_and(|value| value.len() < usize::try_from(minimum).unwrap_or(usize::MAX))
    {
        errors.push(format!("{path}: array is shorter than {minimum}"));
    }

    if let Some(object) = instance.as_object() {
        if let Some(required) = schema_object.get("required").and_then(Value::as_array) {
            for key in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(key) {
                    errors.push(format!("{path}: missing required property {key}"));
                }
            }
        }

        let properties = schema_object.get("properties").and_then(Value::as_object);
        if let Some(properties) = properties {
            for (key, value) in object {
                if let Some(property_schema) = properties.get(key) {
                    let mut child_path = String::with_capacity(path.len() + key.len() + 1);
                    let _ = write!(&mut child_path, "{path}.{key}");
                    validate_value(property_schema, value, &child_path, errors);
                } else if schema_object.get("additionalProperties") == Some(&Value::Bool(false)) {
                    errors.push(format!("{path}: unexpected property {key}"));
                }
            }
        }
    }

    if let Some(items_schema) = schema_object.get("items")
        && let Some(items) = instance.as_array()
    {
        for (index, item) in items.iter().enumerate() {
            validate_value(items_schema, item, &format!("{path}[{index}]"), errors);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::{Value, json};

    use super::{repository_root, validate_repository_examples, validate_schema_document};

    #[test]
    fn every_phase_zero_schema_example_validates() {
        let validations = validate_repository_examples().expect("load schema examples");
        assert_eq!(validations.len(), 5);
        for validation in validations {
            assert!(
                validation.valid,
                "{} failed validation: {:?}",
                validation.example, validation.errors
            );
        }
    }

    fn canonical_artifact_schema() -> Value {
        let path = repository_root().join("schemas/v1/artifact.schema.json");
        serde_json::from_slice(&std::fs::read(path).expect("read artifact schema"))
            .expect("parse artifact schema")
    }

    #[test]
    fn unsupported_keyword_in_unvisited_optional_property_fails_closed() {
        let mut schema = canonical_artifact_schema();
        schema["properties"]["never_present"] = json!({
            "type": "string",
            "pattern": "unsafe-unimplemented-keyword"
        });
        let error = validate_schema_document(&schema, Path::new("negative.schema.json"))
            .expect_err("unsupported optional keyword must fail");
        assert!(error.contains("unsupported Phase 0 schema keyword pattern"));
    }

    #[test]
    fn unsupported_keyword_in_unvisited_array_item_fails_closed() {
        let mut schema = canonical_artifact_schema();
        schema["properties"]["source_hashes"]["items"]["format"] = json!("sha256");
        let error = validate_schema_document(&schema, Path::new("negative.schema.json"))
            .expect_err("unsupported item keyword must fail");
        assert!(error.contains("unsupported Phase 0 schema keyword format"));
    }

    #[test]
    fn malformed_optional_schema_node_fails_closed() {
        let mut schema = canonical_artifact_schema();
        schema["properties"]["never_present"] = json!(true);
        let error = validate_schema_document(&schema, Path::new("negative.schema.json"))
            .expect_err("boolean schemas are outside the Phase 0 subset");
        assert!(error.contains("schema node is not an object"));
    }

    #[test]
    fn phase_zero_policy_cannot_claim_implementation() {
        let root = repository_root();
        let schema: Value = serde_json::from_slice(
            &std::fs::read(root.join("schemas/v1/policy.schema.json")).expect("read policy schema"),
        )
        .expect("parse policy schema");
        let mut instance: Value = serde_json::from_slice(
            &std::fs::read(root.join("schemas/v1/examples/policy.example.json"))
                .expect("read policy example"),
        )
        .expect("parse policy example");
        instance["implementation_status"] = json!("implemented");
        let mut errors = Vec::new();
        super::validate_value(&schema, &instance, "$", &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("does not equal const value"))
        );
    }
}
