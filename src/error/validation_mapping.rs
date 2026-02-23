use validator::{ValidationErrors, ValidationErrorsKind};

use super::app_error::ValidationIssue;

pub(super) fn collect_validation_issues(
    prefix: Option<String>,
    errors: &ValidationErrors,
    out: &mut Vec<ValidationIssue>,
) {
    for (field, kind) in errors.errors() {
        let path = match &prefix {
            Some(prefix) => format!("{prefix}.{field}"),
            None => field.to_string(),
        };

        match kind {
            ValidationErrorsKind::Field(field_errors) => {
                for error in field_errors {
                    let message = error
                        .message
                        .as_ref()
                        .map(std::borrow::Cow::to_string)
                        .unwrap_or_else(|| format!("{path} is invalid"));
                    out.push(ValidationIssue {
                        field: path.clone(),
                        message,
                        code: error.code.to_string(),
                    });
                }
            }
            ValidationErrorsKind::Struct(nested) => {
                collect_validation_issues(Some(path), nested, out);
            }
            ValidationErrorsKind::List(nested_items) => {
                for (index, nested) in nested_items {
                    collect_validation_issues(Some(format!("{path}[{index}]")), nested, out);
                }
            }
        }
    }
}
