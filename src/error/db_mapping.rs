use super::app_error::AppError;

pub(super) fn map_database_error(
    code: Option<&str>,
    constraint: Option<&str>,
    message: &str,
) -> Option<AppError> {
    match code {
        Some("23505") => Some(AppError::Conflict(
            conflict_message_from_constraint(constraint).to_string(),
        )),
        Some("23502") => Some(AppError::validation_error(
            required_field_message_from_db(message)
                .unwrap_or_else(|| "required field is missing".to_string()),
        )),
        Some("23503") => Some(AppError::BadRequest(
            "referenced resource does not exist".to_string(),
        )),
        Some("23514") => Some(AppError::validation_error(
            "request violates validation rules",
        )),
        Some("22P02") => Some(AppError::validation_error("invalid input format")),
        Some("08001") | Some("08006") => Some(AppError::ServiceUnavailable {
            service: "database".to_string(),
            message: "Unable to connect to database. Please try again later.".to_string(),
        }),
        Some("53300") => Some(AppError::ServiceUnavailable {
            service: "database".to_string(),
            message: "Service temporarily unavailable. Please try again later.".to_string(),
        }),
        Some("55P03") => Some(AppError::Conflict(
            "Resource is currently locked. Please try again.".to_string(),
        )),
        Some("P0001") => {
            let error_msg =
                extract_raise_exception_message(message).unwrap_or("Database validation error");
            Some(AppError::validation_error(error_msg))
        }
        _ => None,
    }
}

pub(super) fn conflict_message_from_constraint(constraint: Option<&str>) -> &'static str {
    match constraint {
        Some("profiles_email_key") => "email already registered",
        Some("profiles_username_key") => "username already taken",
        Some("uq_auth_identities_provider_id") => "identity already linked",
        Some("auth_identities_user_id_provider_key") => "auth identity already exists",
        Some("conversation_participants_conversation_id_profile_id_key") => {
            "user is already a participant in this conversation"
        }
        Some("user_favorites_user_id_equipment_id_key") => "equipment already favorited",
        Some("availability_calendar_equipment_id_date_key") => "date is already booked",
        Some("unique_booking_inspection_type") => "inspection already exists for this booking",
        Some("unique_booking_request") => "booking already exists",
        Some("payments_stripe_payment_intent_id_key") => "payment already processed",
        Some("notification_preferences_user_unique") => "notification preferences already exist",
        Some("renter_profiles_profile_id_unique") => "renter profile already exists",
        Some("owner_profiles_profile_id_unique") => "owner profile already exists",
        Some("content_translations_content_type_content_id_field_name_tar_key") => {
            "translation already exists for this content"
        }
        Some("users_phone_key") => "phone number already registered",
        Some("identities_provider_id_provider_unique") => {
            "identity already linked to another account"
        }
        _ => "resource already exists",
    }
}

pub(super) fn required_field_message_from_db(message: &str) -> Option<String> {
    let marker = "column \"";
    let start = message.find(marker)?;
    let rest = &message[start + marker.len()..];
    let end = rest.find('"')?;
    let field = &rest[..end];
    Some(format!("{field} is required"))
}

pub(super) fn extract_raise_exception_message(message: &str) -> Option<&str> {
    if message.contains("RAISE EXCEPTION") || message.starts_with("ERROR:") {
        if let Some(colon_pos) = message.find(':') {
            let msg = message[colon_pos + 1..].trim();
            if !msg.is_empty() {
                return Some(msg);
            }
        }
    }
    let msg = message.trim();
    if msg.is_empty() {
        None
    } else {
        Some(msg)
    }
}
