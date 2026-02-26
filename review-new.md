Starting CodeRabbit review in plain text mode...

Connecting to review service
Setting up
Analyzing
Reviewing

============================================================================
File: src/security/mod.rs
Line: 40 to 41
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/security/mod.rs around lines 40 - 41, Replace the misleading hardcoded rate-limit header by using the actual configured value: instead of adding ("X-RateLimit-Limit", "1") in the response headers, read security_config.global_rate_limit_per_minute and set the header value to that (or remove the header entirely if not needed); locate the header addition in src/security/mod.rs (the code that builds response headers) and change the static string to a formatted value derived from security_config.global_rate_limit_per_minute (or drop the .add call) so the header accurately reflects the configured rate limit.



============================================================================
File: src/api/dtos/auth_dto.rs
Line: 36 to 49
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/dtos/auth_dto.rs around lines 36 - 49, Remove automatic Debug derivation on Auth0SignupRequestDto and Auth0LoginRequestDto to avoid logging plaintext passwords; either (a) replace #[derive(Debug, ...)] with a manual impl Debug for Auth0SignupRequestDto and Auth0LoginRequestDto that redacts the password field (e.g., prints "" or omits it) or (b) change the password field type to secrecy::Secret and keep Debug derived (Secret implements Debug safely), updating imports and any code that constructs/uses the password accordingly; update usages of Auth0SignupRequestDto and Auth0LoginRequestDto (constructors, logs, tests) to handle the chosen approach.



============================================================================
File: src/middleware/request_logging.rs
Line: 18 to 35
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/middleware/request_logging.rs around lines 18 - 35, The get_client_ip function currently trusts the X-Forwarded-For header which is client-controlled; add a configurable trust flag (e.g., trust_x_forwarded_for) checked inside get_client_ip so the header is only used when explicitly enabled by configuration or environment (default to false), otherwise fall back to connection_info().realip_remote_addr(); update any call sites that rely on get_client_ip to pass or access the config and add a short comment/docstring on get_client_ip stating the security/PII implications and that X-Forwarded-For must be set/rewritten by a trusted proxy when enabled.



============================================================================
File: src/middleware/request_logging.rs
Line: 46 to 64
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/middleware/request_logging.rs around lines 46 - 64, The span currently logs the raw path which may include sensitive query parameters; update create_request_span to sanitize the path parameter before logging by stripping query string and fragment (i.e., only log the path component) or require/validate that callers pass a sanitized path; specifically, modify create_request_span (and its callers if you choose caller-side) to parse the incoming path, drop anything after '?' or '#', and use that sanitized value for the path field in tracing::info_span! to avoid logging tokens or PII.



============================================================================
File: src/middleware/request_logging.rs
Line: 10 to 16
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/middleware/request_logging.rs around lines 10 - 16, The get_user_id_from_request function currently returns the raw Auth0 sub (PII) which is then logged by create_request_span; change this to avoid logging raw identifiers by transforming the sub into a non-reversible anonymized token (e.g., compute a deterministic hash like SHA-256 and hex-encode it) or by redacting it when building the span, and update create_request_span to use that anonymized value instead of the raw sub; optionally add a config flag (e.g., LOG_RAW_USER_IDS) to allow raw logging in controlled environments and update references to get_user_id_from_request and create_request_span to use the new behavior.



============================================================================
File: src/security/mod.rs
Line: 56
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/security/mod.rs at line 56, The calculation for requests_per_millisecond uses security_config.global_rate_limit_per_minute and will panic on division by zero; update the code that computes requests_per_millisecond (the let requests_per_millisecond = ... line) to first guard against a zero value from security_config.global_rate_limit_per_minute—either validate/return an error when it's zero or substitute a safe default (or clamp to a minimum of 1) before performing the division—so the division cannot panic at runtime.



============================================================================
File: src/main.rs
Line: 206 to 209
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/main.rs around lines 206 - 209, The code currently captures the raw query string into query via req.query_string().to_string(), which can expose sensitive params; implement a sanitization step (e.g., a new helper like sanitize_query_string or redact_query_params) that parses the query (use form decoding), redacts values for known sensitive keys (token, access_token, api_key, password, secret, auth, etc.), and returns a safe string, then replace uses of query in logging with the sanitized result; reference the existing variable/query capture and keep get_client_ip, get_user_agent, and get_user_id_from_request unchanged.



============================================================================
File: src/infrastructure/auth0/client.rs
Line: 78 to 83
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/infrastructure/auth0/client.rs around lines 78 - 83, Change the server-side error log to use the resolved code value instead of self.code; call or reference the resolved identifier produced by code_or_error() (the same one used later in the match) and use that variable in the error! invocation (replace %self.code with the resolved code variable) so the log consistently shows the effective code whether it comes from self.code or self.error.



============================================================================
File: src/api/routes/auth.rs
Line: 68 to 77
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/auth.rs around lines 68 - 77, The repeated-character check uses byte-length via password.len() while the rest of the checks are character-based; update the comparison to use a character count (either the existing char_count variable if available or password.chars().count()) so that the calculation comparing the HashSet length to half the password length is character-consistent—modify the expression where password.len() appears in the block that builds password_lower and compares the HashSet length.



============================================================================
File: src/api/routes/auth.rs
Line: 27 to 35
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/auth.rs around lines 27 - 35, The password validation currently uses password.len() (byte length) but the message and intended check are in characters; update validate_password to count Unicode scalar values with password.chars().count() for the length check and when reporting "chars provided", i.e., replace uses of password.len() with password.chars().count() (refer to validate_password and MIN_PASSWORD_LENGTH) so multi-byte characters are handled correctly in both the conditional and the error message.



Review completed: 10 findings ✔
