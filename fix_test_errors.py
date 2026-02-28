import re

with open('src/infrastructure/auth0/dtos.rs', 'r') as f:
    content = f.read()

# Fix the test names from the old structs that no longer exist
content = content.replace('fn test_signup_response_deserialization_failure_branch()', 'fn test_signup_response_deserialization_failure_branch<Auth0SignupResponse>()')
content = content.replace('fn test_password_grant_response_deserialization_failure_branch()', 'fn test_password_grant_response_deserialization_failure_branch<Auth0TokenResponse>()')

# But actually, the correct fix is to change the struct inside the test function body too, or delete the test if it's no longer relevant.
# Let's see the full test body first
