import re

files_to_fix = [
    'src/infrastructure/auth0/client_tests.rs',
    'tests/auth0_endpoints.rs',
]

# Fix missing reqwest::StatusCode parameter
for filename in files_to_fix:
    with open(filename, 'r') as f:
        content = f.read()
    content = content.replace('to_app_error()', 'to_app_error(reqwest::StatusCode::BAD_REQUEST)')
    with open(filename, 'w') as f:
        f.write(content)

# Fix missing missing fields in Auth0SignupResponse structs created in tests/routes.
files_to_fix2 = [
    'src/api/routes/auth.rs',
    'tests/auth0_endpoints.rs',
    'tests/core_api.rs',
    'tests/equipment_search/setup.rs',
]

replacement = '''connection: String::new(),
            given_name: None,
            family_name: None,
            nickname: None,'''

for filename in files_to_fix2:
    with open(filename, 'r') as f:
        content = f.read()
    
    # We look for where it returns an OK(Auth0SignupResponse
    # or let signup = Auth0SignupResponse
    # And inject the missing fields.
    content = re.sub(
        r'(username: [^,]+,\s+picture: [^,]+,\s+name: [^,]+,\s+)',
        r'\g<1>' + replacement + '\n            ',
        content
    )
    with open(filename, 'w') as f:
        f.write(content)

