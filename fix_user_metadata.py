import re

files_to_fix = [
    'src/api/routes/auth.rs',
    'tests/auth0_endpoints.rs',
    'tests/core_api.rs',
    'tests/equipment_search/setup.rs',
]

for filename in files_to_fix:
    with open(filename, 'r') as f:
        content = f.read()
    
    content = content.replace('nickname: None,', 'nickname: None,\n            user_metadata: None,')
    
    with open(filename, 'w') as f:
        f.write(content)

