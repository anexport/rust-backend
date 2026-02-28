#!/bin/bash
# Remove the duplicated allow(dead_code) attribute that clippy is angry about
sed -i '' '1d' tests/common/auth0_test_helpers.rs
sed -i '' '1d' tests/common/fixtures.rs

# Fix the iter().count() -> len()
sed -i '' 's/messages.iter().count()/messages.len()/g' tests/security/ws/ordering.rs

# Fix unused imports that cargo fix missed
sed -i '' '/use rust_backend::utils::auth0_jwks::\*/d' tests/auth_middleware/jwks.rs
sed -i '' '/use super::\*/d' tests/repository_integration/phase1.rs
sed -i '' 's/CategoryRepository,//g' tests/repository_integration.rs
sed -i '' 's/EquipmentRepository, UserRepository,//g' tests/repository_integration.rs

# Add Default implementation using python to carefully insert it
cat << 'PY_EOF' > fix_default.py
with open('tests/auth_middleware.rs', 'r') as f:
    content = f.read()

mock_default = """impl Default for MockJwksClient {
    fn default() -> Self {
        Self::new()
    }
}"""
content = content.replace('pub fn new() -> Self {', mock_default + '\n\n    pub fn new() -> Self {', 1)

static_default = """impl Default for StaticJwksProvider {
    fn default() -> Self {
        Self::new()
    }
}"""
content = content.replace('pub fn new() -> Self {', static_default + '\n\n    pub fn new() -> Self {', 1)

with open('tests/auth_middleware.rs', 'w') as f:
    f.write(content)
PY_EOF
python3 fix_default.py
rm fix_default.py

