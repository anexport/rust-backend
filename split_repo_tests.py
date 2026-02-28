import re
import os
import sys

SOURCE_FILE = "tests/repository_integration_tests.rs"

if not os.path.exists(SOURCE_FILE):
    print(f"Error: Source file '{SOURCE_FILE}' not found.")
    print("Please run this script from the repository root directory.")
    sys.exit(1)

with open(SOURCE_FILE, "r") as f:
    content = f.read()

parts = content.split('#[tokio::test]')

header = parts[0]
tests = []

for part in parts[1:]:
    test_body = '#[tokio::test]' + part
    tests.append(test_body)

categories = {
    "user": ["user_repository"],
    "auth": ["auth_repository"],
    "equipment": ["equipment_repository"],
    "message": ["message_repository"],
    "category": ["category_repository"],
    "edge_cases": [] # fallback
}

categorized_tests = {k: [] for k in categories.keys()}

for test in tests:
    match = re.search(r'async fn\s+(\w+)\s*\(', test)
    if not match:
        categorized_tests["edge_cases"].append(test)
        continue
    name = match.group(1)
    
    placed = False
    for cat, keywords in categories.items():
        if cat == "edge_cases":
            continue
        if any(kw in name for kw in keywords):
            categorized_tests[cat].append(test)
            placed = True
            break
            
    if not placed:
        categorized_tests["edge_cases"].append(test)

for cat, test_list in categorized_tests.items():
    if not test_list:
        continue
    
    filename = f"tests/repository_integration_{cat}_tests.rs"
    with open(filename, "w") as f:
        f.write(header)
        for t in test_list:
            f.write(t)

print(f"Split {len(tests)} tests into categories:")
for cat, test_list in categorized_tests.items():
    print(f"  {cat}: {len(test_list)} tests")

