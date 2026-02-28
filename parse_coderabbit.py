import json
import re

coderabbit_findings = []

def load_json(path):
    with open(path) as f:
        try: return json.load(f)
        except: return []

issue_comments = load_json('issue_comments.json')
review_comments = load_json('review_comments.json')
reviews = load_json('reviews.json')

if isinstance(issue_comments, list):
    for c in issue_comments:
        user = c.get('user', {}).get('login', '').lower()
        if 'coderabbit' in user:
            coderabbit_findings.append({
                'type': 'Issue Comment / Summary',
                'body': c.get('body', '')
            })

if isinstance(review_comments, list):
    for c in review_comments:
        user = c.get('user', {}).get('login', '').lower()
        if 'coderabbit' in user:
            coderabbit_findings.append({
                'type': 'Inline Comment',
                'path': c.get('path', ''),
                'body': c.get('body', '')
            })

if isinstance(reviews, list):
    for r in reviews:
        user = r.get('user', {}).get('login', '').lower()
        body = r.get('body', '')
        if 'coderabbit' in user and 'Actionable comments posted:' in body:
            prompt_match = re.search(r'<summary>🤖 Prompt for all review comments with AI agents</summary>\s*````\s*(.*?)\s*````', body, re.DOTALL)
            if prompt_match:
                extracted_prompts = prompt_match.group(1).strip()
                coderabbit_findings.append({
                    'type': 'Extracted AI Prompt Summary',
                    'body': extracted_prompts
                })

with open('coderabbit-review.md', 'w') as f:
    f.write('# CodeRabbit Review Findings\n\n')
    
    for finding in coderabbit_findings:
        if finding['type'] == 'Extracted AI Prompt Summary':
            f.write('## Comprehensive Task List (from AI Prompt Summary)\n\n')
            f.write('```text\n' + finding['body'] + '\n```\n\n')
            f.write('---\n\n')
    
    f.write('## Detailed Inline Comments\n\n')
    for finding in coderabbit_findings:
        if finding['type'] == 'Inline Comment':
            f.write('### `' + finding['path'] + '`\n\n')
            # Clean up the output slightly
            clean_body = finding['body'].split('<!-- fingerprinting')[0].split('<details>')[0].strip()
            f.write(clean_body + '\n\n')
            f.write('---\n\n')

