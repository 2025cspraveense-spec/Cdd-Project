
from app.engines.secret_engine import SECRET_RULES

samples = {
    "SEC-AWS-001": "AKIAIOSFODNN7EXAMPLE",
    "SEC-AWS-002": 'aws_secret_access_key = "' + ("A" * 40) + '"',
"SEC-GH-001": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
    "SEC-GH-002": "gho_abcdefghijklmnopqrstuvwxyz1234567890",
    "SEC-GH-003": "ghu_abcdefghijklmnopqrstuvwxyz1234567890",
    "SEC-GH-004": "ghs_abcdefghijklmnopqrstuvwxyz1234567890",
    "SEC-GH-005": "ghr_abcdefghijklmnopqrstuvwxyz1234567890",
    "SEC-GH-006": "github_pat_abcdefghijklmnopqrstuvwxyz",
    "SEC-GL-001": "glpat-abcdefghijklmnopqrstuvwxyz",
    "SEC-GCP-001": "AIza" + "A" * 35,
    "SEC-AZ-001": 'client_secret = "SuperSecretValue12345"',
    "SEC-AZ-002": 'storage_account_key = "abcdefghijklmnopqrstuvwxyz12345678901234567890"',
    "SEC-SLACK-001": "xoxb-1234567890-abcdefghijkl",
    "SEC-SLACK-002": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXX",
    "SEC-DISCORD-001": "M" + "A" * 24 + "." + "B" * 6 + "." + "C" * 25,
    "SEC-DISCORD-002": "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz",
    "SEC-TG-001": "1234567890:" + "A" * 35,
    "SEC-STRIPE-001": "sk_live_" + "A" * 24,
    "SEC-STRIPE-002": "rk_live_" + "A" * 24,
    "SEC-TWILIO-001": "SK" + "a" * 32,
    "SEC-SG-001": "SG." + "A" * 25 + "." + "B" * 25,
    "SEC-NPM-001": "npm_" + "A" * 36,
    "SEC-PYPI-001": "pypi-" + "A" * 55,
    "SEC-HEROKU-001": 'heroku_api_key = "12345678-1234-1234-1234-123456789012"',
    "SEC-MG-001": "key-" + "A" * 32,
    "SEC-SHOPIFY-001": "shpat_" + "A" * 32,
    "SEC-OPENAI-001": "sk-proj-" + "A" * 25,
    "SEC-ANTHROPIC-001": "sk-ant-" + "A" * 25,
    "SEC-DB-001": "mongodb://admin:SuperSecret123@localhost:27017",
    "SEC-JWT-001": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature123",
    "SEC-KEY-001": "-----BEGIN RSA PRIVATE KEY-----",
    "SEC-GEN-001": 'password = "SuperSecret123!"',
}

rules = {rule["rule_id"]: rule["pattern"] for rule in SECRET_RULES}

passed = 0
failed = 0

print("\nSECRET ENGINE - RULE VALIDATION")
print("=" * 55)

for rule_id, sample in samples.items():
    pattern = rules.get(rule_id)

    if pattern is None:
        print(f"FAIL | {rule_id} | RULE NOT FOUND")
        failed += 1
    elif pattern.search(sample):
        print(f"PASS | {rule_id}")
        passed += 1
    else:
        print(f"FAIL | {rule_id} | SAMPLE NOT DETECTED")
        failed += 1

print("=" * 55)
print(f"Total rules tested : {len(samples)}")
print(f"Passed             : {passed}")
print(f"Failed             : {failed}")

if failed == 0 and len(samples) == 32:
    print("\nALL 32 RULES PASSED!")
else:
    print("\nVALIDATION NEEDS FIXING.")
