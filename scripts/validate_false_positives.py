from app.engines.secret_engine import SECRET_RULES, is_placeholder

samples = [
    'password = "YOUR_PASSWORD_HERE"',
    'api_key = "REPLACE_ME"',
    'secret = "changeme"',
    'token = "example_token"',
    'password = "test123"',
    'request_id = "12345678-1234-1234-1234-123456789012"',
    'database = "localhost:5432"',
    'api_key = "your_api_key"',
]

failures = []

for sample in samples:
    for rule in SECRET_RULES:
        match = rule["pattern"].search(sample)

        if match:
            raw = match.group(1) if match.lastindex else match.group(0)

            if not is_placeholder(raw):
                failures.append((sample, rule["rule_id"]))

if failures:
    for sample, rule_id in failures:
        print(f"FAIL | {rule_id} | {sample}")
else:
    print("ALL FALSE-POSITIVE TESTS PASSED!")

print(f"Failures: {len(failures)}")