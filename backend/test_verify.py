from verify import verify_candidate
result = verify_candidate(
    {"prompt": "fix hardcoded SECRET_KEY", "mode": "secure"},
    {"diff": "+import os\n+SECRET_KEY = os.environ.get('SECRET_KEY')\n+if not SECRET_KEY:\n+    raise ValueError('not set')"}
)
print("verified:", result["verified"])
print("confidence:", result["confidence"])
print("violations:", result["violations"])
