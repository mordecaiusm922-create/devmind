import sys
sys.path.insert(0, ".")
from infra_analyzer import analyze_infra

# Terraform con IAM wildcard y S3 publico
files = [
    {
        "filename": "main.tf",
        "patch": '''
resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      actions  = ["*"]
      resources = ["*"]
    }]
  })
}
resource "aws_s3_bucket" "data" {
  acl = "public-read"
  force_destroy = true
}
'''
    },
    {
        "filename": ".github/workflows/deploy.yml",
        "patch": '''
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://install.sh | bash
      - uses: actions/checkout@v3
'''
    }
]

result = analyze_infra(files)
print(f"Score: {result.risk_score}/100")
print(f"Surfaces: {result.surfaces_detected}")
print(f"Critical: {result.has_critical}")
print(f"Block merge: {result.block_merge}")
print(f"Findings: {len(result.findings)}")
for f in result.findings:
    print(f"  [{f.severity.upper()}] {f.rule_id}: {f.title} ({f.file}:{f.line})")
