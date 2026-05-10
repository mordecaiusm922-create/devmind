from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from safety_flow import SafetyFlowRequest, run_safety_flow


def diff(filename: str, body: str) -> str:
    return f"diff --git a/{filename} b/{filename}\n--- a/{filename}\n+++ b/{filename}\n@@\n{body}\n"


class WangPolicyRuntimeTests(unittest.TestCase):
    def test_terraform_iam_wildcard_blocks_by_deployment_policy(self) -> None:
        result = run_safety_flow(
            SafetyFlowRequest(
                prompt="Review Terraform IAM role for production deploy",
                mode="critical",
                files=[
                    {
                        "filename": "terraform/iam.tf",
                        "diff": diff("terraform/iam.tf", '+action = "*"\n+resource = "*"'),
                        "additions": 2,
                        "deletions": 0,
                    }
                ],
            )
        )

        self.assertEqual(result["deployment_policy"]["action"], "BLOCK")
        self.assertEqual(result["decision"]["action"], "reject")
        self.assertTrue(result["decision"]["merge_blocker"])
        self.assertGreaterEqual(result["risk"]["score"], 90)
        self.assertIn("terraform_iam_wildcard", result["representation"]["execution_evidence"]["failed_checks"])

    def test_pull_request_target_with_secrets_blocks_by_deployment_policy(self) -> None:
        result = run_safety_flow(
            SafetyFlowRequest(
                prompt="Review GitHub Actions deploy workflow",
                mode="critical",
                files=[
                    {
                        "filename": ".github/workflows/deploy.yml",
                        "diff": diff(
                            ".github/workflows/deploy.yml",
                            "+on: pull_request_target\n+env:\n+  TOKEN: ${{ secrets.PROD_TOKEN }}",
                        ),
                        "additions": 3,
                        "deletions": 0,
                    }
                ],
            )
        )

        self.assertEqual(result["deployment_policy"]["action"], "BLOCK")
        self.assertEqual(result["decision"]["action"], "reject")
        self.assertIn("gha_untrusted_secret_access", result["representation"]["execution_evidence"]["failed_checks"])

    def test_low_risk_terraform_change_has_no_deployment_policy_violation(self) -> None:
        result = run_safety_flow(
            SafetyFlowRequest(
                prompt="Review low risk Terraform tag change",
                mode="balanced",
                files=[
                    {
                        "filename": "terraform/tags.tf",
                        "diff": diff("terraform/tags.tf", '+environment = "staging"\n+owner = "platform"'),
                        "additions": 2,
                        "deletions": 0,
                    }
                ],
                max_repair_attempts=0,
            )
        )

        self.assertEqual(result["deployment_policy"]["action"], "ALLOW")
        self.assertFalse(result["deployment_policy"]["merge_blocker"])
        self.assertEqual(result["representation"]["execution_evidence"]["status"], "passed")


if __name__ == "__main__":
    unittest.main()
