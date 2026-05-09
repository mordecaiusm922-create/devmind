from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from safety_flow import CandidatePayload, SafetyFlowRequest, run_safety_flow


class SafetyFlowTests(unittest.TestCase):
    def test_generated_sql_flow_selects_parameterized_candidate(self) -> None:
        result = run_safety_flow(
            SafetyFlowRequest(
                prompt="Fix this SQL injection in users/views.py",
                context={"filename": "users/views.py"},
                mode="secure",
            )
        )

        self.assertEqual(result["decision"]["action"], "needs_verification")
        self.assertIn(result["selected"]["candidate"], {"g1", "g2", "g3"})
        self.assertTrue(result["selected"]["verified"])
        self.assertIn("parameterized_sql", result["properties"])
        self.assertEqual(result["selected"]["critical_violations"], [])

    def test_secret_flow_rejects_hardcoded_candidate(self) -> None:
        result = run_safety_flow(
            SafetyFlowRequest(
                prompt="Fix hardcoded Django SECRET_KEY securely",
                mode="secure",
                candidates=[
                    CandidatePayload(
                        id="bad",
                        diff='+SECRET_KEY = "django-insecure-abc123456"',
                        strategy="hardcoded",
                        explanation="Keep a configured key",
                    ),
                    CandidatePayload(
                        id="good",
                        diff=(
                            '+import os\n'
                            '+SECRET_KEY = os.environ.get("SECRET_KEY")\n'
                            '+if not SECRET_KEY:\n'
                            '+    raise RuntimeError("SECRET_KEY environment variable is not set")'
                        ),
                        strategy="env-fail-fast",
                        explanation="Read secret from environment and fail fast",
                    ),
                ],
            )
        )

        self.assertEqual(result["selected"]["candidate"], "good")
        self.assertTrue(result["verification"]["good"]["verified"])
        self.assertIn("no_hardcoded_secret", result["verification"]["bad"]["critical_violations"])
        self.assertEqual(result["decision"]["action"], "needs_verification")

    def test_flow_returns_representation_and_operational_metrics(self) -> None:
        result = run_safety_flow(
            SafetyFlowRequest(
                prompt="Fix SQL injection in users/views.py with low blast radius",
                context={"filename": "users/views.py"},
                mode="secure",
            )
        )

        self.assertIn("data", result["representation"]["risk_surface"])
        self.assertIn("external_input_to_database_boundary", result["representation"]["trust_boundaries"])
        self.assertIn("verification_pass_rate", result["operational_metrics"])
        self.assertGreater(result["operational_metrics"]["verification_pass_rate"], 0.0)

    def test_repair_loop_can_select_repaired_secret_candidate(self) -> None:
        result = run_safety_flow(
            SafetyFlowRequest(
                prompt="Fix hardcoded Django SECRET_KEY securely",
                mode="secure",
                candidates=[
                    CandidatePayload(
                        id="bad",
                        diff='+SECRET_KEY = "django-insecure-abc123456"',
                        strategy="hardcoded",
                        explanation="Keep a configured key",
                    ),
                ],
            )
        )

        self.assertTrue(result["repair_attempted"])
        self.assertEqual(result["selected"]["candidate"], "bad_repair")
        self.assertTrue(result["selected"]["verified"])
        self.assertEqual(result["selected"]["critical_violations"], [])


if __name__ == "__main__":
    unittest.main()
