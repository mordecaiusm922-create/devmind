from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from calibration import expected_calibration_error_from_events
from safety_flow import CandidatePayload, SafetyFlowRequest, run_safety_flow


class ReliabilityLayerTests(unittest.TestCase):
    def test_ece_calibration_pairs_predictions_with_real_outcomes(self) -> None:
        events = [
            {"event_type": "safety_flow", "entity": "pr#1", "risk": 0.9},
            {"event_type": "outcome", "entity": "pr#1", "outcome": "regression"},
            {"event_type": "safety_flow", "entity": "pr#2", "risk": 0.1},
            {"event_type": "outcome", "entity": "pr#2", "outcome": "merged_without_regression"},
        ]

        summary = expected_calibration_error_from_events(events, bins=2, repo="acme/app")

        self.assertEqual(summary["n"], 2)
        self.assertAlmostEqual(summary["ece"], 0.1)
        self.assertAlmostEqual(summary["brier"], 0.01)

    def test_runtime_evidence_blocks_dangerous_candidate(self) -> None:
        result = run_safety_flow(
            SafetyFlowRequest(
                prompt="Verify generated code execution from LLM output",
                mode="secure",
                properties=["runtime_safety_policy"],
                max_repair_attempts=0,
                candidates=[
                    CandidatePayload(
                        id="unsafe",
                        diff="diff --git a/agent.py b/agent.py\n@@\n+eval(user_input)\n",
                        strategy="direct-eval",
                        explanation="Execute model output directly.",
                    )
                ],
            )
        )

        self.assertEqual(result["runtime_evidence"]["unsafe"]["status"], "failed")
        self.assertEqual(result["decision"]["action"], "revise")
        self.assertGreater(result["risk"]["source_scores"]["candidate_expected_loss"], 0)

    def test_graph_blast_radius_is_connected_to_safety_flow_risk(self) -> None:
        result = run_safety_flow(
            SafetyFlowRequest(
                prompt="Review settings change touching secret configuration",
                mode="secure",
                context={"filename": "project/settings.py"},
                files=[
                    {
                        "filename": "project/settings.py",
                        "diff": "diff --git a/project/settings.py b/project/settings.py\n@@\n+SECRET_KEY = \"hardcoded-secret-123456\"\n+def load_config():\n+    return SECRET_KEY\n",
                        "additions": 3,
                        "deletions": 0,
                    }
                ],
            )
        )

        graph = result["representation"]["blast_radius"]["graph"]
        self.assertIn("score", graph)
        self.assertGreaterEqual(graph["high_risk_node_count"], 1)
        self.assertIn("graph", result["risk"]["source_scores"])


if __name__ == "__main__":
    unittest.main()
