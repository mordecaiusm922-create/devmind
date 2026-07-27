from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from pipeline import DevMindPipeline, Mode, TaskInput
from runtime import CandidateScheduler, CandidateState, VerificationTrap
from runtime.sandbox import run_sandbox
from verify import verify_candidate_evidence


class SandboxRuntimeTests(unittest.TestCase):
    def test_sandbox_detects_static_danger_without_executing_candidate(self) -> None:
        result = run_sandbox(
            {
                "id": "bad",
                "diff": "diff --git a/app.py b/app.py\n@@\n+eval(user_input)\n",
            },
            {"run_tests": False},
        )

        self.assertEqual(result["evidence_type"], "runtime")
        self.assertTrue(result["syntax_valid"])
        self.assertEqual(result["status"], "failed")
        calls = [item["call"] for item in result["static_analysis"]["unsafe_calls"]]
        self.assertIn("eval", calls)
        self.assertIsInstance(result["bandit_issues"], list)

    def test_verify_candidate_evidence_emits_shell_execution_trap(self) -> None:
        result = verify_candidate_evidence(
            {
                "id": "shell",
                "diff": (
                    "diff --git a/jobs.py b/jobs.py\n@@\n"
                    "+import subprocess\n"
                    "+subprocess.run(user_cmd, shell=True)\n"
                ),
            },
            {"run_tests": False},
        )

        self.assertIn(VerificationTrap.SHELL_EXECUTION.value, result["traps"])
        self.assertFalse(result["verified"])

    def test_candidate_scheduler_dispatches_traps_and_preempts_bad_env(self) -> None:
        score = SimpleNamespace(utility=0.7, security=0.9, uncertainty=0.2)
        candidate = SimpleNamespace(id="c1")
        scheduler = CandidateScheduler()
        env = scheduler.add_candidate(candidate, score)
        env.sandbox_evidence = {"status": "failed", "syntax_valid": False}

        snapshot = scheduler.snapshot()

        self.assertEqual(snapshot["envs"][0]["state"], CandidateState.REPAIRING.value)
        self.assertIn(VerificationTrap.SYNTAX_ERROR.value, [m["payload"]["trap"] for m in snapshot["messages"]])

    def test_pipeline_summary_includes_sandbox_evidence(self) -> None:
        result = asyncio.run(
            DevMindPipeline().run(
                TaskInput(
                    prompt="Fix hardcoded SECRET_KEY securely",
                    mode=Mode.SECURE,
                )
            )
        )

        self.assertIn("sandbox_evidence", result.summary)
        self.assertIsInstance(result.summary["sandbox_evidence"], dict)
        self.assertEqual(result.summary["sandbox_evidence"].get("evidence_type"), "runtime")


if __name__ == "__main__":
    unittest.main()
