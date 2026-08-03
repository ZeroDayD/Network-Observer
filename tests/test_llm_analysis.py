import sys
import unittest
from pathlib import Path
from unittest import mock


CORE_DIR = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE_DIR))

import llm_analysis


class LlmAnalysisTests(unittest.TestCase):
    @mock.patch("llm_analysis.subprocess.run")
    def test_llm_is_not_called_when_disabled(self, run):
        with mock.patch.object(llm_analysis, "ENABLE_LLM_ANALYSIS", False):
            self.assertIsNone(llm_analysis.get_llm_attack_insights("scan"))

        run.assert_not_called()

    @mock.patch("llm_analysis.subprocess.run")
    def test_explicit_model_is_required(self, run):
        with (
            mock.patch.object(llm_analysis, "ENABLE_LLM_ANALYSIS", True),
            mock.patch.object(llm_analysis, "LLM_MODEL", ""),
        ):
            self.assertIsNone(llm_analysis.get_llm_attack_insights("scan"))

        run.assert_not_called()

    @mock.patch("llm_analysis.subprocess.run")
    def test_configured_model_is_passed_to_cli(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "analysis"
        with (
            mock.patch.object(llm_analysis, "ENABLE_LLM_ANALYSIS", True),
            mock.patch.object(llm_analysis, "LLM_MODEL", "local/test-model"),
        ):
            self.assertEqual(
                llm_analysis.get_llm_attack_insights("scan"),
                "analysis",
            )

        self.assertEqual(
            run.call_args.args[0],
            ["llm", "-m", "local/test-model"],
        )


if __name__ == "__main__":
    unittest.main()
