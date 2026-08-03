import signal
import sys
import unittest
from pathlib import Path
from unittest import mock


CORE_DIR = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE_DIR))

import runtime_guard


class RuntimeGuardTests(unittest.TestCase):
    @mock.patch("runtime_guard.signal.setitimer")
    @mock.patch("runtime_guard.signal.signal")
    def test_runtime_limit_arms_and_cancels_wall_clock_timer(
        self,
        set_signal_handler,
        set_timer,
    ):
        previous_handler = mock.sentinel.previous_handler
        set_signal_handler.return_value = previous_handler

        with runtime_guard.enforce_runtime_limit(1800):
            pass

        self.assertEqual(
            set_timer.call_args_list,
            [
                mock.call(signal.ITIMER_REAL, 1800.0),
                mock.call(signal.ITIMER_REAL, 0),
            ],
        )
        self.assertEqual(
            set_signal_handler.call_args_list,
            [
                mock.call(signal.SIGALRM, runtime_guard._raise_runtime_limit),
                mock.call(signal.SIGALRM, previous_handler),
            ],
        )

    def test_runtime_interrupt_bypasses_broad_exception_handlers(self):
        self.assertFalse(issubclass(runtime_guard.RuntimeLimitExceeded, Exception))

        with self.assertRaises(runtime_guard.RuntimeLimitExceeded):
            runtime_guard._raise_runtime_limit(signal.SIGALRM, None)


if __name__ == "__main__":
    unittest.main()
