from contextlib import contextmanager
import signal


class RuntimeLimitExceeded(BaseException):
    """Interrupt the workflow even inside broad ``except Exception`` blocks."""


def _raise_runtime_limit(_signal_number, _frame):
    raise RuntimeLimitExceeded


@contextmanager
def enforce_runtime_limit(seconds):
    """Enforce a wall-clock limit for the complete foreground workflow."""
    seconds = float(seconds)
    if seconds <= 0:
        raise ValueError("Runtime limit must be greater than zero")

    previous_handler = signal.signal(signal.SIGALRM, _raise_runtime_limit)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
    except BaseException:
        signal.signal(signal.SIGALRM, previous_handler)
        raise

    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
