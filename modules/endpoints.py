"""Low-impact endpoint discovery adapter."""

from .fuzzer import fuzz_target


def run_endpoints(target: str, timeout: float = 5.0):
    return fuzz_target(target, timeout)
