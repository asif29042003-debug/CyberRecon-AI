"""Optional banner compatibility module.

The main launcher owns rendering so it can select Unicode or ASCII output based
on terminal encoding without requiring Rich.
"""

BANNER = "CyberRecon-AI // 150-Point Autonomous Security Suite"
AUTHOR = "MR ASIF"


def render_banner(console=None) -> str:
    """Return the plain banner for callers that still import this module."""
    value = f"{BANNER}\nDeveloped & Maintained by: {AUTHOR}"
    if console is not None:
        console.print(value)
    return value
