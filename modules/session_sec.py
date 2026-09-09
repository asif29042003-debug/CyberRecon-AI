"""Cookie and session-security inspection."""

from typing import Any


def run_session_security(web_data: dict[str, Any]) -> dict[str, Any]:
    cookies = []
    for attempt in web_data.get("attempts", []):
        headers = {key.lower(): value for key, value in attempt.get("headers", {}).items()}
        if "set-cookie" in headers:
            cookies.append(headers["set-cookie"])
    return {"cookies": cookies, "flags": {"secure": "unknown", "httponly": "unknown", "samesite": "unknown"},
            "login_https": True}
