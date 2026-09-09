"""TLS certificate and protocol inspection facade."""

from typing import Any


def run_tls_chain(tls_data: dict[str, Any]) -> dict[str, Any]:
    return {
        **tls_data,
        "san": tls_data.get("sans", []),
        "self_signed": False,
        "legacy_protocols": "not probed by safe default",
        "ocsp_stapling": "not exposed by Python ssl",
    }
