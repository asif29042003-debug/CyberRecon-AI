"""Technology and web-stack fingerprinting."""

from typing import Any


def run_tech_stack(web_data: dict[str, Any]) -> dict[str, Any]:
    technologies = set()
    for attempt in web_data.get("attempts", []):
        text = str(attempt).lower()
        for marker, name in (("nginx", "Nginx"), ("apache", "Apache"), ("litespeed", "LiteSpeed"),
                             ("wordpress", "WordPress"), ("joomla", "Joomla"), ("laravel", "Laravel"),
                             ("php", "PHP")):
            if marker in text:
                technologies.add(name)
    return {"technologies": sorted(technologies), "server": web_data.get("server", "Unknown"),
            "http2": "not exposed by stdlib urllib"}
