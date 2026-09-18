"""
Security and threat defense components for Project Aegis.
"""
from aegis.security.guard import (
    defang_prompt_injections,
    escape_xml_boundaries,
    sanitize_untrusted_input,
    wrap_untrusted_content,
)

__all__ = [
    "defang_prompt_injections",
    "escape_xml_boundaries",
    "sanitize_untrusted_input",
    "wrap_untrusted_content",
]
