"""
Project Aegis — Autonomous Multi-Agent DevSecOps & Remediation Engine.
"""
__version__ = "2.0.0"

from aegis.core.state import Selector
from aegis.agents.supervisor import aegis_app

__all__ = ["Selector", "aegis_app", "__version__"]
