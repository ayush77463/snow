"""SNOW Web Dashboard module.

Provides a lightweight, localhost-only Vanilla Web Dashboard for SNOW V3.
"""

from snow.web.server import SnowWebServer, run_dashboard

__all__ = ["SnowWebServer", "run_dashboard"]
