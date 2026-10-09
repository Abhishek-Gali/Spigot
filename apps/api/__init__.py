"""Local FastAPI application and typed client for Spigot / DocForge MCP (T19-T21)."""

from apps.api.client import SpigotApiClient, SpigotApiError
from apps.api.server import LocalApiConfig, create_local_app

__all__ = [
    "LocalApiConfig",
    "SpigotApiClient",
    "SpigotApiError",
    "create_local_app",
]
