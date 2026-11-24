from datetime import UTC, datetime
from platform import platform, python_version

from netghost.config import PROJECT_NAME, PROJECT_VERSION


def get_server_status() -> dict:
    """
    Returns the current netghost server status
    """
    return {
        "status":"healthy",
        "server": PROJECT_NAME,
        "version": PROJECT_VERSION,
        "python_version": python_version(),
        "platform": platform(),
        "checked_at": datetime.now(UTC).isoformat(),
    }

def register_tools(mcp) -> None:
    """
    Register health-related tools with the MCP server.
    """
    @mcp.tool
    def netghost_status() -> dict:
        """
        Check whether NetGhost is operational.

        Returns server information, runtime details
        and current health status.
        """
        return get_server_status()
