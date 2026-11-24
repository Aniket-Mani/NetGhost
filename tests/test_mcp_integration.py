import sys

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport


@pytest.mark.asyncio
async def test_server_exposes_release_tools_to_mcp_client():
    transport = StdioTransport(
        command=sys.executable,
        args=["-m", "netghost.server"],
    )
    async with Client(transport) as client:
        tools = await client.list_tools()
        status = await client.call_tool("netghost_status", {})
    names = {tool.name for tool in tools}
    assert names == {
        "netghost_status", "netghost_network_interfaces", "netghost_dns_lookup",
        "netghost_dns_configuration", "netghost_measure_latency",
        "netghost_measure_packet_loss", "netghost_traceroute",
        "netghost_active_connections", "netghost_ip_intelligence",
        "netghost_http_inspect", "netghost_tls_inspect", "netghost_investigate",
    }
    assert status.structured_content["status"] == "healthy"
