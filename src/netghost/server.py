
from fastmcp import FastMCP

from netghost.config import SERVER_INSTRUCTIONS, SERVER_NAME
from netghost.engine.investigator import (
    register_tools as register_investigator_tools,
)
from netghost.tools.connections import (
    register_tools as register_connection_tools,
)
from netghost.tools.dns import (
    register_tools as register_dns_tools,
)
from netghost.tools.health import register_tools as register_health_tools
from netghost.tools.http import register_tools as register_http_tools
from netghost.tools.interfaces import (
    register_tools as register_interface_tools,
)
from netghost.tools.ip_intelligence import (
    register_tools as register_ip_intelligence_tools,
)
from netghost.tools.latency import (
    register_tools as register_latency_tools,
)
from netghost.tools.packet_loss import (
    register_tools as register_packet_loss_tools,
)
from netghost.tools.routing import (
    register_tools as register_routing_tools,
)
from netghost.tools.tls import register_tools as register_tls_tools

mcp = FastMCP(
    name=SERVER_NAME,
    instructions=SERVER_INSTRUCTIONS,
)

# Register available tools
register_health_tools(mcp)
register_interface_tools(mcp)
register_dns_tools(mcp)
register_latency_tools(mcp)
register_packet_loss_tools(mcp)
register_routing_tools(mcp)
register_connection_tools(mcp)
register_ip_intelligence_tools(mcp)
register_http_tools(mcp)
register_tls_tools(mcp)
register_investigator_tools(mcp)

if __name__ == "__main__":
    mcp.run()
