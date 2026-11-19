import logging

from mcp.server import MCPServer

from opencti_mcp.config import Settings
from opencti_mcp.infrastructure.client import OpenCTIClientFactory
from opencti_mcp.services.graph import GraphService
from opencti_mcp.services.intelligence import IntelligenceService
from opencti_mcp.services.ioc import IoCService
from opencti_mcp.services.write import WritePolicy, WriteService
from opencti_mcp.tools.graph import register_graph_tools
from opencti_mcp.tools.read import register_read_tools
from opencti_mcp.tools.write import register_write_tools


def create_server(settings: Settings | None = None) -> MCPServer:
    factory = OpenCTIClientFactory(settings or Settings.from_env())
    intelligence = IntelligenceService(factory)
    server = MCPServer("OpenCTI MCP")
    register_read_tools(server, intelligence, IoCService(factory))
    register_graph_tools(server, GraphService(factory, intelligence))
    register_write_tools(server, WriteService(factory, WritePolicy.from_env()))
    return server


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    create_server().run(transport="stdio")


if __name__ == "__main__":
    main()
