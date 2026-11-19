"""MCP tools for graph exploration and investigation context."""

from __future__ import annotations

from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from opencti_mcp.core.common import execute
from opencti_mcp.services.graph import (
    Direction,
    GraphService,
)

def register_graph_tools(
    mcp: MCPServer,
    graph: GraphService,
) -> None:

    @mcp.tool()
    def get_relationships(
        entity_id: Annotated[str, Field(min_length=1)],
        direction: Direction = "both",
        relationship_types: list[str] | None = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 25,
        cursor: str | None = None,
    ) -> dict:
        """
        Get paginated STIX relationships for an entity.

        direction:
            both: incoming and outgoing relationships
            incoming: relationships targeting the entity
            outgoing: relationships originating from the entity
        """
        return execute(
            lambda: graph.get_relationships(
                entity_id,
                direction,
                relationship_types,
                limit,
                cursor,
            )
        )

    @mcp.tool()
    def get_related_entities(
        entity_id: Annotated[str, Field(min_length=1)],
        direction: Direction = "both",
        relationship_types: list[str] | None = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 25,
        cursor: str | None = None,
    ) -> dict:
        """
        Get neighboring entities and their relationship metadata.
        """
        return execute(
            lambda: graph.get_related_entities(
                entity_id,
                direction,
                relationship_types,
                limit,
                cursor,
            )
        )

    @mcp.tool()
    def traverse_threat_graph(
        entity_id: Annotated[str, Field(min_length=1)],
        direction: Direction = "both",
        relationship_types: list[str] | None = None,
        max_depth: Annotated[int, Field(ge=1, le=3)] = 2,
        max_nodes: Annotated[int, Field(ge=1, le=100)] = 50,
        max_edges: Annotated[int, Field(ge=1, le=200)] = 100,
        max_requests: Annotated[int, Field(ge=1, le=30)] = 20,
    ) -> dict:
        """
        Traverse the OpenCTI threat graph using bounded BFS.

        Returns nodes, edges, traversal statistics
        and truncation status.
        """
        return execute(
            lambda: graph.traverse_threat_graph(
                entity_id,
                direction,
                relationship_types,
                max_depth,
                max_nodes,
                max_edges,
                max_requests,
            )
        )

    @mcp.tool()
    def get_investigation_context(
        entity_id: Annotated[str, Field(min_length=1)],
        max_depth: Annotated[int, Field(ge=1, le=3)] = 1,
        max_nodes: Annotated[int, Field(ge=1, le=100)] = 50,
        max_edges: Annotated[int, Field(ge=1, le=200)] = 100,
    ) -> dict:
        """
        Get an entity, its local threat graph and
        a structured investigation summary.
        """
        return execute(
            lambda: graph.get_investigation_context(
                entity_id,
                max_depth,
                max_nodes,
                max_edges,
            )
        )
