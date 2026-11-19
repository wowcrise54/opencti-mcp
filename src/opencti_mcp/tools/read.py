from typing import Literal

from mcp.server import MCPServer
from pydantic import AliasChoices, BaseModel, Field

from opencti_mcp.core.common import execute
from opencti_mcp.services.intelligence import IntelligenceService
from opencti_mcp.services.ioc import IoCService


class IoCInput(BaseModel):
    observable_type: str = Field(validation_alias=AliasChoices("type", "observable_type"))
    value: str


def register_read_tools(
    mcp: MCPServer, intelligence: IntelligenceService, iocs: IoCService
) -> None:
    @mcp.tool()
    def search_entities(
        query: str, entity_types: list[str] | None = None,
        limit: int = 25, cursor: str | None = None,
    ) -> dict:
        """Search OpenCTI STIX entities by text and optional types."""
        return execute(lambda: intelligence.search_entities(query, entity_types, limit, cursor))

    @mcp.tool()
    def get_entity(entity_id: str) -> dict:
        """Read an OpenCTI entity by ID."""
        return execute(lambda: intelligence.get_entity(entity_id))

    @mcp.tool()
    def lookup_observable(value: str, observable_type: str) -> dict:
        """Find an exact observable in OpenCTI."""
        return execute(lambda: intelligence.lookup_observable(value, observable_type))

    @mcp.tool()
    def search_indicators(query: str, limit: int = 25, cursor: str | None = None) -> dict:
        """Search OpenCTI indicators by text."""
        return execute(lambda: intelligence.search_indicators(query, limit, cursor))

    @mcp.tool()
    def get_recent_intelligence(
        hours: int = 24, limit: int = 25, cursor: str | None = None,
    ) -> dict:
        """List recent intelligence from OpenCTI."""
        return execute(lambda: intelligence.get_recent_intelligence(hours, limit, cursor))

    @mcp.tool()
    def bulk_lookup_iocs(items: list[IoCInput]) -> dict:
        """Look up at most 100 observables, preserving input order."""
        return execute(lambda: intelligence.bulk_lookup_iocs([item.model_dump() for item in items]))

    @mcp.tool()
    def get_iocs_by_label(
        label: str, object_kinds: list[Literal["indicator", "observable"]] | None = None,
        observable_types: list[str] | None = None, min_score: int | None = None,
        min_confidence: int | None = None, active_only: bool = False,
        limit: int = 25, cursor: str | None = None,
    ) -> dict:
        """Read labelled indicators and observables with cursor pagination."""
        return execute(lambda: iocs.by_label(
            label, object_kinds, observable_types, min_score, min_confidence, active_only,
            limit, cursor,
        ))

    @mcp.tool()
    def export_indicators(
        format: Literal["json", "csv", "stix2"] = "json", labels: list[str] | None = None,
        observable_types: list[str] | None = None, min_score: int | None = None,
        active_only: bool = True, created_after: str | None = None,
        limit: int = 25, cursor: str | None = None,
    ) -> dict:
        """Export one page of indicators and return its SHA-256 digest."""
        return execute(lambda: iocs.export(
            format, labels, observable_types, min_score, active_only, created_after, limit, cursor,
        ))

    @mcp.tool()
    def prepare_ioc_feed(
        labels: list[str],
        format: Literal["json", "csv", "stix2"] = "json",
        limit: int = 25, cursor: str | None = None,
    ) -> dict:
        """Prepare one page of active indicators matching the supplied labels."""
        return execute(lambda: iocs.prepare_feed(labels, format, limit, cursor))
