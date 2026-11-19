"""Register guarded OpenCTI mutations."""

from mcp.server import MCPServer

from opencti_mcp.core.common import execute
from opencti_mcp.services.write import WriteService


def register_write_tools(mcp: MCPServer, service: WriteService) -> None:

    @mcp.tool()
    def create_indicator(
        name: str,
        pattern: str,
        main_observable_type: str,
        marking_ids: list[str],
        description: str = "",
        score: int = 50,
        confidence: int = 50,
        valid_from: str | None = None,
        valid_until: str | None = None,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict:
        """create indicator in OpenCTI with dry-run by default."""
        return execute(lambda: {"data": service.create_indicator(
            name=name,
            pattern=pattern,
            main_observable_type=main_observable_type,
            marking_ids=marking_ids,
            description=description,
            score=score,
            confidence=confidence,
            valid_from=valid_from,
            valid_until=valid_until,
            dry_run=dry_run,
            confirm=confirm,
        )})

    @mcp.tool()
    def create_observable(
        observable_type: str,
        value: str,
        marking_ids: list[str],
        description: str = "",
        score: int = 50,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict:
        """create observable in OpenCTI with dry-run by default."""
        return execute(lambda: {"data": service.create_observable(
            observable_type=observable_type,
            value=value,
            marking_ids=marking_ids,
            description=description,
            score=score,
            dry_run=dry_run,
            confirm=confirm,
        )})

    @mcp.tool()
    def create_relationship(
        from_id: str,
        to_id: str,
        relationship_type: str,
        marking_ids: list[str],
        description: str = "",
        confidence: int = 50,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict:
        """create relationship in OpenCTI with dry-run by default."""
        return execute(lambda: {"data": service.create_relationship(
            from_id=from_id,
            to_id=to_id,
            relationship_type=relationship_type,
            marking_ids=marking_ids,
            description=description,
            confidence=confidence,
            dry_run=dry_run,
            confirm=confirm,
        )})

    @mcp.tool()
    def add_label(
        entity_id: str,
        label_name: str,
        create_if_missing: bool = False,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict:
        """add label in OpenCTI with dry-run by default."""
        return execute(lambda: {"data": service.add_label(
            entity_id=entity_id,
            label_name=label_name,
            create_if_missing=create_if_missing,
            dry_run=dry_run,
            confirm=confirm,
        )})

    @mcp.tool()
    def bulk_label_entities(
        entity_ids: list[str],
        label_name: str,
        create_if_missing: bool = False,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict:
        """bulk label entities in OpenCTI with dry-run by default."""
        return execute(lambda: {"data": service.bulk_label_entities(
            entity_ids=entity_ids,
            label_name=label_name,
            create_if_missing=create_if_missing,
            dry_run=dry_run,
            confirm=confirm,
        )})
