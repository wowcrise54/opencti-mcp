# Продолжение реализации

Источник: https://chatgpt.com/c/6afd8a67-45f0-83ed-b169-e38697ae78f5

## Запрос

Продолжай реализацию

## Ответ

Продолжаю разработку **OpenCTI MCP Server** для версии OpenCTI `7.260902.0`\.

В предыдущей итерации был подготовлен базовый read-only слой с поиском сущностей, индикаторов, Observables и работой с IoC.

Теперь реализуем следующий модуль — **Graph &amp; Investigation**, который позволит AI-агентам исследовать взаимосвязи между объектами OpenCTI.

Добавляем четыре MCP-инструмента\:

| Инструмент | Назначение |
|--------|--------|
| `get_relationships` | Получение STIX-связей сущности с фильтрацией и пагинацией |
| `get_related_entities` | Получение связанных сущностей с указанием направления связи |
| `traverse_threat_graph` | Обход графа угроз алгоритмом BFS |
| `get_investigation_context` | Формирование контекста расследования по сущности |

Для взаимодействия используем GraphQL, совместимый со схемой `stixCoreRelationships` версии `7.260902.0`\. citeturn853023view0

## 1\. Реализация GraphService

Новый файл: `src/opencti_mcp/services/graph.py`

В реализации предусмотрены курсорная пагинация, ограничение глубины и количества запросов, защита от циклов, дедупликация связей и признак неполноты результатов.

```python
"""Bounded, read-only traversal of STIX core relationships."""

from __future__ import annotations

from collections import Counter, deque
from typing import Any, Literal

from opencti_mcp.core.common import ToolError

Direction = Literal["both", "incoming", "outgoing"]

_RELATIONSHIPS_QUERY = """
query MCPRelationships(
  $fromOrToId: [String]
  $fromId: [String]
  $toId: [String]
  $relationship_type: [String]
  $first: Int!
  $after: ID
) {
  stixCoreRelationships(
    fromOrToId: $fromOrToId
    fromId: $fromId
    toId: $toId
    relationship_type: $relationship_type
    first: $first
    after: $after
  ) {
    edges {
      node {
        id
        standard_id
        relationship_type
        description
        confidence
        created_at
        from {
          ... on BasicObject { id entity_type }
          ... on BasicRelationship { id entity_type }
        }
        to {
          ... on BasicObject { id entity_type }
          ... on BasicRelationship { id entity_type }
        }
      }
    }
    pageInfo {
      endCursor
      hasNextPage
      globalCount
    }
  }
}
"""

def _validate_limit(
    limit: int,
    *,
    maximum: int = 100,
) -> int:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= maximum
    ):
        raise ToolError(
            "INVALID_ARGUMENT",
            f"limit must be between 1 and {maximum}",
        )

    return limit

def _validate_types(
    values: list[str] | None,
) -> list[str] | None:
    if values is None:
        return None

    if len(values) > 20 or any(
        not isinstance(v, str) or not v.strip()
        for v in values
    ):
        raise ToolError(
            "INVALID_ARGUMENT",
            "relationship_types must contain 0..20 nonempty strings",
        )

    return list(dict.fromkeys(values)) or None

def _normalize_relationship(
    item: dict[str, Any],
) -> dict[str, Any] | None:
    source = item.get("from") or {}
    target = item.get("to") or {}

    if (
        not item.get("id")
        or not source.get("id")
        or not target.get("id")
    ):
        return None

    return {
        "id": item["id"],
        "standard_id": item.get("standard_id"),
        "relationship_type": item.get("relationship_type"),
        "source_id": source["id"],
        "source_type": source.get("entity_type"),
        "target_id": target["id"],
        "target_type": target.get("entity_type"),
        "confidence": item.get("confidence"),
        "description": item.get("description"),
        "created_at": item.get("created_at"),
    }

class GraphService:
    def __init__(
        self,
        factory: Any,
        intelligence: Any,
    ) -> None:
        self._factory = factory
        self._intelligence = intelligence

    @staticmethod
    def _page(
        client: Any,
        entity_id: str,
        *,
        direction: Direction = "both",
        relationship_types: list[str] | None = None,
        limit: int = 25,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        if (
            not isinstance(entity_id, str)
            or not entity_id.strip()
        ):
            raise ToolError(
                "INVALID_ARGUMENT",
                "entity_id must not be blank",
            )

        if direction not in (
            "both",
            "incoming",
            "outgoing",
        ):
            raise ToolError(
                "INVALID_ARGUMENT",
                "invalid direction",
            )

        _validate_limit(limit)
        types = _validate_types(relationship_types)

        variables = {
            "fromOrToId": (
                [entity_id]
                if direction == "both"
                else None
            ),
            "fromId": (
                [entity_id]
                if direction == "outgoing"
                else None
            ),
            "toId": (
                [entity_id]
                if direction == "incoming"
                else None
            ),
            "relationship_type": types,
            "first": limit,
            "after": cursor,
        }

        response = client.query(
            _RELATIONSHIPS_QUERY,
            variables,
        )

        connection = (
            (response.get("data") or {})
            .get("stixCoreRelationships")
        )

        if not isinstance(connection, dict):
            raise RuntimeError(
                "OpenCTI did not return stixCoreRelationships"
            )

        edges = connection.get("edges") or []
        items = []

        for edge in edges:
            if (
                not isinstance(edge, dict)
                or not isinstance(edge.get("node"), dict)
            ):
                continue

            item = _normalize_relationship(
                edge["node"]
            )

            if item is not None:
                items.append(item)

        info = connection.get("pageInfo") or {}

        return {
            "items": items,
            "pagination": {
                "end_cursor": info.get("endCursor"),
                "has_next_page": bool(
                    info.get("hasNextPage")
                ),
                "global_count": info.get("globalCount"),
            },
        }

    def get_relationships(
        self,
        entity_id: str,
        direction: Direction = "both",
        relationship_types: list[str] | None = None,
        limit: int = 25,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        page = self._page(
            self._factory.create(),
            entity_id,
            direction=direction,
            relationship_types=relationship_types,
            limit=limit,
            cursor=cursor,
        )

        return {
            "data": {
                "relationships": page["items"],
            },
            "pagination": page["pagination"],
        }

    def get_related_entities(
        self,
        entity_id: str,
        direction: Direction = "both",
        relationship_types: list[str] | None = None,
        limit: int = 25,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        page = self._page(
            self._factory.create(),
            entity_id,
            direction=direction,
            relationship_types=relationship_types,
            limit=limit,
            cursor=cursor,
        )

        entities: dict[str, dict[str, Any]] = {}

        for rel in page["items"]:
            if rel["source_id"] == entity_id:
                other_id = rel["target_id"]
                other_type = rel["target_type"]
                relation = "outgoing"

            elif rel["target_id"] == entity_id:
                other_id = rel["source_id"]
                other_type = rel["source_type"]
                relation = "incoming"

            else:
                continue

            info = entities.setdefault(
                other_id,
                {
                    "id": other_id,
                    "entity_type": other_type,
                    "relationships": [],
                },
            )

            info["relationships"].append(
                {
                    "id": rel["id"],
                    "type": rel["relationship_type"],
                    "direction": relation,
                }
            )

        return {
            "data": {
                "entity_id": entity_id,
                "entities": list(entities.values()),
            },
            "pagination": page["pagination"],
        }

    def traverse_threat_graph(
        self,
        entity_id: str,
        direction: Direction = "both",
        relationship_types: list[str] | None = None,
        max_depth: int = 2,
        max_nodes: int = 50,
        max_edges: int = 100,
        max_requests: int = 20,
        page_size: int = 50,
    ) -> dict[str, Any]:
        if (
            not isinstance(entity_id, str)
            or not entity_id.strip()
        ):
            raise ToolError(
                "INVALID_ARGUMENT",
                "entity_id must not be blank",
            )

        if not 1 <= max_depth <= 3:
            raise ToolError(
                "INVALID_ARGUMENT",
                "max_depth must be 1..3",
            )

        _validate_limit(max_nodes, maximum=100)
        _validate_limit(max_edges, maximum=200)
        _validate_limit(max_requests, maximum=30)
        _validate_limit(page_size)

        if direction not in (
            "both",
            "incoming",
            "outgoing",
        ):
            raise ToolError(
                "INVALID_ARGUMENT",
                "invalid direction",
            )

        types = _validate_types(relationship_types)

        client = self._factory.create()

        nodes: dict[str, dict[str, Any]] = {
            entity_id: {
                "id": entity_id,
                "entity_type": None,
            }
        }

        edges: dict[str, dict[str, Any]] = {}

        queue: deque[tuple[str, int]] = deque(
            [(entity_id, 0)]
        )

        requests_used = 0
        max_depth_reached = 0
        truncation_reason: str | None = None

        while queue and not truncation_reason:
            current_id, depth = queue.popleft()

            max_depth_reached = max(
                max_depth_reached,
                depth,
            )

            if depth >= max_depth:
                continue

            cursor: str | None = None

            while True:
                if requests_used >= max_requests:
                    truncation_reason = "max_requests"
                    break

                if len(edges) >= max_edges:
                    truncation_reason = "max_edges"
                    break

                remaining = max_edges - len(edges)

                result = self._page(
                    client,
                    current_id,
                    direction=direction,
                    relationship_types=types,
                    limit=min(page_size, remaining),
                    cursor=cursor,
                )

                requests_used += 1

                for rel in result["items"]:
                    if rel["id"] in edges:
                        continue

                    if rel["source_id"] == current_id:
                        other_id = rel["target_id"]
                        other_type = rel["target_type"]

                    elif rel["target_id"] == current_id:
                        other_id = rel["source_id"]
                        other_type = rel["source_type"]

                    else:
                        continue

                    if (
                        other_id not in nodes
                        and len(nodes) >= max_nodes
                    ):
                        truncation_reason = "max_nodes"
                        break

                    for node_id, node_type in (
                        (
                            rel["source_id"],
                            rel["source_type"],
                        ),
                        (
                            rel["target_id"],
                            rel["target_type"],
                        ),
                    ):
                        if (
                            node_id == current_id
                            and nodes[node_id]["entity_type"] is None
                        ):
                            nodes[node_id]["entity_type"] = node_type

                    edges[rel["id"]] = rel

                    if other_id not in nodes:
                        nodes[other_id] = {
                            "id": other_id,
                            "entity_type": other_type,
                        }

                        max_depth_reached = max(
                            max_depth_reached,
                            depth + 1,
                        )

                        queue.append(
                            (other_id, depth + 1)
                        )

                    if len(edges) >= max_edges:
                        truncation_reason = "max_edges"
                        break

                if truncation_reason:
                    break

                pagination = result["pagination"]

                if not pagination["has_next_page"]:
                    break

                next_cursor = pagination["end_cursor"]

                if (
                    not next_cursor
                    or next_cursor == cursor
                ):
                    truncation_reason = "invalid_cursor"
                    break

                cursor = next_cursor

        return {
            "data": {
                "root_entity_id": entity_id,
                "nodes": list(nodes.values()),
                "edges": list(edges.values()),
                "max_depth_reached": max_depth_reached,
                "requests_used": requests_used,
                "truncated": truncation_reason is not None,
                "truncation_reason": truncation_reason,
            }
        }

    def get_investigation_context(
        self,
        entity_id: str,
        max_depth: int = 1,
        max_nodes: int = 50,
        max_edges: int = 100,
    ) -> dict[str, Any]:
        entity_result = self._intelligence.get_entity(
            entity_id
        )

        if entity_result.get("data") is None:
            raise ToolError(
                "NOT_FOUND",
                "Entity not found",
            )

        graph = self.traverse_threat_graph(
            entity_id,
            max_depth=max_depth,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )["data"]

        types = Counter(
            node.get("entity_type") or "Unknown"
            for node in graph["nodes"]
        )

        relations = Counter(
            edge.get("relationship_type") or "Unknown"
            for edge in graph["edges"]
        )

        return {
            "data": {
                "entity": entity_result.get("data"),
                "graph": graph,
                "summary": {
                    "entity_count": len(graph["nodes"]),
                    "relationship_count": len(graph["edges"]),
                    "entities_by_type": dict(types),
                    "relationships_by_type": dict(relations),
                    "complete": not graph["truncated"],
                },
            }
        }
```

## 2\. Регистрация MCP-инструментов

Новый файл: `src/opencti_mcp/tools/graph.py`

Используем существующую функцию `execute()`, чтобы ответы графовых инструментов соответствовали общему контракту MCP-сервера.

```python
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
```

## 3\. Обновление основного сервера

Обновляем существующий `src/opencti_mcp/server.py`, подключая новые инструменты без изменения ранее реализованных.

```python
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from opencti_mcp.config import Settings
from opencti_mcp.infrastructure.client import OpenCTIClientFactory

from opencti_mcp.services.intelligence import IntelligenceService
from opencti_mcp.services.ioc import IOCService
from opencti_mcp.services.graph import GraphService

from opencti_mcp.tools.read_tools import register_tools
from opencti_mcp.tools.graph import register_graph_tools

def create_server(
    settings: Settings | None = None,
) -> MCPServer:

    config = settings or Settings.from_env()

    factory = OpenCTIClientFactory(config)
```

> Здесь заканчивается доступный фрагмент ответа. Полный ответ превышает лимит чтения инструмента.

