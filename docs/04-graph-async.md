# Продолжение разработки графа

Источник: https://chatgpt.com/c/6afd8c6e-19f8-83eb-ada4-386bc4978ef5

## Запрос

Продолжай разработку.

## Ответ

## Этап 3. Реализация графа связей и расследований OpenCTI

Продолжаем проект `opencti-mcp` для OpenCTI `7.260902.0` на Python, PyCTI и MCP SDK 2.x.

Ранее были подготовлены 9 инструментов поиска и работы с IoC. Теперь добавляем ещё 4\:

| Инструмент | Назначение |
|--------|--------|
| `get_relationships` | Получение связей STIX между объектами |
| `get_related_entities` | Поиск непосредственно связанных сущностей |
| `traverse_threat_graph` | Обход графа угроз алгоритмом BFS |
| `get_investigation_context` | Сбор контекста для расследования |

Для запросов используется `stix_core_relationship.list()` с фильтрами `fromOrToId`, `fromId`, `toId` и курсорной пагинацией. Эти интерфейсы поддерживаются PyCTI. citeturn636451view1turn715988view1

### 1\. Новый модуль `src/opencti_mcp/services/graph.py`

Реализация предусматривает ограничение глубины до 3, количества узлов до 200, связей до 500 и GraphQL-запросов до 100. Синхронные вызовы PyCTI выполняются через `asyncio.to_thread()`, чтобы не блокировать MCP-сервер.

```python

"""Read-only OpenCTI graph services (PyCTI 7.260902.0)."""
from __future__ import annotations

import asyncio
from collections import Counter, deque
from typing import Any, Literal

Direction = Literal["both", "outgoing", "incoming"]

# Small, explicit GraphQL selection: avoid customFieldValues
# and expensive nested fields.
RELATIONSHIP_FIELDS = """
    id
    relationship_type
    description
    confidence
    created
    from {
        ... on BasicObject { id entity_type }
        ... on StixObject { standard_id }
        ... on AttackPattern { name }
        ... on Campaign { name }
        ... on CourseOfAction { name }
        ... on Indicator { name }
        ... on Infrastructure { name }
        ... on IntrusionSet { name }
        ... on Malware { name }
        ... on ThreatActor { name }
        ... on Tool { name }
        ... on Vulnerability { name }
        ... on Incident { name }
        ... on Report { name }
        ... on StixCyberObservable { observable_value }
    }
    to {
        ... on BasicObject { id entity_type }
        ... on StixObject { standard_id }
        ... on AttackPattern { name }
        ... on Campaign { name }
        ... on CourseOfAction { name }
        ... on Indicator { name }
        ... on Infrastructure { name }
        ... on IntrusionSet { name }
        ... on Malware { name }
        ... on ThreatActor { name }
        ... on Tool { name }
        ... on Vulnerability { name }
        ... on Incident { name }
        ... on Report { name }
        ... on StixCyberObservable { observable_value }
    }
"""

def _node(
    value: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not value.get("id"):
        return None

    return {
        "id": value["id"],
        "type": value.get("entity_type"),
        "name": (
            value.get("name")
            or value.get("observable_value")
        ),
        "stix_id": value.get("standard_id"),
    }

def _relationship(
    raw: dict[str, Any],
) -> dict[str, Any] | None:
    source = _node(raw.get("from"))
    target = _node(raw.get("to"))

    if not raw.get("id") or source is None or target is None:
        return None

    return {
        "id": raw["id"],
        "type": raw.get("relationship_type"),
        "source": source,
        "target": target,
        "confidence": raw.get("confidence"),
        "description": raw.get("description"),
        "created": raw.get("created"),
    }

def _matches(
    rel: dict[str, Any],
    entity_id: str,
    direction: Direction,
) -> bool:
    source_id = rel["source"]["id"]
    target_id = rel["target"]["id"]

    return (
        (
            direction == "both"
            and entity_id in (source_id, target_id)
        )
        or (
            direction == "outgoing"
            and entity_id == source_id
        )
        or (
            direction == "incoming"
            and entity_id == target_id
        )
    )

def _id(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "entity_id must be a non-empty string"
        )
    return value.strip()

def _types(
    values: list[str] | None,
) -> list[str] | None:
    if values is None:
        return None

    if (
        not isinstance(values, list)
        or len(values) > 20
        or any(
            not isinstance(value, str)
            or not value.strip()
            or len(value) > 128
            for value in values
        )
    ):
        raise ValueError(
            "relationship_types must contain up to "
            "20 non-empty strings"
        )

    return list(
        dict.fromkeys(value.strip() for value in values)
    ) or None

def _limits(
    depth: int,
    nodes: int,
    edges: int,
    calls: int,
) -> None:
    if not 1 <= depth <= 3:
        raise ValueError(
            "depth must be between 1 and 3"
        )

    if not 2 <= nodes <= 200:
        raise ValueError(
            "max_nodes must be between 2 and 200"
        )

    if not 1 <= edges <= 500:
        raise ValueError(
            "max_relationships must be between 1 and 500"
        )

    if not 1 <= calls <= 100:
        raise ValueError(
            "max_api_calls must be between 1 and 100"
        )

class GraphService:
    def __init__(self, client_factory: Any):
        self._factory = client_factory

    async def _page(
        self,
        client: Any,
        *,
        entity_id: str,
        direction: Direction,
        relationship_types: list[str] | None,
        first: int,
        after: str | None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "first": first,
            "after": after,
            "getAll": False,
            "withPagination": True,
            "customAttributes": RELATIONSHIP_FIELDS,
        }

        if direction == "outgoing":
            kwargs["fromId"] = entity_id
        elif direction == "incoming":
            kwargs["toId"] = entity_id
        else:
            kwargs["fromOrToId"] = entity_id

        if relationship_types:
            kwargs["relationship_type"] = (
                relationship_types
            )

        try:
            data = await asyncio.to_thread(
                client.stix_core_relationship.list,
                **kwargs,
            )
        except Exception as exc:
            raise RuntimeError(
                "Failed to fetch OpenCTI relationships"
            ) from exc

        if (
            not isinstance(data, dict)
            or not isinstance(data.get("entities"), list)
        ):
            raise RuntimeError(
                "Unexpected PyCTI paginated response"
            )

        page = data.get("pagination")

        if (
            not isinstance(page, dict)
            or "hasNextPage" not in page
        ):
            raise RuntimeError(
                "Unexpected PyCTI pagination metadata"
            )

        return {
            "entities": data["entities"],
            "pagination": page,
        }

    async def get_relationships(
        self,
        entity_id: str,
        direction: Direction = "both",
        relationship_types: list[str] | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        entity_id = _id(entity_id)

        if direction not in (
            "both", "outgoing", "incoming"
        ):
            raise ValueError("Invalid direction")

        if not 1 <= limit <= 100:
            raise ValueError(
                "limit must be between 1 and 100"
            )

        if cursor is not None and (
            not isinstance(cursor, str)
            or len(cursor) > 4096
        ):
            raise ValueError(
                "Invalid pagination cursor"
            )

        result = await self._page(
            self._factory.create(),
            entity_id=entity_id,
            direction=direction,
            relationship_types=_types(
                relationship_types
            ),
            first=limit,
            after=cursor,
        )

        relationships = []

        for raw in result["entities"]:
            if (
                isinstance(raw, dict)
                and (rel := _relationship(raw))
                and _matches(
                    rel, entity_id, direction
                )
            ):
                relationships.append(rel)

        p = result["pagination"]

        return {
            "entity_id": entity_id,
            "direction": direction,
            "relationships": relationships,
            "pagination": {
                "has_next_page": bool(
                    p.get("hasNextPage", False)
                ),
                "end_cursor": p.get("endCursor"),
                "global_count": p.get("globalCount"),
            },
        }

    async def get_related_entities(
        self,
        entity_id: str,
        direction: Direction = "both",
        relationship_types: list[str] | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        page = await self.get_relationships(
            entity_id,
            direction,
            relationship_types,
            limit,
            cursor,
        )

        related: dict[str, dict[str, Any]] = {}

        for rel in page["relationships"]:
            other = (
                rel["target"]
                if rel["source"]["id"]
                == page["entity_id"]
                else rel["source"]
            )

            item = related.setdefault(
                other["id"],
                {
                    **other,
                    "relationship_ids": [],
                    "relationship_types": [],
                },
            )

            item["relationship_ids"].append(
                rel["id"]
            )

            if (
                rel["type"]
                not in item["relationship_types"]
            ):
                item["relationship_types"].append(
                    rel["type"]
                )

        return {
            "entity_id": page["entity_id"],
            "direction": direction,
            "entities": list(related.values()),
            "pagination": page["pagination"],
        }

    async def traverse_threat_graph(
        self,
        entity_id: str,
        depth: int = 2,
        direction: Direction = "both",
        relationship_types: list[str] | None = None,
        max_nodes: int = 100,
        max_relationships: int = 250,
        max_api_calls: int = 50,
    ) -> dict[str, Any]:
        entity_id = _id(entity_id)

        _limits(
            depth,
            max_nodes,
            max_relationships,
            max_api_calls,
        )

        if direction not in (
            "both", "outgoing", "incoming"
        ):
            raise ValueError(
                "Invalid direction"
            )

        relationship_types = _types(
            relationship_types
        )

        client = self._factory.create()

        nodes: dict[str, dict[str, Any]] = {
            entity_id: {
                "id": entity_id,
                "type": None,
                "name": None,
                "stix_id": None,
                "depth": 0,
            }
        }

        relationships: dict[
            str, dict[str, Any]
        ] = {}

        queue: deque[tuple[str, int]] = deque(
            [(entity_id, 0)]
        )

        calls = 0
        truncated: set[str] = set()

        while queue:
            current, level = queue.popleft()

            if level >= depth:
                continue

            cursor: str | None = None

            while True:
                if calls >= max_api_calls:
                    truncated.add(
                        "max_api_calls"
                    )
                    break

                if (
                    len(relationships)
                    >= max_relationships
                ):
                    truncated.add(
                        "max_relationships"
                    )
                    break

                requested = min(
                    100,
                    max_relationships
                    - len(relationships),
                )

                result = await self._page(
                    client,
                    entity_id=current,
                    direction=direction,
                    relationship_types=(
                        relationship_types
                    ),
                    first=requested,
                    after=cursor,
                )

                calls += 1

                for index, raw in enumerate(
                    result["entities"]
                ):
                    rel = (
                        _relationship(raw)
                        if isinstance(raw, dict)
                        else None
                    )

                    if (
                        rel is None
                        or not _matches(
                            rel,
                            current,
                            direction,
                        )
                    ):
                        continue

                    if rel["id"] in relationships:
                        continue

                    other = (
                        rel["target"]
                        if rel["source"]["id"]
                        == current
                        else rel["source"]
                    )

                    if (
                        other["id"] not in nodes
                        and len(nodes) >= max_nodes
                    ):
                        truncated.add("max_nodes")
                        continue

                    if other["id"] not in nodes:
                        nodes[other["id"]] = {
                            **other,
                            "depth": level + 1,
                        }

                        if level + 1 < depth:
                            queue.append(
                                (
                                    other["id"],
                                    level + 1,
                                )
                            )

                    if (
                        current == entity_id
                        and nodes[current]["type"]
                        is None
                    ):
                        here = (
                            rel["source"]
                            if rel["source"]["id"]
                            == current
                            else rel["target"]
                        )

                        nodes[current].update(
                            {
                                **here,
                                "depth": 0,
                            }
                        )

                    relationships[rel["id"]] = rel

                    if (
                        len(relationships)
                        >= max_relationships
                    ):
                        if (
                            index
                            < len(result["entities"]) - 1
                            or result["pagination"].get(
                                "hasNextPage"
                            )
                            or queue
                        ):
                            truncated.add(
                                "max_relationships"
                            )
                        break

                if (
                    len(relationships)
                    >= max_relationships
                ):
                    break

                p = result["pagination"]
                next_cursor = p.get("endCursor")

                if not p.get("hasNextPage"):
                    break

                if (
                    not next_cursor
                    or next_cursor == cursor
                ):
                    truncated.add(
                        "invalid_cursor"
                    )
                    break

                cursor = next_cursor

            if (
                "max_api_calls" in truncated
                or len(relationships)
                >= max_relationships
            ):
                break

        return {
            "root_id": entity_id,
            "depth": depth,
            "direction": direction,
            "nodes": list(nodes.values()),
            "relationships": list(
                relationships.values()
            ),
            "meta": {
                "node_count": len(nodes),
                "relationship_count": len(
                    relationships
                ),
                "api_calls": calls,
                "truncated": bool(truncated),
                "truncation_reasons": sorted(
                    truncated
                ),
            },
        }

    async def get_investigation_context(
        self,
        entity_id: str,
        depth: int = 2,
        relationship_types: list[str] | None = None,
        max_nodes: int = 100,
        max_relationships: int = 250,
        max_api_calls: int = 50,
    ) -> dict[str, Any]:
        graph = await self.traverse_threat_graph(
            entity_id,
            depth=depth,
            direction="both",
            relationship_types=(
                relationship_types
            ),
            max_nodes=max_nodes,
            max_relationships=(
                max_relationships
            ),
            max_api_calls=max_api_calls,
        )

        node_counts = Counter(
            node["type"] or "Unknown"
            for node in graph["nodes"]
        )

        rel_counts = Counter(
            rel["type"] or "Unknown"
            for rel in graph["relationships"]
        )

        direct = [
            node
            for node in graph["nodes"]
            if node["depth"] == 1
        ]

        return {
            "root_id": graph["root_id"],
            "summary": {
                "entities_by_type": dict(
                    node_counts
                ),
                "relationships_by_type": dict(
                    rel_counts
                ),
                "direct_neighbors": direct,
            },
            "graph": graph,
        }
```

### 2\. Регистрация MCP-инструментов — `src/opencti_mcp/tools/graph_tools.py`

Каждый инструмент получает `GraphService` через dependency injection. Используем декоратор `@mcp.tool()` из MCP SDK 2.x. citeturn636451view2

```python

"""MCP tool registration for read-only graph analysis."""
from __future__ import annotations

from typing import Any, Literal

from mcp.server import MCPServer

from opencti_mcp.services.graph import GraphService

def register_graph_tools(
    mcp: MCPServer,
    graph: GraphService,
) -> None:

    @mcp.tool()
    async def get_relationships(
        entity_id: str,
        direction: Literal[
            "both", "outgoing", "incoming"
        ] = "both",
        relationship_types: list[str] | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve STIX relationships of an OpenCTI entity."""
        return await graph.get_relationships(
            entity_id,
            direction,
            relationship_types,
            limit,
            cursor,
        )

    @mcp.tool()
    async def get_related_entities(
        entity_id: str,
        direction: Literal[
            "both", "outgoing", "incoming"
        ] = "both",
        relationship_types: list[str] | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve directly linked entities."""
        return await graph.get_related_entities(
            entity_id,
            direction,
            relationship_types,
            limit,
            cursor,
        )

    @mcp.tool()
    async de
```

> Здесь заканчивается доступный фрагмент ответа. Полный ответ превышает лимит чтения инструмента.

