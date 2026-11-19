# Реализация OpenCTI сервера

Источник: https://chatgpt.com/c/6afd876b-26c4-83eb-b35d-fdbf6154ffd4

## Запрос

начинай реализовывать исходя из ТЗ. Версия OpenCTI 7.260902.0

## Ответ

# Реализация OpenCTI MCP Server

(Этап 1 — базовая реализация)

Разрабатываем MCP-сервер под **OpenCTI 7.260902.0** с использованием Python 3.12+, официального клиента PyCTI и MCP SDK 2.x.

Для совместимости зафиксируем `pycti==7.260902.0` — эта версия опубликована 2 сентября 2026 года. citeturn541147view0 В MCP SDK 2.x используем `MCPServer` вместо устаревшего `FastMCP`\. citeturn541147view2

Архитектуру строим так, чтобы инструменты поиска, расследования, экспорта IoC и изменения данных использовали общий слой доступа к OpenCTI.

## 1\. Структура проекта

```text
opencti-mcp/
├── pyproject.toml
├── .env.example
├── src/
│   └── opencti_mcp/
│       ├── __init__.py
│       ├── config.py
│       ├── server.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── errors.py
│       │   └── responses.py
│       ├── infrastructure/
│       │   ├── __init__.py
│       │   └── opencti_client.py
│       ├── services/
│       │   ├── __init__.py
│       │   ├── intelligence.py
│       │   ├── graph.py
│       │   ├── ioc.py
│       │   └── mutations.py
│       └── tools/
│           ├── __init__.py
│           ├── intelligence.py
│           ├── graph.py
│           ├── ioc.py
│           └── mutations.py
└── tests/
    ├── test_filters.py
    ├── test_intelligence.py
    └── test_ioc.py
```

На первом этапе реализуем девять инструментов\:

| Инструмент | Назначение |
|--------|--------|
| `search_entities` | Универсальный поиск сущностей |
| `get_entity` | Получение сущности по ID |
| `lookup_observable` | Поиск Observable по значению |
| `search_indicators` | Поиск индикаторов |
| `get_recent_intelligence` | Получение новых CTI-данных |
| `get_iocs_by_label` | Выборка IoC по метке |
| `bulk_lookup_iocs` | Массовая проверка IoC |
| `export_indicators` | Экспорт индикаторов |
| `prepare_ioc_feed` | Формирование содержимого IoC-фида |

В первой версии сервер работает через `stdio` и использует read-only токен OpenCTI. Он не содержит произвольного GraphQL-инструмента, не выполняет изменений в базе и ограничивает объём возвращаемых данных.

## 2\. Зависимости и конфигурация

`pyproject.toml`

```toml
[build-system]
requires = ["hatchling>=1.25"]
build-backend = "hatchling.build"

[project]
name = "opencti-mcp"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "mcp>=2.0,<3.0",
    "pycti==7.260902.0",
    "pydantic>=2.7,<3.0",
    "python-dotenv>=1.0,<2.0",
]

[project.optional-dependencies]
dev = ["pytest>=8,<10"]

[project.scripts]
opencti-mcp = "opencti_mcp.server:main"

[tool.hatch.build.targets.wheel]
packages = ["src/opencti_mcp"]

[tool.pytest.ini_options]
pythonpath = ["src"]
```

`.env.example`

```dotenv
OPENCTI_URL=https://opencti.example.org
OPENCTI_API_TOKEN=replace-with-a-read-only-token

OPENCTI_TLS_VERIFY=true
OPENCTI_REQUEST_TIMEOUT=30

# Только для разрешённого внутреннего HTTP:
# OPENCTI_ALLOW_HTTP=false
```

В `OPENCTI_API_TOKEN` указываем токен отдельного технического пользователя OpenCTI, имеющего только необходимые права чтения. Проверка TLS включена по умолчанию.

`src/opencti_mcp/config.py`

```python
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

from dotenv import load_dotenv

@dataclass(frozen=True)
class Settings:
    url: str
    token: str
    verify_tls: bool = True
    timeout: int = 30

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()

        url = os.getenv("OPENCTI_URL", "").strip().rstrip("/")
        token = os.getenv("OPENCTI_API_TOKEN", "").strip()

        parsed = urlsplit(url)

        allow_http = (
            os.getenv("OPENCTI_ALLOW_HTTP", "false").lower()
            == "true"
        )

        if not url or not token:
            raise ValueError(
                "OPENCTI_URL и OPENCTI_API_TOKEN обязательны"
            )

        if (
            parsed.scheme not in ("https", "http")
            or not parsed.hostname
        ):
            raise ValueError(
                "OPENCTI_URL должен быть абсолютным HTTP(S) URL"
            )

        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "OPENCTI_URL не должен содержать учетные данные "
                "или query"
            )

        if (
            parsed.scheme == "http"
            and parsed.hostname not in (
                "localhost",
                "127.0.0.1",
                "::1",
            )
            and not allow_http
        ):
            raise ValueError(
                "Для удаленного OpenCTI требуется HTTPS"
            )

        verify_tls = (
            os.getenv("OPENCTI_TLS_VERIFY", "true").lower()
            == "true"
        )

        timeout = int(
            os.getenv("OPENCTI_REQUEST_TIMEOUT", "30")
        )

        if not 1 <= timeout <= 120:
            raise ValueError(
                "OPENCTI_REQUEST_TIMEOUT должен быть "
                "в диапазоне 1..120"
            )

        return cls(
            url=url,
            token=token,
            verify_tls=verify_tls,
            timeout=timeout,
        )
```

## 3\. Общие функции, обработка ошибок и FilterGroup

`src/opencti_mcp/core/common.py`

```python
import logging

from time import monotonic
from typing import Any, Callable
from uuid import uuid4

log = logging.getLogger(__name__)

class ToolError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

def validate_page(
    limit: int,
    cursor: str | None,
) -> None:
    if not 1 <= limit <= 100:
        raise ToolError(
            "INVALID_ARGUMENT",
            "limit должен быть от 1 до 100",
        )

    if cursor is not None and (
        not cursor or len(cursor) > 2048
    ):
        raise ToolError(
            "INVALID_ARGUMENT",
            "Некорректный cursor",
        )

def text_arg(
    value: str,
    name: str,
    max_length: int = 2048,
) -> str:
    value = value.strip()

    if not value or len(value) > max_length:
        raise ToolError(
            "INVALID_ARGUMENT",
            f"Некорректный параметр {name}",
        )

    return value

def filter_group(*filters: dict) -> dict:
    return {
        "mode": "and",
        "filters": list(filters),
        "filterGroups": [],
    }

def eq(key: str, values: list[str]) -> dict:
    return {
        "key": [key],
        "values": values,
        "operator": "eq",
        "mode": "or",
    }

def gte(key: str, value: str) -> dict:
    return {
        "key": [key],
        "values": [value],
        "operator": "gte",
        "mode": "or",
    }

def unpack_page(raw: Any) -> tuple[list[dict], dict]:
    if isinstance(raw, list):
        return raw, {
            "has_next_page": False,
            "next_cursor": None,
        }

    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("entities"), list)
    ):
        raise ToolError(
            "UPSTREAM_BAD_RESPONSE",
            "Неожиданный формат ответа OpenCTI",
        )

    info = raw.get("pagination") or {}
    more = bool(info.get("hasNextPage", False))

    return raw["entities"], {
        "has_next_page": more,
        "next_cursor": (
            info.get("endCursor") if more else None
        ),
    }

def summary(entity: dict) -> dict:
    def labels(key: str, field: str) -> list[str]:
        return [
            item[field]
            for item in (entity.get(key) or [])
            if isinstance(item, dict) and item.get(field)
        ]

    return {
        "id": entity.get("id"),
        "standard_id": entity.get("standard_id"),
        "entity_type": entity.get("entity_type"),
        "name": (
            entity.get("name")
            or entity.get("observable_value")
            or entity.get("value")
        ),
        "description": (
            entity.get("description") or ""
        )[:4000],
        "pattern": entity.get("pattern"),
        "observable_value": (
            entity.get("observable_value")
            or entity.get("value")
        ),
        "confidence": entity.get("confidence"),
        "created_at": entity.get("created_at"),
        "updated_at": entity.get("updated_at"),
        "valid_until": entity.get("valid_until"),
        "revoked": entity.get("revoked"),
        "labels": labels("objectLabel", "value"),
        "markings": labels(
            "objectMarking",
            "definition",
        ),
    }

def execute(
    operation: Callable[[], dict],
    request_id: str | None = None,
) -> dict:
    started = monotonic()

    if request_id is None:
        request_id = str(uuid4())

    if len(request_id) > 100:
        request_id = request_id[:100]

    try:
        payload = operation()

        result = {
            "success": True,
            "data": payload.get("data"),
            "pagination": payload.get("pagination"),
            "error": None,
        }

    except ToolError as error:
        result = {
            "success": False,
            "data": None,
            "pagination": None,
            "error": {
                "code": error.code,
                "message": error.message,
            },
        }

    except Exception as error:
        # Не возвращаем модели traceback,
        # токены и внутренние запросы OpenCTI.
        log.error(
            "OpenCTI operation failed "
            "request_id=%s exception=%s",
            request_id,
            type(error).__name__,
        )

        result = {
            "success": False,
            "data": None,
            "pagination": None,
            "error": {
                "code": "OPENCTI_ERROR",
                "message": "Ошибка обращения к OpenCTI",
            },
        }

    result["meta"] = {
        "request_id": request_id,
        "source": "opencti",
        "duration_ms": round(
            (monotonic() - started) * 1000
        ),
    }

    return result
```

Формат ответа каждого инструмента унифицирован\:

```json
{
  "success": true,
  "data": {},
  "pagination": {
    "has_next_page": false,
    "next_cursor": null
  },
  "error": null,
  "meta": {
    "request_id": "generated-uuid",
    "source": "opencti",
    "duration_ms": 120
  }
}
```

При ошибке `success=false`, а поле `error` содержит код и безопасное описание. Так MCP-клиент сможет отличать отсутствие данных от проблем с OpenCTI.

## 4\. Подключение к OpenCTI через PyCTI

`src/opencti_mcp/infrastructure/client.py`

```python
from pycti import OpenCTIApiClient

from opencti_mcp.config import Settings

class OpenCTIClientFactory:
    def __init__(self, settings: Settings):
        self.settings = settings

    def create(self) -> OpenCTIApiClient:
        return OpenCTIApiClient(
            self.settings.url,
            self.settings.token,
            ssl_verify=self.settings.verify_tls,
            log_level="error",
            requests_timeout=self.settings.timeout,
            perform_health_check=False,
        )
```

Здесь создаётся клиент OpenCTI для каждой операции MCP. Внутри массовых операций один экземпляр клиента переиспользуется, чтобы не создавать его для каждого IoC.

Параметр `perform_health_check=False` убирает предварительную проверку при создании клиента, но не отключает проверку ответов самих API-запросов. Отдельный health-check сервера добавим при развёртывании HTTP-транспорта.

## 5\. Сервис поиска и получения CTI

`src/opencti_mcp/services/intelligence.py`

```python
from datetime import UTC, datetime, timedelta

from opencti_mcp.core.common import (
    ToolError,
    eq,
    filter_group,
    gte,
    summary,
    text_arg,
    unpack_page,
    validate_page,
)

ALLOWED_TYPES = {
    "Indicator",
    "Report",
    "Malware",
    "Campaign",
    "Intrusion-Set",
    "Threat-Actor-Group",
    "Threat-Actor-Individual",
    "Attack-Pattern",
    "Infrastructure",
    "Tool",
    "Vulnerability",
    "Incident",
    "Course-Of-Action",
    "Observed-Data",
    "Identity",
    "Note",
}

OBSERVABLE_TYPES = {
    "IPv4-Addr",
    "IPv6-Addr",
    "Domain-Name",
    "Url",
    "Email-Addr",
}

class IntelligenceService:
    def __init__(self, factory):
        self.factory = factory

    def search_entities(
        self,
        query: str,
        entity_types: list[str] | None,
        limit: int,
        cursor: str | None,
    ) -> dict:
        validate_page(limit, cursor)

        query = text_arg(query, "query", 256)

        if entity_types and (
            len(entity_types) > 20
            or set(entity_types) - ALLOWED_TYPES
        ):
            raise ToolError(
                "INVALID_ARGUMENT",
                "Неизвестный или недопустимый entity_type",
            )

        c = self.factory.create()

        raw = c.stix_core_object.list(
            types=entity_types or None,
            search=query,
            first=limit,
            after=cursor,
            withPagination=True,
            getAll=False,
        )

        items, page = unpack_page(raw)

        return {
            "data": {
                "items": [summary(x) for x in items],
            },
            "pagination": page,
        }

    def get_entity(self, entity_id: str) -> dict:
        entity_id = text_arg(
            entity_id,
            "entity_id",
            200,
        )

        c = self.factory.create()

        entity = c.stix_core_object.read(
            id=entity_id,
        )

        if entity is None:
            entity = c.stix_cyber_observable.read(
                id=entity_id,
            )

        if entity is None:
            raise ToolError(
                "NOT_FOUND",
                "Сущность не найдена или недоступна",
            )

        return {
            "data": summary(entity),
        }

    def _find_observable(
        self,
        c,
        value: str,
        observable_type: str,
    ) -> dict:
        if observable_type not in OBSERVABLE_TYPES:
            raise ToolError(
                "INVALID_ARGUMENT",
                "Неподдерживаемый тип Observable",
            )

        value = text_arg(value, "value", 2048)

        raw = c.stix_cyber_observable.list(
            types=[observable_type],
            filters=filter_group(
                eq("value", [value]),
            ),
            first=20,
            withPagination=True,
            getAll=False,
        )

        items, pagination = unpack_page(raw)

        exact = [
            summary(x)
            for x in items
            if str(
                x.get("observable_value")
                or x.get("value")
                or ""
            ).casefold() == value.casefold()
        ]

        return {
            "value": value,
            "observable_type": observable_type,
            "matched": bool(exact),
            "items": exact,
            "has_more_matches": pagination[
                "has_next_page"
            ],
        }

    def lookup_observable(
        self,
        value: str,
        observable_type: str,
    ) -> dict:
        c = self.factory.create()

        return {
            "data": self._find_observable(
                c,
                value,
                observable_type,
            ),
        }

    def bulk_lookup_iocs(
        self,
        items: list[dict],
    ) -> dict:
        if not 1 <= len(items) <= 100:
            raise ToolError(
                "INVALID_ARGUMENT",
                "Количество IoC должно быть от 1 до 100",
            )

        c = self.factory.create()
        results = []

        for i, item in enumerate(items):
            if not isinstance(item, dict):
                raise ToolError(
                    "INVALID_ARGUMENT",
                    f"Некорректный элемент #{i}",
                )

            try:
                results.append(
                    self._find_observable(
                        c,
                        item["value"],
                        item["observable_type"],
                    )
                )

            except (KeyError, TypeError, ToolError):
                results.append({
                    "value": item.get("value"),
                    "observable_type": item.get(
                        "observable_type"
                    ),
                    "matched": None,
                    "error": "INVALID_ITEM",
                })

        return {
            "data": {
                "items": results,
            },
        }

    def search_indicators(
        self,
        query: str,
        limit: int,
        cursor: str | None,
    ) -> dict:
        validate_page(limit, cursor)

        c = self.factory.create()

        raw = c.indicator.list(
            search=text_arg(
                query,
                "query",
                256,
            ),
            first=limit,
            after=cursor,
            withPagination=True,
            getAll=False,
        )

        items, page = unpack_page(raw)

        return {
            "data": {
                "items": [summary(x) for x in items],
            },
            "pagination": page,
        }

    def get_recent_intelligence(
        self,
        hours: int,
        limit: int,
        cursor: str | None,
    ) -> dict:
        validate_page(limit, cursor)

        if not 1 <= hours <= 720:
            raise ToolError(
                "INVALID_ARGUMENT",
                "hours должен быть от 1 до 720",
            )

        since = (
            datetime.now(UTC)
            - timedelta(hours=hours)
        ).isoformat().replace("+00:00", "Z")

        c = self.factory.create()

        raw = c.stix_core_object.list(
            types=[
                "Report",
                "Indicator",
                "Malware",
                "Campaign",
                "Intrusion-Set",
                "Threat-Actor-Group",
            ],
            filters=filter_group(
                gte("created_at", since),
            ),
            orderBy="created_at",
            orderMode="desc",
            first=limit,
            after=cursor,
            withPagination=True,
            getAll=False,
        )

        items, page = unpack_page(raw)

        return {
            "data": {
                "since": since,
                "items": [
                    summary(x) for x in items
                ],
            },
            "pagination": page,
        }
```

Важные особенности этого слоя\:

- Поиск работает с ограниченным списком STIX-типов.
- `bulk_lookup_iocs` поддерживает до 100 объектов за вызов.
- `get_recent_intelligence` возвращает данные по времени создания записи в OpenCTI, а не по времени самого инцидента.
- Для фильтров используется структура `FilterGroup`, применяемая в OpenCTI 7.x. citeturn386212search0
- Функция `_find_observable` дополнительно проверяет точное совпадение значения, поскольку частичные совпадения для проверки IoC нежелательны.

## 6\. Обработка IoC и экспорт по меткам

Здесь реализуем необходимую для интеграций функциональность: получение индикаторов по метке и преобразование их в безопасные текстовые списки.

Первоначально поддерживаем атомарные STIX-паттерны со сравнением `=`\. Сложные выражения с `AND`, `OR`, временными квалификаторами и дополнительными условиями не преобразуем автоматически в блок-листы — это предотвращает изменение смысла индикатора.

`src/opencti_mcp/services/ioc.py`

```python
import csv
import ipaddress
import io
import json
import re

from datetime import UTC, datetime
from urllib.parse import urlsplit

from opencti_mcp.core.common import (
    ToolError,
    eq,
    filter_group,
    summary,
    text_arg,
    unpack_page,
    validate_page,
)

PATTERN = re.compile(
    r"^\[\s*(?P<kind>"
    r"ipv4-addr|ipv6-addr|domain-name|url|email-addr|file"
    r"):"
    r"(?P<field>value|hashes\.'SHA-256')"
    r"\s*=\s*"
    r"'(?P<value>(?:\\'|[^'])+)'"
    r"\s*\]$",
    re.IGNORECASE,
)


```

> Здесь заканчивается доступный фрагмент ответа. Полный ответ превышает лимит чтения инструмента.

