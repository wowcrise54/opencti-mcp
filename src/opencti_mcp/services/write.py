from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from stix2patterns.validator import run_validator

from opencti_mcp.core.common import ToolError, eq, filter_group
from opencti_mcp.infrastructure.client import OpenCTIClientFactory

logger = logging.getLogger(__name__)

OBSERVABLE_KEYS = {
    "IPv4-Addr": "IPv4-Addr.value",
    "IPv6-Addr": "IPv6-Addr.value",
    "Domain-Name": "Domain-Name.value",
    "Url": "Url.value",
    "Hostname": "Hostname.value",
    "StixFile": None,
}

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")

@dataclass(frozen=True)
class WritePolicy:
    enabled: bool = False
    max_bulk: int = 100

    @classmethod
    def from_env(cls) -> "WritePolicy":
        enabled = (
            os.getenv("OPENCTI_MCP_WRITE_ENABLED", "false").lower()
            == "true"
        )
        max_bulk = int(
            os.getenv("OPENCTI_MCP_MAX_BULK_WRITE", "100")
        )
        if not 1 <= max_bulk <= 500:
            raise ValueError("MAX_BULK_WRITE must be between 1 and 500")

        return cls(enabled=enabled, max_bulk=max_bulk)

class WriteService:
    def __init__(
        self,
        factory: OpenCTIClientFactory,
        policy: WritePolicy | None = None,
    ):
        self.factory = factory
        self.policy = policy or WritePolicy()

    def _authorize(self, dry_run: bool, confirm: bool) -> None:
        if dry_run:
            return
        if not self.policy.enabled:
            raise ToolError(
                "WRITE_DISABLED",
                "OpenCTI write operations are disabled",
            )
        if not confirm:
            raise ToolError(
                "CONFIRMATION_REQUIRED",
                "Set confirm=true to execute the mutation",
            )

    @staticmethod
    def _validate_id(value: str) -> str:
        if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
            raise ToolError("INVALID_ID", "Invalid OpenCTI identifier")
        return value

    @staticmethod
    def _validate_markings(marking_ids: list[str]) -> list[str]:
        if not isinstance(marking_ids, list) or not marking_ids:
            raise ToolError(
                "INVALID_MARKINGS",
                "At least one marking definition ID is required",
            )
        return list(dict.fromkeys(
            WriteService._validate_id(item)
            for item in marking_ids
        ))

    @staticmethod
    def _validate_text(value: str, maximum: int = 255) -> str:
        if not isinstance(value, str):
            raise ToolError("INVALID_VALUE", "Expected a string")
        value = value.strip()
        if not value or len(value) > maximum:
            raise ToolError(
                "INVALID_VALUE",
                f"String length must be between 1 and {maximum}",
            )
        return value

    @staticmethod
    def _validate_score(score: int) -> int:
        if isinstance(score, bool) or not isinstance(score, int):
            raise ToolError("INVALID_SCORE", "Score must be an integer")
        if not 0 <= score <= 100:
            raise ToolError("INVALID_SCORE", "Score must be 0..100")
        return score

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        if value is None:
            return None
        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except (ValueError, AttributeError) as exc:
            raise ToolError(
                "INVALID_DATE",
                "Expected an ISO 8601 date-time",
            ) from exc

        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ToolError(
                "INVALID_DATE",
                "Date-time must include a timezone",
            )
        return parsed

    def _verify_markings(self, api, marking_ids: list[str]) -> None:
        for marking_id in marking_ids:
            if api.marking_definition.read(id=marking_id) is None:
                raise ToolError(
                    "MARKING_NOT_FOUND",
                    f"Marking definition not found: {marking_id}",
                )

    @staticmethod
    def _result(result: dict | None, operation: str) -> dict:
        if not isinstance(result, dict) or not result.get("id"):
            raise ToolError(
                "EMPTY_RESULT",
                "OpenCTI returned no entity identifier",
            )

        logger.info(
            "opencti_write operation=%s entity_id=%s",
            operation,
            result["id"],
        )

        return {
            "status": "submitted",
            "operation": operation,
            "id": result["id"],
            "standard_id": result.get("standard_id"),
            "entity_type": result.get("entity_type"),
        }

    @staticmethod
    def _validate_observable(
        observable_type: str,
        value: str,
    ) -> str:
        value = WriteService._validate_text(value, 2048)

        if observable_type in {"IPv4-Addr", "IPv6-Addr"}:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ToolError(
                    "INVALID_IOC", "Invalid IP address"
                ) from exc

            expected_version = (
                4 if observable_type == "IPv4-Addr" else 6
            )
            if address.version != expected_version:
                raise ToolError(
                    "INVALID_IOC", "Incorrect IP address version"
                )
            return str(address)

        if observable_type in {"Domain-Name", "Hostname"}:
            value = value.rstrip(".").lower()
            try:
                value = value.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ToolError(
                    "INVALID_IOC", "Invalid domain encoding"
                ) from exc

            if len(value) > 253 or not all(
                re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                    part,
                )
                for part in value.split(".")
            ):
                raise ToolError("INVALID_IOC", "Invalid domain")

            if observable_type == "Domain-Name" and "." not in value:
                raise ToolError(
                    "INVALID_IOC", "Expected a qualified domain name"
                )
            return value

        if observable_type == "Url":
            try:
                parsed = urlsplit(value)
                hostname = parsed.hostname
                port = parsed.port
            except ValueError as exc:
                raise ToolError("INVALID_IOC", "Invalid URL") from exc

            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ToolError(
                    "INVALID_IOC",
                    "Expected an HTTP(S) URL without credentials",
                )
            return value

        if observable_type == "StixFile":
            if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
                raise ToolError(
                    "INVALID_IOC",
                    "StixFile currently accepts SHA-256 hashes",
                )
            return value.lower()

        raise ToolError(
            "UNSUPPORTED_TYPE",
            f"Unsupported observable type: {observable_type}",
        )

    def create_indicator(
        self,
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
        name = self._validate_text(name)
        pattern = self._validate_text(pattern, 8192)
        score = self._validate_score(score)
        confidence = self._validate_score(confidence)
        marking_ids = self._validate_markings(marking_ids)

        if main_observable_type not in OBSERVABLE_KEYS:
            raise ToolError(
                "UNSUPPORTED_TYPE",
                "Unsupported main observable type",
            )

        errors = run_validator(pattern, stix_version="2.1")
        if errors:
            raise ToolError(
                "INVALID_STIX_PATTERN",
                str(errors[0])[:300],
            )

        expected_type = (
            "file" if main_observable_type == "StixFile"
            else main_observable_type.lower()
        )
        if not re.search(
            rf"(?<![\w-]){re.escape(expected_type)}\s*:",
            pattern,
            flags=re.IGNORECASE,
        ):
            raise ToolError(
                "PATTERN_TYPE_MISMATCH",
                "Pattern does not contain the selected observable type",
            )

        start = self._parse_datetime(valid_from)
        end = self._parse_datetime(valid_until)
        if start and end and end <= start:
            raise ToolError(
                "INVALID_DATE",
                "valid_until must be later than valid_from",
            )

        self._authorize(dry_run, confirm)

        if dry_run:
            return {
                "status": "dry_run",
                "operation": "create_indicator",
                "name": name,
                "main_observable_type": main_observable_type,
                "marking_ids": marking_ids,
                "validated": True,
            }

        api = self.factory.create()
        self._verify_markings(api, marking_ids)

        result = api.indicator.create(
            name=name,
            description=description,
            pattern_type="stix",
            pattern_version="2.1",
            pattern=pattern,
            x_opencti_main_observable_type=main_observable_type,
            x_opencti_score=score,
            confidence=confidence,
            valid_from=valid_from,
            valid_until=valid_until,
            objectMarking=marking_ids,
            x_opencti_create_observables=False,
            update=False,
        )

        return self._result(result, "create_indicator")

    def create_observable(
        self,
        observable_type: str,
        value: str,
        marking_ids: list[str],
        description: str = "",
        score: int = 50,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict:
        if observable_type not in OBSERVABLE_KEYS:
            raise ToolError(
                "UNSUPPORTED_TYPE",
                "Unsupported observable type",
            )

        value = self._validate_observable(observable_type, value)
        score = self._validate_score(score)
        marking_ids = self._validate_markings(marking_ids)
        self._authorize(dry_run, confirm)

        if dry_run:
            return {
                "status": "dry_run",
                "operation": "create_observable",
                "observable_type": observable_type,
                "value": value,
                "marking_ids": marking_ids,
            }

        api = self.factory.create()
        self._verify_markings(api, marking_ids)

        arguments = {
            "objectMarking": marking_ids,
            "x_opencti_score": score,
            "update": False,
            "createIndicator": False,
        }

        if observable_type == "StixFile":
            arguments["observableData"] = {
                "type": "file",
                "hashes": {"SHA-256": value},
                "x_opencti_description": description,
            }
        else:
            arguments.update({
                "simple_observable_key":
                    OBSERVABLE_KEYS[observable_type],
                "simple_observable_value": value,
                "simple_observable_description": description,
            })

        result = api.stix_cyber_observable.create(**arguments)
        return self._result(result, "create_observable")

    def create_relationship(
        self,
        from_id: str,
        to_id: str,
        relationship_type: str,
        marking_ids: list[str],
        description: str = "",
        confidence: int = 50,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict:
        from_id = self._validate_id(from_id)
        to_id = self._validate_id(to_id)
        marking_ids = self._validate_markings(marking_ids)
        confidence = self._validate_score(confidence)

        if from_id == to_id:
            raise ToolError(
                "INVALID_RELATIONSHIP",
                "Source and target cannot be identical",
            )

        if not re.fullmatch(
            r"[a-z][a-z0-9-]{0,79}", relationship_type
        ):
            raise ToolError(
                "INVALID_RELATIONSHIP",
                "Invalid relationship type",
            )

        self._authorize(dry_run, confirm)

        if dry_run:
            return {
                "status": "dry_run",
                "operation": "create_relationship",
                "from_id": from_id,
                "to_id": to_id,
                "relationship_type": relationship_type,
                "marking_ids": marking_ids,
            }

        api = self.factory.create()
        self._verify_markings(api, marking_ids)

        for entity_id in (from_id, to_id):
            if api.stix_core_object.read(
                id=entity_id,
                customAttributes="id",
            ) is None:
                raise ToolError(
                    "ENTITY_NOT_FOUND",
                    f"Entity not found: {entity_id}",
                )

        existing = api.stix_core_relationship.read(
            fromId=from_id,
            toId=to_id,
            relationship_type=relationship_type,
        )
        if existing:
            return {
                "status": "already_exists",
                "operation": "create_relationship",
                "id": existing["id"],
            }

        result = api.stix_core_relationship.create(
            fromId=from_id,
            toId=to_id,
            relationship_type=relationship_type,
            description=description,
            confidence=confidence,
            objectMarking=marking_ids,
            update=False,
        )

        return self._result(result, "create_relationship")

    def _read_target(self, api, entity_id: str):
        fields = "id entity_type parent_types objectLabel { id }"

        entity = api.stix_core_object.read(
            id=entity_id,
            customAttributes=fields,
        )

        if entity:
            parents = entity.get("parent_types") or []
            if "Stix-Cyber-Observable" in parents:
                return entity, "observable"
            if "Stix-Domain-Object" in parents:
                return entity, "domain"

        relationship = api.stix_core_relationship.read(
            id=entity_id,
            customAttributes=fields,
        )
        if relationship:
            return relationship, "relationship"

        raise ToolError(
            "ENTITY_NOT_FOUND",
            f"Unsupported or missing entity: {entity_id}",
        )

    @staticmethod
    def _get_label(
        api,
        label_name: str,
        create_if_missing: bool,
    ) -> dict:
        filters = filter_group(eq("value", [label_name]))
        label = api.label.read(filters=filters)
        if label is None and create_if_missing:
            label = api.label.create(value=label_name)

        if not label:
            raise ToolError(
                "LABEL_NOT_FOUND",
                "Label does not exist",
            )

        return label

    def _apply_label(
        self,
        api,
        entity_id: str,
        label_id: str,
    ) -> dict:
        target, kind = self._read_target(api, entity_id)

        existing_labels = {
            item["id"]
            for item in (target.get("objectLabel") or [])
        }
        if label_id in existing_labels:
            return {
                "id": entity_id,
                "status": "already_exists",
            }

        handlers = {
            "observable": api.stix_cyber_observable,
            "domain": api.stix_domain_object,
            "relationship": api.stix_core_relationship,
        }

        success = handlers[kind].add_label(
            id=entity_id,
            label_id=label_id,
        )

        if success is not True:
            raise ToolError(
                "LABEL_FAILED",
                "OpenCTI did not confirm label assignment",
            )

        logger.info(
            "opencti_write operation=add_label entity_id=%s",
            entity_id,
        )
        return {"id": entity_id, "status": "applied"}

    def add_label(
        self,
        entity_id: str,
        label_name: str,
        create_if_missing: bool = False,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict:
        entity_id = self._validate_id(entity_id)
        label_name = self._validate_text(label_name, 80)
        self._authorize(dry_run, confirm)

        if dry_run:
            return {
                "status": "dry_run",
                "operation": "add_label",
                "entity_id": entity_id,
                "label_name": label_name,
            }

        api = self.factory.create()
        target, _ = self._read_target(api, entity_id)
        label = self._get_label(
            api, label_name, create_if_missing
        )
        return self._apply_label(
            api, entity_id, label["id"]
        )

    def bulk_label_entities(
        self,
        entity_ids: list[str],
        label_name: str,
        create_if_missing: bool = False,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict:
        if not 1 <= len(entity_ids) <= self.policy.max_bulk:
            raise ToolError("BATCH_LIMIT", "Invalid bulk write size")
        entity_ids = list(dict.fromkeys(self._validate_id(item) for item in entity_ids))
        label_name = self._validate_text(label_name, 80)
        self._authorize(dry_run, confirm)
        if dry_run:
            return {"status": "dry_run", "entity_ids": entity_ids, "label_name": label_name}

        api = self.factory.create()
        for entity_id in entity_ids:
            self._read_target(api, entity_id)
        label = self._get_label(api, label_name, create_if_missing)
        results = []
        for entity_id in entity_ids:
            try:
                results.append(self._apply_label(api, entity_id, label["id"]))
            except Exception:
                logger.error("Bulk label failed for entity_id=%s", entity_id)
                results.append({"id": entity_id, "status": "failed"})
        return {"items": results, "complete": all(item["status"] != "failed" for item in results)}
