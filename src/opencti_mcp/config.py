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
