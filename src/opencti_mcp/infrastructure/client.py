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
