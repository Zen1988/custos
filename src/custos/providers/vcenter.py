"""Read-only vCenter REST adapter. No credentials or tickets reach the UI."""
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import requests


class VCenterError(Exception):
    """Sanitized provider failure suitable for operator output."""


@dataclass(frozen=True)
class VCenterConfig:
    url: str
    username: str
    password: str = field(repr=False)
    ca_bundle: str | None = None
    timeout: float = 15

    def __post_init__(self):
        parsed = urlsplit(self.url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment):
            raise ValueError("vCenter URL must be an HTTPS origin without credentials or a path")
        if not self.username or not self.password or not 0 < self.timeout <= 120:
            raise ValueError("Credentials and a timeout between 0 and 120 seconds are required")


@dataclass(frozen=True)
class VirtualMachine:
    id: str
    name: str
    power_state: str
    cpu_count: int
    memory_mib: int


class VCenterClient:
    def __init__(self, config: VCenterConfig):
        self.config = config
        self._session = requests.Session()
        # Do not inherit proxy settings or .netrc credentials for management traffic.
        self._session.trust_env = False

    def _request(self, method, path, **kwargs):
        try:
            response = self._session.request(
                method, self.config.url.rstrip("/") + path,
                timeout=self.config.timeout, verify=self.config.ca_bundle or True,
                allow_redirects=False, **kwargs,
            )
        except requests.RequestException:
            raise VCenterError("vCenter connection failed; check network, CA trust and hostname") from None
        if not 200 <= response.status_code < 300:
            messages = {401: "vCenter authentication failed or session expired",
                        403: "vCenter account lacks the required permission"}
            raise VCenterError(messages.get(response.status_code,
                               f"vCenter returned HTTP {response.status_code}"))
        return response

    def __enter__(self):
        try:
            response = self._request("POST", "/api/session",
                                     auth=(self.config.username, self.config.password))
            token = response.json()
            if not isinstance(token, str) or not token:
                raise ValueError()
            self._session.headers["vmware-api-session-id"] = token
            return self
        except (ValueError, requests.exceptions.JSONDecodeError):
            self._session.close()
            raise VCenterError("vCenter returned an invalid session response") from None
        except Exception:
            self._session.close()
            raise

    def __exit__(self, exc_type, exc, traceback):
        try:
            self._request("DELETE", "/api/session")
        except VCenterError:
            if exc_type is None:
                raise
        finally:
            self._session.headers.pop("vmware-api-session-id", None)
            self._session.close()

    def list_vms(self):
        try:
            rows = self._request("GET", "/api/vcenter/vm").json()
            if not isinstance(rows, list):
                raise ValueError()
            return [VirtualMachine(id=row["vm"], name=row["name"],
                                   power_state=row["power_state"],
                                   cpu_count=row["cpu_count"],
                                   memory_mib=(row["memory_size_MiB"] if "memory_size_MiB" in row
                                               else row["memory_size_mib"]))
                    for row in rows]
        except (ValueError, KeyError, TypeError):
            raise VCenterError("vCenter returned an invalid VM inventory response") from None
