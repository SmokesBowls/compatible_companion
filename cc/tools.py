import json
import urllib.request
import urllib.error
from datetime import datetime, timezone


class ToolGatewayError(Exception):
    """Raised when ToolGateway blocks a call due to allowlist violation."""
    def __init__(self, receipt: dict):
        self.receipt = receipt
        super().__init__(receipt['error'])


class ToolGateway:
    """
    Typed external tool call gateway with allowlist enforcement.

    The allowlist is a set of hostnames (no scheme, no path).
    Example: ['api.example.com', 'hooks.slack.com']

    Callers receive a tool_receipt dict on success.
    ToolGatewayError is raised (carrying a tool_receipt) on block.
    Network errors return a tool_receipt with error set.
    """

    def __init__(self, allowlist: list[str]):
        self._allowlist = frozenset(allowlist)

    def call(
        self,
        tool_name: str,
        host: str,
        path: str,
        method: str = 'GET',
        payload: dict = None,
    ) -> dict:
        """
        Make one external tool call.

        Returns a tool_receipt dict.
        Raises ToolGatewayError (with receipt) if host not in allowlist.
        """
        ts = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

        # ── ALLOWLIST CHECK (before any network I/O) ──────────────
        if host not in self._allowlist:
            receipt = {
                'tool_name': tool_name, 'host': host, 'path': path,
                'method': method, 'allowed': False,
                'network_call_made': False,  # guaranteed: no bytes sent
                'status_code': None, 'response_body': None, 'ts': ts,
                'error': f"host '{host}' not in tool_allowlist",
            }
            raise ToolGatewayError(receipt)

        # ── NETWORK CALL ──────────────────────────────────────────
        url = f'https://{host}{path}'
        body_bytes = json.dumps(payload or {}).encode() if payload else None
        req = urllib.request.Request(
            url, data=body_bytes, method=method,
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json'},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                response_body = resp.read().decode('utf-8', errors='replace')
                status_code   = resp.status
        except urllib.error.HTTPError as e:
            response_body = e.read().decode('utf-8', errors='replace')
            status_code   = e.code
            return {
                'tool_name': tool_name, 'host': host, 'path': path,
                'method': method, 'allowed': True,
                'network_call_made': True,
                'status_code': status_code, 'response_body': response_body,
                'ts': ts, 'error': f'HTTP {status_code}',
            }
        except Exception as exc:
            return {
                'tool_name': tool_name, 'host': host, 'path': path,
                'method': method, 'allowed': True,
                'network_call_made': True,   # attempt was made
                'status_code': None, 'response_body': None,
                'ts': ts, 'error': str(exc),
            }

        return {
            'tool_name': tool_name, 'host': host, 'path': path,
            'method': method, 'allowed': True,
            'network_call_made': True,
            'status_code': status_code, 'response_body': response_body,
            'ts': ts, 'error': None,
        }
