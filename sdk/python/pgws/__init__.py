"""Synchronous PGWS client using only the Python standard library."""
from __future__ import annotations
import ipaddress
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

class Error(Exception):
    def __init__(self, status: int, body: dict):
        self.status = status
        self.code = body.get("code", "HTTP_ERROR")
        self.retryable = bool(body.get("retryable", False))
        self.body = body
        super().__init__(self.code)

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None

def _id(value: str) -> str:
    return str(uuid.UUID(value))

class Client:
    def __init__(self, url: str, project_id: str, token: str, timeout: float = 15):
        parsed = urllib.parse.urlsplit(url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
            raise ValueError("Invalid PGWS URL")
        if parsed.scheme != "https":
            try:
                local = ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                local = False
            if parsed.scheme != "http" or not local:
                raise ValueError("Use HTTPS or an explicit loopback HTTP address")
        if not token or timeout <= 0:
            raise ValueError("Token and positive timeout are required")
        self.url = url.rstrip("/") + "/v1/projects/" + _id(project_id)
        self._token, self.timeout = token, timeout
        self._opener = urllib.request.build_opener(_NoRedirect())

    def _request(self, method: str, path: str, body=None, key: str | None = None, timeout=None):
        if method != "GET" and (not key or len(key.encode()) > 200):
            raise ValueError("A stable idempotency key of 1 to 200 bytes is required")
        headers = {"Authorization": "Bearer " + self._token, "Content-Type": "application/json"}
        if key is not None:
            headers["Idempotency-Key"] = key
        payload = None if body is None else json.dumps(body, allow_nan=False).encode()
        if payload is not None and len(payload) > 1 << 20:
            raise ValueError("Request exceeds 1 MiB")
        request = urllib.request.Request(self.url + path, data=payload, headers=headers, method=method)
        try:
            response = self._opener.open(request, timeout=self.timeout if timeout is None else timeout)
        except urllib.error.HTTPError as response:
            with response:
                raw = response.read(2 << 20)
            try:
                error = json.loads(raw)
                if not isinstance(error, dict):
                    error = {}
            except (ValueError, UnicodeError):
                error = {}
            raise Error(response.code, error) from None
        with response:
            raw = response.read((2 << 20) + 1)
            if len(raw) > 2 << 20:
                raise ValueError("Response exceeds 2 MiB")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError("Response must be an object")
            return result

    def register_source(self, endpoint: str, secret: str, *, key: str):
        return self._request("POST", "/sources", {"connector": "physical", "approved_endpoint_reference": endpoint, "secret_reference": secret}, key)

    def source(self, source_id: str):
        return self._request("GET", "/sources/" + _id(source_id))

    def reseed_source(self, source_id: str, expected_source_epoch: int, *, key: str):
        if type(expected_source_epoch) is not int or not 1 <= expected_source_epoch < 1_000_000_000:
            raise ValueError("Source epoch must be a positive integer below one billion")
        return self._request("POST", "/sources/" + _id(source_id) + "/actions", {"action": "reseed", "expected_source_epoch": expected_source_epoch}, key)

    def baselines(self, *, cursor=None, limit=100):
        query = {"limit": limit}
        if cursor is not None:
            query["cursor"] = cursor
        return self._request("GET", "/baselines?" + urllib.parse.urlencode(query))

    def usage(self, *, cursor=None, limit=100):
        """Observed capacity gauges; decimal amounts remain strings."""
        query = {"limit": limit}
        if cursor is not None:
            query["cursor"] = cursor
        return self._request("GET", "/usage?" + urllib.parse.urlencode(query))

    def barrier(self, source_id: str, *, key: str):
        """Call only after the source transaction's commit has been acknowledged."""
        return self._request("POST", "/sources/" + _id(source_id) + "/barriers", {"after_commit_asserted": True}, key)

    def create(self, baseline_id: str, task_id: str, *, key: str, freshness=None, profile="small", ttl=3600):
        return self._request("POST", "/workspaces", {"baseline_id": _id(baseline_id), "task_id": task_id, "freshness": {"mode": "latest"} if freshness is None else freshness, "resource_profile": profile, "ttl_seconds": ttl}, key)

    def get(self, workspace_id: str):
        return self._request("GET", "/workspaces/" + _id(workspace_id))

    def action(self, workspace_id: str, action: dict, *, key: str):
        return self._request("POST", "/workspaces/" + _id(workspace_id) + "/actions", action, key)

    def credentials(self, workspace_id: str, generation: int, *, key: str, role="owner", ttl=900):
        return self._request("POST", "/workspaces/" + _id(workspace_id) + "/credentials", {"expected_generation": generation, "role": role, "ttl_seconds": ttl}, key)

    def delete(self, workspace_id: str, generation: int, *, key: str):
        if type(generation) is not int or generation < 1:
            raise ValueError("Generation must be a positive integer")
        return self._request("DELETE", "/workspaces/" + _id(workspace_id) + "?expected_generation=" + str(generation), key=key)

    def operation(self, operation_id: str):
        return self._request("GET", "/operations/" + _id(operation_id))

    def wait(self, operation_id: str, *, timeout=120, interval=0.25):
        if timeout <= 0 or interval <= 0:
            raise ValueError("Wait timeout and interval must be positive")
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Operation remains recorded; inspect it before retrying")
            result = self._request("GET", "/operations/" + _id(operation_id), timeout=min(self.timeout, remaining))
            if result["status"] == "succeeded":
                return result
            if result["status"] in ("failed", "cancelled"):
                raise Error(409, result.get("error") or {"code": "OPERATION_" + result["status"].upper()})
            if result["status"] not in ("queued", "running"):
                raise ValueError("Unknown operation status")
            time.sleep(min(interval, max(0, deadline - time.monotonic())))
