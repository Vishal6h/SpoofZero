"""Bounded HTTP requests, classified failures, retries, and an in-memory TTL cache."""
from collections import OrderedDict
from copy import deepcopy
from hashlib import sha256
import json
import socket
from threading import RLock, Semaphore
import time
import urllib.error
import urllib.request
from .observability import log_event

SUCCESS, UNAVAILABLE, TIMEOUT = "SUCCESS", "UNAVAILABLE", "TIMEOUT"
RATE_LIMITED, NOT_FOUND, ERROR, SKIPPED = "RATE_LIMITED", "NOT_FOUND", "ERROR", "SKIPPED"
FAILURE_STATUSES = frozenset({UNAVAILABLE, TIMEOUT, RATE_LIMITED, ERROR})
MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_HTTP_ATTEMPTS = 2
HTTP_CONCURRENCY = 4
_HTTP_SLOTS = Semaphore(HTTP_CONCURRENCY)

def service_result(status, message=None, **fields):
    result = {
        "status": {SUCCESS: "success", NOT_FOUND: "not_found", SKIPPED: "skipped"}.get(status, "error"),
        "service_status": status,
    }
    if status != SUCCESS:
        result["verdict"] = "UNKNOWN"
    if message:
        result["message"] = message
    result.update(fields)
    return result

class TTLCache:
    """Thread-safe, bounded, process-local cache. Keys are SHA-256 digests."""
    def __init__(self, max_entries=512, clock=None):
        if max_entries < 1:
            raise ValueError("Cache size must be positive")
        self.max_entries = max_entries
        self.clock = clock or time.monotonic
        self._items = OrderedDict()
        self._lock = RLock()
        self.hits = self.misses = self.expirations = 0

    @staticmethod
    def _key(value):
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
        return sha256(data).hexdigest()

    def get(self, key):
        digest = self._key(key)
        with self._lock:
            item = self._items.get(digest)
            if item is None:
                self.misses += 1
                return None
            expires, value = item
            if expires <= self.clock():
                self._items.pop(digest, None)
                self.expirations += 1
                self.misses += 1
                return None
            self._items.move_to_end(digest)
            self.hits += 1
            return deepcopy(value)

    def set(self, key, value, ttl_seconds):
        if ttl_seconds <= 0:
            return
        digest = self._key(key)
        with self._lock:
            self._items[digest] = (self.clock() + ttl_seconds, deepcopy(value))
            self._items.move_to_end(digest)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def clear(self):
        with self._lock:
            self._items.clear()
            self.hits = self.misses = self.expirations = 0

    def stats(self):
        with self._lock:
            return {"entries": len(self._items), "hits": self.hits, "misses": self.misses,
                    "expirations": self.expirations, "max_entries": self.max_entries}

def _read_json_response(response):
    payload = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
    if len(payload) > MAX_HTTP_RESPONSE_BYTES:
        return service_result(ERROR, "External service response exceeded the safe size limit.",
                              error_type="RESPONSE_TOO_LARGE")
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return service_result(ERROR, "External service returned malformed JSON.",
                              error_type="MALFORMED_RESPONSE")
    if not isinstance(data, dict):
        return service_result(ERROR, "External service returned an unexpected response shape.",
                              error_type="MALFORMED_RESPONSE")
    return service_result(SUCCESS, data=data)

def _http_error(error):
    code = int(error.code)
    if code == 429:
        return service_result(RATE_LIMITED, "External service rate limit reached.", http_status=code)
    if code == 404:
        return service_result(NOT_FOUND, "Requested intelligence record was not found.", http_status=code)
    if code in {401, 403}:
        return service_result(ERROR, "External service authorization was rejected.",
                              http_status=code, error_type="AUTHORIZATION")
    return service_result(ERROR, "External service returned an HTTP error.",
                          http_status=code, error_type="HTTP")

def request_json(service, url, *, headers=None, timeout=10, cache=None,
                 cache_key=None, ttl_seconds=300, failure_ttl_seconds=20,
                 max_attempts=MAX_HTTP_ATTEMPTS, opener=None, sleep=None):
    """Never return/log exception text, endpoints, auth headers, or response bodies."""
    if not 1 <= max_attempts <= MAX_HTTP_ATTEMPTS:
        raise ValueError(f"HTTP attempts must be between 1 and {MAX_HTTP_ATTEMPTS}")
    started = time.perf_counter()
    key = (service, cache_key if cache_key is not None else url)
    if cache is not None:
        cached = cache.get(key)
        if cached is not None:
            cached.update(cache_hit=True, attempts=0)
            log_event("external_request", analyzer=service,
                      duration_ms=(time.perf_counter() - started) * 1000,
                      service_status=cached.get("service_status"), cache_hit=True, attempts=0)
            return cached
    opener, sleep = opener or urllib.request.urlopen, sleep or time.sleep
    result, attempts = None, 0
    for attempt in range(1, max_attempts + 1):
        attempts = attempt
        request = urllib.request.Request(url, headers=headers or {})
        retryable = False
        try:
            with _HTTP_SLOTS:
                with opener(request, timeout=timeout) as response:
                    result = _read_json_response(response)
        except urllib.error.HTTPError as error:
            try:
                result = _http_error(error)
                retryable = 500 <= int(error.code) <= 599
            finally:
                error.close()
        except (TimeoutError, socket.timeout):
            result = service_result(TIMEOUT, "External service request timed out.")
            retryable = True
        except urllib.error.URLError as error:
            status = TIMEOUT if isinstance(error.reason, (TimeoutError, socket.timeout)) else UNAVAILABLE
            result = service_result(status, "External service is unavailable or timed out.")
            retryable = True
        except (ConnectionError, OSError):
            result = service_result(UNAVAILABLE, "External service is unavailable.")
            retryable = True
        except Exception:
            result = service_result(ERROR, "External service request failed.")
        if not retryable or attempt == max_attempts:
            break
        sleep(0.2 * (2 ** (attempt - 1)))
    result = result or service_result(ERROR, "External service request failed.")
    result.update(cache_hit=False, attempts=attempts)
    if cache is not None:
        ttl = ttl_seconds if result.get("service_status") in {SUCCESS, NOT_FOUND} else failure_ttl_seconds
        cache.set(key, result, ttl)
    log_event("external_request", analyzer=service,
              duration_ms=(time.perf_counter() - started) * 1000,
              service_status=result.get("service_status"), cache_hit=False, attempts=attempts)
    return result
