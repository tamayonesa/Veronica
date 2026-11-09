"""
http.py - Cliente HTTP mínimo (solo librería estándar) usado por todos los módulos.

Características:
  * Pausa mínima por host (cortesía y para evitar bloqueos).
  * Caché en memoria durante el escaneo (no repite peticiones idénticas).
  * No lanza excepción en errores HTTP (404, 403...): devuelve la respuesta, porque
    para OSINT un 404 suele ser información ("el usuario no existe").
  * Modo demo: si se pasa `fixtures`, NO se sale a Internet; las respuestas salen de un
    fichero JSON con reglas {"match": regex, "status": 200, "json"|"text": ...}.
"""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_UA = "Mozilla/5.0 (compatible; OSINT-Orquestador/1.0; +uso-educativo)"


@dataclass
class Response:
    status: int
    text: str = ""
    url: str = ""
    headers: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self):
        try:
            return json.loads(self.text)
        except (ValueError, TypeError):
            return None


class HttpClient:
    def __init__(self, timeout: float = 10, delay: float = 0.25, user_agent: str = DEFAULT_UA,
                 fixtures: list[dict] | None = None, max_bytes: int = 2_000_000):
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.max_bytes = max_bytes
        self.fixtures = fixtures
        self._cache: dict[tuple, Response] = {}
        self._last_call: dict[str, float] = {}
        self._host_locks: dict[str, threading.Lock] = {}
        self._glock = threading.Lock()
        self.requests_made = 0

    # -- utilidades --------------------------------------------------------- #
    def _host_lock(self, host: str) -> threading.Lock:
        with self._glock:
            return self._host_locks.setdefault(host, threading.Lock())

    def _fixture(self, url: str) -> Response:
        for rule in self.fixtures or []:
            if re.search(rule["match"], url):
                body = json.dumps(rule["json"]) if "json" in rule else rule.get("text", "")
                return Response(rule.get("status", 200), body, url)
        return Response(404, "", url)  # en demo, todo lo no definido "no existe"

    # -- API pública -------------------------------------------------------- #
    def get(self, url: str, headers: dict | None = None) -> Response:
        cache_key = (url, tuple(sorted((headers or {}).items())))
        with self._glock:
            if cache_key in self._cache:
                return self._cache[cache_key]

        if self.fixtures is not None:                       # modo demo / tests
            resp = self._fixture(url)
        else:
            host = urlsplit(url).netloc
            with self._host_lock(host):                     # una petición a la vez por host
                wait = self.delay - (time.time() - self._last_call.get(host, 0))
                if wait > 0:
                    time.sleep(wait)
                resp = self._do_request(url, headers)
                self._last_call[host] = time.time()
        with self._glock:
            self.requests_made += 1
            self._cache[cache_key] = resp
        return resp

    def get_json(self, url: str, headers: dict | None = None):
        """Devuelve (respuesta, json|None)."""
        r = self.get(url, headers)
        return r, r.json()

    def _do_request(self, url: str, headers: dict | None) -> Response:
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent,
                                                   "Accept": "application/json, text/html;q=0.8, */*;q=0.5",
                                                   **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(self.max_bytes).decode(r.headers.get_content_charset() or "utf-8", "replace")
                return Response(r.status, body, r.geturl(), dict(r.headers))
        except urllib.error.HTTPError as e:                 # 4xx/5xx: devolvemos la respuesta
            try:
                body = e.read(self.max_bytes).decode("utf-8", "replace")
            except Exception:
                body = ""
            return Response(e.code, body, url, dict(e.headers or {}))
        except Exception as e:                              # DNS, timeout, TLS...
            return Response(0, f"{type(e).__name__}: {e}", url)
