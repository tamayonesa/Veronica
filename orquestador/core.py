"""
core.py - Núcleo del orquestador OSINT.

Contiene:
  * Selector  -> dato de entrada (nombre, email, username, teléfono, dominio).
  * Entity    -> entidad relacionada descubierta (alimenta el grafo y los "pivotes").
  * Finding   -> hallazgo individual producido por un módulo.
  * Module    -> clase base que deben extender todos los módulos/plugins.
  * Context   -> recursos compartidos (cliente HTTP, claves, configuración).
  * Orchestrator -> ejecuta los módulos en paralelo y "pivota" sobre lo descubierto.

Idea central: cada módulo recibe UN selector y devuelve hallazgos. Si un hallazgo
incluye una Entity marcada como pivot=True (p. ej. un email nuevo encontrado en GitHub),
el orquestador la convierte en un nuevo selector y la procesa en la siguiente "ronda".
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("osint")

# --------------------------------------------------------------------------- #
# Selectores y validación
# --------------------------------------------------------------------------- #
SELECTOR_KINDS = ("name", "email", "username", "phone", "domain")

_RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$")
_RE_DOMAIN = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")
_RE_USER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RE_PHONE = re.compile(r"^\+[1-9]\d{6,14}$")


class InvalidSelector(ValueError):
    """El valor no es válido para el tipo indicado."""


def normalize_selector_value(kind: str, value: str, default_region: str | None = None) -> str:
    """Normaliza y valida un valor. Lanza InvalidSelector si no es aceptable.

    Importante para la seguridad: los valores acaban como argumentos de herramientas
    externas, así que se rechaza cualquier cosa que empiece por '-' o contenga espacios
    de control (evita inyección de argumentos).
    """
    value = (value or "").strip()
    if not value:
        raise InvalidSelector(f"{kind}: valor vacío")
    if kind == "email":
        value = value.lower()
        if not _RE_EMAIL.match(value):
            raise InvalidSelector(f"email no válido: {value!r}")
    elif kind == "domain":
        value = value.lower().rstrip(".")
        value = re.sub(r"^https?://", "", value).split("/")[0]
        if not _RE_DOMAIN.match(value):
            raise InvalidSelector(f"dominio no válido: {value!r}")
    elif kind == "username":
        value = value.lstrip("@")
        if not _RE_USER.match(value):
            raise InvalidSelector(f"username no válido: {value!r} (usa letras, números, . _ -)")
    elif kind == "phone":
        from .modules.phone import to_e164  # import tardío para evitar ciclos
        value = to_e164(value, default_region)
        if not _RE_PHONE.match(value):
            raise InvalidSelector(f"teléfono no válido: {value!r} (usa formato +34600000000)")
    elif kind == "name":
        value = re.sub(r"\s+", " ", value)
        if len(value) < 3 or len(value) > 100 or value.startswith("-") or re.search(r"[\x00-\x1f]", value):
            raise InvalidSelector(f"nombre no válido: {value!r}")
    else:
        raise InvalidSelector(f"tipo de selector desconocido: {kind}")
    return value


@dataclass(frozen=True)
class Selector:
    """Dato de entrada. `guess`/`depth` no cuentan para la igualdad (dos selectores
    con el mismo tipo y valor son el mismo aunque se hayan descubierto de forma distinta)."""
    kind: str
    value: str
    guess: bool = field(default=False, compare=False)   # ¿deducido y no confirmado?
    depth: int = field(default=0, compare=False)        # 0 = dato original del usuario
    origin: str = field(default="usuario", compare=False)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value.lower()}"

    def __str__(self) -> str:
        return self.key


@dataclass
class Entity:
    """Entidad relacionada con un selector (nodo del grafo).

    pivot=True  -> el orquestador la investigará como un nuevo selector (si su tipo lo permite).
    guess=True  -> es una suposición (p. ej. variaciones de nombre de usuario); solo se
                   investiga si el usuario activó --guess.
    """
    kind: str            # email, username, domain, account, breach, ip, name, location, company, url...
    value: str
    relation: str        # texto de la arista: "tiene cuenta en", "expuesto en", "resuelve a"...
    pivot: bool = False
    guess: bool = False
    label: str | None = None


@dataclass
class Finding:
    """Un hallazgo concreto producido por un módulo."""
    module: str
    kind: str                         # breach, account, dns_record, whois, subdomain, profile, lead, info...
    title: str
    selector: Selector
    data: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5           # 0..1
    url: str | None = None
    entities: list[Entity] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        return {
            "module": self.module, "kind": self.kind, "title": self.title,
            "selector": self.selector.key, "confidence": round(self.confidence, 2),
            "url": self.url, "data": self.data, "timestamp": self.timestamp,
            "entities": [e.__dict__ for e in self.entities],
        }


# --------------------------------------------------------------------------- #
# Contexto y clase base de módulos
# --------------------------------------------------------------------------- #
@dataclass
class Context:
    """Recursos compartidos por todos los módulos."""
    http: Any                                   # orquestador.http.HttpClient
    config: dict = field(default_factory=dict)  # config.json (claves, herramientas externas...)
    allow_guesses: bool = False

    def key(self, name: str) -> str | None:
        """Devuelve una clave de API desde config.json ("keys") o variable de entorno."""
        return (self.config.get("keys", {}) or {}).get(name) or os.environ.get(name)


class Module:
    """Clase base. Para crear un módulo nuevo basta con heredar y definir `run`.

        class MiModulo(Module):
            name = "mi_modulo"
            description = "Qué hace"
            accepts = ("email",)
            def run(self, selector): return [Finding(...)]
    """
    name: str = ""
    description: str = ""
    accepts: tuple[str, ...] = ()
    external: bool = False          # True si depende de una herramienta de terceros

    def __init__(self, ctx: Context):
        self.ctx = ctx

    def available(self) -> tuple[bool, str]:
        """(disponible, motivo). Un módulo no disponible se omite con un aviso."""
        return True, ""

    def run(self, selector: Selector) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError

    # Atajo para crear hallazgos sin repetir el nombre del módulo.
    def finding(self, selector: Selector, kind: str, title: str, **kw) -> Finding:
        return Finding(module=self.name, kind=kind, title=title, selector=selector, **kw)


# --------------------------------------------------------------------------- #
# Resultado de un escaneo
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    seeds: list[Selector]
    findings: list[Finding] = field(default_factory=list)
    selectors: list[Selector] = field(default_factory=list)       # todos los investigados
    module_status: dict[str, dict] = field(default_factory=dict)  # estadísticas por módulo
    errors: list[dict] = field(default_factory=list)
    started: str = ""
    finished: str = ""
    graph: Any = None            # orquestador.graph.Graph (se rellena al final)
    correlations: list[dict] = field(default_factory=list)
    profiles: list[dict] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Orquestador
# --------------------------------------------------------------------------- #
class Orchestrator:
    def __init__(self, modules: list[Module], ctx: Context, *, max_depth: int = 2,
                 workers: int = 6, max_selectors: int = 40, progress=None):
        self.modules = modules
        self.ctx = ctx
        self.max_depth = max_depth
        self.workers = workers
        self.max_selectors = max_selectors
        self.progress = progress or (lambda msg: None)
        self._lock = threading.Lock()

    # -- ejecución de un (módulo, selector) ---------------------------------- #
    def _run_one(self, module: Module, selector: Selector):
        t0 = time.time()
        try:
            found = module.run(selector) or []
            return module, selector, found, None, time.time() - t0
        except Exception as exc:  # un módulo roto nunca debe tumbar el escaneo
            log.debug("fallo en %s", module.name, exc_info=True)
            return module, selector, [], f"{type(exc).__name__}: {exc}", time.time() - t0

    def run(self, seeds: list[Selector]) -> ScanResult:
        res = ScanResult(seeds=list(seeds), started=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        # Estado de cada módulo (disponibilidad comprobada una sola vez)
        usable: list[Module] = []
        for m in self.modules:
            ok, why = m.available()
            res.module_status[m.name] = {"description": m.description, "status": "ok" if ok else "omitido",
                                         "reason": why, "selectors": 0, "findings": 0,
                                         "external": m.external, "errors": 0}
            if ok:
                usable.append(m)
            else:
                self.progress(f"[-] {m.name} omitido: {why}")

        seen: set[Selector] = set()
        level: list[Selector] = []
        for s in seeds:
            if s not in seen:
                seen.add(s)
                level.append(s)

        depth = 0
        while level:
            res.selectors.extend(level)
            jobs = [(m, s) for s in level for m in usable if s.kind in m.accepts]
            self.progress(f"[*] Ronda {depth}: {len(level)} selector(es), {len(jobs)} tarea(s)")
            next_level: list[Selector] = []
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                futures = [pool.submit(self._run_one, m, s) for m, s in jobs]
                for fut in as_completed(futures):
                    module, sel, found, err, dt = fut.result()
                    st = res.module_status[module.name]
                    st["selectors"] += 1
                    if err:
                        st["errors"] += 1
                        res.errors.append({"module": module.name, "selector": sel.key, "error": err})
                        self.progress(f"[!] {module.name}({sel.value}): {err}")
                        continue
                    st["findings"] += len(found)
                    res.findings.extend(found)
                    self.progress(f"[+] {module.name}({sel.value}): {len(found)} hallazgo(s) en {dt:.1f}s")
                    # --- pivotes: nuevas entidades → nuevos selectores ---------------
                    if depth >= self.max_depth:
                        continue
                    for f in found:
                        for e in f.entities:
                            if not e.pivot or e.kind not in SELECTOR_KINDS:
                                continue
                            if e.guess and not self.ctx.allow_guesses:
                                continue
                            try:
                                val = normalize_selector_value(e.kind, e.value)
                            except InvalidSelector:
                                continue
                            ns = Selector(e.kind, val, guess=e.guess or sel.guess,
                                          depth=depth + 1, origin=f"{module.name}({sel.value})")
                            if ns in seen or len(seen) >= self.max_selectors:
                                continue
                            seen.add(ns)
                            next_level.append(ns)
            level = next_level
            depth += 1

        res.finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return res


def strip_accents(text: str) -> str:
    """'Lucía Marín' -> 'Lucia Marin' (para generar usernames/emails)."""
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
