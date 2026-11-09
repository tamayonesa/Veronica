"""
external.py - Integración con herramientas de línea de comandos de terceros o propias.

Patrón: ejecutar el binario SIN shell (lista de argumentos), con tiempo máximo, y parsear su
salida a Findings. Incluye:

  * TheHarvesterModule -> `theHarvester -d <dominio> -b ... -f <fichero>` y parseo del JSON.
  * SherlockModule     -> `sherlock <username> --print-found` y parseo de líneas "[+] Sitio: URL".
  * GenericCommandModule -> cualquier herramienta definida en config.json ("external_tools"),
    con tres formas de parseo: "json" (contrato propio), "lines" y "regex".

Contrato "json" para scripts propios (stdout):
    [{"title": "...", "kind": "info", "data": {...}, "confidence": 0.7, "url": "...",
      "entities": [{"kind": "email", "value": "a@b.com", "relation": "encontrado", "pivot": true}]}]
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..core import Entity, Module, Selector


def run_command(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """Ejecuta un comando sin shell. Devuelve (código, stdout, stderr)."""
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)  # noqa: S603
    return p.returncode, p.stdout, p.stderr


class ExternalModule(Module):
    """Base para módulos que envuelven un binario externo."""
    external = True
    binary_names: tuple[str, ...] = ()
    config_key = ""          # clave en config["tools"] para fijar la ruta del binario

    def binary(self) -> str | None:
        custom = (self.ctx.config.get("tools", {}) or {}).get(self.config_key)
        if custom:
            return custom if (Path(custom).exists() or shutil.which(custom)) else None
        for n in self.binary_names:
            if shutil.which(n):
                return shutil.which(n)
        return None

    def available(self):
        if self.binary():
            return True, ""
        return False, f"herramienta no instalada ({'/'.join(self.binary_names)}); instálala o indica su ruta en config.json"


class TheHarvesterModule(ExternalModule):
    name = "theharvester"
    description = "Ejecuta theHarvester y recoge emails, hosts e IPs del dominio"
    accepts = ("domain",)
    binary_names = ("theHarvester", "theharvester")
    config_key = "theharvester"

    def run(self, sel: Selector):
        sources = self.ctx.config.get("theharvester_sources", "crtsh,hackertarget,rapiddns,otx")
        with tempfile.TemporaryDirectory() as tmp:
            outfile = str(Path(tmp) / "th")
            cmd = [self.binary(), "-d", sel.value, "-b", sources, "-l", "200", "-f", outfile]
            custom = self.ctx.config.get("tools", {}).get(self.config_key, "")
            if custom.endswith(".py"):                        # p. ej. el simulador de demo
                cmd = ["python3"] + cmd
            code, out, err = run_command(cmd, self.ctx.config.get("external_timeout", 300))
            jf = Path(outfile + ".json")
            if not jf.exists():
                raise RuntimeError(f"theHarvester no generó JSON (código {code}): {(err or out)[-200:]}")
            data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
        return self.parse(sel, data)

    def parse(self, sel: Selector, data: dict):
        emails = sorted({e.lower() for e in data.get("emails", [])})
        hosts, ips = set(), set(data.get("ips", []))
        for h in data.get("hosts", []):                       # "sub.dominio.com:1.2.3.4" o "sub.dominio.com"
            name, _, ip = str(h).partition(":")
            hosts.add(name.lower())
            if ip:
                ips.add(ip)
        ents = [Entity("email", e, "email encontrado por theHarvester", pivot=e.endswith("@" + sel.value))
                for e in emails]
        ents += [Entity("domain", h, "host de") for h in sorted(hosts)[:25]]
        ents += [Entity("ip", ip, "IP asociada") for ip in sorted(ips)[:15]]
        if not (emails or hosts or ips):
            return []
        return [self.finding(
            sel, "recon", f"theHarvester: {len(emails)} email(s), {len(hosts)} host(s), {len(ips)} IP(s)",
            data={"emails": emails, "hosts": sorted(hosts)[:60], "ips": sorted(ips)[:30]},
            confidence=0.7, entities=ents)]


class SherlockModule(ExternalModule):
    name = "sherlock"
    description = "Ejecuta Sherlock para buscar el username en cientos de redes sociales"
    accepts = ("username",)
    binary_names = ("sherlock",)
    config_key = "sherlock"
    LINE = re.compile(r"^\[\+\]\s+(.+?):\s+(https?://\S+)", re.M)

    def run(self, sel: Selector):
        cmd = [self.binary(), sel.value, "--print-found", "--timeout", "10", "--no-color"]
        code, out, err = run_command(cmd, self.ctx.config.get("external_timeout", 300))
        return self.parse(sel, out)

    def parse(self, sel: Selector, stdout: str):
        conf = 0.3 if sel.guess else 0.5     # Sherlock da falsos positivos: confianza media
        return [self.finding(sel, "account", f"Cuenta en {site} (Sherlock)", url=url, confidence=conf,
                             data={"plataforma": site, "username": sel.value},
                             entities=[Entity("account", f"{site}:{sel.value}", "tiene cuenta en",
                                              label=f"{site}: {sel.value}")])
                for site, url in self.LINE.findall(stdout)]


class GenericCommandModule(ExternalModule):
    """Módulo creado dinámicamente a partir de una entrada de config.json -> external_tools."""

    def __init__(self, ctx, spec: dict):
        super().__init__(ctx)
        self.spec = spec
        self.name = spec["name"]
        self.description = spec.get("description", f"Herramienta externa: {spec['command'][0]}")
        self.accepts = tuple(spec.get("accepts", ()))

    def available(self):
        exe = self.spec["command"][0]
        ok = Path(exe).exists() or shutil.which(exe)
        return (True, "") if ok else (False, f"no se encuentra el ejecutable {exe!r}")

    def run(self, sel: Selector):
        cmd = [part.replace("{value}", sel.value) for part in self.spec["command"]]
        code, out, err = run_command(cmd, self.spec.get("timeout", 120))
        mode = self.spec.get("parser", "lines")
        if mode == "json":
            return [self.finding(sel, f.get("kind", "info"), f.get("title", self.name), data=f.get("data", {}),
                                 confidence=float(f.get("confidence", 0.5)), url=f.get("url"),
                                 entities=[Entity(e["kind"], e["value"], e.get("relation", "relacionado"),
                                                  pivot=bool(e.get("pivot")), guess=bool(e.get("guess")))
                                           for e in f.get("entities", [])])
                    for f in json.loads(out or "[]")]
        if mode == "regex":
            kind = self.spec.get("entity_kind", "info")
            hits = sorted(set(re.findall(self.spec["regex"], out, re.M)))
            if not hits:
                return []
            ents = [Entity(kind, h if isinstance(h, str) else h[0], self.spec.get("relation", "encontrado"),
                           pivot=bool(self.spec.get("pivot"))) for h in hits]
            return [self.finding(sel, "recon", f"{self.name}: {len(hits)} resultado(s)", data={"resultados": hits[:100]},
                                 confidence=0.5, entities=ents)]
        lines = [l.strip() for l in out.splitlines() if l.strip()]       # modo "lines"
        return [self.finding(sel, "recon", f"{self.name}: {len(lines)} línea(s)",
                             data={"salida": lines[:200]}, confidence=0.4)] if lines else []
