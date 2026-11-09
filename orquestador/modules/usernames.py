"""
usernames.py - Comprueba si un nombre de usuario existe en plataformas públicas.

Cada sitio de data/sites.json define una URL con '{}' y una forma de decidir si el perfil existe:
  * "status"         -> 200 = existe; 404 = no existe; otro código = desconocido.
  * "message_absent" -> existe salvo que el cuerpo sea exactamente el texto de "absent".

Limitación honesta: sitios como Instagram, X o Facebook exigen JavaScript/login y no se pueden
verificar sin herramientas más pesadas. Para eso está la integración con Sherlock
(modules/external.py).
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..core import Entity, Module, Selector

SITES_FILE = Path(__file__).resolve().parent.parent / "data" / "sites.json"


class UsernamesModule(Module):
    name = "usernames"
    description = "Busca el username en 18 plataformas públicas (código, foros, ajedrez, blogs...)"
    accepts = ("username",)

    def __init__(self, ctx):
        super().__init__(ctx)
        self.sites = json.loads(SITES_FILE.read_text(encoding="utf-8"))
        # Se pueden añadir sitios propios en config.json -> "extra_sites"
        self.sites += ctx.config.get("extra_sites", [])

    def _check(self, site: dict, user: str):
        r = self.ctx.http.get(site["url"].format(user))
        kind = site.get("type", "status")
        if r.status == 0:
            return "error"
        if kind == "message_absent":
            if not r.ok:
                return "no" if r.status == 404 else "desconocido"
            return "no" if r.text.strip() == site.get("absent", "null") else "si"
        if r.status == 200:
            return "si"
        if r.status == 404:
            return "no"
        return "desconocido"      # 403/429/5xx: bloqueo o límite de peticiones

    def run(self, sel: Selector):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda s: (s, self._check(s, sel.value)), self.sites))

        found = [s for s, st in results if st == "si"]
        unknown = [s["name"] for s, st in results if st in ("desconocido", "error")]
        out = []
        # Un username "deducido" (guess) da menos confianza: puede ser otra persona distinta.
        base_conf = 0.35 if sel.guess else 0.6
        for site in found:
            url = site["profile"].format(sel.value)
            out.append(self.finding(
                sel, "account", f"Cuenta en {site['name']}", url=url, confidence=base_conf,
                data={"plataforma": site["name"], "username": sel.value},
                entities=[Entity("account", f"{site['name']}:{sel.value}", "tiene cuenta en",
                                 label=f"{site['name']}: {sel.value}")]))
        out.append(self.finding(
            sel, "info", f"Resumen de usernames: {len(found)} de {len(self.sites)} plataformas",
            confidence=1.0,
            data={"encontrado_en": [s["name"] for s in found], "comprobadas": len(self.sites),
                  "sin_respuesta_fiable": unknown}))
        return out
