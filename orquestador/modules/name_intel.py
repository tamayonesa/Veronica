"""
name_intel.py - A partir de un nombre completo genera pistas (no consulta Internet):

  * Candidatos de username (lucia.marin, lmarin, marinlucia...). Son SUPOSICIONES: solo se
    investigan si el usuario activa --guess, y sus resultados llevan menos confianza.
  * Candidatos de email para los dominios que el usuario haya indicado (solo se listan).
  * Enlaces de búsqueda manual ("dorks") para que el analista los revise.
"""
from __future__ import annotations

import re
from urllib.parse import quote_plus

from ..core import Entity, Module, Selector, strip_accents

PARTICLES = {"de", "del", "la", "las", "los", "y", "van", "von", "da", "di"}


def split_name(full: str) -> tuple[str, str]:
    """('Lucía Marín Ortega') -> ('lucia', 'marin'): primer nombre y primer apellido, sin tildes."""
    parts = [p for p in re.split(r"\s+", strip_accents(full).lower()) if p and p not in PARTICLES]
    parts = [re.sub(r"[^a-z0-9]", "", p) for p in parts]
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return (parts[0] if parts else ""), ""
    return parts[0], parts[1]


def username_candidates(full: str) -> list[str]:
    f, l = split_name(full)
    if not f or not l:
        return [f] if f else []
    cands = [f"{f}.{l}", f"{f}{l}", f"{f}_{l}", f"{f[0]}{l}", f"{f}{l[0]}", f"{l}{f}", f"{f[0]}.{l}", f"{l}.{f}"]
    return list(dict.fromkeys(cands))      # sin duplicados, conservando el orden


class NameIntelModule(Module):
    name = "name_intel"
    description = "Genera candidatos de username/email y enlaces de búsqueda manual a partir de un nombre"
    accepts = ("name",)

    def run(self, sel: Selector):
        cands = username_candidates(sel.value)
        out = []
        if cands:
            # Solo los 5 primeros se ofrecen como pivote para no disparar el número de peticiones.
            ents = [Entity("username", c, "posible username", pivot=True, guess=True) for c in cands[:5]]
            out.append(self.finding(sel, "guess", f"{len(cands)} posibles usernames derivados del nombre",
                                    data={"candidatos": cands, "nota": "Suposiciones sin confirmar"},
                                    confidence=0.2, entities=ents))

        # Candidatos de email para los dominios que el usuario ha pasado como dominio objetivo.
        f, l = split_name(sel.value)
        dominios = self.ctx.config.get("_seed_domains", [])
        if f and l and dominios:
            mails = [f"{p}@{d}" for d in dominios for p in (f"{f}.{l}", f"{f}{l}", f"{f[0]}{l}", f"{f}")]
            out.append(self.finding(sel, "guess", "Posibles emails corporativos (sin verificar)",
                                    data={"candidatos": mails}, confidence=0.2))

        q = quote_plus(f'"{strip_accents(sel.value)}"')
        out.append(self.finding(
            sel, "lead", "Enlaces de búsqueda manual", confidence=1.0,
            data={"google": f"https://www.google.com/search?q={q}",
                  "linkedin": f"https://www.google.com/search?q={q}+site%3Alinkedin.com%2Fin",
                  "github": f"https://github.com/search?q={q}&type=users",
                  "documentos": f"https://www.google.com/search?q={q}+filetype%3Apdf",
                  "noticias": f"https://news.google.com/search?q={q}"}))
        return out
