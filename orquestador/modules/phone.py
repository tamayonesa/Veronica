"""
phone.py - Análisis offline de números de teléfono (sin consultar ningún servicio).

Normaliza a formato E.164, deduce el país por el prefijo y, para España, el tipo de línea.
Añade enlaces de comprobación manual (WhatsApp, Telegram) para que el analista decida:
no se consultan automáticamente para no tocar a terceros sin necesidad.
"""
from __future__ import annotations

import re

from ..core import Entity, Module, Selector

# Prefijo internacional -> (país, región ISO). Tabla reducida; amplíala si la necesitas.
COUNTRY_CODES = {
    "1": ("EE. UU./Canadá", "US"), "7": ("Rusia/Kazajistán", "RU"), "20": ("Egipto", "EG"),
    "27": ("Sudáfrica", "ZA"), "30": ("Grecia", "GR"), "31": ("Países Bajos", "NL"), "32": ("Bélgica", "BE"),
    "33": ("Francia", "FR"), "34": ("España", "ES"), "351": ("Portugal", "PT"), "352": ("Luxemburgo", "LU"),
    "353": ("Irlanda", "IE"), "358": ("Finlandia", "FI"), "36": ("Hungría", "HU"), "39": ("Italia", "IT"),
    "40": ("Rumanía", "RO"), "41": ("Suiza", "CH"), "43": ("Austria", "AT"), "44": ("Reino Unido", "GB"),
    "45": ("Dinamarca", "DK"), "46": ("Suecia", "SE"), "47": ("Noruega", "NO"), "48": ("Polonia", "PL"),
    "49": ("Alemania", "DE"), "52": ("México", "MX"), "54": ("Argentina", "AR"), "55": ("Brasil", "BR"),
    "56": ("Chile", "CL"), "57": ("Colombia", "CO"), "58": ("Venezuela", "VE"), "51": ("Perú", "PE"),
    "61": ("Australia", "AU"), "81": ("Japón", "JP"), "82": ("Corea del Sur", "KR"), "86": ("China", "CN"),
    "90": ("Turquía", "TR"), "91": ("India", "IN"), "212": ("Marruecos", "MA"), "213": ("Argelia", "DZ"),
}
REGION_TO_CODE = {v[1]: k for k, v in COUNTRY_CODES.items()}


def to_e164(raw: str, default_region: str | None = None) -> str:
    """'+34 600 00 00 01' / '0034600000001' / '600000001' (con región ES) -> '+34600000001'."""
    s = re.sub(r"[\s().-]", "", raw or "")
    if s.startswith("00"):
        s = "+" + s[2:]
    if not s.startswith("+"):
        code = REGION_TO_CODE.get((default_region or "").upper())
        if code:
            s = f"+{code}{s.lstrip('0')}"
    return s


def split_country(e164: str):
    digits = e164.lstrip("+")
    for n in (3, 2, 1):                       # los prefijos más largos primero
        if digits[:n] in COUNTRY_CODES:
            return digits[:n], COUNTRY_CODES[digits[:n]], digits[n:]
    return None, None, digits


class PhoneModule(Module):
    name = "phone_info"
    description = "Normaliza el teléfono (E.164), deduce país/tipo de línea y genera enlaces de verificación manual"
    accepts = ("phone",)

    def run(self, sel: Selector):
        code, country, national = split_country(sel.value)
        data = {"e164": sel.value, "prefijo": f"+{code}" if code else "desconocido",
                "pais": country[0] if country else "desconocido", "numero_nacional": national}
        if code == "34" and len(national) == 9:      # plan de numeración español
            data["tipo_linea"] = {"6": "móvil", "7": "móvil", "8": "fijo", "9": "fijo"}.get(national[0], "otro")
        data["comprobacion_manual"] = {
            "whatsapp": f"https://wa.me/{sel.value.lstrip('+')}",
            "telegram": f"https://t.me/{sel.value}",
            "busqueda_web": f'https://www.google.com/search?q="{sel.value}"+OR+"{national}"',
        }
        return [self.finding(sel, "info", f"Análisis del teléfono {sel.value}", data=data, confidence=0.9,
                             entities=[Entity("location", data["pais"], "país del número")] if country else [])]
