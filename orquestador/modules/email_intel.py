"""
email_intel.py - Módulos centrados en direcciones de email.

  * BreachesModule    -> brechas de datos (HaveIBeenPwned con clave, XposedOrNot sin clave).
  * EmailIntelModule  -> validación del dominio (MX), correo desechable y perfil Gravatar.
"""
from __future__ import annotations

import hashlib
from urllib.parse import quote

from ..core import Entity, Module, Selector

# Proveedores gratuitos: su dominio NO es interesante como pivote (gmail.com no es "de la persona").
FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.es", "live.com", "msn.com",
    "yahoo.com", "yahoo.es", "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com",
    "gmx.es", "aol.com", "mail.com", "yandex.com", "tutanota.com", "zoho.com", "telefonica.net",
}
DISPOSABLE = {"mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com", "yopmail.com",
              "trashmail.com", "sharklasers.com", "getnada.com", "maildrop.cc", "throwawaymail.com"}


class BreachesModule(Module):
    name = "breaches"
    description = "Brechas de datos donde aparece el email (HaveIBeenPwned y XposedOrNot)"
    accepts = ("email",)

    def run(self, sel: Selector):
        out = self._hibp(sel)
        seen = {f.title: f for f in out}
        for f in self._xposed(sel):
            if f.title in seen:                      # misma brecha en ambas fuentes: se corrobora, no se duplica
                seen[f.title].data["confirmada_por"] = ["HaveIBeenPwned", "XposedOrNot"]
                seen[f.title].confidence = min(0.95, seen[f.title].confidence + 0.1)
            else:
                out.append(f)
        return out

    # -- HaveIBeenPwned (requiere clave de pago: HIBP_API_KEY) --------------- #
    def _hibp(self, sel):
        key = self.ctx.key("HIBP_API_KEY")
        if not key:
            return []
        r = self.ctx.http.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(sel.value)}?truncateResponse=false",
            headers={"hibp-api-key": key})
        if r.status == 404:
            return []
        if r.status != 200:
            raise RuntimeError(f"HIBP devolvió HTTP {r.status}")
        out = []
        for b in r.json() or []:
            out.append(self.finding(
                sel, "breach", f"Brecha: {b.get('Name')}",
                data={"fuente": "HaveIBeenPwned", "fecha": b.get("BreachDate"), "dominio": b.get("Domain"),
                      "datos_expuestos": b.get("DataClasses", []), "cuentas_afectadas": b.get("PwnCount"),
                      "verificada": b.get("IsVerified")},
                confidence=0.9 if b.get("IsVerified") else 0.7,
                url=f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name')}",
                entities=[Entity("breach", b.get("Name", "?"), "expuesto en")]))
        return out

    # -- XposedOrNot (gratuito, sin clave) ----------------------------------- #
    def _xposed(self, sel):
        r = self.ctx.http.get(f"https://api.xposedornot.com/v1/check-email/{quote(sel.value)}")
        if r.status == 404:
            return []
        if r.status != 200:
            raise RuntimeError(f"XposedOrNot devolvió HTTP {r.status}")
        names: list[str] = []
        for item in (r.json() or {}).get("breaches", []):      # lista de listas de nombres
            names += item if isinstance(item, list) else [item]
        out = []
        for n in sorted(set(map(str, names))):
            out.append(self.finding(
                sel, "breach", f"Brecha: {n}", data={"fuente": "XposedOrNot"}, confidence=0.7,
                url="https://xposedornot.com/", entities=[Entity("breach", n, "expuesto en")]))
        return out


class EmailIntelModule(Module):
    name = "email_intel"
    description = "Validación del email: MX del dominio, correo desechable y perfil público de Gravatar"
    accepts = ("email",)

    def run(self, sel: Selector):
        out = []
        local, domain = sel.value.split("@", 1)

        # 1) Dominio del email: ¿tiene MX? ¿es desechable? ¿es un dominio propio (pivote)?
        r, js = self.ctx.http.get_json(f"https://dns.google/resolve?name={quote(domain)}&type=MX")
        mx = [a.get("data", "") for a in (js or {}).get("Answer", []) if a.get("type") == 15]
        is_free = domain in FREE_PROVIDERS
        ents = [Entity("domain", domain, "dominio del email", pivot=not is_free and domain not in DISPOSABLE)]
        out.append(self.finding(
            sel, "info", f"Dominio del email: {domain}",
            data={"tiene_mx": bool(mx), "mx": mx[:5], "proveedor_gratuito": is_free,
                  "desechable": domain in DISPOSABLE},
            confidence=0.8, entities=ents))

        # 2) Gravatar: el hash MD5 del email identifica el avatar; si hay perfil público, aporta
        #    nombre, usernames y cuentas enlazadas (fuente muy fiable de correlación).
        h = hashlib.md5(sel.value.encode()).hexdigest()  # noqa: S324 - lo exige Gravatar
        r, js = self.ctx.http.get_json(f"https://www.gravatar.com/{h}.json")
        if r.status == 200 and js and js.get("entry"):
            e = js["entry"][0]
            ents, data = [], {}
            if e.get("displayName"):
                data["nombre_visible"] = e["displayName"]
                ents.append(Entity("name", e["displayName"], "nombre en Gravatar"))
            full = (e.get("name") or {}).get("formatted")
            if full:
                data["nombre_completo"] = full
                ents.append(Entity("name", full, "nombre en Gravatar"))
            if e.get("preferredUsername"):
                data["username"] = e["preferredUsername"]
                ents.append(Entity("username", e["preferredUsername"], "username en Gravatar", pivot=True))
            if e.get("currentLocation"):
                data["ubicacion"] = e["currentLocation"]
                ents.append(Entity("location", e["currentLocation"], "ubicación declarada"))
            if e.get("aboutMe"):
                data["bio"] = e["aboutMe"][:300]
            cuentas = []
            for acc in e.get("accounts", []):
                cuentas.append({"red": acc.get("shortname"), "usuario": acc.get("username"), "url": acc.get("url")})
                ents.append(Entity("account", f"{acc.get('shortname')}:{acc.get('username')}", "cuenta enlazada",
                                   label=f"{acc.get('shortname')}: {acc.get('username')}"))
            if cuentas:
                data["cuentas_enlazadas"] = cuentas
            out.append(self.finding(sel, "profile", "Perfil público de Gravatar", data=data, confidence=0.85,
                                    url=e.get("profileUrl"), entities=ents))
        return out
