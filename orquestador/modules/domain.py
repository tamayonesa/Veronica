"""
domain.py - Módulos para dominios.

  * WhoisRdapModule -> registro del dominio vía RDAP (el sucesor JSON de WHOIS; sin clave).
  * DnsModule       -> registros A/AAAA/MX/NS/TXT + SPF/DMARC usando DNS-over-HTTPS (dns.google).
  * CrtshModule     -> subdominios que aparecen en certificados TLS públicos (crt.sh).

Todo con librería estándar: no se necesita `dig` ni `whois` instalados.
"""
from __future__ import annotations

from urllib.parse import quote

from ..core import Entity, Module, Selector

DNS_TYPES = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16}


class WhoisRdapModule(Module):
    name = "whois_rdap"
    description = "Datos de registro del dominio (registrador, fechas, servidores DNS, contactos) vía RDAP"
    accepts = ("domain",)

    @staticmethod
    def _vcard(entity: dict, field_name: str):
        """Extrae un campo (fn, email, org...) de un vCard RDAP."""
        for item in (entity.get("vcardArray") or [None, []])[1]:
            if item and item[0] == field_name:
                return item[3]
        return None

    def run(self, sel: Selector):
        r, js = self.ctx.http.get_json(f"https://rdap.org/domain/{quote(sel.value)}")
        if r.status == 404 or not js:
            return []
        if r.status != 200:
            raise RuntimeError(f"RDAP devolvió HTTP {r.status}")
        events = {e.get("eventAction"): e.get("eventDate") for e in js.get("events", [])}
        ns = sorted({n.get("ldhName", "").lower() for n in js.get("nameservers", []) if n.get("ldhName")})
        data = {"estado": js.get("status", []), "registrado": events.get("registration"),
                "expira": events.get("expiration"), "ultimo_cambio": events.get("last changed"),
                "servidores_dns": ns}
        ents = [Entity("nameserver", n, "usa servidor DNS") for n in ns]
        contactos = []
        for ent in js.get("entities", []):
            roles = ent.get("roles", [])
            nombre, email, org = self._vcard(ent, "fn"), self._vcard(ent, "email"), self._vcard(ent, "org")
            if "registrar" in roles and nombre:
                data["registrador"] = nombre
            elif nombre or email:
                contactos.append({"rol": roles, "nombre": nombre, "email": email, "organizacion": org})
                if nombre and "REDACTED" not in str(nombre).upper():
                    ents.append(Entity("name", nombre, f"contacto ({'/'.join(roles) or 'dominio'})"))
                if email and "@" in str(email):
                    ents.append(Entity("email", email, "contacto del dominio", pivot=True))
        if contactos:
            data["contactos"] = contactos
        # Dato clave para el analista: con RDAP moderno muchos contactos están ocultos por RGPD.
        data["nota"] = "Sin contactos visibles (probable redacción RGPD)" if not contactos else ""
        return [self.finding(sel, "whois", f"Registro RDAP de {sel.value}", data=data, confidence=0.9,
                             url=f"https://rdap.org/domain/{sel.value}", entities=ents)]


class DnsModule(Module):
    name = "dns_records"
    description = "Registros DNS (A, AAAA, MX, NS, TXT), SPF y DMARC mediante DNS-over-HTTPS"
    accepts = ("domain",)

    def _query(self, name: str, rtype: str) -> list[str]:
        r, js = self.ctx.http.get_json(f"https://dns.google/resolve?name={quote(name)}&type={rtype}")
        if r.status != 200 or not js:
            return []
        return [a.get("data", "").strip('"') for a in js.get("Answer", []) if a.get("type") == DNS_TYPES[rtype]]

    def run(self, sel: Selector):
        records = {t: self._query(sel.value, t) for t in DNS_TYPES}
        dmarc = self._query(f"_dmarc.{sel.value}", "TXT")
        if not any(records.values()):
            return []
        spf = [t for t in records["TXT"] if t.lower().startswith("v=spf1")]
        ents = [Entity("ip", ip, "resuelve a") for ip in records["A"] + records["AAAA"]]
        ents += [Entity("nameserver", ns.rstrip("."), "usa servidor DNS") for ns in records["NS"]]
        data = {**{k: v for k, v in records.items() if v}, "SPF": spf, "DMARC": dmarc,
                "observaciones": []}
        if not spf:
            data["observaciones"].append("Sin registro SPF: el dominio es más fácil de suplantar por email")
        if not dmarc:
            data["observaciones"].append("Sin registro DMARC")
        return [self.finding(sel, "dns_record", f"Registros DNS de {sel.value}", data=data,
                             confidence=0.95, entities=ents)]


class CrtshModule(Module):
    name = "crtsh"
    description = "Subdominios descubiertos en certificados TLS públicos (Certificate Transparency)"
    accepts = ("domain",)

    def run(self, sel: Selector):
        r, js = self.ctx.http.get_json(f"https://crt.sh/?q=%25.{quote(sel.value)}&output=json")
        if r.status != 200 or not isinstance(js, list):
            return []
        subs = set()
        for row in js:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(sel.value) and name != sel.value:
                    subs.add(name)
        if not subs:
            return []
        subs_sorted = sorted(subs)
        shown = subs_sorted[:60]            # el grafo y el informe no necesitan cientos de nodos
        return [self.finding(
            sel, "subdomain", f"{len(subs)} subdominio(s) en certificados públicos",
            data={"subdominios": shown, "total": len(subs), "truncado": len(subs) > len(shown)},
            confidence=0.8, url=f"https://crt.sh/?q={sel.value}",
            entities=[Entity("domain", s, "subdominio de") for s in shown[:25]])]
