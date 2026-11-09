"""
github.py - Información pública de GitHub.

  * username -> perfil (nombre, empresa, web, ubicación, bio) y emails que el usuario ha dejado
                en commits públicos (eventos PushEvent). Es una fuente clásica de correlación.
  * email    -> usuarios cuyo email público coincide (API de búsqueda).

Opcional: GITHUB_TOKEN sube el límite de peticiones (60/h sin token).
"""
from __future__ import annotations

from urllib.parse import quote

from ..core import Entity, Module, Selector

API = "https://api.github.com"


class GithubModule(Module):
    name = "github"
    description = "Perfil público de GitHub y emails expuestos en commits (por username o email)"
    accepts = ("username", "email")

    def _headers(self):
        h = {"Accept": "application/vnd.github+json"}
        tok = self.ctx.key("GITHUB_TOKEN")
        if tok:
            h["Authorization"] = f"Bearer {tok}"
        return h

    def run(self, sel: Selector):
        if sel.kind == "email":
            return self._by_email(sel)
        return self._by_username(sel)

    # -- email -> usuario ---------------------------------------------------- #
    def _by_email(self, sel):
        r, js = self.ctx.http.get_json(f"{API}/search/users?q={quote(sel.value)}+in:email", self._headers())
        if r.status in (403, 429):
            raise RuntimeError("límite de la API de GitHub alcanzado (usa GITHUB_TOKEN)")
        out = []
        for u in (js or {}).get("items", [])[:3]:
            out.append(self.finding(
                sel, "account", f"Usuario de GitHub con ese email: {u['login']}", url=u.get("html_url"),
                confidence=0.85, data={"login": u["login"]},
                entities=[Entity("username", u["login"], "usuario de GitHub", pivot=True),
                          Entity("account", f"GitHub:{u['login']}", "tiene cuenta en", label=f"GitHub: {u['login']}")]))
        return out

    # -- username -> perfil + emails de commits ------------------------------ #
    def _by_username(self, sel):
        r, u = self.ctx.http.get_json(f"{API}/users/{quote(sel.value)}", self._headers())
        if r.status == 404 or not u:
            return []
        if r.status in (403, 429):
            raise RuntimeError("límite de la API de GitHub alcanzado (usa GITHUB_TOKEN)")
        ents = [Entity("account", f"GitHub:{u['login']}", "tiene cuenta en", label=f"GitHub: {u['login']}")]
        data = {k: u.get(k) for k in ("name", "company", "blog", "location", "bio", "email", "twitter_username",
                                      "created_at", "public_repos", "followers") if u.get(k)}
        if u.get("name"):
            ents.append(Entity("name", u["name"], "nombre en GitHub"))
        if u.get("location"):
            ents.append(Entity("location", u["location"], "ubicación declarada"))
        if u.get("company"):
            ents.append(Entity("company", u["company"].lstrip("@"), "trabaja en"))
        if u.get("email"):
            ents.append(Entity("email", u["email"], "email público en GitHub", pivot=True))
        if u.get("twitter_username"):
            ents.append(Entity("username", u["twitter_username"], "usuario de X/Twitter enlazado",
                               pivot=True, label=f"X: {u['twitter_username']}"))
        blog = (u.get("blog") or "").strip()
        if blog:
            host = blog.replace("https://", "").replace("http://", "").split("/")[0].lower()
            ents.append(Entity("domain", host, "web personal", pivot=True))
        out = [self.finding(sel, "profile", f"Perfil de GitHub: {u['login']}", data=data, confidence=0.9,
                            url=u.get("html_url"), entities=ents)]

        # Emails en commits públicos (los noreply de GitHub no sirven)
        r2, events = self.ctx.http.get_json(f"{API}/users/{quote(sel.value)}/events/public", self._headers())
        emails: dict[str, int] = {}
        for ev in events if isinstance(events, list) else []:
            for c in (ev.get("payload") or {}).get("commits", []) or []:
                mail = ((c.get("author") or {}).get("email") or "").lower()
                if mail and "noreply" not in mail:
                    emails[mail] = emails.get(mail, 0) + 1
        if emails:
            out.append(self.finding(
                sel, "email_leak", f"{len(emails)} email(s) visibles en commits públicos",
                data={"emails": emails}, confidence=0.8, url=u.get("html_url"),
                entities=[Entity("email", m, "email usado en commits", pivot=True) for m in emails]))
        return out
