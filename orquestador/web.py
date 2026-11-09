"""
web.py - Interfaz web básica (solo librería estándar, sin dependencias).

  * Escucha por defecto SOLO en 127.0.0.1: la herramienta no debe exponerse en una red.
  * Formulario -> lanza el escaneo en un hilo -> página de progreso -> informe HTML.
  * Token aleatorio por arranque en el formulario (protege contra peticiones cruzadas
    desde otras páginas abiertas en tu navegador).
"""
from __future__ import annotations

import html
import json
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .core import SELECTOR_KINDS, InvalidSelector, Selector, normalize_selector_value
from .report import to_html, to_json_dict
from .runner import run_scan

JOBS: dict[str, dict] = {}
TOKEN = secrets.token_urlsafe(16)

PAGE = """<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>OSINT Orquestador</title>{refresh}
<style>
:root{{--bg:#edf0f3;--s:#fff;--ink:#17212b;--mut:#5b6b7a;--line:#d5dbe1;--acc:#0b6e99}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0e151c;--s:#16212b;--ink:#e6edf3;--mut:#9fb0bf;--line:#2a3a48;--acc:#5cb8e6}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif}}
main{{max-width:640px;margin:0 auto;padding:2rem 1.25rem}}
h1{{font-family:Georgia,serif;font-size:1.8rem;margin:.2rem 0 1rem}}
label{{display:block;margin:.9rem 0 .2rem;font-size:.9rem;color:var(--mut)}}
input[type=text]{{width:100%;padding:.55rem .7rem;border:1px solid var(--line);border-radius:5px;background:var(--s);color:var(--ink);font:inherit}}
input:focus-visible,button:focus-visible{{outline:2px solid var(--acc);outline-offset:2px}}
button{{margin-top:1.4rem;padding:.6rem 1.3rem;border:0;border-radius:5px;background:var(--acc);color:#fff;font:inherit;font-weight:600;cursor:pointer}}
.row{{display:flex;gap:1.2rem;align-items:center;margin-top:1rem;font-size:.92rem}}.note{{color:var(--mut);font-size:.88rem}}
pre{{background:var(--s);border:1px solid var(--line);padding:.8rem;border-radius:5px;overflow:auto;font-size:.85rem}}
</style></head><body><main>{body}</main></body></html>"""

FORM = """<h1>Huella digital</h1>
<p class="note">Rellena uno o varios datos. Usa la herramienta solo con tu información o con autorización expresa.</p>
<form method="post" action="/scan">
<input type="hidden" name="token" value="{token}">
<label for="name">Nombre completo</label><input type="text" id="name" name="name" autocomplete="off">
<label for="email">Email</label><input type="text" id="email" name="email" autocomplete="off">
<label for="username">Username</label><input type="text" id="username" name="username" autocomplete="off">
<label for="phone">Teléfono (+34600000000)</label><input type="text" id="phone" name="phone" autocomplete="off">
<label for="domain">Dominio</label><input type="text" id="domain" name="domain" autocomplete="off">
<div class="row"><label style="margin:0"><input type="checkbox" name="guess"> Investigar suposiciones</label>
{demo_box}</div>
<button type="submit">Buscar</button></form>"""


def serve(port: int, *, host: str = "127.0.0.1", config: dict, fixtures, plugin_dir: str | None) -> int:
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="text/html; charset=utf-8"):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):          # sin ruido en consola
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/":
                demo_box = '<span class="note">Modo demo</span>' if fixtures is not None else ""
                return self._send(200, PAGE.format(refresh="", body=FORM.format(token=TOKEN, demo_box=demo_box)))
            parts = path.strip("/").split("/")
            if len(parts) >= 2 and parts[0] == "job" and parts[1] in JOBS:
                job = JOBS[parts[1]]
                if len(parts) == 3 and parts[2] == "json" and job["res"]:
                    return self._send(200, json.dumps(to_json_dict(job["res"]), ensure_ascii=False, indent=2),
                                      "application/json; charset=utf-8")
                if job["res"]:
                    return self._send(200, to_html(job["res"]))
                log = html.escape("\n".join(job["log"][-25:]))
                msg = f"<h1>Investigando…</h1><p class='note'>Esta página se actualiza sola.</p><pre>{log}</pre>"
                if job.get("error"):
                    msg = f"<h1>Error</h1><pre>{html.escape(job['error'])}</pre><p><a href='/'>Volver</a></p>"
                    return self._send(200, PAGE.format(refresh="", body=msg))
                return self._send(200, PAGE.format(refresh='<meta http-equiv="refresh" content="2">', body=msg))
            self._send(404, "No encontrado", "text/plain; charset=utf-8")

        def do_POST(self):
            if urlsplit(self.path).path != "/scan":
                return self._send(404, "No encontrado", "text/plain; charset=utf-8")
            length = min(int(self.headers.get("Content-Length", 0) or 0), 20_000)
            form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode("utf-8", "replace")).items()}
            if form.get("token") != TOKEN:
                return self._send(403, "Token no válido", "text/plain; charset=utf-8")
            seeds, errors = [], []
            for kind in SELECTOR_KINDS:
                if form.get(kind, "").strip():
                    try:
                        seeds.append(Selector(kind, normalize_selector_value(kind, form[kind], "ES")))
                    except InvalidSelector as exc:
                        errors.append(str(exc))
            if errors or not seeds:
                msg = "<h1>Revisa los datos</h1><ul>" + "".join(f"<li>{html.escape(e)}</li>" for e in errors or ["No has indicado ningún dato."]) \
                      + "</ul><p><a href='/'>Volver</a></p>"
                return self._send(400, PAGE.format(refresh="", body=msg))
            jid = uuid.uuid4().hex[:12]
            JOBS[jid] = {"res": None, "log": [], "error": None}

            def work():
                try:
                    JOBS[jid]["res"] = run_scan(seeds, config=config, fixtures=fixtures, guess=bool(form.get("guess")),
                                                plugin_dir=plugin_dir, progress=JOBS[jid]["log"].append)
                except Exception as exc:     # mostrar el fallo en la página en vez de dejarla "cargando"
                    JOBS[jid]["error"] = f"{type(exc).__name__}: {exc}"

            threading.Thread(target=work, daemon=True).start()
            self.send_response(303)
            self.send_header("Location", f"/job/{jid}")
            self.end_headers()

    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"Interfaz web en http://{host}:{port}  (Ctrl+C para salir)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando…")
    return 0
