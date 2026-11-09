"""
cli.py - Interfaz de línea de comandos.

Sin argumentos (python osint.py) te pregunta los datos paso a paso.

Ejemplos con argumentos:
    python osint.py -e persona@dominio.com
    python osint.py -u usuario -d ejemplo.com --out resultados/
    python osint.py -n "Nombre Apellido" -p +34600000001 --guess
    python osint.py --list-modules
    python osint.py --web                       # interfaz web local
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from colorama import Fore, Style, init

# Habilita la compatibilidad con colores ANSI en Windows CMD y PowerShell.
init(autoreset=True)

from .core import SELECTOR_KINDS, InvalidSelector, Selector, normalize_selector_value
from .report import write_reports
from .runner import run_scan

NOTICE = ("Aviso: usa esta herramienta solo con tu propia información o con autorización expresa. "
          "Recopila datos públicos, pero tratarlos puede estar regulado (RGPD/LOPDGDD).")
ALL_FORMATS = ["json", "html", "dot", "svg", "graphml", "csv"]

BANNER = r"""
 ██▒   █▓▓█████  ██▀███   ▒█████   ███▄    █  ██▓ ▄████▄   ▄▄▄
▓██░   █▒▓█   ▀ ▓██ ▒ ██▒▒██▒  ██▒ ██ ▀█   █ ▓██▒▒██▀ ▀█  ▒████▄
 ▓██  █▒░▒███   ▓██ ░▄█ ▒▒██░  ██▒▓██  ▀█ ██▒▒██▒▒▓█    ▄ ▒██  ▀█▄
  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄  ▒██   ██░▓██▒  ▐▌██▒░██░▒▓▓▄ ▄██▒░██▄▄▄▄██
   ▒▀█░  ░▒████▒░██▓ ▒██▒░ ████▓▒░▒██░   ▓██░░██░▒ ▓███▀ ░ ▓█   ▓██▒
   ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░▓  ░ ░▒ ▒  ░ ▒▒   ▓▒█░
   ░ ░░   ░ ░  ░  ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░░   ░ ▒░ ▒ ░  ░  ▒     ▒   ▒▒ ░
     ░░     ░     ░░   ░ ░ ░ ░ ▒     ░   ░ ░  ▒ ░░          ░   ▒
      ░     ░  ░   ░         ░ ░           ░  ░  ░ ░            ░  ░
     ░                                           ░
                 ORQUESTADOR OSINT DE HUELLA DIGITAL
"""

# Colores ANSI: no se muestran al redirigir la salida ni si se define NO_COLOR.
USE_COLORS = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def paint(value: str, color: str) -> str:
    palette = {
        "cyan": Fore.LIGHTCYAN_EX,
        "blue": Fore.LIGHTBLUE_EX,
        "green": Fore.LIGHTGREEN_EX,
        "yellow": Fore.LIGHTYELLOW_EX,
        "red": Fore.LIGHTRED_EX,
        "magenta": Fore.LIGHTMAGENTA_EX,
        "bold": Style.BRIGHT,
    }
    if not USE_COLORS:
        return value
    return f"{palette[color]}{value}{Style.RESET_ALL}"


def show_banner() -> None:
    print(paint(BANNER, "cyan"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="osint", description="Orquestador OSINT modular de huella digital.",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    g = p.add_argument_group("datos de entrada (al menos uno; puedes repetir y combinar)")
    g.add_argument("-n", "--name", action="append", default=[], help="nombre completo")
    g.add_argument("-e", "--email", action="append", default=[], help="dirección de email")
    g.add_argument("-u", "--username", action="append", default=[], help="nombre de usuario")
    g.add_argument("-p", "--phone", action="append", default=[], help="teléfono (+34600000000)")
    g.add_argument("-d", "--domain", action="append", default=[], help="dominio")
    g.add_argument("--region", default="ES", help="región por defecto para teléfonos sin prefijo (def. ES)")

    m = p.add_argument_group("módulos y comportamiento")
    m.add_argument("-m", "--modules", help="solo estos módulos (separados por coma)")
    m.add_argument("-x", "--exclude", help="excluir módulos (separados por coma)")
    m.add_argument("--list-modules", action="store_true", help="lista los módulos disponibles y sale")
    m.add_argument("--depth", type=int, default=2, help="rondas de pivote sobre lo descubierto (0 = sin pivotes; def. 2)")
    m.add_argument("--guess", action="store_true", help="investigar también suposiciones (usernames derivados del nombre)")
    m.add_argument("--max-selectors", type=int, default=40, help="tope de selectores a investigar (def. 40)")
    m.add_argument("--workers", type=int, default=6, help="tareas en paralelo (def. 6)")
    m.add_argument("--timeout", type=float, default=10, help="timeout HTTP en segundos (def. 10)")
    m.add_argument("--delay", type=float, default=0.25, help="pausa mínima entre peticiones al mismo host (def. 0.25 s)")
    m.add_argument("--config", help="fichero config.json (claves de API, herramientas externas)")
    m.add_argument("--plugins", default="plugins", help="carpeta con módulos propios (def. ./plugins)")

    o = p.add_argument_group("salida")
    o.add_argument("-o", "--out", default="resultados", help="carpeta de salida (def. ./resultados)")
    o.add_argument("-f", "--formats", default="json,html,dot,svg,graphml,csv",
                   help=f"formatos separados por coma: {','.join(ALL_FORMATS)}")
    o.add_argument("-q", "--quiet", action="store_true", help="sin mensajes de progreso")
    o.add_argument("-v", "--verbose", action="store_true", help="registro de depuración")

    x = p.add_argument_group("otros")
    x.add_argument("--web", action="store_true", help="arranca la interfaz web local")
    x.add_argument("--port", type=int, default=8080, help="puerto de la interfaz web (def. 8080)")
    x.add_argument("--host", default="127.0.0.1",
                   help="dirección de escucha de la web (def. 127.0.0.1; usa 0.0.0.0 solo dentro de Docker)")
    return p


def load_config(path: str | None) -> dict:
    candidates = [path] if path else ["config.json"]
    for c in candidates:
        if c and Path(c).is_file():
            return json.loads(Path(c).read_text(encoding="utf-8"))
    if path:
        sys.exit(f"No se encuentra el fichero de configuración: {path}")
    return {}


def ask_inputs(region: str):
    """Asistente interactivo: pide los datos uno a uno (Enter para omitir). Acepta varios separados por coma."""
    print()
    show_banner()
    print(paint(NOTICE, "yellow"))
    print(paint("[+] Introduce los datos que quieras investigar.", "green"))
    print(paint("[i] Pulsa Enter para omitir un campo. Puedes separar varios valores con comas.\n", "blue"))
    fields = [("name", "Nombre completo", False), ("email", "Email(s)", True), ("username", "Username(s)", True),
              ("phone", "Teléfono(s) (+34600000000)", True), ("domain", "Dominio(s)", True)]
    while True:
        raw = []
        for kind, label, multi in fields:
            while True:
                text = input(paint(f"[?] {label}: ", "magenta")).strip()
                if not text:
                    break
                values = [v.strip() for v in text.split(",")] if multi else [text]
                try:
                    for v in values:
                        if v:
                            normalize_selector_value(kind, v, region)
                except InvalidSelector as exc:
                    print(paint(f"  [!] {exc}. Inténtalo de nuevo.", "red"))
                    continue
                raw += [(kind, v) for v in values if v]
                break
        if raw:
            break
        print(paint("\n[!] Necesitas introducir al menos un dato.\n", "red"))
    guess = False
    if any(k == "name" for k, _ in raw):
        guess = input(paint("\n[?] ¿Investigar también usernames deducidos del nombre? (menos fiable) [s/N]: ", "magenta")).strip().lower() in ("s", "si", "sí", "y")
    out = input(paint("[?] Carpeta de salida [resultados]: ", "magenta")).strip() or "resultados"
    print()
    return raw, {"guess": guess, "out": out}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    config = load_config(args.config)
    fixtures = None

    if args.web:
        from .web import serve
        print(NOTICE, file=sys.stderr)
        return serve(args.port, host=args.host, config=config, fixtures=fixtures, plugin_dir=args.plugins)

    if args.list_modules:
        from .core import Context
        from .http import HttpClient
        from .modules import build_modules
        mods = build_modules(Context(HttpClient(), config), plugin_dir=args.plugins)
        for mod in mods:
            ok, why = mod.available()
            print(f"{mod.name:<14} {','.join(mod.accepts):<16} {'[externa]' if mod.external else '[nativa] '} "
                  f"{mod.description}{'' if ok else '  (NO DISPONIBLE: ' + why + ')'}")
        return 0

    # --- construir selectores ---------------------------------------------------------------
    raw = [(k, v) for k in SELECTOR_KINDS for v in getattr(args, k)]
    interactive = not raw
    if interactive:                       # sin argumentos: modo asistente
        if not sys.stdin.isatty():
            print("Indica al menos un dato (-n, -e, -u, -p, -d) o ejecuta sin argumentos en una terminal.", file=sys.stderr)
            return 2
        raw, extra = ask_inputs(args.region)
        args.guess = args.guess or extra["guess"]
        args.out = extra["out"]
    seeds = []
    for kind, value in raw:
        try:
            seeds.append(Selector(kind, normalize_selector_value(kind, value, args.region)))
        except InvalidSelector as exc:
            print(f"Error en la entrada: {exc}", file=sys.stderr)
            return 2

    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    bad = [f for f in formats if f not in ALL_FORMATS]
    if bad:
        print(f"Formato(s) desconocido(s): {', '.join(bad)}", file=sys.stderr)
        return 2

    progress = (lambda msg: None) if args.quiet else (lambda msg: print(msg, file=sys.stderr))
    if not args.quiet:
        print(NOTICE, file=sys.stderr)

    res = run_scan(seeds, config=config, fixtures=fixtures,
                   only=args.modules.split(",") if args.modules else None,
                   exclude=args.exclude.split(",") if args.exclude else None,
                   depth=args.depth, guess=args.guess, workers=args.workers, timeout=args.timeout,
                   delay=args.delay, max_selectors=args.max_selectors, plugin_dir=args.plugins, progress=progress)

    files = write_reports(res, args.out, formats)
    print(paint(f"\n[+] {len(res.findings)} hallazgos · {len(res.selectors)} selectores · {len(res.profiles)} perfil(es) · "
          f"{len(res.errors)} error(es)", "green"))
    for f in files:
        print(paint(f"  [>] {f}", "cyan"))
    if "svg" in formats and not any(f.suffix == ".svg" for f in files):
        print("  (grafo.svg no generado: instala Graphviz -> sudo apt install graphviz; "
              "el grafo interactivo sigue disponible en informe.html y grafo.dot)")
    html = next((f for f in files if f.suffix == ".html"), None)
    if interactive and html:
        if input("\n¿Abrir el informe con el grafo en el navegador? [S/n]: ").strip().lower() not in ("n", "no"):
            import webbrowser
            webbrowser.open(html.resolve().as_uri())
    return 0
