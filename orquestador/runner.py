"""
runner.py - Punto de entrada programático: construye todo y ejecuta un escaneo completo.

Lo usan la CLI (cli.py) y la interfaz web (web.py), de modo que ambas se comportan igual.
También puedes importarlo desde tus propios scripts:

    from orquestador.runner import run_scan
    from orquestador.core import Selector
    res = run_scan([Selector("domain", "example.com")])
"""
from __future__ import annotations

import json
from pathlib import Path

from .core import Context, Orchestrator, ScanResult, Selector
from .http import HttpClient
from .modules import build_modules

ROOT = Path(__file__).resolve().parent.parent

def run_scan(seeds: list[Selector], *, config: dict | None = None, fixtures: list | None = None,
             only: list[str] | None = None, exclude: list[str] | None = None, depth: int = 2,
             guess: bool = False, workers: int = 6, timeout: float = 10, delay: float = 0.25,
             max_selectors: int = 40, plugin_dir: str | None = None, progress=None) -> ScanResult:
    from .graph import Graph

    config = dict(config or {})
    config["_seed_domains"] = [s.value for s in seeds if s.kind == "domain"]
    http = HttpClient(timeout=timeout, delay=0 if fixtures is not None else delay, fixtures=fixtures)
    ctx = Context(http=http, config=config, allow_guesses=guess)
    modules = build_modules(ctx, only=only, exclude=exclude, plugin_dir=plugin_dir)
    res = Orchestrator(modules, ctx, max_depth=depth, workers=workers, max_selectors=max_selectors,
                       progress=progress).run(seeds)
    res.graph = Graph.from_result(res)
    res.correlations = res.graph.correlations()
    res.profiles = res.graph.profiles()
    return res
