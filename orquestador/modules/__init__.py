"""
Registro de módulos.

Los módulos se descubren solos: cualquier subclase de `Module` con atributo `name` definida en
este paquete (o en un fichero .py de la carpeta de plugins) queda registrada. No hay que tocar
el núcleo para añadir fuentes nuevas.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import pkgutil
from pathlib import Path

from ..core import Context, Module

log = logging.getLogger("osint")


def _classes_in(mod) -> list[type[Module]]:
    return [c for _, c in inspect.getmembers(mod, inspect.isclass)
            if issubclass(c, Module) and c.__module__ == mod.__name__ and getattr(c, "name", "")
            and c.__name__ not in ("ExternalModule", "GenericCommandModule")]


def discover_classes(plugin_dir: str | Path | None = None) -> list[type[Module]]:
    """Devuelve todas las clases de módulo instanciables (internas + plugins)."""
    found: list[type[Module]] = []
    for info in pkgutil.iter_modules(__path__):
        mod = importlib.import_module(f"{__name__}.{info.name}")
        found += _classes_in(mod)
    if plugin_dir and Path(plugin_dir).is_dir():
        for py in sorted(Path(plugin_dir).glob("*.py")):
            if py.name.startswith("_"):
                continue
            spec = importlib.util.spec_from_file_location(f"osint_plugin_{py.stem}", py)
            mod = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(mod)
                found += _classes_in(mod)
                log.info("plugin cargado: %s", py.name)
            except Exception as exc:
                log.warning("no se pudo cargar el plugin %s: %s", py.name, exc)
    return found


def build_modules(ctx: Context, *, only: list[str] | None = None, exclude: list[str] | None = None,
                  plugin_dir: str | Path | None = None) -> list[Module]:
    """Instancia los módulos activos, aplicando --modules / --exclude."""
    from .external import GenericCommandModule

    mods: list[Module] = [cls(ctx) for cls in discover_classes(plugin_dir)]
    for spec in ctx.config.get("external_tools", []):         # herramientas propias del usuario
        try:
            mods.append(GenericCommandModule(ctx, spec))
        except KeyError as exc:
            log.warning("external_tools: falta el campo %s en %s", exc, spec)
    if only:
        mods = [m for m in mods if m.name in only]
    if exclude:
        mods = [m for m in mods if m.name not in exclude]
    return sorted(mods, key=lambda m: m.name)
