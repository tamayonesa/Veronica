"""
graph.py - Correlación y grafo de relaciones entre entidades.

Cada hallazgo conecta el selector que lo originó con las entidades que descubrió. Como los
nodos se identifican por (tipo, valor normalizado), el MISMO email/nombre/username hallado por
fuentes distintas converge en un único nodo: eso es la correlación.

Sobre ese grafo:
  * correlations -> hechos que se refuerzan entre fuentes (p. ej. "este nombre aparece en
    Gravatar y GitHub", "este username existe en 7 plataformas").
  * profiles     -> componentes conectados de identificadores "personales" (emails, usernames,
    nombres, cuentas, teléfonos, dominios) con una confianza combinada (noisy-OR por fuente).
  * exportación a Graphviz (DOT/SVG), GraphML (Gephi/yEd) y CSV importable en Maltego.
"""
from __future__ import annotations

import csv
import io
import shutil
import subprocess
from collections import defaultdict
from xml.sax.saxutils import escape, quoteattr

from .core import ScanResult, strip_accents

# Tipos que identifican a una persona y pueden unir "perfiles". Excluimos brechas, IPs, servidores DNS...
# porque son recursos COMPARTIDOS: dos emails distintos en la misma brecha no son la misma persona.
LINK_KINDS = {"name", "email", "username", "phone", "account", "domain"}
MIN_LINK_CONFIDENCE = 0.4          # las suposiciones (guess) no unen perfiles

COLORS = {"target": "#1f2937", "name": "#c2410c", "email": "#1d4ed8", "username": "#047857",
          "account": "#0f766e", "domain": "#6d28d9", "phone": "#be185d", "breach": "#b91c1c",
          "ip": "#64748b", "nameserver": "#64748b", "location": "#a16207", "company": "#7c3aed"}
KIND_ES = {"target": "Objetivo", "name": "Nombre", "email": "Email", "username": "Username",
           "account": "Cuenta", "domain": "Dominio", "phone": "Teléfono", "breach": "Brecha",
           "ip": "IP", "nameserver": "Servidor DNS", "location": "Ubicación", "company": "Empresa"}
MALTEGO = {"name": "maltego.Person", "email": "maltego.EmailAddress", "username": "maltego.Alias",
           "account": "maltego.Alias", "domain": "maltego.Domain", "phone": "maltego.PhoneNumber",
           "ip": "maltego.IPv4Address", "nameserver": "maltego.NSRecord", "location": "maltego.Location",
           "company": "maltego.Company", "breach": "maltego.Phrase", "target": "maltego.Phrase"}


def node_id(kind: str, value: str) -> str:
    v = value.strip().lower()
    if kind == "name":
        v = " ".join(strip_accents(v).split())        # 'Lucía Marín' == 'lucia marin'
    return f"{kind}:{v}"


class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple, dict] = {}

    def add_node(self, kind: str, value: str, label: str | None = None, module: str | None = None,
                 seed: bool = False) -> str:
        nid = node_id(kind, value)
        n = self.nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label or value,
                                        "sources": set(), "seed": False})
        if (label or value) != n["label"] and n["label"] == n["label"].lower() and (label or value) != (label or value).lower():
            n["label"] = label or value          # 'github: x' -> 'GitHub: x'
        if module:
            n["sources"].add(module)
        n["seed"] = n["seed"] or seed
        return nid

    def add_edge(self, a: str, b: str, relation: str, module: str, confidence: float):
        if a == b:
            return
        key = (a, b, relation)
        e = self.edges.setdefault(key, {"source": a, "target": b, "relation": relation,
                                        "modules": set(), "confidence": 0.0})
        e["modules"].add(module)
        e["confidence"] = max(e["confidence"], confidence)

    # ------------------------------------------------------------------ #
    @classmethod
    def from_result(cls, res: ScanResult) -> "Graph":
        g = cls()
        target = g.add_node("target", "objetivo", label="Objetivo", seed=True)
        for s in res.selectors:
            sid = g.add_node(s.kind, s.value, seed=s.depth == 0)
            if s.depth == 0:
                g.add_edge(target, sid, "dato de entrada", "usuario", 1.0)
        for f in res.findings:
            src = g.add_node(f.selector.kind, f.selector.value)   # el selector no suma "fuente"
            for e in f.entities:
                # Una suposición (confianza baja) no cuenta como fuente que "confirma" la entidad.
                dst = g.add_node(e.kind, e.value, label=e.label,
                                 module=f.module if f.confidence >= MIN_LINK_CONFIDENCE else None)
                g.add_edge(src, dst, e.relation, f.module, f.confidence)
        return g

    # ------------------------------------------------------------------ #
    def correlations(self) -> list[dict]:
        """Hechos reforzados por más de una fuente o patrones multi-plataforma."""
        out = []
        for n in self.nodes.values():
            if n["kind"] in ("name", "email", "username", "domain", "phone") and len(n["sources"]) >= 2:
                out.append({"tipo": "confirmación", "entidad": f"{KIND_ES[n['kind']]}: {n['label']}",
                            "detalle": f"Aparece en {len(n['sources'])} fuentes independientes: "
                                       + ", ".join(sorted(n["sources"])), "peso": len(n["sources"])})
        # username presente en muchas plataformas = identidad digital consistente
        accounts = defaultdict(set)
        for e in self.edges.values():
            if e["source"].startswith("username:") and e["target"].startswith("account:"):
                accounts[e["source"]].add(self.nodes[e["target"]]["label"].split(":")[0])
        for uid, sites in accounts.items():
            if len(sites) >= 3:
                out.append({"tipo": "reutilización", "entidad": f"Username: {self.nodes[uid]['label']}",
                            "detalle": f"El mismo username se usa en {len(sites)} plataformas: "
                                       + ", ".join(sorted(sites)), "peso": len(sites)})
        # emails distintos que apuntan al mismo nombre/username
        for nid, n in self.nodes.items():
            if n["kind"] in ("name", "username"):
                mails = {e["source"] for e in self.edges.values() if e["target"] == nid and e["source"].startswith("email:")}
                mails |= {e["target"] for e in self.edges.values() if e["source"] == nid and e["target"].startswith("email:")}
                if len(mails) >= 2:
                    out.append({"tipo": "vínculo", "entidad": f"{KIND_ES[n['kind']]}: {n['label']}",
                                "detalle": "Vinculado a varios emails: " + ", ".join(sorted(self.nodes[m]["label"] for m in mails)),
                                "peso": len(mails)})
        return sorted(out, key=lambda c: -c["peso"])

    def profiles(self) -> list[dict]:
        """Agrupa identificadores conectados (union-find) y estima la confianza del grupo."""
        parent: dict[str, str] = {}

        def find(x):
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def link(a, b):
            parent[find(a)] = find(b)

        linkable = {i for i, n in self.nodes.items() if n["kind"] in LINK_KINDS}
        used = [e for e in self.edges.values() if e["source"] in linkable and e["target"] in linkable
                and e["confidence"] >= MIN_LINK_CONFIDENCE and e["relation"] != "dominio del email"
                and "subdominio" not in e["relation"] and e["relation"] != "host de"]
        for e in used:
            link(e["source"], e["target"])
        groups = defaultdict(list)
        for i in linkable:
            if any(i in (e["source"], e["target"]) for e in used):
                groups[find(i)].append(i)

        profiles = []
        for members in groups.values():
            mset = set(members)
            evid = [e for e in used if e["source"] in mset and e["target"] in mset]
            best: dict[str, float] = {}                       # mejor evidencia por módulo
            for e in evid:
                for m in e["modules"]:
                    best[m] = max(best.get(m, 0), e["confidence"])
            miss = 1.0
            for c in best.values():
                miss *= (1 - c)                               # noisy-OR: fuentes independientes se refuerzan
            by_kind = defaultdict(list)
            for m in members:
                by_kind[self.nodes[m]["kind"]].append(self.nodes[m]["label"])
            title = (by_kind["name"] or by_kind["username"] or by_kind["email"] or by_kind["domain"] or ["?"])[0]
            profiles.append({"titulo": title, "confianza": round(min(0.99, 1 - miss), 2),
                             "fuentes": sorted(best), "miembros": {KIND_ES[k]: sorted(set(v)) for k, v in by_kind.items()},
                             "total": len(members)})
        return sorted(profiles, key=lambda p: (-p["confianza"], -p["total"]))

    # ------------------------------------------------------------------ #
    # Exportaciones
    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict:
        return {"nodes": [{**n, "sources": sorted(n["sources"])} for n in self.nodes.values()],
                "edges": [{**e, "modules": sorted(e["modules"])} for e in self.edges.values()]}

    def to_dot(self) -> str:
        lines = ["graph OSINT {", '  graph [overlap=false, splines=true, bgcolor="white", fontname="Helvetica"];',
                 '  node [style=filled, fontcolor=white, fontname="Helvetica", fontsize=10, shape=ellipse];',
                 '  edge [color="#94a3b8", fontname="Helvetica", fontsize=8, fontcolor="#475569"];']
        for n in self.nodes.values():
            shape = "doublecircle" if n["kind"] == "target" else ("box" if n["kind"] in ("breach", "account") else "ellipse")
            lines.append(f'  {quoteattr(n["id"])} [label={quoteattr(n["label"])}, fillcolor="{COLORS.get(n["kind"], "#475569")}", shape={shape}];')
        for e in self.edges.values():
            lines.append(f'  {quoteattr(e["source"])} -- {quoteattr(e["target"])} [label={quoteattr(e["relation"])}];')
        lines.append("}")
        return "\n".join(lines)

    def to_svg(self) -> str | None:
        """Renderiza con Graphviz si está instalado (`dot`); si no, devuelve None."""
        if not shutil.which("dot"):
            return None
        p = subprocess.run(["dot", "-Kfdp", "-Tsvg"], input=self.to_dot(), capture_output=True, text=True, timeout=60)
        return p.stdout if p.returncode == 0 else None

    def to_graphml(self) -> str:
        x = ['<?xml version="1.0" encoding="UTF-8"?>', '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
             '  <key id="kind" for="node" attr.name="kind" attr.type="string"/>',
             '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
             '  <key id="relation" for="edge" attr.name="relation" attr.type="string"/>',
             '  <graph id="OSINT" edgedefault="undirected">']
        for n in self.nodes.values():
            x.append(f'    <node id={quoteattr(n["id"])}><data key="kind">{escape(n["kind"])}</data>'
                     f'<data key="label">{escape(n["label"])}</data></node>')
        for i, e in enumerate(self.edges.values()):
            x.append(f'    <edge id="e{i}" source={quoteattr(e["source"])} target={quoteattr(e["target"])}>'
                     f'<data key="relation">{escape(e["relation"])}</data></edge>')
        x += ["  </graph>", "</graphml>"]
        return "\n".join(x)

    def to_maltego_csv(self) -> str:
        """CSV de aristas para 'Import Graph from Table' de Maltego (mapea las columnas a entidades)."""
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["source_type", "source_value", "target_type", "target_value", "link_label"])
        for e in self.edges.values():
            a, b = self.nodes[e["source"]], self.nodes[e["target"]]
            w.writerow([MALTEGO.get(a["kind"], "maltego.Phrase"), a["label"],
                        MALTEGO.get(b["kind"], "maltego.Phrase"), b["label"], e["relation"]])
        return buf.getvalue()
