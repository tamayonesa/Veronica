"""
report.py - Informes del escaneo.

Formatos:
  json     -> resultado completo y estructurado (lo más útil para encadenar con otras herramientas)
  html     -> informe autocontenido (sin recursos externos) con grafo interactivo
  dot/svg  -> grafo para Graphviz (svg solo si `dot` está instalado)
  graphml  -> grafo para Gephi / yEd
  csv      -> aristas para importar en Maltego

SEGURIDAD: todo lo que viene de Internet (biografías, nombres...) es no confiable. Se escapa con
html.escape y solo se convierten en enlaces las URLs http(s).
"""
from __future__ import annotations

import html
import json
import re
from collections import defaultdict
from pathlib import Path

from .core import ScanResult
from .graph import COLORS, KIND_ES, Graph

_URL = re.compile(r"^https?://[^\s<>\"']+$")


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def to_json_dict(res: ScanResult) -> dict:
    return {
        "herramienta": "OSINT Orquestador 1.0",
        "inicio": res.started, "fin": res.finished,
        "entradas": [{"tipo": s.kind, "valor": s.value} for s in res.seeds],
        "selectores_investigados": [{"tipo": s.kind, "valor": s.value, "profundidad": s.depth,
                                     "origen": s.origin, "suposicion": s.guess} for s in res.selectors],
        "modulos": res.module_status,
        "hallazgos": [f.to_dict() for f in res.findings],
        "perfiles": res.profiles,
        "correlaciones": res.correlations,
        "grafo": res.graph.to_dict() if res.graph else None,
        "errores": res.errors,
    }


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def _e(x) -> str:
    return html.escape(str(x), quote=True)


def _val(v) -> str:
    """Renderiza recursivamente un valor de `data`."""
    if isinstance(v, dict):
        rows = "".join(f"<dt>{_e(k)}</dt><dd>{_val(x)}</dd>" for k, x in v.items() if x not in (None, "", [], {}))
        return f"<dl>{rows}</dl>"
    if isinstance(v, (list, tuple)):
        if all(not isinstance(i, (dict, list)) for i in v):
            return ", ".join(_val(i) for i in v) or "—"
        return "<ul>" + "".join(f"<li>{_val(i)}</li>" for i in v) + "</ul>"
    s = str(v)
    if _URL.match(s):
        return f'<a href="{_e(s)}" rel="noopener noreferrer nofollow" target="_blank">{_e(s)}</a>'
    return _e(s)


def _conf(c: float) -> str:
    label = "alta" if c >= 0.75 else "media" if c >= 0.45 else "baja"
    return f'<span class="conf c-{label}" title="confianza {c:.2f}">{label} · {c:.2f}</span>'


def to_html(res: ScanResult) -> str:
    by_mod = defaultdict(list)
    for f in res.findings:
        by_mod[f.module].append(f)

    # --- Resumen ---------------------------------------------------------------
    seeds = "".join(f'<li><span class="k">{_e(KIND_ES.get(s.kind, s.kind))}</span> <code>{_e(s.value)}</code></li>'
                    for s in res.seeds)
    n_graph = len(res.graph.nodes) if res.graph else 0
    summary = (f"<p class='lead'>{len(res.findings)} hallazgos de {len([m for m in res.module_status.values() if m['status']=='ok'])} "
               f"módulos sobre {len(res.selectors)} selectores; {n_graph} entidades en el grafo.</p>")

    # --- Perfiles -----------------------------------------------------------------
    profs = []
    for p in res.profiles:
        members = "".join(f"<dt>{_e(k)}</dt><dd>{', '.join(f'<code>{_e(x)}</code>' for x in v[:12])}"
                          f"{' …' if len(v) > 12 else ''}</dd>" for k, v in p["miembros"].items())
        profs.append(f"<article class='profile'><h3>{_e(p['titulo'])} {_conf(p['confianza'])}</h3>"
                     f"<p class='muted'>{p['total']} identificadores · fuentes: {_e(', '.join(p['fuentes']))}</p>"
                     f"<dl>{members}</dl></article>")
    profiles_html = "".join(profs) or "<p class='muted'>No hay suficientes vínculos para agrupar perfiles.</p>"

    # --- Correlaciones -----------------------------------------------------------
    corr = "".join(f"<li><strong>{_e(c['entidad'])}</strong> <span class='chip'>{_e(c['tipo'])}</span><br>"
                   f"<span class='muted'>{_e(c['detalle'])}</span></li>" for c in res.correlations)
    corr_html = f"<ul class='plain'>{corr}</ul>" if corr else "<p class='muted'>Sin correlaciones entre fuentes.</p>"

    # --- Hallazgos por módulo ----------------------------------------------------------
    mods = []
    for name in sorted(by_mod):
        items = []
        for f in sorted(by_mod[name], key=lambda x: -x.confidence):
            link = (f' <a href="{_e(f.url)}" rel="noopener noreferrer nofollow" target="_blank">abrir</a>'
                    if f.url and _URL.match(f.url) else "")
            items.append(f"<article class='finding'><header><h4>{_e(f.title)}</h4>"
                         f"<span class='chip'>{_e(f.kind)}</span> {_conf(f.confidence)}{link}</header>"
                         f"<p class='muted'>origen: <code>{_e(f.selector.key)}</code></p>{_val(f.data) if f.data else ''}</article>")
        desc = res.module_status.get(name, {}).get("description", "")
        mods.append(f"<details open><summary><span>{_e(name)}</span><span class='muted'>{len(items)} hallazgo(s) — {_e(desc)}</span></summary>"
                    + "".join(items) + "</details>")

    # --- Estado de módulos -----------------------------------------------------------
    rows = "".join(f"<tr><td><code>{_e(n)}</code></td><td>{_e(s['status'])}{' · ' + _e(s['reason']) if s['reason'] else ''}</td>"
                   f"<td>{s['selectors']}</td><td>{s['findings']}</td><td>{s['errors']}</td>"
                   f"<td>{'externa' if s['external'] else 'nativa'}</td></tr>" for n, s in sorted(res.module_status.items()))
    errs = "".join(f"<li><code>{_e(e['module'])}</code> en <code>{_e(e['selector'])}</code>: {_e(e['error'])}</li>" for e in res.errors)

    graph_json = json.dumps(res.graph.to_dict() if res.graph else {"nodes": [], "edges": []}, ensure_ascii=True)
    graph_json = graph_json.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    legend = "".join(f'<button type="button" class="lg" data-kind="{k}" aria-pressed="true">'
                     f'<i style="background:{COLORS[k]}"></i>{_e(KIND_ES[k])}</button>' for k in COLORS)

    return _TEMPLATE.format(
        css=_CSS, js=_JS, seeds=seeds, summary=summary, started=_e(res.started), finished=_e(res.finished),
        profiles=profiles_html, correlations=corr_html, modules="".join(mods) or "<p class='muted'>Sin hallazgos.</p>",
        status_rows=rows, errors=f"<h3>Errores</h3><ul class='plain'>{errs}</ul>" if errs else "",
        graph_json=graph_json, legend=legend)


# --------------------------------------------------------------------------- #
# Escritura a disco
# --------------------------------------------------------------------------- #
def write_reports(res: ScanResult, out_dir: str | Path, formats: list[str]) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []

    def put(name, content):
        p = out / name
        p.write_text(content, encoding="utf-8")
        written.append(p)

    for fmt in formats:
        if fmt == "json":
            put("informe.json", json.dumps(to_json_dict(res), indent=2, ensure_ascii=False))
        elif fmt == "html":
            put("informe.html", to_html(res))
        elif fmt == "dot":
            put("grafo.dot", res.graph.to_dot())
        elif fmt == "svg":
            svg = res.graph.to_svg()
            if svg:
                put("grafo.svg", svg)
        elif fmt == "graphml":
            put("grafo.graphml", res.graph.to_graphml())
        elif fmt == "csv":
            put("maltego.csv", res.graph.to_maltego_csv())
    return written


_CSS = """
:root{--bg:#edf0f3;--surface:#fff;--ink:#17212b;--muted:#5b6b7a;--line:#d5dbe1;--accent:#0b6e99;--hi:#1f7a4d;--mid:#9a6a00;--lo:#a33a2a;--chip:#e3e9ef}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0e151c;--surface:#16212b;--ink:#e6edf3;--muted:#9fb0bf;--line:#2a3a48;--accent:#5cb8e6;--hi:#5fcf93;--mid:#e0b04a;--lo:#f08a78;--chip:#223140}}
*{box-sizing:border-box}html{scroll-padding-top:1rem}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1040px;margin:0 auto;padding:2rem 1.25rem 4rem}
h1,h2,h3,h4{font-family:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;line-height:1.25;margin:0}
h1{font-size:2rem}h2{font-size:1.4rem;margin:2.6rem 0 .8rem;padding-bottom:.4rem;border-bottom:1px solid var(--line)}
h3{font-size:1.1rem}h4{font-size:1rem}
code,.k{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.88em}
code{background:var(--chip);padding:.05em .35em;border-radius:3px;overflow-wrap:anywhere}
a{color:var(--accent)}a:focus-visible,button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.muted{color:var(--muted);font-size:.9rem;margin:.2rem 0}
.lead{font-size:1.05rem;margin:.4rem 0 1rem}
.meta{display:flex;flex-wrap:wrap;gap:.4rem 1.5rem;color:var(--muted);font-size:.9rem}
ul.plain,ul.seeds{list-style:none;padding:0;margin:0}ul.seeds{display:flex;flex-wrap:wrap;gap:.5rem 1.25rem}
ul.plain li{padding:.55rem 0;border-bottom:1px solid var(--line)}
.chip{background:var(--chip);border-radius:3px;padding:.05rem .45rem;font-size:.78rem;margin-right:.3rem}
.conf{font-size:.8rem;font-weight:600}.c-alta{color:var(--hi)}.c-media{color:var(--mid)}.c-baja{color:var(--lo)}
.profile,.finding{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:.9rem 1.1rem;margin:.7rem 0}
dl{margin:.4rem 0 0;display:grid;grid-template-columns:minmax(8rem,max-content) 1fr;gap:.2rem 1rem}
dt{color:var(--muted);font-size:.88rem}dd{margin:0;overflow-wrap:anywhere}dd ul{margin:0;padding-left:1.1rem}
details{margin:.8rem 0}summary{cursor:pointer;display:flex;flex-direction:column;padding:.55rem 0;font-weight:600}
summary span:first-child{font-family:ui-monospace,Menlo,Consolas,monospace}summary .muted{font-weight:400}
.finding header{display:flex;flex-wrap:wrap;align-items:baseline;gap:.2rem .6rem}
table{width:100%;border-collapse:collapse;font-size:.9rem;background:var(--surface)}th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--line)}
.scroll{overflow-x:auto}
#graph-wrap{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:.5rem}
#graph{width:100%;height:560px;display:block;cursor:grab;touch-action:none}
#graph text{fill:var(--ink);pointer-events:none;paint-order:stroke;stroke:var(--surface)}
#graph line{stroke:var(--line);stroke-width:1.4}.hidden{display:none}
.legend{display:flex;flex-wrap:wrap;gap:.4rem;margin:.3rem 0 .6rem}
.lg{display:inline-flex;align-items:center;gap:.4rem;border:1px solid var(--line);background:var(--surface);color:var(--ink);border-radius:999px;padding:.2rem .7rem;font-size:.82rem;cursor:pointer}
.lg i{width:.7rem;height:.7rem;border-radius:50%;display:inline-block}.lg[aria-pressed=false]{opacity:.4}
footer{margin-top:3rem;color:var(--muted);font-size:.85rem}
@media (max-width:640px){dl{grid-template-columns:1fr}#graph{height:420px}}
"""

_JS = r"""
(function(){
  const data = JSON.parse(document.getElementById('graph-data').textContent);
  const svg = document.getElementById('graph'), NS = 'http://www.w3.org/2000/svg';
  const area = Math.max(750000, data.nodes.length*30000), H = Math.round(Math.sqrt(area/1.55)), W = Math.round(H*1.55), S = W/1050, color = JSON.parse(document.getElementById('graph-colors').textContent);
  const nodes = data.nodes.map((n,i)=>({...n, x:W/2+Math.cos(i)*200*Math.random(), y:H/2+Math.sin(i)*200*Math.random(), vx:0, vy:0}));
  const idx = Object.fromEntries(nodes.map((n,i)=>[n.id,i]));
  const edges = data.edges.filter(e=>e.source in idx && e.target in idx).map(e=>({a:idx[e.source], b:idx[e.target], rel:e.relation}));
  // Layout de fuerzas (Fruchterman-Reingold simplificado)
  const k = Math.sqrt(W*H/Math.max(nodes.length,1))*0.8;
  for(let it=0; it<300; it++){
    const t = 1 - it/300;
    for(const n of nodes){n.vx=0;n.vy=0}
    for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){
      const a=nodes[i], b=nodes[j]; let dx=a.x-b.x, dy=a.y-b.y, d=Math.hypot(dx,dy)||0.01, f=k*k/d;
      a.vx+=dx/d*f; a.vy+=dy/d*f; b.vx-=dx/d*f; b.vy-=dy/d*f;
    }
    for(const e of edges){
      const a=nodes[e.a], b=nodes[e.b]; let dx=a.x-b.x, dy=a.y-b.y, d=Math.hypot(dx,dy)||0.01, f=d*d/k;
      a.vx-=dx/d*f; a.vy-=dy/d*f; b.vx+=dx/d*f; b.vy+=dy/d*f;
    }
    for(const n of nodes){            // gravedad suave hacia el centro: evita que los nodos se peguen a los bordes
      const dx=n.x-W/2, dy=n.y-H/2, d=Math.hypot(dx,dy)||1, f=0.12*d*d/k;
      n.vx-=dx/d*f; n.vy-=dy/d*f;
    }
    for(const n of nodes){
      const d=Math.hypot(n.vx,n.vy)||1, m=Math.min(d, 40*t+2);
      n.x=Math.min(W-40,Math.max(40,n.x+n.vx/d*m)); n.y=Math.min(H-40,Math.max(40,n.y+n.vy/d*m));
    }
  }
  svg.setAttribute('viewBox',`0 0 ${W} ${H}`);
  const gE = document.createElementNS(NS,'g'), gN = document.createElementNS(NS,'g'); svg.append(gE,gN);
  const lines = edges.map(e=>{const l=document.createElementNS(NS,'line'); gE.append(l); return l});
  const els = nodes.map(n=>{
    const g=document.createElementNS(NS,'g'); g.dataset.kind=n.kind;
    const c=document.createElementNS(NS,'circle'); c.setAttribute('r', (n.kind==='target'?14:n.seed?9:6)*S); c.setAttribute('fill', color[n.kind]||'#475569');
    const ti=document.createElementNS(NS,'title'); ti.textContent=n.kind+': '+n.label+(n.sources.length?'\nfuentes: '+n.sources.join(', '):'');
    const tx=document.createElementNS(NS,'text'); tx.setAttribute('dx',10*S); tx.setAttribute('dy',3*S); tx.setAttribute('font-size',10*S); tx.setAttribute('stroke-width',3*S);
    tx.textContent = ['ip','nameserver','breach'].includes(n.kind) && !n.seed ? '' : (n.label.length>24?n.label.slice(0,23)+'…':n.label);
    g.append(c,ti,tx); gN.append(g); return g;
  });
  function draw(){
    edges.forEach((e,i)=>{const l=lines[i],a=nodes[e.a],b=nodes[e.b]; l.setAttribute('x1',a.x);l.setAttribute('y1',a.y);l.setAttribute('x2',b.x);l.setAttribute('y2',b.y)});
    nodes.forEach((n,i)=>els[i].setAttribute('transform',`translate(${n.x},${n.y})`));
  }
  draw();
  // Arrastrar nodos
  let drag=null;
  const pt = ev=>{const p=svg.createSVGPoint(); p.x=ev.clientX; p.y=ev.clientY; return p.matrixTransform(svg.getScreenCTM().inverse())};
  els.forEach((g,i)=>g.addEventListener('pointerdown',ev=>{drag=i; g.setPointerCapture(ev.pointerId)}));
  svg.addEventListener('pointermove',ev=>{if(drag===null)return; const p=pt(ev); nodes[drag].x=p.x; nodes[drag].y=p.y; draw()});
  svg.addEventListener('pointerup',()=>drag=null);
  // Filtro por tipo de entidad
  const hiddenKinds = new Set();
  function refresh(){
    els.forEach((g,i)=>g.classList.toggle('hidden', hiddenKinds.has(nodes[i].kind)));
    edges.forEach((e,i)=>lines[i].classList.toggle('hidden', hiddenKinds.has(nodes[e.a].kind)||hiddenKinds.has(nodes[e.b].kind)));
  }
  document.querySelectorAll('.lg').forEach(b=>b.addEventListener('click',()=>{
    const k=b.dataset.kind, on=b.getAttribute('aria-pressed')==='true';
    b.setAttribute('aria-pressed', String(!on)); on?hiddenKinds.add(k):hiddenKinds.delete(k); refresh();
  }));
})();
"""

_TEMPLATE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Informe OSINT</title>
<style>{css}</style></head>
<body><main>
<header>
  <h1>Informe de huella digital</h1>
  <p class="meta"><span>Inicio: {started}</span><span>Fin: {finished}</span></p>
  <h2 style="font-size:1rem;border:0;margin:1.2rem 0 .4rem;padding:0">Datos de entrada</h2>
  <ul class="seeds">{seeds}</ul>
  {summary}
</header>

<h2>Perfiles correlacionados</h2>{profiles}
<h2>Correlaciones entre fuentes</h2>{correlations}

<h2>Grafo de relaciones</h2>
<p class="muted">Arrastra los nodos para reorganizar; pulsa un tipo para ocultarlo (por ejemplo, IPs o servidores DNS).</p>
<div class="legend">{legend}</div>
<div id="graph-wrap"><svg id="graph" role="img" aria-label="Grafo de relaciones entre las entidades encontradas"></svg></div>
<script id="graph-data" type="application/json">{graph_json}</script>
<script id="graph-colors" type="application/json">{{"target":"#1f2937","name":"#c2410c","email":"#1d4ed8","username":"#047857","account":"#0f766e","domain":"#6d28d9","phone":"#be185d","breach":"#b91c1c","ip":"#64748b","nameserver":"#64748b","location":"#a16207","company":"#7c3aed"}}</script>

<h2>Hallazgos por módulo</h2>{modules}

<h2>Estado de los módulos</h2>
<div class="scroll"><table><thead><tr><th>Módulo</th><th>Estado</th><th>Selectores</th><th>Hallazgos</th><th>Errores</th><th>Tipo</th></tr></thead>
<tbody>{status_rows}</tbody></table></div>
{errors}

<footer>Generado con OSINT Orquestador. Solo fuentes públicas. Los datos pueden ser incorrectos o corresponder a homónimos:
verifica siempre antes de sacar conclusiones y usa la herramienta únicamente con autorización o sobre tu propia huella.</footer>
</main>
<script>{js}</script></body></html>
"""
