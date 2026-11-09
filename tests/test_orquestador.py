"""
Tests (sin red, sin dependencias):  python -m unittest discover -s tests -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orquestador.core import Context, InvalidSelector, Selector, normalize_selector_value  # noqa: E402
from orquestador.graph import Graph  # noqa: E402
from orquestador.http import HttpClient  # noqa: E402
from orquestador.modules.external import SherlockModule, TheHarvesterModule  # noqa: E402
from orquestador.modules.name_intel import username_candidates  # noqa: E402
from orquestador.modules.phone import to_e164  # noqa: E402
from orquestador.report import to_html, write_reports  # noqa: E402
from orquestador.runner import run_scan  # noqa: E402


class TestSelectores(unittest.TestCase):
    def test_validacion_correcta(self):
        self.assertEqual(normalize_selector_value("email", " Ana@Ejemplo.COM "), "ana@ejemplo.com")
        self.assertEqual(normalize_selector_value("domain", "https://Ejemplo.com/ruta"), "ejemplo.com")
        self.assertEqual(normalize_selector_value("username", "@ana_99"), "ana_99")
        self.assertEqual(normalize_selector_value("phone", "600 00 00 01", "ES"), "+34600000001")
        self.assertEqual(normalize_selector_value("phone", "0034600000001"), "+34600000001")

    def test_rechaza_inyeccion_de_argumentos(self):
        # Los valores acaban como argumentos de herramientas externas: nada que empiece por '-'.
        for kind, bad in [("username", "-oX"), ("username", "a b"), ("domain", "-d evil.com"),
                          ("email", "a@b"), ("name", "--help"), ("phone", "12")]:
            with self.assertRaises(InvalidSelector, msg=f"{kind}:{bad}"):
                normalize_selector_value(kind, bad)

    def test_igualdad_ignora_origen(self):
        self.assertEqual(Selector("email", "a@b.com", guess=True), Selector("email", "a@b.com"))


class TestUtilidades(unittest.TestCase):
    def test_candidatos_username(self):
        c = username_candidates("Lucía Marín Ortega")
        self.assertIn("lucia.marin", c)
        self.assertIn("lmarin", c)
        self.assertTrue(all(x.isascii() for x in c))

    def test_e164(self):
        self.assertEqual(to_e164("+34 600-000-001"), "+34600000001")


class TestParsersExternos(unittest.TestCase):
    def setUp(self):
        self.ctx = Context(HttpClient(fixtures=[]), {})

    def test_sherlock(self):
        out = "[*] Checking username x\n[+] GitHub: https://github.com/x\n[+] Reddit: https://www.reddit.com/user/x\n[-] Foo: Not Found!\n"
        f = SherlockModule(self.ctx).parse(Selector("username", "x"), out)
        self.assertEqual([x.url for x in f], ["https://github.com/x", "https://www.reddit.com/user/x"])

    def test_theharvester(self):
        data = {"emails": ["A@b.com"], "hosts": ["www.b.com:1.2.3.4", "api.b.com"], "ips": ["1.2.3.4"]}
        f = TheHarvesterModule(self.ctx).parse(Selector("domain", "b.com"), data)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].data["emails"], ["a@b.com"])
        self.assertEqual(f[0].data["hosts"], ["api.b.com", "www.b.com"])


FIXTURES = [
    {"match": r"api\.github\.com/users/ana$", "json": {"login": "ana", "name": "Ana Prueba", "html_url": "https://github.com/ana",
                                                    "blog": "https://ana-prueba.example"}},
    {"match": r"api\.github\.com/users/ana/events", "json": [{"payload": {"commits": [{"author": {"email": "ana@ana-prueba.example"}}]}}]},
    {"match": r"^https://github\.com/ana$", "status": 200, "text": "ok"},
]


class TestFlujoCompleto(unittest.TestCase):
    """Ejecuta el orquestador completo con respuestas HTTP simuladas (sin red)."""

    @classmethod
    def setUpClass(cls):
        cls.res = run_scan([Selector("username", "ana")], fixtures=FIXTURES,
                           only=["github", "usernames", "email_intel"])

    def test_pivote_descubre_email_y_dominio(self):
        valores = {s.value for s in cls_sel(self.res)}
        self.assertIn("ana@ana-prueba.example", valores)
        self.assertIn("ana-prueba.example", valores)

    def test_sin_errores_y_con_grafo(self):
        self.assertEqual(self.res.errors, [])
        g: Graph = self.res.graph
        self.assertIn("graph OSINT", g.to_dot())
        self.assertIn("<graphml", g.to_graphml())
        self.assertTrue(g.to_maltego_csv().startswith("source_type,"))

    def test_html_escapa_contenido_no_confiable(self):
        self.res.findings[0].data["bio"] = "<script>alert(1)</script>"
        self.res.findings[0].url = "javascript:alert(1)"
        html = to_html(self.res)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn('href="javascript:', html)

    def test_escritura_de_informes(self):
        with tempfile.TemporaryDirectory() as d:
            files = write_reports(self.res, d, ["json", "html", "dot", "graphml", "csv"])
            self.assertEqual(len(files), 5)
            self.assertIn("hallazgos", json.loads((Path(d) / "informe.json").read_text(encoding="utf-8")))


def cls_sel(res):
    return res.selectors


if __name__ == "__main__":
    unittest.main()
