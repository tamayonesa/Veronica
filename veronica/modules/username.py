import shutil
import subprocess
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

PLATAFORMAS = {
    "GitHub": "https://github.com/{}/",
    "GitLab": "https://gitlab.com/{}/",
    "Reddit": "https://www.reddit.com/user/{}/",
    "Instagram": "https://www.instagram.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}/",
    "YouTube": "https://www.youtube.com/@{}/",
    "X": "https://x.com/{}"
}

def comprobar_usuario(usuario, ejecutar_sherlock=False):
    """Comprueba la accesibilidad HTTP de perfiles públicos."""
    resultados = []
    for plataforma, plantilla in PLATAFORMAS.items():
        url = plantilla.format(usuario)
        estado = "desconocido"
        try:
            peticion = Request(
                url,
                headers={"User-Agent": "Veronica-OSINT/1.0"}
            )
            with urlopen(peticion, timeout=7) as respuesta:
                estado = "accesible" if respuesta.status < 400 else f"http_{respuesta.status}"
        except HTTPError as error:
            estado = f"http_{error.code}"
        except (URLError, TimeoutError):
            estado = "no_disponible_o_bloqueado"

        resultados.append({
            "plataforma": plataforma,
            "url": url,
            "estado": estado,
            "nota": "La accesibilidad HTTP no confirma la titularidad de la cuenta."
        })

    integracion = {
        "solicitada": bool(ejecutar_sherlock),
        "disponible": False,
        "resultado": None
    }

    if ejecutar_sherlock:
        ejecutable = shutil.which("sherlock")
        if ejecutable:
            integracion["disponible"] = True
            try:
                proceso = subprocess.run(
                    [ejecutable, usuario, "--print-found"],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                integracion["resultado"] = (proceso.stdout + proceso.stderr)[-12000:]
                integracion["codigo_salida"] = proceso.returncode
            except Exception as error:
                integracion["error"] = str(error)
        else:
            integracion["nota"] = "No se encuentra Sherlock en el PATH. Instálalo para activar esta integración."

    return {
        "usuario": usuario,
        "comprobaciones": resultados,
        "sherlock": integracion
    }
