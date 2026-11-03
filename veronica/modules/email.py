import re
from .domain import analizar_dominio

PATRON_CORREO = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)

def analizar_correo(correo):
    """Valida el formato y analiza el dominio asociado al correo."""
    correo = correo.strip()
    if not PATRON_CORREO.match(correo):
        return {
            "correo": correo,
            "formato_valido": False,
            "nota": "El correo no cumple la comprobación básica de formato."
        }

    dominio = correo.rsplit("@", 1)[1]
    return {
        "correo": correo,
        "formato_valido": True,
        "dominio": dominio,
        "analisis_dominio": analizar_dominio(dominio),
        "nota": "No se comprueba el buzón ni se consulta una base de datos de filtraciones."
    }
