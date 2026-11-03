from urllib.parse import quote_plus

def buscar_nombre(nombre):
    """Genera enlaces de búsqueda pública para revisión manual."""
    consulta = quote_plus(nombre)
    return {
        "consulta": nombre,
        "enlaces": [
            {"fuente": "DuckDuckGo", "url": f"https://duckduckgo.com/?q={consulta}"},
            {"fuente": "Google", "url": f"https://www.google.com/search?q={consulta}"},
            {"fuente": "Bing", "url": f"https://www.bing.com/search?q={consulta}"}
        ],
        "nota": "Los nombres no son identificadores únicos. Revisa el contexto de cada resultado."
    }
