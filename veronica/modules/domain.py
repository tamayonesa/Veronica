import shutil
import subprocess
import socket

def ejecutar_comando(comando, tiempo_espera=12):
    try:
        proceso = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            timeout=tiempo_espera
        )
        return {
            "codigo_salida": proceso.returncode,
            "resultado": (proceso.stdout + proceso.stderr)[:10000]
        }
    except Exception as error:
        return {"error": str(error)}

def analizar_dominio(dominio):
    """Consulta registros DNS y WHOIS cuando las utilidades están disponibles."""
    dominio = dominio.strip().lower().rstrip(".")
    resultado = {"dominio": dominio, "dns": {}, "whois": None}
    dig = shutil.which("dig")

    for tipo in ("A", "AAAA", "MX", "NS", "TXT"):
        if dig:
            resultado["dns"][tipo] = ejecutar_comando([dig, "+short", dominio, tipo])
        elif tipo in ("A", "AAAA"):
            try:
                familia = socket.AF_INET if tipo == "A" else socket.AF_INET6
                direcciones = socket.getaddrinfo(dominio, None, familia)
                resultado["dns"][tipo] = {
                    "resultado": sorted({dato[4][0] for dato in direcciones})
                }
            except Exception as error:
                resultado["dns"][tipo] = {"error": str(error)}
        else:
            resultado["dns"][tipo] = {
                "nota": "Instala dig (dnsutils o bind-tools) para consultar este tipo de registro."
            }

    whois = shutil.which("whois")
    if whois:
        resultado["whois"] = ejecutar_comando([whois, dominio], tiempo_espera=20)
    else:
        resultado["whois"] = {"nota": "La utilidad whois no está instalada."}

    return resultado
