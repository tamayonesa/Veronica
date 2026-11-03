import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .modules.username import comprobar_usuario
from .modules.domain import analizar_dominio
from .modules.email import analizar_correo
from .modules.name import buscar_nombre

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

def main():
    parser = argparse.ArgumentParser(
        description="Veronica: herramienta modular de recopilación OSINT."
    )
    parser.add_argument("--nombre", help="Nombre que se desea investigar")
    parser.add_argument("--usuario", help="Nombre de usuario que se desea comprobar")
    parser.add_argument("--correo", help="Correo electrónico que se desea analizar")
    parser.add_argument("--dominio", help="Dominio que se desea analizar")
    parser.add_argument("--salida", default="informe-veronica.json",
                        help="Ruta del informe JSON de salida")
    parser.add_argument("--sherlock", action="store_true",
                        help="Ejecutar Sherlock si está instalado")
    args = parser.parse_args()

    if not any([args.nombre, args.usuario, args.correo, args.dominio]):
        parser.error("Indica al menos uno de estos parámetros: --nombre, --usuario, --correo o --dominio")

    print(BANNER)
    informe = {
        "herramienta": "Veronica",
        "version": "1.0.0",
        "fecha_utc": datetime.now(timezone.utc).isoformat(),
        "alcance": {
            "nombre": args.nombre,
            "usuario": args.usuario,
            "correo": args.correo,
            "dominio": args.dominio
        },
        "modulos": {},
        "aviso": "Uso autorizado. Los resultados son indicios y deben verificarse."
    }

    if args.nombre:
        informe["modulos"]["busqueda_nombre"] = buscar_nombre(args.nombre)
    if args.usuario:
        informe["modulos"]["usuario"] = comprobar_usuario(args.usuario, args.sherlock)
    if args.correo:
        informe["modulos"]["correo"] = analizar_correo(args.correo)
    if args.dominio:
        informe["modulos"]["dominio"] = analizar_dominio(args.dominio)

    ruta = Path(args.salida)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(json.dumps(informe, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Informe guardado en: {ruta.resolve()}")
    print("[!] Verifica manualmente las coincidencias antes de sacar conclusiones.")

if __name__ == "__main__":
    main()
