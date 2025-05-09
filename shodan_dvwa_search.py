import shodan
import os

# Clave de API (puedes usar una variable de entorno para mayor seguridad)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
print(f"SHODAN_API_KEY: {SHODAN_API_KEY}")
if not SHODAN_API_KEY:
    raise ValueError("Falta la API Key de Shodan (usa SHODAN_API_KEY como variable de entorno)")

# Inicializa el cliente de Shodan
api = shodan.Shodan(SHODAN_API_KEY)

try:
    # Buscar máquinas con DVWA
    results = api.search("DVWA")

    print(f"Resultados encontrados: {results['total']}")

    for result in results['matches']:
        print("="*60)
        print(f"IP: {result['ip_str']}")
        print(f"Puerto: {result['port']}")
        print(f"Organización: {result.get('org', 'N/A')}")
        print(f"Banner: {result['data']}")
except shodan.APIError as e:
    print(f"Error en la API: {e}")
