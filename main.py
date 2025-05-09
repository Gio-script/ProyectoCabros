import json
import csv
import os
import requests
import logging
from datetime import datetime
from dotenv import load_dotenv
from typing import List, Dict, Optional
from requests.exceptions import ConnectionError, Timeout, RequestException

# ---------------- Crear carpetas necesarias ----------------
def crear_carpetas():
    os.makedirs("json", exist_ok=True)
    os.makedirs("logs", exist_ok=True)

# ---------------- Configuración de Logging ----------------
crear_carpetas()
log_path = os.path.join("logs", "busquedas.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(log_path, encoding='utf-8'), logging.StreamHandler()]
)

# ---------------- Cargar variables de entorno ----------------
def load_env_variables() -> Optional[Dict[str, str]]:
    load_dotenv()
    api_key = os.getenv('API_KEY_SEARCH_GOOGLE')
    search_engine_id = os.getenv('SEARCH_ENGINE_ID')

    if not api_key or not search_engine_id:
        logging.error("API Key o Search Engine ID no encontrados en el archivo .env")
        return None
    logging.info("API Key y Search Engine ID cargados correctamente.")
    return {
        'api_key': api_key,
        'search_engine_id': search_engine_id
    }

# ---------------- Realizar búsqueda en Google ----------------
def perform_google_search(api_key: str, search_engine_id: str, query: str, start: int = 1, lang: str = "lang_es") -> Optional[List[Dict]]:
    base_url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": api_key,
        "cx": search_engine_id,
        "q": query,
        "start": start,
        "lr": lang
    }

    try:
        response = requests.get(base_url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("items", [])

    except ConnectionError:
        logging.error("Error de conexión.")
    except Timeout:
        logging.error("La solicitud ha superado el tiempo de espera.")
    except RequestException as e:
        logging.error(f"Error HTTP: {e}")
    except ValueError as e:
        logging.error(f"Error al parsear JSON: {e}")
    except Exception as e:
        logging.exception("Error inesperado")
    
    return None

# ---------------- Evaluar nivel de riesgo ----------------
def analyze_risk(result: Dict) -> str:
    risk_keywords = ["password", "passwd", "secret", "config", "credentials","DB"]
    snippet = result.get("snippet", "").lower()
    score = sum(kw in snippet for kw in risk_keywords)
    return "ALTO" if score >= 2 else "MEDIO" if score == 1 else "BAJO"

# ---------------- Mostrar resultados ----------------
def display_results(results: List[Dict]) -> None:
    for result in results:
        print("------- Resultado -------")
        print(f"Título: {result.get('title')}")
        print(f"Descripción: {result.get('snippet')}")
        print(f"Enlace: {result.get('link')}")
        print(f"Nivel de Riesgo: {analyze_risk(result)}")
        print("-------------------------")

# ---------------- Exportar resultados ----------------
def export_results(results: List[Dict], format: str = "json", filename: str = "results") -> None:
    if format == "json":
        ruta_json = os.path.join("json", f"{filename}.json")
        with open(ruta_json, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        logging.info(f"[✓] Resultados guardados en {ruta_json}")
    elif format == "csv":
        ruta_csv = os.path.join("json", f"{filename}.csv")
        with open(ruta_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["title", "snippet", "link"])
            writer.writeheader()
            for result in results:
                writer.writerow({
                    "title": result.get("title", ""),
                    "snippet": result.get("snippet", ""),
                    "link": result.get("link", "")
                })
        logging.info(f"[✓] Resultados guardados en {ruta_csv}")

# ---------------- Guardar historial de consultas ----------------
def log_query(query: str):
    with open(os.path.join("logs", "busquedas.log"), "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} - {query}\n")

# ---------------- Ejecución Principal ----------------
def main():
    env_vars = load_env_variables()
    if not env_vars:
        return

    dorks = [
        'filetype:sql "MySQL dump"',
        'intitle:"index of" "backup"',
        'filetype:env DB_PASSWORD'
    ]

    all_results = []
    for query in dorks:
        print(f"\n🔍 Ejecutando búsqueda: {query}")
        log_query(query)
        results = perform_google_search(env_vars['api_key'], env_vars['search_engine_id'], query)

        if results:
            display_results(results)
            all_results.extend(results)
        else:
            logging.info("No se encontraron resultados o error en la búsqueda.")

    if all_results:
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"results_{now}"
        export_results(all_results, "json", filename)

if __name__ == "__main__":
    main()
