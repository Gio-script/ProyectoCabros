import json
import dns.resolver
import whois
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
import os


class DNSResolver:
    def __init__(self, domain, record_types=None):
        self.domain = domain
        self.record_types = record_types or ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
        self.resolver = dns.resolver.Resolver()
        self.report = {
            "domain": domain,
            "resolved_at": datetime.utcnow().isoformat(),
            "records": {},
            "whois": {},
            "nmap": []
        }

    def resolve_all(self):
        for record_type in self.record_types:
            try:
                answers = self.resolver.resolve(self.domain, record_type)
                self.report["records"][record_type] = [str(data) for data in answers]
            except dns.resolver.NoAnswer:
                self.report["records"][record_type] = []
            except dns.resolver.NXDOMAIN:
                print(f"❌ Dominio no existe: {self.domain}")
                break
            except Exception as e:
                print(f"⚠️ Error al resolver {record_type} para {self.domain}: {e}")
                self.report["records"][record_type] = []

    def resolve_whois(self):
        try:
            w = whois.whois(self.domain)
            self.report["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "country": w.country,
                "whois_server": w.whois_server,
                "updated_date": str(w.updated_date),
                "domain_name": w.domain_name,
            }
        except Exception as e:
            print(f"⚠️ Error al obtener WHOIS de {self.domain}: {e}")
            self.report["whois"] = {"error": str(e)}
            
    def extract_ips_for_scan(self):
        # Extraer IPs de los registros A y NS
        ips = self.report["records"].get("A", [])
    
    # Resolver los servidores NS (si terminan en el mismo dominio)
        ns_records = self.report["records"].get("NS", [])
        for ns in ns_records:
            try:
                ns_ip = self.resolver.resolve(ns.rstrip('.'), 'A')
                ips.extend([str(ip) for ip in ns_ip])
            except:
                continue

    # También puedes hacer esto para los registros MX si necesitas
        return list(set(ips))  # Evitar duplicados

    
    def scan_with_nmap(self):
        if not self.report["records"].get("A"):
            print("aplicar a ")
            ips = self.extract_ips_for_scan()

        ips = self.report["records"].get("A", [])
        for ip in ips:
            print(f"🔍 Escaneando IP: {ip}")
            try:
                xml_output = f"/tmp/nmap_{ip}.xml"
                subprocess.run(
                    ["nmap", "-A", "-Pn", "-T4", "-oX", xml_output, ip],
                    check=True,
                    capture_output=True
                )
                self.parse_nmap(xml_output)
                os.remove(xml_output)  # Limpieza opcional
            except subprocess.CalledProcessError as e:
                print(f"⚠️ Error al ejecutar Nmap: {e}")

    def parse_nmap(self, xml_path):
        tree = ET.parse(xml_path)
        root = tree.getroot()
        host = root.find("host")

        host_info = {"ip": "", "ports": []}
        address = host.find("address")
        if address is not None:
            host_info["ip"] = address.attrib["addr"]

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                port_info = {
                    "port": port.attrib["portid"],
                    "protocol": port.attrib["protocol"],
                    "state": port.find("state").attrib["state"],
                    "service": {}
                }
                service = port.find("service")
                if service is not None:
                    port_info["service"] = {
                        "name": service.attrib.get("name", ""),
                        "product": service.attrib.get("product", ""),
                        "version": service.attrib.get("version", "")
                    }
                host_info["ports"].append(port_info)

        self.report["nmap"].append(host_info)

    def export_to_json(self, output_path):
        output_path = os.getenv("OUTPUT_PATH", output_path)
        if not output_path.endswith(".json"):
            output_path += ".json"
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(self.report, file, indent=4, default=str)
        print(f"✅ Reporte guardado en {output_path}")


if __name__ == "__main__":
    target_domain = "educativaipchile.cl"
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

    dns_checker = DNSResolver(target_domain, record_types)
    dns_checker.resolve_all()
    dns_checker.resolve_whois()
    dns_checker.scan_with_nmap()
    dns_checker.export_to_json(f"reportes_dns/{target_domain}_dns_report.json")
