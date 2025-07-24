import os
import xml.etree.ElementTree as ET
from collections import defaultdict
import re

NESSUS_FILE = "file.nessus"
OUTPUT_DIR = "output_obsidian"

def sanitize(text):
    # Reemplaza espacios, slashes y elimina caracteres inválidos para nombres de archivos en Windows
    text = text.replace(" ", "_").replace("/", "-")
    return re.sub(r'[<>:"\\|?*]', '', text)

def get_severity_tag(sev):
    return {
        '0': '#info',
        '1': '#low',
        '2': '#medium',
        '3': '#high',
        '4': '#critical'
    }.get(sev, '#unknown')

tree = ET.parse(NESSUS_FILE)
root = tree.getroot()

hosts = defaultdict(list)
vulns = defaultdict(lambda: {'hosts': set(), 'severity': '0', 'cves': set()})
cves = defaultdict(set)

for report_host in root.findall(".//ReportHost"):
    ip = report_host.attrib.get("name")
    for item in report_host.findall(".//ReportItem"):
        plugin_name = sanitize(item.attrib.get("pluginName"))
        severity = item.attrib.get("severity")
        plugin_id = item.attrib.get("pluginID")
        port = item.attrib.get("port")
        protocol = item.attrib.get("protocol")
        svc_name = item.attrib.get("svc_name", "")
        description = item.findtext("description", "").strip()
        solution = item.findtext("solution", "").strip()
        cve_list = item.findtext("cve") or ""
        cves_found = [c.strip() for c in cve_list.split(",") if c.strip()]

        entry = {
            "plugin_name": plugin_name,
            "severity": severity,
            "plugin_id": plugin_id,
            "port": port,
            "protocol": protocol,
            "svc_name": svc_name,
            "description": description,
            "solution": solution,
            "cves": cves_found,
            "plugin_output": item.findtext("plugin_output", "").strip()
        }

        hosts[ip].append(entry)
        vulns[plugin_name]['hosts'].add(ip)
        vulns[plugin_name]['severity'] = severity
        vulns[plugin_name]['cves'].update(cves_found)
        vulns[plugin_name]['plugin_id'] = plugin_id
        vulns[plugin_name]['description'] = description
        vulns[plugin_name]['solution'] = solution
        for cve in cves_found:
            cves[cve].add(plugin_name)

# Crear carpetas
os.makedirs(f"{OUTPUT_DIR}/por_ip", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/por_vulnerabilidad", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/por_cve", exist_ok=True)

# Exportar por IP
for ip, items in hosts.items():
    with open(f"{OUTPUT_DIR}/por_ip/{sanitize(ip)}.md", "w", encoding="utf-8") as f:
        f.write(f"# {ip}\n\n")

        open_ports = {(entry['port'], entry['protocol'], entry['svc_name']) for entry in items}
        f.write("## Puertos abiertos\n")
        for port, proto, svc in sorted(open_ports, key=lambda x: int(x[0])):
            f.write(f"- `{port}/{proto}` ({svc})\n")

        f.write("\n## Vulnerabilidades\n")
        for entry in items:
            f.write(f"### [[{entry['plugin_name']}]] {get_severity_tag(entry['severity'])}\n")
            f.write(f"- **Puerto:** `{entry['port']}/{entry['protocol']}`\n")
            if entry['svc_name']:
                f.write(f"- **Servicio:** `{entry['svc_name']}`\n")
            if entry['cves']:
                f.write(f"- **CVEs:** " + ", ".join([f"[[{cve}]]" for cve in entry['cves']]) + "\n")
            
            # Aquí agregas el plugin_output
            if entry['plugin_output']:
                f.write("\n#### Evidencia:\n")
                f.write("```text\n")
                f.write(entry['plugin_output'][:5000])  # para evitar que archivos enormes rompan Obsidian
                f.write("\n```\n")

            f.write("\n---\n")



# Exportar por vulnerabilidad
for vuln, data in vulns.items():
    with open(f"{OUTPUT_DIR}/por_vulnerabilidad/{sanitize(vuln)}.md", "w", encoding="utf-8") as f:
        f.write(f"# {vuln}\n")
        f.write(f"- Plugin ID: `{data['plugin_id']}`\n")
        f.write(f"- Severidad: {get_severity_tag(data['severity'])}\n")

        if data['cves']:
            f.write("- CVEs: " + ", ".join([f"[[{c}]]" for c in sorted(data['cves'])]) + "\n")

        f.write("\n## Afecta a:\n")
        for ip in sorted(data['hosts']):
            f.write(f"- [[{ip}]]\n")

        f.write("\n## Descripción\n")
        f.write(f"{data['description']}\n\n")

        f.write("## Solución\n")
        f.write(f"{data['solution']}\n")

# Exportar por CVE
for cve, plugins in cves.items():
    with open(f"{OUTPUT_DIR}/por_cve/{sanitize(cve)}.md", "w") as f:
        f.write(f"# {cve}\n\nRelacionado con:\n")
        for plugin_name in sorted(plugins):
            f.write(f"- [[{plugin_name}]]\n")

# Crear resumen
with open(f"{OUTPUT_DIR}/resumen.md", "w") as f:
    f.write("# Resumen del Scan\n\n")
    f.write(f"IPs encontradas: {len(hosts)}\n\n## IPs\n")
    for ip in sorted(hosts):
        f.write(f"- [[{ip}]]\n")
    f.write("\n## Vulnerabilidades\n")
    for vuln in sorted(vulns):
        f.write(f"- [[{vuln}]]\n")
    f.write("\n## CVEs\n")
    for cve in sorted(cves):
        f.write(f"- [[{cve}]]\n")
