import os
import re
import xml.etree.ElementTree as ET
import ipaddress
import json

# Función para limpiar nombres de archivo
def limpiar_nombre_archivo(nombre):
    # Remueve caracteres no permitidos en nombres de archivos
    nombre_limpio = re.sub(r'[<>:"/\\|?*]', '', nombre)
    return nombre_limpio[:100]

# Función para leer el archivo .nessus y generar los archivos correspondientes
def leer_archivo_nessus_y_generar_md(ruta_archivo):
    tree = ET.parse(ruta_archivo)
    root = tree.getroot()

    # Crear la carpeta SYNscanner si no existe
    synscanner_dir = 'SYNscanner'
    if not os.path.exists(synscanner_dir):
        os.makedirs(synscanner_dir)

    syn_ips_afectadas = {}  # Almacenar datos específicos para Nessus SYN Scanner

    # Recorrer las IPs y reportes en el archivo .nessus
    for report_host in root.findall('.//ReportHost'):
        ip = report_host.attrib.get('name', 'Desconocido')
        
        for report_item in report_host.findall('.//ReportItem'):            
            plugin_name = report_item.attrib.get('pluginName')
            port = report_item.attrib.get('port', 'Desconocido')
            protocol = report_item.attrib.get('protocol', 'Desconocido')
            svc_name = report_item.attrib.get('svc_name', 'Desconocido')
            evidence = report_item.findtext('plugin_output', '').strip()
            print(f"Plugin Name: {plugin_name}")

            # Verificar si el plugin es "Nessus SYN Scanner"
            if plugin_name == "Nessus SYN scanner":
                print(f"Encontrado 'Nessus SYN Scanner' en IP: {ip}, Puerto: {port}")
                if ip not in syn_ips_afectadas:
                    syn_ips_afectadas[ip] = []
                syn_ips_afectadas[ip].append({
                    'port': port,
                    'protocol': protocol,
                    'svc_name': svc_name,
                    'Evidence': evidence
                })

    # Crear archivo consolidado para "Nessus SYN Scanner"
    crear_archivo_md_syn_scanner(syn_ips_afectadas, synscanner_dir)

def crear_archivo_md_syn_scanner(ips_afectadas, synscanner_dir):
    # Crear el archivo específico en la carpeta SYNscanner
    ruta_archivo_vuln = os.path.join(synscanner_dir, "Nessus SYN Scanner.md")
    with open(ruta_archivo_vuln, 'w') as f:
        f.write("# Nessus SYN Scanner\n\n")
        f.write("Consolidación de todas las IPs, puertos y evidencias afectadas por la vulnerabilidad Nessus SYN Scanner.\n\n")

        for ip, ports in ips_afectadas.items():
            f.write(f"## IP: {ip}\n")
            for port_info in ports:
                f.write(f"- **Puerto**: {port_info['port']} ({port_info['protocol']})/{port_info['svc_name']}\n")
                if port_info.get('Evidence'):
                    f.write(f"  - **Evidencia**:\n```\n{port_info['Evidence']}\n```\n")
            f.write("\n")  # Espacio adicional entre IPs

    print(f"Archivo consolidado creado para Nessus SYN Scanner en: {ruta_archivo_vuln}")

# Ruta al archivo .nessus
leer_archivo_nessus_y_generar_md('PLAT-1_xn4dam.nessus')
