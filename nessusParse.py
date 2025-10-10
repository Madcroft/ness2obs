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

# Función para obtener la subred de una IP
def obtener_subred(ip, prefijo=24):
    ip_obj = ipaddress.ip_network(f"{ip}/{prefijo}", strict=False)
    return str(ip_obj.network_address)

# Función para crear un archivo Markdown por IP
def crear_archivo_md_por_ip(host, ip, puertos_abiertos, vulnerabilidades):
    nombre_archivo_ip = f"{limpiar_nombre_archivo(ip)}.md"
    ruta_archivo_ip = os.path.join('ips', nombre_archivo_ip)

    with open(ruta_archivo_ip, 'w') as f:
        f.write(f"# IP: {ip}\n\n")
        f.write(f"**Nombre de Host**: {host}\n\n")
        f.write("## Puertos Abiertos:\n\n")
        for puerto in puertos_abiertos:
            enlace_puerto = f"[[{puerto['port']} ({puerto['protocol']}) - {ip}]]"
            f.write(f"- {enlace_puerto}\n")

        f.write("\n## Vulnerabilidades:\n\n")
        for v in vulnerabilidades:
            enlace_vuln = f"[[{limpiar_nombre_archivo(v['Plugin ID'])} - {limpiar_nombre_archivo(v['Plugin Name'])}]]"
            f.write(f"- {enlace_vuln} (Severidad: {v['Severity']})\n")

    print(f"Archivo creado para la IP: {ruta_archivo_ip}")

# Función para crear un archivo Markdown por vulnerabilidad
def crear_archivo_md_por_vulnerabilidad(vulnerabilidad, ips_afectadas):
    nombre_archivo_vuln = f"{limpiar_nombre_archivo(vulnerabilidad['Plugin ID'])} - {limpiar_nombre_archivo(vulnerabilidad['Plugin Name'])}.md"
    ruta_archivo_vuln = os.path.join('vulnerabilidades', nombre_archivo_vuln)

    with open(ruta_archivo_vuln, 'w') as f:
        f.write(f"# {vulnerabilidad['Plugin Name']}\n\n")
        f.write(f"**Plugin ID**: {vulnerabilidad['Plugin ID']}\n\n")
        f.write(f"**Severidad**: {vulnerabilidad['Severity']}\n\n")
        f.write(f"**Descripción**: {vulnerabilidad.get('Description', 'No disponible')}\n\n")

        f.write("## IPs Afectadas:\n\n")
        for ip in ips_afectadas:
            enlace_ip = f"[[{limpiar_nombre_archivo(ip)}]]"
            f.write(f"- {enlace_ip}\n")

    print(f"Archivo creado para la vulnerabilidad: {ruta_archivo_vuln}")

# Función para crear un archivo Markdown por puerto
def crear_archivo_md_por_puerto(host, puerto, vulnerabilidades):
    nombre_archivo_puerto = f"{puerto['port']} ({puerto['protocol']}) - {limpiar_nombre_archivo(host)}.md"
    ruta_archivo_puerto = os.path.join('puertos', nombre_archivo_puerto)

    with open(ruta_archivo_puerto, 'w') as f:
        f.write(f"# Puerto: {puerto['port']} ({puerto['protocol']}) - {host}\n\n")
        f.write("## Vulnerabilidades asociadas:\n\n")
        for v in vulnerabilidades:
            enlace_vuln = f"[[{limpiar_nombre_archivo(v['Plugin ID'])} - {limpiar_nombre_archivo(v['Plugin Name'])}]]"
            f.write(f"- {enlace_vuln} (Severidad: {v['Severity']})\n")
            if 'Evidence' in v and v['Evidence']:
                f.write(f"  - **Evidencia**:\n```\n{v['Evidence']}\n```\n")

    print(f"Archivo creado para el puerto: {ruta_archivo_puerto}")

# Función para leer el archivo .nessus y generar los archivos correspondientes
def leer_archivo_nessus_y_generar_md(ruta_archivo):
    tree = ET.parse(ruta_archivo)
    root = tree.getroot()

    if not os.path.exists('ips'): os.makedirs('ips')
    if not os.path.exists('vulnerabilidades'): os.makedirs('vulnerabilidades')
    if not os.path.exists('puertos'): os.makedirs('puertos')
    if not os.path.exists('subredes'): os.makedirs('subredes')

    subredes = {}
    vulnerabilidad_a_ips = {}

    for report_host in root.findall('.//ReportHost'):
        ip = report_host.attrib.get('name', 'Desconocido')
        
        # Intentar obtener el DNS hostname desde el campo `host-fqdns`
        host_name = 'Desconocido'
        for tag in report_host.findall(".//HostProperties/tag"):
            if tag.attrib.get("name") == "host-fqdns":
                try:
                    # Intenta cargar el contenido como JSON
                    fqdn_data = json.loads(tag.text)
                    # Si `fqdn_data` es una lista, toma el primer elemento
                    if isinstance(fqdn_data, list):
                        host_name = fqdn_data[0].get("FQDN", 'Desconocido')
                    else:
                        host_name = fqdn_data.get("FQDN", 'Desconocido')
                except json.JSONDecodeError:
                    # Si no se puede decodificar como JSON, usa el valor sin procesar
                    host_name = tag.text
                break

        # Si `host-fqdns` no se encuentra, intenta con otros campos
        if host_name == 'Desconocido':
            host_name = report_host.findtext('.//dnsName', 'Desconocido')
        if host_name == 'Desconocido':
            host_name = report_host.findtext('.//NetBIOS', 'Desconocido')
        if host_name == 'Desconocido':
            host_name = report_host.attrib.get('name', 'Desconocido')  # Usa la IP si no hay nombre de host disponible

        subred = obtener_subred(ip)

        if subred not in subredes:
            subredes[subred] = []
        subredes[subred].append(ip)

        puertos_abiertos = {}
        for report_item in report_host.findall('.//ReportItem'):
            plugin_id = report_item.attrib.get('pluginID')
            plugin_name = report_item.attrib.get('pluginName')
            severity = report_item.attrib.get('severity')
            description = report_item.findtext('description', 'No disponible')
            evidence = report_item.findtext('plugin_output', '')
            port = report_item.attrib.get('port', 'Desconocido')
            protocol = report_item.attrib.get('protocol', 'Desconocido')

            vulnerabilidad = {
                'Plugin ID': plugin_id,
                'Plugin Name': plugin_name,
                'Severity': severity,
                'Description': description,
                'Evidence': evidence.strip()
            }

            if plugin_id not in vulnerabilidad_a_ips:
                vulnerabilidad_a_ips[plugin_id] = {
                    'vulnerabilidad': vulnerabilidad,
                    'ips_afectadas': []
                }
            vulnerabilidad_a_ips[plugin_id]['ips_afectadas'].append(ip)

            if port not in puertos_abiertos:
                puertos_abiertos[port] = {'protocol': protocol, 'vulnerabilidades': []}
            puertos_abiertos[port]['vulnerabilidades'].append(vulnerabilidad)

        vulnerabilidades = [v for datos_puerto in puertos_abiertos.values() for v in datos_puerto['vulnerabilidades']]
        crear_archivo_md_por_ip(host_name, ip, [{'port': port, 'protocol': datos_puerto['protocol']} for port, datos_puerto in puertos_abiertos.items()], vulnerabilidades)

        for port, datos_puerto in puertos_abiertos.items():
            crear_archivo_md_por_puerto(ip, {'port': port, 'protocol': datos_puerto['protocol']}, datos_puerto['vulnerabilidades'])

    for subred, ips in subredes.items():
        with open(os.path.join('subredes', f"{limpiar_nombre_archivo(subred)}.md"), 'w') as f:
            f.write(f"# Subred: {subred}\n\n")
            f.write("## IPs en esta subred:\n\n")
            for ip in ips:
                f.write(f"- [[{limpiar_nombre_archivo(ip)}]]\n")

    for plugin_id, data in vulnerabilidad_a_ips.items():
        crear_archivo_md_por_vulnerabilidad(data['vulnerabilidad'], data['ips_afectadas'])

# Ruta al archivo .nessus
leer_archivo_nessus_y_generar_md('file.nessus')

