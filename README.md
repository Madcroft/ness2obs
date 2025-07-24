# 📄 Nessus to Obsidian Markdown Exporter

Este script convierte un archivo `.nessus` (formato XML de Tenable/Nessus) en una colección de notas Markdown interconectadas, listas para usar en [Obsidian](https://obsidian.md). Permite visualizar hallazgos por IP, vulnerabilidad y CVE, con evidencia incluida por puerto.

---

## 🎯 Objetivo

- Organizar hallazgos de escaneos Nessus de forma estructurada y navegable.
- Visualizar relaciones entre IPs, vulnerabilidades y CVEs en el **graph view** de Obsidian.
- Integrar evidencias técnicas (`plugin_output`) para auditoría y análisis detallado.
- Facilitar documentación y reporte para pentesters, Red Team y equipos de seguridad ofensiva.

---

## 📁 Estructura generada

```
output_obsidian/
├── resumen.md                    # Vista general del escaneo
├── por_ip/                      # Notas por dirección IP
│   ├── 192.168.1.1.md
│   └── ...
├── por_vulnerabilidad/          # Notas por vulnerabilidad (pluginName)
│   ├── SSL_Version_Too_Low.md
│   └── ...
├── por_cve/                     # Notas por CVE
│   ├── CVE-2023-1234.md
│   └── ...
```

---

## ✅ Funcionalidades

- 🔍 Parseo completo del archivo `.nessus` en formato XML.
- 📌 Agrupación por IP con:
  - Puertos abiertos detectados
  - Servicios y protocolos
  - Vulnerabilidades encontradas
  - Evidencia técnica (plugin_output)
- 📎 Relación cruzada IP ↔ Vulnerabilidad ↔ CVE
- 🧷 Etiquetas por severidad: `#critical`, `#high`, etc.
- 🧠 Ideal para visualización de nodos en Obsidian y navegación contextual.

---

## ⚙️ Uso

1. Guarda tu archivo `.nessus` con el nombre `file.nessus` (o cambia la variable `NESSUS_FILE`).
2. Ejecuta el script:

```bash
python3 nessus_to_obsidian.py
```

3. Abre la carpeta `output_obsidian/` como un nuevo Vault en Obsidian.

---

## 🧪 Ejemplo de salida por IP (`por_ip/192.168.1.1.md`)

```markdown
# 192.168.1.1

## Puertos abiertos
- `80/tcp` (http)
- `443/tcp` (https)

## Vulnerabilidades

### [[SSL Certificate Expiry]] #medium
- **Puerto:** `443/tcp`
- **Servicio:** `https`
- **CVEs:** [[CVE-2021-3449]]

#### Evidencia:
```text
The certificate expires in 3 days.
Subject: CN=example.com
Issuer: Let's Encrypt Authority
```
---

## 🔧 Requisitos

- Python 3.x
- Archivo `.nessus` válido (exportado desde Tenable/Nessus)

---

## ✍️ Personalización

Puedes modificar fácilmente:
- `NESSUS_FILE` para cambiar el input
- `OUTPUT_DIR` para cambiar el nombre del directorio de salida
- Agregar más metadata del XML si necesitas campos como `risk_factor`, `plugin_family`, etc.

---

## 📜 Licencia

Este proyecto es de uso libre bajo la licencia MIT.

---

## 💡 Ideas futuras

- Generar gráficos (pie/bar) por severidad o CVEs
- Exportar CSV para reporting
- Integración con herramientas como BloodHound o mitre-attack-navigator
