# ness2obs — Convertir exportaciones de Nessus a Markdown para Obsidian

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-Active-brightgreen.svg)](#)
[![Obsidian](https://img.shields.io/badge/Obsidian-Compatible-7C3AED.svg)](https://obsidian.md/)

> Convierte resultados de **Nessus** a notas **Markdown** listas para **Obsidian**, para que puedas documentar hallazgos, hosts y puertos de forma rápida y reutilizable en tus auditorías.

Repositorio: https://github.com/Madcroft/ness2obs

---

## ✨ Resumen

**ness2obs** es un conjunto de utilidades en Python orientadas a transformar exportaciones de Nessus en notas Markdown estructuradas, con foco en un flujo de trabajo de **pentesting / OSCP**.  
Incluye scripts para:

- Parsear resultados de Nessus y generar notas por **host** y/o por **vulnerabilidad**.
- Incluir información de **SYN scan** cuando está disponible (p. ej., lista de puertos detectados).
- Organizar la salida con una estructura de carpetas compatible con **Obsidian** (vault).

> Nota: A fecha de redacción, el repositorio expone estos scripts principales: `nessusParse.py`, `nessusParseWithNessusSyn.py` y `nessusSynScan.py`. Usa `-h`/`--help` para ver opciones y flags exactos de cada script.

---

## 🚀 Características

- **Markdown listo para Obsidian**: Frontmatter YAML, enlaces internos y jerarquía clara.
- **Separación por contexto**: Generación de notas por `hosts/` y por `findings/`.
- **Etiquetado útil**: etiquetas por severidad, origen (nessus), activo, etc.
- **Flujo OSCP-friendly**: pensado para recopilar evidencia y redactar recomendaciones rápido.
- **Sin dependencias pesadas** (normalmente basta Python 3.9+).

---

## 📦 Requisitos

- **Python 3.9+**
- Se recomienda crear un entorno virtual:  
  ```bash
  python -m venv .venv
  source .venv/bin/activate  # En Windows: .venv\Scripts\activate
  python -m pip install --upgrade pip
  ```
- Si el repositorio incluye `requirements.txt` en el futuro, instálalo con:  
  ```bash
  pip install -r requirements.txt
  ```

---

## 🔧 Instalación

Clona el repositorio:

```bash
git clone https://github.com/Madcroft/ness2obs.git
cd ness2obs
```

---

## 🏁 Uso rápido

> Sustituye rutas y nombres según tu caso. Consulta siempre la ayuda de cada script con `-h`.

### 1) Generar notas a partir de una exportación `.nessus` (XML)
```bash
python nessusParse.py -i scans/mi_escaneo.nessus -o vault/Nessus/2025-10-05_ACME
# Opciones típicas (pueden variar): --by host|vuln --prefix "ACME-Q4" --tag "pentest"
```

### 2) Parsear resultados incluyendo información de SYN scan
```bash
python nessusParseWithNessusSyn.py   -n scans/mi_escaneo_principal.nessus   -s scans/mi_syn_scan.nessus   -o vault/Nessus/2025-10-05_ACME
```

### 3) Extraer puertos/servicios desde un SYN scan de Nessus
```bash
python nessusSynScan.py -i scans/mi_syn_scan.nessus -o exports/puertos_abiertos.csv
```

> **Consejo**: si tus scripts admiten CSV/HTML además de `.nessus`, puedes integrarlos al flujo exportando desde Nessus en esos formatos y apuntando la entrada correcta.

---

## 🧱 Estructura de salida recomendada

```text
vault/
└── Nessus/
    └── 2025-10-05_ACME/
        ├── hosts/
        │   ├── 192.0.2.15.md
        │   ├── 192.0.2.23.md
        │   └── ...
        └── findings/
            ├── CVE-2023-12345.md
            ├── Unsupported_TLS_1_0.md
            └── ...
```

Cada nota incluye un **frontmatter YAML** para facilitar búsquedas y vistas en Obsidian. Ejemplo para una vulnerabilidad:

```markdown
---
type: finding
source: nessus
asset: 192.0.2.15
hostname: web01.acme.local
scan_date: 2025-10-05
severity: High
plugin_id: 12345
cve: [CVE-2023-12345]
cvss: 8.1
tags: [nessus, pentest, tls]
---

# TLS 1.0 / 1.1 soportado (obsoleto)

**Resumen**  
El servicio expone protocolos TLS desaconsejados, lo que permite downgrade attacks y reduce la seguridad del canal.

**Evidencia**  
- Puerto: 443/tcp
- Cipher suites: ...

**Riesgo**  
La negociación de protocolos inseguros expone el canal a interceptación y manipulación.

**Recomendación**  
Deshabilitar TLS 1.0/1.1 y habilitar únicamente TLS 1.2+ con cifrados fuertes. Verifica compatibilidad de clientes antes del cambio.
```

Y ejemplo para una nota de host:

```markdown
---
type: asset
source: nessus
ip: 192.0.2.15
hostname: web01.acme.local
os: Windows Server 2019
open_ports: [80, 443]
scan_date: 2025-10-05
tags: [acme, web, perimeter]
---

# web01.acme.local (192.0.2.15)

## Servicios detectados
- 80/tcp – HTTP
- 443/tcp – HTTPS (TLS 1.0/1.1 habilitado)

## Hallazgos (resumen)
- High: 1  
- Medium: 3  
- Low: 5

> Enlaza aquí los findings concretos con `[[findings/TLS_1_0_1_1_obsoleto]]`, etc.
```

---

## 🧭 Buenas prácticas para OSCP / Pentest Notes

- **Una carpeta por engagement** y por fecha/cliente.
- **Evidencia siempre cerca del hallazgo** (capturas, PoCs, hashes, versiones).  
- **Checklist de mitigación** alineada con CWE/CIS/NIST cuando sea posible.
- **Etiquetas consistentes**: `severity/High`, `service/http`, `cve/CVE-2024-XXXX`, `net/DMZ`, etc.
- **Plantillas en Obsidian** para findings y hosts; reutilízalas en cada engagement.

---

## 🧪 Pruebas rápidas

1. Exporta desde Nessus un `.nessus` (XML) con todos los campos.
2. Ejecuta `nessusParse.py` hacia una carpeta temporal.
3. Abre esa carpeta como **vault** en Obsidian y comprueba que:
   - El índice de hosts y findings se navega bien.
   - Los enlaces internos funcionan.
   - El frontmatter se parsea (búsqueda por `severity: High`, etc.).

---

## 🛠️ Desarrollo

- Estándar: **Python 3.9+**, código estilo **PEP8**.
- Se aceptan PRs con:
  - Soporte de nuevos formatos de exportación (CSV/HTML).
  - Mejoras de rendimiento y memoria en parseo de `.nessus` grandes.
  - Nuevos templates de salida para Obsidian.
  - Tests unitarios básicos para los parsers.

---

## 🗺️ Roadmap (ideas)

- [ ] Índices automáticos (`index.md`) por severidad/servicio.
- [ ] Mapeo a CWE y mitre ATT&CK cuando se detecten CVEs.
- [ ] Exportación adicional a **JSON/YAML** para pipelines.
- [ ] Integración con **Nuclei**/**OpenVAS** en el futuro.

---

## 🤝 Contribuir

1. Haz un fork y crea una rama: `feature/mi-mejora`  
2. Añade tests si aplica.  
3. Abre un Pull Request explicando el cambio.

---

## 👤 Autor & contacto

- Autor del repo: **Madcroft**  
- Sugerencias o issues: usa la pestaña **Issues** del repositorio.

---

## ❓FAQ

**¿Qué formatos de entrada soporta?**  
Primario: `.nessus` (XML exportado por Nessus). Si tus scripts también aceptan CSV/HTML, consúltalo con `-h`.

**¿Dónde se guardan las notas?**  
En la ruta de salida indicada con `-o`, organizada en subcarpetas `hosts/` y `findings/` (puede variar según flags).

**¿Incluye plantillas Obsidian?**  
Este README incluye ejemplos. Puedes añadir tus propias plantillas en `.obsidian/templates/` y referenciarlas.

---

> _Sigue la convención de nombres y carpetas para que tu vault sea navegable y reutilizable entre proyectos. ¡Buen hunting!_

