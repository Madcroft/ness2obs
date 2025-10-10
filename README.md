🛡️ Nessus to Obsidian Importer

Python Version
License
Build Status
📌 Descripción

Ness2Obs es una herramienta especializada en convertir archivos de escaneo Nessus (.nessus) en documentos estructurados compatibles con Obsidian, facilitando la documentación y análisis de vulnerabilidades de seguridad.
🚀 Características Principales

✅ Conversión automática de archivos Nessus a Markdown
✅ Estructura modular para fácil navegación en Obsidian
✅ Compatibilidad con múltiples versiones de archivos Nessus
✅ Metadatos integrados para filtrado y búsqueda avanzada
✅ Formato profesional listo para integración en flujos de trabajo de ciberseguridad
📦 Instalación

pip install -r requirements.txt

    ⚠️ Requiere Python 3.8 o superior.
    Recomendado usar en entornos virtuales (python -m venv env).

📥 Uso Básico

python ness2obs.py --input archivo.nessus --output carpeta_obsidian/

Parámetros Disponibles
Opción	Descripción	Ejemplo
--input	Ruta del archivo Nessus	--input scans/scan1.nessus
--output	Carpeta de salida en Obsidian	--output ~/Obsidian/Vulnerables/
--format	Formato de salida (Markdown/JSON)	--format markdown
--filter-sev	Filtrar por severidad (alta/media/baja)	--filter-sev high
📁 Estructura de Salida

carpeta_obsidian/
├── INFORME_PRINCIPAL.md           # Resumen ejecutivo
├── METADATOS.json                 # Datos estructurados
├── VULNERABILIDADES/
│   ├── CRÍTICA_001.md             # Detalles de vulnerabilidad crítica
│   ├── MEDIA_002.md              # Detalles de vulnerabilidad media
│   └── BAJA_003.md               # Detalles de vulnerabilidad baja
└── GRÁFICAS/
    └── RESUMEN_SEVERIDAD.png      # Gráficos generados (opcional)

