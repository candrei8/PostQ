# Quant-Scan — Product Requirements Document

## 1. Visión del Producto

**Quant-Scan** es un scanner de criptografía que detecta algoritmos vulnerables a ataques cuánticos en código fuente, certificados, configuraciones y dependencias de software. Genera reportes profesionales con scoring de riesgo, recomendaciones de migración PQC (Post-Quantum Cryptography) y mapeo de compliance regulatorio.

### Propuesta de Valor

- **Primer scanner PQC dedicado para el mercado español/europeo**
- Inventario criptográfico automatizado alineado con los plazos de la UE (2026 inventario, 2030 migración)
- Recomendaciones accionables de migración a algoritmos post-cuánticos (ML-KEM, ML-DSA, SLH-DSA)
- Mapeo directo a frameworks de compliance: ENS, CCN-STIC, NIST SP 800-208, EU PQC Roadmap

### Mercado Objetivo

- Empresas españolas con infraestructura crítica (banca, energía, telecomunicaciones, sanidad)
- Entidades del sector público sujetas al ENS
- Empresas europeas con requisitos de compliance criptográfico

---

## 2. Contexto Regulatorio

| Regulación | Requisito | Plazo |
|---|---|---|
| EU PQC Roadmap | Inventario criptográfico completo | Q4 2026 |
| EU PQC Roadmap | Migración infraestructura crítica | 2030 |
| NIST SP 800-208 | Uso de algoritmos PQC en sistemas federales | En vigor |
| ENS (España) | Catálogo de criptografía aprobada — actualización PQC pendiente | 2025-2026 |
| CCN-STIC | Guías de configuración segura — PQC en borrador | 2025-2026 |
| DORA (UE) | Resiliencia digital sector financiero — incluye cripto | 2025 |

---

## 3. Funcionalidades

### 3.1 Scanning de Código Fuente

Detecta uso de algoritmos criptográficos vulnerables en código fuente mediante análisis de patrones (imports, llamadas a funciones, constantes).

**Lenguajes soportados (Fase 1):** Python
**Lenguajes planificados:** Java, JavaScript/TypeScript, Go, C/C++, C#

**Detecta:**
- Imports de librerías criptográficas (hashlib, cryptography, PyCryptodome, etc.)
- Uso de algoritmos específicos (RSA, ECC, DSA, DH, DES, 3DES, MD5, SHA-1, etc.)
- Tamaños de clave insuficientes
- Modos de operación inseguros (ECB)
- Generación de números aleatorios insegura

### 3.2 Scanning de Certificados (Fase 2)

- Parsing de archivos `.pem`, `.crt`, `.cer`, `.der`
- Sondeo TLS en vivo a endpoints
- Detección de algoritmo de firma y tamaño de clave
- Verificación de fechas de expiración

### 3.3 Scanning de Configuración (Fase 3)

- Archivos SSH (`sshd_config`, `ssh_config`)
- Servidores TLS (nginx, Apache, HAProxy)
- Configuración de contenedores
- Configuración cloud (AWS, Azure, GCP)

### 3.4 Scanning de Dependencias (Fase 3)

- `requirements.txt`, `Pipfile`, `pyproject.toml` (Python)
- `package.json`, `package-lock.json` (Node.js)
- `pom.xml`, `build.gradle` (Java)
- `go.mod` (Go)

### 3.5 Reporting

| Formato | Descripción |
|---|---|
| Console | Tabla Rich con colores por severidad |
| JSON | Exportable, parseable, integrable en CI/CD |
| HTML | Reporte profesional con branding EYD (Fase 3) |

### 3.6 Scoring

- **Puntuación 0-100** basada en hallazgos ponderados por severidad y riesgo cuántico
- **Grado A-F** para comunicación ejecutiva
- **% PQC Readiness** — porcentaje de criptografía ya migrada a PQC

---

## 4. Interfaz CLI

```bash
# Scan completo
quant-scan scan <target> [--format console|json] [--severity critical,high]

# Solo código fuente
quant-scan source <target> [--languages python,java]

# Solo certificados (Fase 2)
quant-scan certificate <target> [--check-tls host:port]

# Solo configuraciones (Fase 3)
quant-scan config <target>

# Solo dependencias (Fase 3)
quant-scan dependencies <target>
```

### Opciones Globales
- `--format` — Formato de salida (console, json, html)
- `--severity` — Filtrar por severidad mínima
- `--output` / `-o` — Archivo de salida
- `--exclude` — Patrones de exclusión tipo gitignore
- `--no-color` — Desactivar colores

---

## 5. Requisitos No Funcionales

- **Rendimiento:** < 30 segundos para proyectos de hasta 10,000 archivos
- **Falsos positivos:** < 5% en código de producción típico
- **Extensibilidad:** Nuevas reglas vía YAML sin modificar código Python
- **Instalación:** `pip install quant-scan` sin dependencias del sistema
- **Compatibilidad:** Python 3.11+, Linux, macOS, Windows

---

## 6. Roadmap

| Fase | Entregable | Estado |
|---|---|---|
| 1 | Scanner de código Python + CLI + Console output | En desarrollo |
| 2 | Más lenguajes + Certificados + JSON report | Planificado |
| 3 | Config scanner + Dependency scanner + HTML report | Planificado |
| 4 | Compliance mapping + CBOM + Branding enterprise | Planificado |

---

## 7. Métricas de Éxito

- Detección de ≥95% de algoritmos vulnerables conocidos en fixtures de prueba
- 0 falsos positivos en fixtures de código seguro
- Tiempo de scan < 5s para repositorio de 1,000 archivos
- Instalación sin errores en Python 3.11, 3.12
