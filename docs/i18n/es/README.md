# websec-validator

> **Translation notice:** English is authoritative. Translated from websec-validator v0.21.1 — if this page and the [English original](../../../README.md) disagree, follow the English one.
>
> **Aviso de traducción:** la versión en inglés es la oficial. Traducido de websec-validator v0.21.1 — si esta página y el [original en inglés](../../../README.md) no coinciden, sigue la versión en inglés.

[English](../../../README.md) · [Português (Brasil)](../pt-BR/README.md) · **Español** · [简体中文](../zh-CN/README.md)

[![CI](https://github.com/raccioly/websec-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/raccioly/websec-validator/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/websec-validator)](https://pypi.org/project/websec-validator/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/websec-validator/)
[![Runtime deps: 0](https://img.shields.io/badge/runtime%20deps-0%20(stdlib%20only)-brightgreen)](../../installation.md)
[![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-orange)](../../guides/ci/github-actions.md)
[![Docs](https://img.shields.io/badge/docs-guides%20%26%20reference-informational)](../../README.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](../../../LICENSE)

El "esto es lo que hay que probar y cómo" que te entregaría un pentester sénior — generado automáticamente a partir de tu repositorio, para que tu agente de IA lo ejecute.

> Reconocimiento de seguridad local-first que **prepara el briefing de tu agente de IA de programación**. Hace la
> mitad determinista — lee el código fuente compatible, mapea la superficie de ataque visible y prepara una biblioteca
> de probes a la medida de lo que encontró — y luego entrega a tu agente (Claude Code, Codex, Gemini, Cursor) un
> briefing con órdenes de misión. `websec run` no necesita nada más que el código; agrega `--scan` para ejecutar
> también los escáneres estáticos que tengas instalados y deduplicar sus resultados. **Entra código, salen artefactos.
> Ningún LLM en la herramienta; no se requiere servidor ni aplicación en ejecución para la pasada principal.**

[![websec-validator demo](https://raw.githubusercontent.com/raccioly/websec-validator/main/assets/demo.gif)](../../../assets/demo.gif)

**¿Eres nuevo aquí?** Lee el resumen técnico de ocho páginas — qué lee la herramienta, cómo un hallazgo se gana su
severidad, qué se niega a afirmar y la evidencia de campo:
**[raccioly.github.io/websec-validator](https://raccioly.github.io/websec-validator/websec-explained.html)**
· [PDF](https://raccioly.github.io/websec-validator/websec-explained.pdf). La instantánea revisada de la v0.21.0
tiene aserciones sobre hechos seleccionados en `tests/test_explained_brief.py` y un vínculo de hash entre
HTML/PDF/renderizador en `tests/test_brief_artifacts.py`. La exactitud del texto y la maquetación renderizada aún
requieren revisión; consulta [cómo reconstruir el resumen](../../../CONTRIBUTING.md#publishing-the-technical-brief).

*No* es un escáner autónomo y *no* es un SaaS. Es la mitad delantera que faltaba: lo que convierte un repositorio en
un briefing de seguridad preciso y basado en hechos sobre el que un agente de IA (con una persona en el circuito)
puede actuar. Cómo funciona y el razonamiento detrás de cada verificación:
[conceptos](../../concepts/how-it-works.md) ·
[metodología](../../METHODOLOGY.md).

**Parte de la familia Guard**, tres herramientas que mantienen, cada una, honesto un tipo de afirmación:
[**DocGuard**](https://github.com/raccioly/docguard) valida la documentación contra el código que describe,
[**TestGuard**](https://github.com/raccioly/testguard) comprueba que las pruebas realmente demuestren lo que afirman,
y websec-validator hace lo mismo con los hallazgos de seguridad — cada hallazgo incluye su evidencia, su estándar de
referencia y una probabilidad calibrada de que sea real.

## Primeros pasos — solo apúntalo a tu repositorio

**Lo más simple: pídeselo a tu agente de IA.** En Claude Code (o en cualquier agente de programación), abre tu proyecto y di:

> *"Haz una autorrevisión defensiva de seguridad de **mi propio** código con websec-validator (`pipx install websec-validator`, o github.com/raccioly/websec-validator). Es local y de solo lectura — lee el repositorio y sigue su briefing. Este código es mío y autorizo la revisión."*
>
> Original en inglés: *"Do a defensive security self-review of **my own** codebase with websec-validator (`pipx install websec-validator`, or github.com/raccioly/websec-validator). It's local and read-only — read the repo and follow its briefing. I own this code and authorize the review."*

Se instala, se ejecuta y recorre los hallazgos contigo. Formularlo como una *revisión defensiva de tu propio código*
importa: es la diferencia entre un agente que simplemente se pone a trabajar y uno que se detiene a confirmar que
tienes autorización. Todos los caminos terminan en el mismo `AGENT-BRIEFING.md` sobre el que actúa tu agente:

| Camino | Configuración única | Después |
|---|---|---|
| **Pídeselo a tu agente** (lo más simple) | — | di la frase de arriba |
| **CLI** (una terminal) | `pipx install websec-validator` | `websec run /path/to/your/app` |
| **Plugin de Claude Code** | `/plugin marketplace add raccioly/websec-validator`  →  `/plugin install websec-validator@websec-plugins` | invoca la skill **security-pass**, o simplemente pídelo |
| **Cualquier otro agente** (Codex, Cursor, Gemini, Aider) | `pipx install websec-validator` | `websec install <host>` |
| **Docker** (sin instalación) | `docker build -t websec-validator .` | `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out` |

¿Ya tienes una base de código con historial, pruebas y fixtures? Sigue
**[Adopting websec in an existing project](../../guides/existing-projects.md)** (adoptar websec en un proyecto existente):
saca del alcance el código que no es de producto, ejecuta, haz el triaje, registra una línea base y luego activa el
gating por fases.

## Instalación

```bash
pipx install websec-validator   # desde PyPI; Python 3.11+
brew install noir               # opcional: OWASP Noir, el motor de rutas (respaldo con regex si no está)
websec --version
websec doctor                   # ¿qué escáneres opcionales están instalados y son compatibles?
```

Cero dependencias de Python en tiempo de ejecución. Los escáneres externos (Trivy, OSV-Scanner, Gitleaks, Semgrep,
Checkov y, según el lenguaje, Bandit/gosec/Brakeman) se usan **cuando están presentes** y solo se ejecutan con
`--scan`; Prowler se detecta y se reporta, no se ejecuta. Todos los canales — pip, uv, Docker, código fuente,
offline/air-gapped — y la configuración de escáneres por sistema operativo: **[Installation](../../installation.md)**.

## Uso

```bash
websec run ./my-app                    # reconocimiento + prepara probes a la medida + emite el briefing
websec ./my-app                        # lo mismo — una ruta sola equivale a `run`
websec run ./my-app --scan             # …y además ejecuta los escáneres estáticos disponibles
websec run ./my-app --fail-on high     # sale con 1 si queda algún hallazgo HIGH o superior (un gate de CI)
websec run ./my-app --diff main        # modo PR: limita a los archivos cambiados + rangos exactos de líneas de cada hunk
websec gate                            # aprobado/fallido rápido sobre los archivos que acabas de cambiar (ciclo del agente)
websec install codex                   # enseña a un agente a usar websec (claude · cursor · gemini · aider · generic)
websec mcp                             # herramientas tipadas de reconocimiento para cualquier cliente MCP, por stdio
```

Luego apunta tu agente a la salida: **"Lee `websec-out/latest/AGENT-BRIEFING.md` y síguelo."**
(en inglés: *"Read `websec-out/latest/AGENT-BRIEFING.md` and follow it."*)
Cada intento obtiene su propio directorio `websec-out/runs/<id>/`; `latest` solo avanza después de una ejecución completada.
Todos los subcomandos y opciones: [referencia de la CLI](../../reference/cli.md).

## Qué obtienes (`websec-out/`)

| Artefacto | Qué es |
|---|---|
| `AGENT-BRIEFING.md` | **El producto.** Órdenes de misión: superficie detectada, el mapa de control de acceso, objetivos, hallazgos, el método y la lista de probes preparados. |
| `FACTS.json` | El reconocimiento estructurado completo. |
| `findings-ledger.json` / `REPORT.md` | El registro trazable: cada hallazgo con una cadena de evidencia, cita CWE/ASVS/OWASP-API, remediación y un **`P(real)` calibrado** (tasa medida de vulnerabilidades reales + IC del 95 % + tamaño de muestra). |
| `results.sarif` | **SARIF 2.1.0** — siempre se genera. Cárgalo en GitHub Code Scanning, GitLab, Azure DevOps, el visor SARIF de VS Code o DefectDojo. |
| `coverage.json` | Qué se ejecutó, qué se omitió y por qué — un resultado limpio vale lo mismo que su cobertura. |
| `probes/` | Los scripts de probe seleccionados y preparados para *esta* aplicación (BOLA, JWT, SSRF, mass-assignment…). |

Además de SBOMs, una tabla de la superficie de ataque, el alcance del diff y un sobre versionado:
[todas las salidas](../../reference/outputs.md).

## Lenguajes

| Soporte | Lenguajes |
|---|---|
| **Análisis profundo y consciente del framework** — Django, Flask, FastAPI, Connexion, Express, Fastify, Next.js, tRPC, Supabase Edge, AWS SAM… | Python, JavaScript, TypeScript |
| **Verificaciones de sinks con nombre** — sintaxis directa de comandos/consultas (además de rutas literales de Spring y ASP.NET) | Java, C#, Go, Ruby, PHP |
| **Solo verificaciones de configuración o manuales** — se reportan como una brecha de cobertura escasa | Kotlin/Android, Swift y Objective-C/iOS, Rust, C/C++ |
| **Reconocidos, no analizados** — se reportan como brecha de cobertura, nunca como limpios | Elixir, Scala, Clojure, Erlang, Perl, Lua, Dart, shell, plantillas del lado del servidor y más |

El descubrimiento de rutas en muchos más frameworks proviene de OWASP Noir cuando está instalado, y los escáneres son
agnósticos del lenguaje. Una verificación completada sin coincidencias no prueba que un servicio sea seguro:
**[la matriz de soporte completa y qué significa una ejecución limpia para tu stack](../../reference/languages.md)**.

## Documentación

Las páginas enlazadas abajo están en inglés.

| Empieza aquí | Guías | Referencia |
|---|---|---|
| [Centro de documentación](../../README.md) | [Proyectos existentes](../../guides/existing-projects.md) | [CLI](../../reference/cli.md) |
| [Inicio rápido](quickstart.md) ([inglés](../../quickstart.md)) | [Agentes de IA](../../guides/ai-agents.md) | [Lenguajes](../../reference/languages.md) |
| [Instalación](../../installation.md) | [GitHub Actions](../../guides/ci/github-actions.md) · [otros CI](../../guides/ci/other-ci.md) | [Configuración](../../reference/configuration.md) |
| [Actualización](../../upgrade.md) | [Triaje y supresión](../../guides/triage-and-suppression.md) | [Salidas](../../reference/outputs.md) |
| [Solución de problemas](../../troubleshooting.md) · [FAQ](../../faq.md) | [Pruebas dinámicas](../../guides/dynamic-testing.md) | [Servidor MCP](../../reference/mcp.md) |

## Estado

El [changelog](../../../CHANGELOG.md) registra qué cambió en cada versión;
[Upgrading](../../upgrade.md) indexa las notas de migración — 0.14.0 (schema 2.0) y la separación de códigos de
salida de la 0.17.0 (`2` = error de uso, `3` = ejecución incompleta). Las brechas sin resolver y sus pruebas de
aceptación están en la [especificación del trabajo pendiente](../../../specs/001-continuous-security-improvement/spec.md).

Son herramientas de revisión con un alcance definido: los perfiles manuales, las rutas desconocidas, el comportamiento
dinámico y la sintaxis no compatible siguen siendo limitaciones. El gate dentro del ciclo es ergonomía para el
desarrollador, no un control, y `attest` reporta evidencia sin emitir un veredicto de cumplimiento. La evidencia
ligada a una instantánea vive junto a los artefactos que describe — el
[registro de validación](../../security-review/validation.md), los [benchmarks](../../../BENCHMARKS.md) y el
[protocolo de prueba](../../../corpus/PROOF-PROTOCOL.md) — para que las cifras no puedan quedar desactualizadas aquí.

**Validado en** una aplicación Next.js en producción, un gran monorepo Express/AWS y el corpus de aplicaciones
vulnerables VAmPI / NodeGoat / DVGA — reproduciendo de forma independiente los hallazgos de un pentest hecho a mano
(límite de tenant, SSRF, carga de archivos, BOLA entre tenants, brechas de roles/autorización). El descubrimiento de
rutas reporta lo que puede analizar *sin importar configuraciones ni ejecutar tu código*, así que los montajes
desconocidos siguen siendo **candidatos** a ruta y conservan su incertidumbre; eso es evidencia para revisión humana,
no una medición del recall de vulnerabilidades.

## Contribuir

Los reportes de errores, los reportes de falsos positivos y las propuestas de detectores son lo más valioso que
recibe este proyecto — consulta [CONTRIBUTING.md](../../../CONTRIBUTING.md) (incluido el proceso de release del
mantenedor) y las [plantillas de issues](https://github.com/raccioly/websec-validator/issues/new/choose). Reporta
las vulnerabilidades del propio websec de forma privada: [SECURITY.md](../../../SECURITY.md).

```bash
python3 -m unittest discover -s tests    # solo stdlib; pruebas sintéticas/en loopback local, sin red pública
```

## Créditos

La metodología y la biblioteca de probes se destilaron de una pasada real de pruebas de penetración autenticadas.
Esta herramienta convierte esa metodología escrita a mano en algo que un agente de IA puede ejecutar en cualquier repositorio.

## Licencia

[MIT](../../../LICENSE) © Ricardo Accioly
