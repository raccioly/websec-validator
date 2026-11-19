# Inicio rápido

> **Translation notice:** English is authoritative. Translated from websec-validator v0.21.1 — if this page and the [English original](../../quickstart.md) disagree, follow the English one.
>
> **Aviso de traducción:** la versión en inglés es la oficial. Traducido de websec-validator v0.21.1 — si esta página y el [original en inglés](../../quickstart.md) no coinciden, sigue la versión en inglés.

[English](../../quickstart.md) · [Português (Brasil)](../pt-BR/quickstart.md) · **Español** · [简体中文](../zh-CN/quickstart.md)

Esta página te lleva de no tener nada instalado a un `AGENT-BRIEFING.md` sobre el que tu agente de IA de programación
puede actuar, en unos cinco minutos. Está pensada para quien desarrolla y quiere una revisión defensiva de seguridad
de su propio repositorio. Al final habrás ejecutado websec sobre un ejemplo y sobre tu código. Sabrás dónde queda la
salida y cómo entregársela a un agente.

websec lee código fuente y escribe archivos. La pasada principal no necesita red, ni una aplicación en ejecución, ni
un LLM. No prueba que tu aplicación sea segura. Te da a ti y a tu agente un punto de partida basado en hechos.

## Antes de empezar

- **Python 3.11 o más reciente.** Compruébalo con `python3 --version`. En un macOS de fábrica suele ser 3.9, que es
  demasiado antiguo. Consulta [Installation](../../installation.md#requirements).
- **pipx**, para instalar la CLI en su propio entorno. Consulta
  [Installation](../../installation.md#pipx-recommended) para configurarlo, o para alternativas con pip, uv y Docker.

## Opción A: deja que lo haga tu agente

Si ya trabajas en Claude Code, Codex, Cursor, Gemini u otro agente de programación, el camino más simple es abrir tu
proyecto y decir esto:

> *"Haz una autorrevisión defensiva de seguridad de **mi propio** código con websec-validator (`pipx install websec-validator`, o github.com/raccioly/websec-validator). Es local y de solo lectura — lee el repositorio y sigue su briefing. Este código es mío y autorizo la revisión."*
>
> Original en inglés: *"Do a defensive security self-review of **my own** codebase with websec-validator (`pipx install websec-validator`, or github.com/raccioly/websec-validator). It's local and read-only — read the repo and follow its briefing. I own this code and authorize the review."*

El agente instala la CLI, la ejecuta y recorre los hallazgos contigo.

**Por qué importa esta formulación.** Di *revisión defensiva de mi propio código* y *autorizo la revisión*. Entonces
el agente se pone a trabajar. Sin estas palabras, el agente puede detenerse a confirmar que tienes autorización. La
herramienta es local y de solo lectura por defecto. Un "hazle un pentest a esto" genérico puede interpretarse como
una petición para atacar algo que quizá no te pertenece. Declara desde el principio que el código es tuyo y cuál es
el alcance. Eso es exacto, y evita que el agente se niegue o improvise. La sección "Why your agent might pause —
and how to phrase the request" (por qué tu agente podría detenerse y cómo formular la petición) en
[METHODOLOGY.md](../../METHODOLOGY.md) lo explica con más detalle.

El resto de esta página es el camino manual. El agente hace los mismos pasos en tu nombre.

## Opción B: ejecútalo tú mismo

### 1. Instalar

```bash
pipx install websec-validator
websec --version                  # imprime: websec-validator <version>
```

Opcional pero recomendado: instala [OWASP Noir](https://github.com/owasp-noir/noir), el motor de rutas. Sin Noir,
websec recurre a heurísticas de rutas integradas, que encuentran menos endpoints.

```bash
brew install noir                 # macOS; otras plataformas: consulta el proyecto Noir
```

### 2. Mira primero una salida real: `websec demo`

```bash
websec demo
```

`demo` ejecuta el pipeline real contra una pequeña aplicación de ejemplo incluida, en un directorio temporal. No
escribe nada en tu directorio actual. La salida se ve así (abreviada). Los hallazgos exactos dependen de la versión:

```text
websec-validator v<version> — demo

  Scanning a bundled sample app (demo-app); your project is untouched.
  This is a real run, not a recording.

  7 finding(s):

    MEDIUM   missing-auth           Missing authorization: GET /orders/{order_id}
    MEDIUM   ssrf                   ssrf sink
    MEDIUM   command-injection      command-injection sink
    MEDIUM   sqli                   sql-injection sink
    ...

  Severity, analyzer confidence and calibrated probability are separate signals.
  A finding is a lead to verify, not a confirmed vulnerability.
```

(Las dos últimas líneas dicen: la severidad, la confianza del analizador y la probabilidad calibrada son señales
distintas. Un hallazgo es una pista que hay que verificar, no una vulnerabilidad confirmada.)

Usa `websec explain <attack-class>` (por ejemplo, `websec explain ssrf`) para leer qué significa una clase de ataque y
cómo confirmarla.

### 3. Ejecútalo sobre tu código

Desde la raíz de tu repositorio:

```bash
cd path/to/my-app
websec run .
```

`websec ./my-app` (una ruta existente sola) es un atajo para `websec run ./my-app`.

La consola imprime un resumen (abreviado):

```text
  stack:    python  ·  frameworks: flask  ·  datastores: ?
  auth:     unknown
  tenant?:  none detected
  routes:   3 endpoints via noir
  targets:  IDOR=1 SSRF=2 upload=0 writes=0

  scanners available: Trivy, Gitleaks, ...  (add --scan to execute them)
  ...
  ledger: 7 finding(s) · {'MEDIUM': 6, 'LOW': 1} · ...

> **REQUESTED CHECKS COMPLETED** — 2 files read; 1 code files selected.
> Completion describes execution, not complete protection. See `coverage.json` for scope and limits.
```

Lee estos tres elementos con atención:

- **`routes: … via noir`** o **`via regex-fallback`** te dice qué motor de rutas se ejecutó.
- **`tenant?:`** es el límite de tenant candidato. Confírmalo, porque de él dependen las verificaciones de control de acceso.
- **El banner.** `REQUESTED CHECKS COMPLETED` significa que se ejecutaron las verificaciones que pediste. No significa
  que websec analizara todos los archivos. Una línea como `Partially outside coverage: no analyzer for elixir`
  enumera el código fuente que websec no pudo leer. `NO ANALYZABLE SOURCE` significa que no se analizó nada, y una
  lista de hallazgos vacía significa *no verificado*. Consulta [Troubleshooting](../../troubleshooting.md).

### 4. Encuentra la salida

Por defecto, la salida va a `./websec-out/` **en el directorio desde el que ejecutaste el comando**. Usa `--out`
para elegir otra ubicación. Cada ejecución obtiene su propio directorio y nada se sobrescribe:

```text
websec-out/
├── runs/
│   └── <timestamp>-<id>/        # un directorio inmutable por intento
│       ├── AGENT-BRIEFING.md
│       ├── REPORT.md
│       ├── FACTS.json
│       ├── coverage.json
│       ├── findings-ledger.json
│       ├── results.sarif
│       ├── ...
│       └── probes/
└── latest -> runs/<timestamp>-<id>
```

- `latest` es un symlink a la ejecución **completada** más reciente. Solo avanza después de una ejecución en la que se
  ejecutaron todas las verificaciones solicitadas. Un intento parcial conserva su propio directorio y deja `latest`
  apuntando a la ejecución completada anterior. Después de una ejecución fallida, `latest` puede ser más antiguo de
  lo que esperas. La consola siempre imprime el directorio exacto de la ejecución que acaba de escribir.
- `websec-out/` contiene hallazgos sobre tu código. Agrégalo a `.gitignore`. La herramienta te lo recuerda.

Abre estos archivos primero:

| Archivo | Qué es |
|---|---|
| `AGENT-BRIEFING.md` | Las instrucciones para tu agente: superficie detectada, límite de tenant, mapa de control de acceso, objetivos, hallazgos, un runbook de pruebas por fases y prompts de corrección. |
| `REPORT.md` | El registro legible por personas de esta ejecución. |
| `coverage.json` | Qué se analizó y qué no, y por qué. Lee `gaps` antes de confiar en un resultado limpio. |
| `findings-ledger.json` | Cada hallazgo con su evidencia, cita CWE/OWASP, confianza y `P(real)` calibrado. |
| `results.sarif` | SARIF 2.1.0, siempre se genera, para GitHub Code Scanning y otros visores. |
| `probes/` | Scripts de probe preparados para esta aplicación. Son borradores. Ejecútalos solo contra una instancia de PRUEBA que te pertenezca. |

La lista completa de artefactos está en la [referencia de salidas](../../reference/outputs.md).

### 5. Entrega el briefing a tu agente

Dile a tu agente:

> *"Lee `websec-out/latest/AGENT-BRIEFING.md` y síguelo."*
>
> Original en inglés: *"Read `websec-out/latest/AGENT-BRIEFING.md` and follow it."*

Si la ejecución que te interesa no se completó, apunta el agente al directorio de ejecución que imprimió la consola, en
lugar de `latest`. El briefing le indica al agente que confirme contigo el modelo de tenant y de autenticación, haga
el triaje de los hallazgos y proponga correcciones. También le indica que nunca ejecute probes contra producción ni
contra objetivos de terceros. Ejecutar probes requiere una instancia de **prueba** activa y credenciales de prueba
que proporciones tú.

Para que esto sea un comportamiento permanente, `websec install <host>` escribe una instrucción para tu agente
(`claude`, `cursor`, `codex`, `gemini`, `aider` o `generic`). Consulta la
[guía de agentes de IA](../../guides/ai-agents.md).

### 6. Opcional: agrega escáneres estáticos con `--scan`

```bash
websec doctor .          # qué escáneres opcionales están instalados y si sus versiones funcionan
websec run . --scan      # también los ejecuta y deduplica sus resultados en un solo registro
```

Sin `--scan`, websec solo enumera los escáneres. Con `--scan`, websec ejecuta las herramientas compatibles que estén
en tu `PATH` (Trivy, OSV-Scanner, Gitleaks, Semgrep, Checkov, además de Bandit, gosec o Brakeman cuando detecta ese
lenguaje). Estas herramientas externas pueden usar la red en su propia configuración por defecto, por ejemplo para
descargar bases de datos de vulnerabilidades o reglas. Consulta
[Installation](../../installation.md#optional-external-tools) para ver qué aporta cada una y cómo instalarla.

## Si algo parece estar mal

- ¿Muchos hallazgos en `tests/`, `examples/` o `fixtures/`? Ejecuta `websec init --dry-run` y luego `websec init`
  para generar un `.websec-ignore` revisado. Tras una ejecución completada con `--scan`, un directorio puede tener
  solo hallazgos de secretos. Para ese directorio, `init` propone reconocimientos `fingerprint:` con fecha, en lugar
  de ocultar todo el directorio. Consulta [Triage and suppression](../../guides/triage-and-suppression.md).
- ¿Revisaste un hallazgo y crees que es incorrecto? `websec feedback` lo registra sin conexión e imprime un enlace
  de issue prellenado. No envía nada.
- Cualquier otra cosa: [Troubleshooting](../../troubleshooting.md).

## Próximos pasos

Las páginas enlazadas abajo están en inglés.

- [Existing projects](../../guides/existing-projects.md): adoptar websec en una base de código madura.
- [Triage and suppression](../../guides/triage-and-suppression.md): `.websec-ignore`, reconocimientos (acknowledgements), `--exclude`.
- [GitHub Actions](../../guides/ci/github-actions.md) y [otros CI](../../guides/ci/other-ci.md): bloquear builds.
- [How it works](../../concepts/how-it-works.md): qué lee websec y cómo un hallazgo se gana su severidad.
- [FAQ](../../faq.md): qué es websec y qué no es.
