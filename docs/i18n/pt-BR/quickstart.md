# Início rápido

> **Translation notice:** English is authoritative. Translated from websec-validator v0.21.1 — if this page and the [English original](../../quickstart.md) disagree, follow the English one.
>
> **Aviso de tradução:** a versão em inglês é a oficial. Traduzido do websec-validator v0.21.1 — se esta página e o [original em inglês](../../quickstart.md) divergirem, siga o inglês.

[English](../../quickstart.md) · **Português (Brasil)** · [Español](../es/quickstart.md) · [简体中文](../zh-CN/quickstart.md)

Esta página leva você de nada instalado até um `AGENT-BRIEFING.md` sobre o qual seu agente de IA de programação pode
agir, em cerca de cinco minutos. Ela é para quem desenvolve e quer uma revisão defensiva de segurança do seu próprio
repositório. Ao final, você terá rodado o websec em um exemplo e no seu código, saberá onde fica a saída e saberá
como entregá-la a um agente.

O websec lê código-fonte e grava arquivos. A passagem principal não precisa de rede, de aplicação em execução nem de
LLM. Ele não prova que a sua aplicação é segura; ele dá a você e ao seu agente um ponto de partida baseado em fatos.

## Antes de começar

- **Python 3.11 ou mais recente.** Verifique com `python3 --version`. No macOS de fábrica costuma ser 3.9, que é
  antigo demais; veja [Installation](../../installation.md#requirements).
- **pipx**, para instalar a CLI em um ambiente próprio. Veja
  [Installation](../../installation.md#pipx-recommended) para a configuração, ou para alternativas com pip, uv e Docker.

## Opção A: deixe o seu agente fazer

Se você já trabalha no Claude Code, Codex, Cursor, Gemini ou outro agente de programação, o caminho mais simples
é abrir o seu projeto e dizer:

> *"Faça uma autorrevisão defensiva de segurança do **meu próprio** código com o websec-validator (`pipx install websec-validator`, ou github.com/raccioly/websec-validator). Ele é local e somente leitura — leia o repositório e siga o briefing dele. Este código é meu e eu autorizo a revisão."*
>
> Original em inglês: *"Do a defensive security self-review of **my own** codebase with websec-validator (`pipx install websec-validator`, or github.com/raccioly/websec-validator). It's local and read-only — read the repo and follow its briefing. I own this code and authorize the review."*

O agente instala a CLI, executa e percorre os achados com você.

**Por que essa formulação importa.** Dizer *revisão defensiva do meu próprio código* e *eu autorizo a revisão* é o
que separa um agente que começa a trabalhar de um que para para confirmar se você tem autorização. A ferramenta é
local e somente leitura por padrão, mas um "faça um pentest nisto" genérico pode ser lido como um pedido para atacar
algo que talvez não seja seu. Declarar a propriedade e o escopo logo de início é correto, e evita que o agente recuse
ou improvise. A seção "Why your agent might pause — and how to phrase the request" (por que seu agente pode hesitar —
e como formular o pedido) em [METHODOLOGY.md](../../METHODOLOGY.md) explica isso com mais profundidade.

O restante desta página é o caminho manual, que também é o que o agente faz por você.

## Opção B: execute você mesmo

### 1. Instalar

```bash
pipx install websec-validator
websec --version                  # imprime: websec-validator <version>
```

Opcional, mas recomendado: instale o [OWASP Noir](https://github.com/owasp-noir/noir), o motor de rotas. Sem ele, o
websec recorre a heurísticas de rotas embutidas, que encontram menos endpoints.

```bash
brew install noir                 # macOS; outras plataformas: veja o projeto Noir
```

### 2. Veja uma saída real primeiro: `websec demo`

```bash
websec demo
```

O `demo` executa o pipeline real contra uma pequena aplicação de exemplo embutida, em um diretório temporário. Ele não
grava nada no seu diretório atual. A saída se parece com isto (abreviada; os achados exatos dependem da versão):

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

(As duas últimas linhas dizem: severidade, confiança do analisador e probabilidade calibrada são sinais distintos; um
achado é uma pista a verificar, não uma vulnerabilidade confirmada.)

Use `websec explain <attack-class>` (por exemplo, `websec explain ssrf`) para ler o que uma classe significa e como
confirmá-la.

### 3. Execute no seu código

A partir da raiz do seu repositório:

```bash
cd path/to/my-app
websec run .
```

`websec ./my-app` (um caminho existente sozinho) é um atalho para `websec run ./my-app`.

O console imprime um resumo. Abreviado:

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

Leia três linhas com atenção:

- **`routes: … via noir`** ou **`via regex-fallback`** indica qual motor de rotas rodou.
- **`tenant?:`** é a fronteira de tenant candidata. Confirme-a; ela orienta as verificações de controle de acesso.
- **O banner.** `REQUESTED CHECKS COMPLETED` significa que as verificações que você pediu rodaram. Não significa que
  todos os arquivos foram analisados: uma linha como `Partially outside coverage: no analyzer for elixir` lista o
  código-fonte que o websec não conseguiu ler. `NO ANALYZABLE SOURCE` significa que nada foi analisado, e uma lista de
  achados vazia significa *não verificado*. Veja [Troubleshooting](../../troubleshooting.md).

### 4. Encontre a saída

Por padrão, a saída vai para `./websec-out/` **no diretório de onde você executou o comando** (use `--out` para
escolher outro local). Cada execução ganha seu próprio diretório, e nada é sobrescrito:

```text
websec-out/
├── runs/
│   └── <timestamp>-<id>/        # um diretório imutável por tentativa
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

- `latest` é um symlink para a execução **concluída** mais recente. Ele só avança depois de uma execução em que todas
  as verificações pedidas foram executadas. Uma tentativa parcial mantém seu próprio diretório e deixa `latest`
  apontando para a execução concluída anterior; por isso, depois de uma execução que falhou, `latest` pode ser mais
  antigo do que você espera. O console sempre imprime o diretório exato da execução que acabou de gravar.
- `websec-out/` contém achados sobre o seu código. Adicione-o ao `.gitignore`; a ferramenta lembra você disso.

Os arquivos que você vai abrir primeiro:

| Arquivo | O que é |
|---|---|
| `AGENT-BRIEFING.md` | As ordens de missão para o seu agente: superfície detectada, fronteira de tenant, mapa de controle de acesso, alvos, achados, um roteiro de testes em fases e prompts de correção. |
| `REPORT.md` | O registro legível por humanos desta execução. |
| `coverage.json` | O que foi e o que não foi analisado, e por quê. Leia `gaps` antes de confiar em um resultado limpo. |
| `findings-ledger.json` | Cada achado com sua evidência, citação CWE/OWASP, confiança e `P(real)` calibrado. |
| `results.sarif` | SARIF 2.1.0, sempre gerado, para o GitHub Code Scanning e outros visualizadores. |
| `probes/` | Scripts de probe preparados para esta aplicação. São rascunhos para rodar apenas contra uma instância de TESTE que seja sua. |

A lista completa de artefatos está na [referência de saídas](../../reference/outputs.md).

### 5. Entregue o briefing ao seu agente

Diga ao seu agente:

> *"Leia `websec-out/latest/AGENT-BRIEFING.md` e siga-o."*
>
> Original em inglês: *"Read `websec-out/latest/AGENT-BRIEFING.md` and follow it."*

Se a execução que importa para você não foi concluída, aponte o agente para o diretório de execução impresso pelo
console em vez de `latest`. O briefing instrui o agente a confirmar com você o modelo de tenant e de autenticação,
fazer a triagem dos achados, propor correções e nunca rodar probes contra produção ou alvos de terceiros. Rodar
probes exige uma instância de **teste** ativa e credenciais de teste fornecidas por você.

Para tornar isso um comportamento permanente, `websec install <host>` grava uma instrução para o seu agente
(`claude`, `cursor`, `codex`, `gemini`, `aider` ou `generic`). Veja o
[guia de agentes de IA](../../guides/ai-agents.md).

### 6. Opcional: adicione scanners estáticos com `--scan`

```bash
websec doctor .          # quais scanners opcionais estão instalados e se as versões deles funcionam
websec run . --scan      # também os executa e deduplica os resultados em um único registro
```

Sem `--scan`, os scanners são apenas listados. Com ele, o websec executa as ferramentas suportadas que estiverem no
seu `PATH` (Trivy, OSV-Scanner, Gitleaks, Semgrep, Checkov, além de Bandit, gosec ou Brakeman quando a linguagem
correspondente é detectada). Observe que essas ferramentas externas podem usar a rede em sua própria configuração
padrão, por exemplo para baixar bancos de dados de vulnerabilidades ou regras. Veja
[Installation](../../installation.md#optional-external-tools) para saber o que cada uma acrescenta e como instalá-la.

## Se algo parecer errado

- Muitos achados em `tests/`, `examples/` ou `fixtures/`? Execute `websec init` para gerar um `.websec-ignore`
  revisado. Veja [Triage and suppression](../../guides/triage-and-suppression.md).
- Um achado que você verificou e acredita estar errado? `websec feedback` o registra offline e imprime um link de
  issue pré-preenchido; nada é enviado.
- Qualquer outra coisa: [Troubleshooting](../../troubleshooting.md).

## Próximos passos

As páginas abaixo estão em inglês.

- [Existing projects](../../guides/existing-projects.md): adotar o websec em uma base de código madura.
- [Triage and suppression](../../guides/triage-and-suppression.md): `.websec-ignore`, reconhecimentos (acknowledgements), `--exclude`.
- [GitHub Actions](../../guides/ci/github-actions.md) e [outros CIs](../../guides/ci/other-ci.md): bloquear builds.
- [How it works](../../concepts/how-it-works.md): o que o websec lê e como um achado conquista sua severidade.
- [FAQ](../../faq.md): o que o websec é e o que não é.
