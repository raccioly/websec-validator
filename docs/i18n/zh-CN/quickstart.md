# 快速入门

> **Translation notice:** English is authoritative. Translated from websec-validator v0.21.1 — if this page and the [English original](../../quickstart.md) disagree, follow the English one.
>
> **翻译说明：** 以英文版为准。本文译自 websec-validator v0.21.1 —— 如果本页与[英文原文](../../quickstart.md)不一致，请以英文版为准。

[English](../../quickstart.md) · [Português (Brasil)](../pt-BR/quickstart.md) · [Español](../es/quickstart.md) · **简体中文**

本页带你从零开始，在大约五分钟内得到一份可供 AI 编程智能体执行的 `AGENT-BRIEFING.md`。它面向希望对自己的代码仓库
做一次防御性安全审查的开发者。读完后，你将已经在示例和自己的代码上运行过 websec，知道输出存放在哪里，
也知道如何把它交给智能体。

websec 读取源代码并写出文件。核心流程不需要网络、不需要运行中的应用，也不需要 LLM。它并不能证明你的应用是安全的；
它为你和你的智能体提供一个基于事实的起点。

## 开始之前

- **Python 3.11 或更新版本。** 用 `python3 --version` 检查。macOS 自带的版本通常是 3.9，太旧了；
  参见 [Installation](../../installation.md#requirements)。
- **pipx**，用于把 CLI 安装到独立的环境中。设置方法，或 pip、uv 与 Docker 等替代方式，参见
  [Installation](../../installation.md#pipx-recommended)。

## 方案 A：让你的智能体来做

如果你已经在使用 Claude Code、Codex、Cursor、Gemini 或其他编程智能体，最简单的做法是打开你的项目，然后说：

> *"请用 websec-validator（`pipx install websec-validator`，或 github.com/raccioly/websec-validator）对**我自己的**代码库做一次防御性的安全自查。它在本地运行且只读 —— 请读取仓库并按照它生成的简报执行。这些代码归我所有，我授权进行这次审查。"*
>
> 英文原文：*"Do a defensive security self-review of **my own** codebase with websec-validator (`pipx install websec-validator`, or github.com/raccioly/websec-validator). It's local and read-only — read the repo and follow its briefing. I own this code and authorize the review."*

智能体会安装 CLI、运行它，并和你一起逐条过一遍发现项。

**为什么这样措辞很重要。** 说出*对我自己代码的防御性审查*和*我授权进行这次审查*，决定了智能体是直接开始工作，
还是先停下来确认你是否有授权。该工具默认在本地运行且只读，但一句笼统的"对这个做渗透测试"可能会被理解为
要攻击某个未必属于你的东西。一开始就说明所有权和范围既准确，又能避免智能体拒绝执行或自行发挥。
[METHODOLOGY.md](../../METHODOLOGY.md) 中的 "Why your agent might pause — and how to phrase the request"
（为什么你的智能体可能会停下来，以及如何表述请求）一节对此有更深入的解释。

本页其余部分是手动路径，也正是智能体代你执行的步骤。

## 方案 B：自己运行

### 1. 安装

```bash
pipx install websec-validator
websec --version                  # 输出：websec-validator <version>
```

可选但推荐：安装路由引擎 [OWASP Noir](https://github.com/owasp-noir/noir)。没有它时，websec 会回退到内置的路由启发式规则，
能找到的端点会更少。

```bash
brew install noir                 # macOS；其他平台：参见 Noir 项目
```

### 2. 先看看真实输出：`websec demo`

```bash
websec demo
```

`demo` 会在一个临时目录中，针对一个内置的小型示例应用运行真实的流水线。它不会向你的当前目录写入任何内容。
输出大致如下（有删节；具体发现项取决于版本）：

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

（最后两行的意思是：严重级别、分析器置信度和校准概率是相互独立的信号；一个发现项是有待验证的线索，而不是已确认的漏洞。）

使用 `websec explain <attack-class>`（例如 `websec explain ssrf`）来了解某一攻击类别的含义以及如何确认它。

### 3. 在你的代码上运行

在你的代码仓库根目录下：

```bash
cd path/to/my-app
websec run .
```

`websec ./my-app`（只给一个已存在的路径）是 `websec run ./my-app` 的简写。

控制台会打印一份摘要。节选如下：

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

请仔细看三行：

- **`routes: … via noir`** 或 **`via regex-fallback`** 告诉你运行的是哪个路由引擎。
- **`tenant?:`** 是候选的租户边界。请确认它；访问控制检查以它为依据。
- **横幅（banner）。** `REQUESTED CHECKS COMPLETED` 表示你所要求的检查都已运行，但并不表示每个文件都被分析过：
  像 `Partially outside coverage: no analyzer for elixir` 这样的行会列出 websec 无法读取的源代码。
  `NO ANALYZABLE SOURCE` 表示什么都没有分析，此时空的发现项列表意味着*未检查*。参见 [Troubleshooting](../../troubleshooting.md)。

### 4. 找到输出

默认情况下，输出写入 `./websec-out/`，**位于你运行命令时所在的目录**（用 `--out` 可以选择其他位置）。
每次运行都有自己的目录，不会覆盖任何内容：

```text
websec-out/
├── runs/
│   └── <timestamp>-<id>/        # 每次尝试一个不可变的目录
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

- `latest` 是指向最近一次**已完成**运行的符号链接。只有当某次运行所要求的检查全部执行之后，它才会前移。
  部分完成的尝试会保留自己的目录，并让 `latest` 继续指向上一次已完成的运行，因此在一次失败的运行之后，
  `latest` 可能比你预想的要旧。控制台总会打印它刚刚写入的确切运行目录。
- `websec-out/` 包含关于你代码的发现项。请把它加入 `.gitignore`；工具也会提醒你。

你最先会打开的文件：

| 文件 | 说明 |
|---|---|
| `AGENT-BRIEFING.md` | 给智能体的行动指令：检测到的攻击面、租户边界、访问控制图、目标、发现项、分阶段的测试手册以及修复提示词。 |
| `REPORT.md` | 本次运行的人类可读记录。 |
| `coverage.json` | 哪些内容被分析了、哪些没有，以及原因。在相信一个干净的结果之前，请先阅读 `gaps`。 |
| `findings-ledger.json` | 每个发现项及其证据、CWE/OWASP 引用、置信度和校准后的 `P(real)`。 |
| `results.sarif` | SARIF 2.1.0，始终生成，可用于 GitHub Code Scanning 和其他查看器。 |
| `probes/` | 为本应用准备的探测脚本。它们是草稿，只能针对你自己拥有的测试（TEST）实例运行。 |

完整的产物列表见[输出参考](../../reference/outputs.md)。

### 5. 把简报交给你的智能体

告诉你的智能体：

> *"请阅读 `websec-out/latest/AGENT-BRIEFING.md` 并按其执行。"*
>
> 英文原文：*"Read `websec-out/latest/AGENT-BRIEFING.md` and follow it."*

如果你关心的那次运行没有完成，请把智能体指向控制台打印的运行目录，而不是 `latest`。简报会要求智能体与你确认租户
和认证模型、对发现项进行分诊、提出修复方案，并且绝不针对生产环境或第三方目标运行探测脚本。运行探测脚本需要一个
由你提供的、正在运行的**测试**实例和测试凭据。

要让这成为长期生效的行为，`websec install <host>` 会为你的智能体写入一条指令（`claude`、`cursor`、`codex`、
`gemini`、`aider` 或 `generic`）。参见 [AI 智能体指南](../../guides/ai-agents.md)。

### 6. 可选：用 `--scan` 加入静态扫描器

```bash
websec doctor .          # 安装了哪些可选扫描器，以及它们的版本是否可用
websec run . --scan      # 同时运行它们，并把结果去重合并到同一份台账中
```

不加 `--scan` 时，扫描器只会被列出。加上之后，websec 会运行你 `PATH` 中所有受支持的工具（Trivy、OSV-Scanner、
Gitleaks、Semgrep、Checkov，以及在检测到相应语言时运行的 Bandit、gosec 或 Brakeman）。请注意，这些外部工具在其
自身的默认配置下可能会使用网络，例如下载漏洞数据库或规则。各工具的作用及安装方法参见
[Installation](../../installation.md#optional-external-tools)。

## 如果有些结果看起来不对

- `tests/`、`examples/` 或 `fixtures/` 中有大量发现项？运行 `websec init` 生成一份经过审阅的 `.websec-ignore` 框架。
  参见 [Triage and suppression](../../guides/triage-and-suppression.md)。
- 某个发现项你已经核查过，认为是错的？`websec feedback` 会离线记录它，并打印一个预先填好的 issue 链接；不会发送任何内容。
- 其他任何问题：[Troubleshooting](../../troubleshooting.md)。

## 后续步骤

下方链接的页面为英文。

- [Existing projects](../../guides/existing-projects.md)：在成熟的代码库中采用 websec。
- [Triage and suppression](../../guides/triage-and-suppression.md)：`.websec-ignore`、确认标记（acknowledgements）、`--exclude`。
- [GitHub Actions](../../guides/ci/github-actions.md) 和[其他 CI](../../guides/ci/other-ci.md)：为构建设置门禁。
- [How it works](../../concepts/how-it-works.md)：websec 读取什么，以及一个发现项如何获得其严重级别。
- [FAQ](../../faq.md)：websec 是什么、不是什么。
