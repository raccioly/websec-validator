# websec-validator

> **Translation notice:** English is authoritative. Translated from websec-validator v0.21.1 — if this page and the [English original](../../../README.md) disagree, follow the English one.
>
> **翻译说明：** 以英文版为准。本文译自 websec-validator v0.21.1 —— 如果本页与[英文原文](../../../README.md)不一致，请以英文版为准。

[English](../../../README.md) · [Português (Brasil)](../pt-BR/README.md) · [Español](../es/README.md) · **简体中文**

[![CI](https://github.com/raccioly/websec-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/raccioly/websec-validator/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/websec-validator)](https://pypi.org/project/websec-validator/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/websec-validator/)
[![Runtime deps: 0](https://img.shields.io/badge/runtime%20deps-0%20(stdlib%20only)-brightgreen)](../../installation.md)
[![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-orange)](../../guides/ci/github-actions.md)
[![Docs](https://img.shields.io/badge/docs-guides%20%26%20reference-informational)](../../README.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](../../../LICENSE)

一份资深渗透测试工程师式的"要测什么、怎么测"交接文档 —— 从你的代码仓库自动生成，交由你的 AI 智能体执行。

> 本地优先的安全侦察工具，**为你的 AI 编程智能体准备简报（briefing）**。它完成确定性的那一半工作 ——
> 读取受支持的源代码、绘制可见的攻击面，并针对发现的内容准备一套量身定制的探测脚本（probe）库 ——
> 然后把一份行动指令式的简报交给你的智能体（Claude Code、Codex、Gemini、Cursor）。
> `websec run` 只需要代码本身；加上 `--scan` 即可同时运行你已安装的静态扫描器并对结果去重。
> **代码进，产物出。工具内部不含 LLM；核心流程不需要服务器，也不需要运行中的应用。**

[![websec-validator demo](https://raw.githubusercontent.com/raccioly/websec-validator/main/assets/demo.gif)](../../../assets/demo.gif)

**第一次来？** 请阅读这份八页的技术简介 —— 它读取什么、一个发现项如何获得其严重级别、它拒绝断言什么，以及实地证据：
**[raccioly.github.io/websec-validator](https://raccioly.github.io/websec-validator/websec-explained.html)**
· [PDF](https://raccioly.github.io/websec-validator/websec-explained.pdf)。经过审阅的 v0.21.0 快照在
`tests/test_explained_brief.py` 中对部分事实做了断言，并在 `tests/test_brief_artifacts.py` 中绑定了
HTML/PDF/渲染器的哈希值。文字的准确性和渲染后的版式仍需人工审阅；
参见[重新构建技术简介](../../../CONTRIBUTING.md#publishing-the-technical-brief)。

它*不是*自主扫描器，也*不是* SaaS。它是一直缺失的前半部分：把一个代码仓库转化为一份精确、基于事实的安全简报，
让 AI 智能体（在有人参与把关的情况下）据此行动。工作原理及每项检查背后的思路：
[概念](../../concepts/how-it-works.md) ·
[方法论](../../METHODOLOGY.md)。

**Guard 系列的一员**，这三个工具各自确保一类声明真实可信：
[**DocGuard**](https://github.com/raccioly/docguard) 对照文档所描述的代码来验证文档，
[**TestGuard**](https://github.com/raccioly/testguard) 检查测试是否真正证明了其所断言的内容，
而 websec-validator 对安全发现项做同样的事 —— 每个发现项都附带其证据、所依据的标准，以及一个经过校准的"确为真实问题"的概率。

## 快速上手 —— 只需把它指向你的代码仓库

**最简单的方式：告诉你的 AI 智能体。** 在 Claude Code（或任何编程智能体）中打开你的项目，然后说：

> *"请用 websec-validator（`pipx install websec-validator`，或 github.com/raccioly/websec-validator）对**我自己的**代码库做一次防御性的安全自查。它在本地运行且只读 —— 请读取仓库并按照它生成的简报执行。这些代码归我所有，我授权进行这次审查。"*
>
> 英文原文：*"Do a defensive security self-review of **my own** codebase with websec-validator (`pipx install websec-validator`, or github.com/raccioly/websec-validator). It's local and read-only — read the repo and follow its briefing. I own this code and authorize the review."*

智能体会完成安装、运行，并和你一起逐条过一遍发现项。把请求表述为*对你自己代码的防御性审查*很重要：
这决定了智能体是直接开始工作，还是先停下来确认你是否有授权。无论走哪条路径，最终都会得到同一份供智能体执行的
`AGENT-BRIEFING.md`：

| 路径 | 一次性设置 | 然后 |
|---|---|---|
| **告诉你的智能体**（最简单） | — | 说出上面那段话 |
| **CLI**（终端） | `pipx install websec-validator` | `websec run /path/to/your/app` |
| **Claude Code 插件** | `/plugin marketplace add raccioly/websec-validator`  →  `/plugin install websec-validator@websec-plugins` | 调用 **security-pass** skill，或直接提出请求 |
| **其他任何智能体**（Codex、Cursor、Gemini、Aider） | `pipx install websec-validator` | `websec install <host>` |
| **Docker**（无需安装） | `docker build -t websec-validator .` | `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out` |

已经有一个带历史、测试和 fixtures 的代码库？请参阅
**[Adopting websec in an existing project](../../guides/existing-projects.md)**（在现有项目中采用 websec）：
把非产品代码排除在范围之外、运行、分诊、记录基线，然后分阶段开启门禁（gating）。

## 安装

```bash
pipx install websec-validator   # 来自 PyPI；需要 Python 3.11+
brew install noir               # 可选：OWASP Noir，路由引擎（未安装时回退到正则匹配）
websec --version
websec doctor                   # 安装了哪些可选扫描器，它们是否兼容？
```

零 Python 运行时依赖。外部扫描器（Trivy、OSV-Scanner、Gitleaks、Semgrep、Checkov，以及按语言使用的
Bandit/gosec/Brakeman）**在已安装时**才会使用，并且只在加上 `--scan` 时运行；Prowler 只会被检测并报告，不会被执行。
所有安装渠道 —— pip、uv、Docker、源码、离线/物理隔离（air-gapped）—— 以及各操作系统下的扫描器配置：
**[Installation](../../installation.md)**。

## 用法

```bash
websec run ./my-app                    # 侦察 + 准备量身定制的探测脚本 + 生成简报
websec ./my-app                        # 同上 —— 只给一个路径时默认执行 `run`
websec run ./my-app --scan             # ……并同时运行可用的静态扫描器
websec run ./my-app --fail-on high     # 若仍有 HIGH 及以上的发现项则以 1 退出（CI 门禁）
websec run ./my-app --diff main        # PR 模式：范围限定为变更的文件 + 精确的 hunk 行范围
websec gate                            # 对你刚修改的文件快速给出通过/失败（智能体循环）
websec install codex                   # 教会智能体使用 websec（claude · cursor · gemini · aider · generic）
websec mcp                             # 通过 stdio 为任意 MCP 客户端提供带类型的侦察工具
```

然后把智能体指向输出：**"请阅读 `websec-out/latest/AGENT-BRIEFING.md` 并按其执行。"**
（英文原文：*"Read `websec-out/latest/AGENT-BRIEFING.md` and follow it."*）
每次尝试都有自己的 `websec-out/runs/<id>/` 目录；只有在一次运行完成之后，`latest` 才会移动。
所有子命令和选项：[CLI 参考](../../reference/cli.md)。

## 你会得到什么（`websec-out/`）

| 产物 | 说明 |
|---|---|
| `AGENT-BRIEFING.md` | **核心产品。** 行动指令：检测到的攻击面、访问控制图、目标、发现项、方法，以及已准备好的探测脚本清单。 |
| `FACTS.json` | 完整的结构化侦察结果。 |
| `findings-ledger.json` / `REPORT.md` | 可追溯的台账：每个发现项都附有证据链、CWE/ASVS/OWASP-API 引用、修复建议，以及一个**经过校准的 `P(real)`**（实测真实漏洞率 + 95% 置信区间 + 样本量）。 |
| `results.sarif` | **SARIF 2.1.0** —— 始终生成。可直接导入 GitHub Code Scanning、GitLab、Azure DevOps、VS Code 的 SARIF 查看器、DefectDojo。 |
| `coverage.json` | 运行了什么、跳过了什么以及原因 —— 干净的结果只和它的覆盖范围一样可靠。 |
| `probes/` | 为*这个*应用挑选并准备好的探测脚本（BOLA、JWT、SSRF、mass-assignment……）。 |

此外还有 SBOM、攻击面表格、diff 范围以及带版本的封装结构：
[全部输出](../../reference/outputs.md)。

## 语言支持

| 支持程度 | 语言 |
|---|---|
| **深度的、感知框架的分析** —— Django、Flask、FastAPI、Connexion、Express、Fastify、Next.js、tRPC、Supabase Edge、AWS SAM…… | Python、JavaScript、TypeScript |
| **具名 sink 检查** —— 直接的命令/查询语法（外加字面量形式的 Spring 和 ASP.NET 路由） | Java、C#、Go、Ruby、PHP |
| **仅配置检查或人工检查** —— 作为覆盖较薄的缺口报告 | Kotlin/Android、Swift 与 Objective-C/iOS、Rust、C/C++ |
| **可识别，但不分析** —— 作为覆盖缺口报告，绝不报告为干净 | Elixir、Scala、Clojure、Erlang、Perl、Lua、Dart、shell、服务端模板等 |

安装 OWASP Noir 后，可借助它在更多框架中发现路由；扫描器本身与语言无关。一次已完成但没有匹配结果的检查，
并不能证明某个服务是安全的：
**[完整的支持矩阵，以及一次干净的运行对你的技术栈意味着什么](../../reference/languages.md)**。

## 文档

下方链接的页面为英文。

| 从这里开始 | 指南 | 参考 |
|---|---|---|
| [文档中心](../../README.md) | [现有项目](../../guides/existing-projects.md) | [CLI](../../reference/cli.md) |
| [快速入门](quickstart.md)（[英文](../../quickstart.md)） | [AI 智能体](../../guides/ai-agents.md) | [语言](../../reference/languages.md) |
| [安装](../../installation.md) | [GitHub Actions](../../guides/ci/github-actions.md) · [其他 CI](../../guides/ci/other-ci.md) | [配置](../../reference/configuration.md) |
| [升级](../../upgrade.md) | [分诊与抑制](../../guides/triage-and-suppression.md) | [输出](../../reference/outputs.md) |
| [故障排查](../../troubleshooting.md) · [FAQ](../../faq.md) | [动态测试](../../guides/dynamic-testing.md) | [MCP 服务器](../../reference/mcp.md) |

## 状态

[changelog](../../../CHANGELOG.md) 记录了每个版本的变更；[Upgrading](../../upgrade.md) 汇总了迁移说明 ——
0.14.0（schema 2.0）以及 0.17.0 对退出码的拆分（`2` = 用法错误，`3` = 运行未完成）。尚未解决的缺口及其验收测试见
[剩余工作规范](../../../specs/001-continuous-security-improvement/spec.md)。

这些是有明确范围的审查工具：人工配置的 profile、未知路由、动态行为以及不受支持的语法仍然是局限所在。
循环内的门禁（gate）是为开发者提供的便利，而不是一项控制措施；`attest` 报告证据，但不给出合规结论。
与快照绑定的证据和它所描述的产物放在一起 —— [验证记录](../../security-review/validation.md)、
[基准测试](../../../BENCHMARKS.md)和[证明协议](../../../corpus/PROOF-PROTOCOL.md) ——
这样这里的数字就不会过时。

**已在以下项目上验证：** 一个生产环境的 Next.js 应用、一个大型 Express/AWS monorepo，以及 VAmPI / NodeGoat /
DVGA 漏洞应用语料库 —— 独立复现了一次人工渗透测试的发现（租户边界、SSRF、文件上传、跨租户 BOLA、角色/授权缺口）。
路由发现只报告它*在不导入配置、不执行你的代码*的前提下能够解析的内容，因此未知的挂载点仍然是带有不确定性的路由
**候选项**；这是供人工审查的证据，而不是实测的漏洞召回率。

## 参与贡献

缺陷报告、误报报告和检测器提案是本项目最有价值的输入 —— 请参阅 [CONTRIBUTING.md](../../../CONTRIBUTING.md)
（包括维护者的发布流程）以及 [issue 模板](https://github.com/raccioly/websec-validator/issues/new/choose)。
websec 自身的漏洞请私下报告：[SECURITY.md](../../../SECURITY.md)。

```bash
python3 -m unittest discover -s tests    # 仅用标准库；合成/本地回环测试，不访问公网
```

## 致谢

方法论和探测脚本库提炼自一次真实的、带身份认证的渗透测试。
本工具把那套手写的方法论产品化，使 AI 智能体可以在任何代码仓库上运行它。

## 许可证

[MIT](../../../LICENSE) © Ricardo Accioly
