"""LLM / AI-agent security extractor — the OWASP LLM Top 10 surface.

The whole-class blind spot found when validating against a production LLM-agent monorepo: the tool
mapped HTTP routes, auth, SSRF and IaC but had ZERO coverage of the agentic surface — prompt
construction, model output handling, tool dispatch, and guardrails. This adds high-precision static
tells for the patterns that actually shipped as bugs:

  - LLM01 Prompt injection — UNTRUSTED retrieved/tool/web content concatenated into a model prompt
    with no sanitizer/fence (indirect injection), esp. when the prompt is told to render a supplied
    URL "verbatim".
  - LLM02 Insecure output handling — model TEXT parsed into an executable structure (JSON.parse of
    the completion → tool dispatch; a `tool_calls`/`tool_use` regex over model prose) so injected
    text becomes tool execution.
  - LLM06/08 Excessive agency — a state-changing tool (send/email/delete/exec/transfer/spend)
    executed inside an agent loop with model-chosen args and no human-confirmation gate.
  - LLM10 Unbounded consumption — an LLM call with no output-token cap (and no timeout) → cost /
    latency amplification, worst on an unauthenticated endpoint.
  - Guardrail integrity — a moderation/guard scan that FAILS OPEN (returns allow on error/timeout)
    or is constructed only when an env URL is set (off by default).

All heuristics are server-side, test-excluded, and framed as leads (LOW/MEDIUM) — an LLM call is not
itself a vuln. Detection is regex over code, not an AST/dataflow engine, so it points the agent at
the file to verify, it doesn't prove exploitability.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext, is_client_file, is_script_file, is_test_file
from .syntax import (without_comments, call_expression, direct_options, expression_end,
                     direct_call, server_file, split_arguments)

# LLM SDK call sites (Vercel AI SDK, OpenAI, Anthropic, LangChain, litellm, Bedrock, Gemini).
LLM_CALL = re.compile(
    r"\b(?:generateText|streamText|generateObject|streamObject)\s*\(|"
    r"\b(?:chat\.completions|completions|responses|messages)\.(?:create|stream)\s*\(|"
    r"\.(?:invoke|stream|generate|predict|complete)\s*\(\s*[^)]*\b(?:prompt|messages|input)\b|"
    r"\b(?:ChatOpenAI|ChatAnthropic|ChatBedrock|ChatGoogleGenerativeAI|createAnthropic|createOpenAI)\b|"
    r"\blitellm\.\w+\(|generateContent\s*\(", re.I)
# a prompt being assembled (the sink whose inputs matter)
PROMPT_SINK = re.compile(r"\b(?:prompt|system|systemPrompt|messages)\s*[:=]", re.I)
TOKEN_CAP = re.compile(r"\bmax(?:_?(?:output_?)?tokens|_completion_tokens|OutputTokens|Tokens)\b", re.I)
TIMEOUT = re.compile(r"\babortSignal\b|AbortSignal|\bsignal\s*:|\btimeout\b|maxRetries", re.I)

# model TEXT → executable structure (insecure output handling). Narrowed to MODEL-output names +
# tool-call-from-text extraction so a generic `JSON.parse(result)` doesn't fire.
OUTPUT_PARSE = re.compile(
    r"JSON\.parse\s*\(\s*[^)]*\b(?:completion|modelResponse|llmResponse|aiResponse|assistantMessage"
    r"|generatedText|model\w*\.text|response\.text|result\.text|message\.content|\.choices)\b"
    r"|\b(?:extract|parse)\w*Tool\w*Call\w*\s*\(|\"tool_calls\"|'tool_calls'|\"tool_use\"|'tool_use'", re.I)
# explicit tool-call-from-prose extraction can live in its own module (no LLM call there)
TOOLCALL_FROM_TEXT = re.compile(r"\b(?:extract|parse)\w*Tool\w*Call\w*\s*\(|\"tool_calls\"|\"tool_use\"|'tool_use'", re.I)
# untrusted content variables (RAG / tool result / web / user document) feeding a prompt
UNTRUSTED_VAR = re.compile(
    r"\b(?:excerpt|excerptText|chunk\w*|ragText|ragContent|retrieved\w*|context(?:Text|Content|Chunks)?"
    r"|document\w*(?:Text|Content)?|webResult\w*|searchResult\w*|toolResult\w*|scraped\w*|emailBody"
    r"|messageText|sourceUrl|citation\w*|memory(?:Text|Content|Entries)?)\b", re.I)
SANITIZER = re.compile(
    r"sanitize\w*Prompt|sanitizePromptString|escapePrompt|fence\w*|stripInstruction|redactPrompt|"
    r"promptGuard|defang|neutraliz|injectionFilter", re.I)
VERBATIM_URL = re.compile(r"verbatim|render[^.\n]{0,30}link|\[[^\]]+\]\(\$\{|USE[-_]LINK", re.I)

# excessive agency — a state-changing/side-effecting tool definition or call
ACTION_TOOL = re.compile(
    r"\b(?:send(?:Email|Message|Sms|Push|Teams|Slack)?|delete\w*|remove\w*|transfer\w*|pay\w*|charge\w*"
    r"|execute\w*|runCommand|exec\b|spawn\b|createUser|grant\w*|provision\w*|publish\w*|approve\w*)\s*\(", re.I)
TOOL_DEF = re.compile(r"\btool\s*\(|\btools\s*[:=]\s*\{|\bzodFunction|\bDynamicTool\b|registerTool|defineTool|StructuredTool", re.I)
HUMAN_GATE = re.compile(r"confirm\w*|requireApproval|humanInTheLoop|awaitConfirmation|pendingApproval|review\w*Required", re.I)

# guardrail / moderation that FAILS OPEN
GUARD_FN = re.compile(r"\b(?:guard|scan(?:Input|Output)?|moderat\w*|checkContent|safetyCheck|nemo|llmGuard)\w*\s*[\(=]", re.I)
FAIL_OPEN = re.compile(
    r"catch[^{]*\{[^}]*\breturn\b[^}]*(?:allowed\s*:\s*true|action\s*:\s*['\"](?:allow|error|continue)|true)"
    r"|fail[-_ ]?open|continuing[^.\n]{0,20}(?:fail|open)|return\s*\{\s*allowed\s*:\s*true", re.I)


def _llm_call_without(text: str, guard_rx: re.Pattern) -> bool:
    for match in LLM_CALL.finditer(text):
        options = direct_options(call_expression(text, match.start()))
        if not any(guard_rx.fullmatch(key) and re.fullmatch(r"[1-9]\d*", value.strip())
                   for key, value in options.items()):
            return True
    return False


def _references(expression: str) -> str:
    # Literal prompt prose such as "Context:" is not a variable named context.
    def replace(match):
        value = match[0]
        if value.startswith("`"):
            return " ".join(re.findall(r"\$\{([^}]*)\}", value))
        return " "
    return re.sub(r"`(?:\\.|[^`])*`|\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'", replace, expression)


def _untrusted_value(expression: str, prefix: str, depth: int = 0) -> bool:
    references = _references(expression)
    if UNTRUSTED_VAR.search(references):
        return True
    if depth >= 8:
        return True  # unresolved deep alias chain cannot establish a trusted prompt value
    for name in re.findall(r"\b[A-Za-z_$]\w*\b", references):
        assignments = list(re.finditer(r"\b(?:const|let|var)?\s*" + re.escape(name)
                                      + r"\s*=(?!=)\s*([^;\n]+)", prefix))
        if any(_untrusted_value(item[1], prefix[:item.start()], depth + 1) for item in assignments):
            return True
    return False


def _untrusted_prompt(text: str) -> bool:
    for match in PROMPT_SINK.finditer(text):
        expression = text[match.end():expression_end(text, match.end())].strip()
        # prompt: inside options ends at an outer comma; other object fields are unrelated.
        expression = split_arguments(expression)[0]
        if UNTRUSTED_VAR.search(_references(expression)):
            if not direct_call(expression, SANITIZER.pattern, text[:match.start()], program=text):
                return True
        # One immutable local binding is supported; reassignment/alias chains remain unresolved.
        for name in re.findall(r"\b[A-Za-z_$]\w*\b", _references(expression)):
            assignments = list(re.finditer(r"\b(?:const|let|var)?\s*" + re.escape(name)
                                          + r"\s*=(?!=)\s*([^;\n]+)", text[:match.start()]))
            if not assignments:
                continue
            if len(assignments) > 1 and any(_untrusted_value(item[1], text[:item.start()]) for item in assignments):
                return True  # conflicting or shadowed bindings remain unresolved
            value = assignments[-1][1]
            if _untrusted_value(value, text[:assignments[-1].start()]):
                immutable = assignments[-1][0].lstrip().startswith("const ") and len(assignments) == 1
                if not immutable or not direct_call(value.strip(), SANITIZER.pattern, text[:assignments[-1].start()], program=text):
                    return True
    return False


def _human_gated(text: str, position: int) -> bool:
    # Credit only an action nested in the positive branch of an explicit approval predicate.
    # A guard helper declaration, an unchecked call, or a branch around another action is unverified.
    for match in re.finditer(r"\bif\s*\(", text):
        end = expression_end(text, text.find("(", match.start()), closing=")")
        condition = text[text.find("(", match.start()) + 1:end - 1]
        opening = end
        while opening < len(text) and text[opening].isspace():
            opening += 1
        if opening >= len(text) or text[opening] != "{":
            continue
        body_end = expression_end(text, opening, closing="}")
        if opening < position < body_end and not re.search(r"!|\|\||\bor\b", condition):
            gate = HUMAN_GATE.search(condition)
            if gate is None:
                continue
            guard_call = call_expression(condition, gate.start())
            action_call = call_expression(text, position)
            guard_args = split_arguments(guard_call[guard_call.find("(") + 1:-1])
            action_args = split_arguments(action_call[action_call.find("(") + 1:-1])
            if (guard_args and guard_args[0] and guard_args == action_args
                    and text[opening + 1:position].strip() in ("", "await", "return", "return await")
                    and re.sub(r"^\s*await\s+", "", condition).strip() == guard_call.strip()
                    and direct_call(guard_call, HUMAN_GATE.pattern, text[:match.start()], program=text)):
                return True
    return False


class LlmSecurityExtractor(Extractor):
    name = "llm_security"
    category = "llm"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        findings: list = []
        llm_files: list = []
        seen_kind_file: set = set()

        def add(sev, kind, attack, rel, detail):
            if (kind, rel) in seen_kind_file:
                return
            seen_kind_file.add((kind, rel))
            findings.append({"severity": sev, "kind": kind, "attack_class": attack,
                             "file": rel, "detail": detail})

        for _p, rel, raw in ctx.iter_code():
            text = without_comments(raw, _p.suffix.lower())
            # tests, browser code, and build/CLI scripts are not the runtime agentic surface
            if is_test_file(rel) or not server_file(rel, text, is_client_file(rel, text)) or is_script_file(rel):
                continue
            has_llm = bool(LLM_CALL.search(text))
            has_prompt = bool(PROMPT_SINK.search(text))
            if has_llm:
                llm_files.append(rel)

            # LLM10 — unbounded generation (no output-token cap on the call)
            if has_llm and _llm_call_without(text, TOKEN_CAP):
                no_timeout = not TIMEOUT.search(text)
                add("MEDIUM", "llm-unbounded-generation", "llm-unbounded", rel,
                    "An LLM call has no output-token cap (maxTokens/maxOutputTokens)"
                    + (" and no timeout/abortSignal" if no_timeout else "")
                    + " — output length and wall-clock are unbounded, so a crafted prompt can amplify "
                      "cost/latency (LLM10). Worst on an unauthenticated endpoint. Set an explicit "
                      "maxOutputTokens + an AbortSignal timeout, and cap in-flight concurrency.")

            # LLM02 — model output parsed into an executable structure / tool dispatch. Require an LLM
            # call in the file OR an explicit tool-call-from-prose extractor (the high-signal form).
            if OUTPUT_PARSE.search(text) and (has_llm or TOOLCALL_FROM_TEXT.search(text)):
                add("MEDIUM", "llm-insecure-output-handling", "llm-insecure-output", rel,
                    "Model output appears to be parsed into an executable structure (JSON.parse of the "
                    "completion, or a tool_calls/tool_use parse over model TEXT). Injected text can then "
                    "become tool execution, bypassing the structured tool-calling contract (LLM02/LLM08). "
                    "Treat model prose as display-only; never as a control channel — require any "
                    "fallback-derived call to match a strict allow-list and never fire state-changing tools.")

            # LLM01 — untrusted retrieved/tool content into a prompt with no sanitizer/fence. Require
            # the file to actually build AND call a model (has_llm + a prompt sink) to stay precise.
            if has_llm and has_prompt and _untrusted_prompt(text):
                verbatim = bool(VERBATIM_URL.search(text))
                add("MEDIUM" if verbatim else "LOW", "llm-indirect-prompt-injection",
                    "llm-prompt-injection", rel,
                    "Externally-sourced content (RAG excerpt / tool result / document / sourceUrl) is "
                    "interpolated into a model prompt with no visible sanitizer/fence (LLM01 indirect "
                    "prompt injection)."
                    + (" The prompt also renders a supplied URL VERBATIM as a link — an attacker who "
                       "controls the indexed source controls a clickable link in the output." if verbatim else "")
                    + " Fence retrieved content as untrusted data, run it through a prompt scrubber, and "
                      "allow-list any URL host/scheme before emitting it. VERIFY the data's trust level.")

            # LLM06/08 — a DEFINED agent tool that takes a state-changing action with no human gate
            if TOOL_DEF.search(text) and any(not _human_gated(text, m.start()) for m in ACTION_TOOL.finditer(text)):
                add("LOW", "llm-excessive-agency", "excessive-agency", rel,
                    "A state-changing/side-effecting action (send/delete/transfer/exec/grant/…) appears in "
                    "an agent tool surface with no visible human-confirmation gate (LLM06/LLM08 excessive "
                    "agency). VERIFY: if the model chooses the args (recipient/amount/target) and the tool "
                    "executes them unattended, gate it behind explicit human approval and scope its authority.")

            # Guardrail fails open
            if GUARD_FN.search(text) and FAIL_OPEN.search(text):
                add("MEDIUM", "llm-guardrail-fail-open", "llm-guardrail", rel,
                    "A moderation/guard path appears to FAIL OPEN — on error/timeout it returns allow/continue "
                    "rather than blocking, so an attacker who stalls or floods the guard disables it while the "
                    "model keeps answering. Fail CLOSED for sensitive turns (return the refusal on guard error) "
                    "and alert when the guard is unavailable.")

        for finding in findings:
            finding["control_scope"] = "per invocation/expression; named controls without a proven relation remain unverified"

        by_sev: dict = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        ai_app = bool(llm_files) or "openai" in str(facts.get("integrations", {})).lower()
        return {
            "is_ai_app": ai_app,
            "llm_call_sites": sorted(set(llm_files))[:40],
            "findings": findings,
            "by_severity": by_sev,
            "note": (f"AI/LLM surface detected ({len(set(llm_files))} file(s) call an LLM SDK). " if llm_files
                     else "No direct LLM SDK call sites detected. ")
                    + "LLM findings are leads (regex, not dataflow) — verify each: is the content untrusted, "
                      "does model output drive a tool, is the action human-gated, is generation bounded? "
                      "The agentic surface (prompt construction → tool dispatch → output) is where the real "
                      "risk in an AI app lives.",
        }
