"""Spring Security as route-guard evidence (#241).

Two independent sources of authorization, each credited only where it applies:

* **Filter chains.** A `SecurityFilterChain` bean (or a legacy `WebSecurityConfigurerAdapter`) lists
  request rules in order; the first rule whose matcher covers a request decides it. A route is
  guarded when that rule is `authenticated()`/`hasRole(...)`/`access(...)`/`denyAll()`, and public
  when it is `permitAll()`/`anonymous()`. A chain applies to routes in its own Maven/Gradle module,
  or in a module whose build file depends on it (the shared-security-library layout).
* **Method security.** `@PreAuthorize`/`@PostAuthorize` (and `@Secured`, `@RolesAllowed`) on the
  handler or its class guard that handler, but only when `@EnableMethodSecurity` /
  `@EnableGlobalMethodSecurity` turns that annotation family on. `@PreAuthorize("permitAll()")`
  is not a guard.

What stays unresolved is reported as such, never as a guard: matchers built from non-literal
arguments, XML `<http>` configuration, chains reached only through auto-configuration, and a module
that depends on Spring Security with no chain this analysis can see (Spring Boot's default secures
everything, but a library chain may relax it).
"""
from __future__ import annotations

import re

from .jvm import (JVM_SUFFIXES, balanced_end, build_module, handler_for, handlers, mask_literals,
                  module_depends_on, module_text, string_literals)
from .syntax import without_comments

_CHAIN_MARKER = re.compile(r"authorizeHttpRequests|authorizeRequests|authorizeExchange|\bauthorize\s*\(")
_BEAN = re.compile(r"\b(?:SecurityFilterChain|SecurityWebFilterChain)\s+\w+\s*\(|"
                   r"\bfun\s+\w+\s*\([^)]*\)\s*:\s*(?:SecurityFilterChain|SecurityWebFilterChain)|"
                   r"\bvoid\s+configure\s*\(\s*(?:final\s+)?HttpSecurity\b")
_MATCHER = re.compile(r"\.\s*(requestMatchers|antMatchers|mvcMatchers|regexMatchers|pathMatchers"
                      r"|anyRequest|anyExchange)\s*\(")
_DECISION = re.compile(r"\s*\.\s*(permitAll|anonymous|authenticated|fullyAuthenticated|rememberMe|hasRole"
                       r"|hasAnyRole|hasAuthority|hasAnyAuthority|hasIpAddress|access|denyAll)\s*\(")
_KOTLIN_RULE = re.compile(r"\bauthorize\s*\(\s*(?:(?:HttpMethod\.(\w+))\s*,\s*)?(\"(?:\\.|[^\"\\])*\"|anyRequest|anyExchange)"
                          r"\s*,\s*(permitAll|anonymous|authenticated|fullyAuthenticated|denyAll|hasRole|hasAnyRole"
                          r"|hasAuthority|hasAnyAuthority|access)")
_SECURITY_MATCHER = re.compile(r"\.\s*(?:securityMatcher|antMatcher|mvcMatcher|regexMatcher)\s*\(|\bsecurityMatcher\s*\(")
_IGNORING = re.compile(r"\.\s*ignoring\s*\(\s*\)\s*\.\s*(?:requestMatchers|antMatchers|mvcMatchers)\s*\(")
_PUBLIC = {"permitAll", "anonymous"}
_DENY = {"denyAll"}

_METHOD_ANNOTATION = re.compile(r"@(PreAuthorize|PostAuthorize|Secured|RolesAllowed|DenyAll|PermitAll)\b")
_FAMILY = {"PreAuthorize": "prepost", "PostAuthorize": "prepost", "Secured": "secured",
           "RolesAllowed": "jsr250", "DenyAll": "jsr250", "PermitAll": "jsr250"}
_SPRING_SECURITY_DEP = re.compile(r"spring-boot-starter-security|spring-security-(?:config|web)|"
                                  r"spring-boot-starter-oauth2-resource-server|spring-boot-starter-oauth2-client")


def ant_regex(pattern: str) -> re.Pattern:
    """Spring path pattern → regex. A trailing `/**` also matches the bare prefix (PathPattern)."""
    pattern = "/" + pattern.strip().lstrip("/")
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("/**", i):
            out += "(?:/.*)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        elif pattern[i] == "{":
            close = pattern.find("}", i)
            close = len(pattern) - 1 if close < 0 else close
            out += "[^/]+"
            i = close + 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out.rstrip("/") + "/?$" if out not in ("", "/") else "/?$")


def _route_sample(path: str) -> str:
    """A concrete request path for a route template: `{id}` becomes one segment."""
    return "/" + re.sub(r"\{[^}/]*\}", "_p_", (path or "").strip().strip("/"))


def _chain_rules(text: str, masked: str, start: int, end: int) -> dict:
    rules, unresolved = [], []
    for matcher in _MATCHER.finditer(masked, start, end):
        close = balanced_end(masked, matcher.end() - 1)
        decision = _DECISION.match(masked, close)
        if not decision:
            continue
        args = text[matcher.end():close - 1]
        kind = matcher[1]
        method = None
        verb = re.search(r"HttpMethod\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)", args)
        if verb:
            method = verb[1]
        if kind in ("anyRequest", "anyExchange"):
            patterns = ["/**"]
        else:
            patterns = string_literals(args)
            if kind == "regexMatchers" or not patterns:
                unresolved.append(text[matcher.start():decision.end()].strip()[:120])
                if not patterns:
                    continue
        arg_close = balanced_end(masked, decision.end() - 1)
        verdict = decision[1]
        if verdict == "access" and "permitAll" in text[decision.end():arg_close]:
            verdict = "permitAll"
        rules.append({"method": method, "patterns": patterns, "decision": verdict,
                      "regex": kind == "regexMatchers", "pos": matcher.start(),
                      "evidence": re.sub(r"\s+", " ", text[matcher.start():arg_close]).strip()[:160]})
    for rule in _KOTLIN_RULE.finditer(masked, start, end):
        target = text[rule.start(2):rule.end(2)]
        patterns = ["/**"] if target in ("anyRequest", "anyExchange") else string_literals(target)
        rules.append({"method": rule[1], "patterns": patterns, "decision": rule[3], "regex": False,
                      "pos": rule.start(), "evidence": re.sub(r"\s+", " ", text[rule.start():rule.end()]).strip()[:160]})
    rules.sort(key=lambda row: row["pos"])  # Spring evaluates rules in declaration order
    scope = []
    for matcher in _SECURITY_MATCHER.finditer(masked, start, end):
        close = balanced_end(masked, masked.find("(", matcher.start()))
        scope.extend(string_literals(text[matcher.start():close]))
    return {"rules": rules, "scope": scope, "unresolved": unresolved}


def _chains_in(text: str) -> list[dict]:
    masked = mask_literals(text)
    chains = []
    for bean in _BEAN.finditer(masked):
        opening = masked.find("{", bean.end())
        if opening < 0:
            continue
        end = balanced_end(masked, opening)
        if not _CHAIN_MARKER.search(masked, opening, end):
            continue
        chain = _chain_rules(text, masked, opening, end)
        chain["line"] = text.count("\n", 0, bean.start()) + 1
        chains.append(chain)
    ignored = []
    for ignoring in _IGNORING.finditer(masked):
        close = balanced_end(masked, ignoring.end() - 1)
        ignored.extend(string_literals(text[ignoring.end():close - 1]))
    if ignored:
        chains.append({"rules": [{"method": None, "patterns": ignored, "decision": "permitAll", "regex": False,
                                  "evidence": "web.ignoring() " + ", ".join(ignored)[:120]}],
                       "scope": ignored, "unresolved": [], "line": 0, "ignoring": True})
    return chains


def _rule_matches(rule: dict, method: str, sample: str) -> bool:
    if rule["method"] and method not in (rule["method"], "ANY", "ALL"):
        return False
    for pattern in rule["patterns"]:
        try:
            regex = re.compile(pattern) if rule["regex"] else ant_regex(pattern)
        except re.error:
            continue
        if regex.match(sample) if not rule["regex"] else regex.fullmatch(sample):
            return True
    return False


class SpringSecurity:
    """Repository-wide Spring Security facts, resolved per route on demand."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.chains: list[dict] = []           # each with "file" and "module"
        self.method_security: dict = {}        # module -> set of enabled annotation families
        self._handlers: dict = {}
        for path in ctx.code_files:
            if path.suffix.lower() not in JVM_SUFFIXES:
                continue
            rel = ctx.rel(path)
            raw = ctx.text(path)
            if not raw or not re.search(r"springframework\.security|EnableMethodSecurity|"
                                        r"EnableGlobalMethodSecurity|SecurityFilterChain|HttpSecurity", raw):
                continue
            text = without_comments(raw, path.suffix.lower())
            module = build_module(ctx, rel)
            for chain in _chains_in(text):
                chain.update(file=rel, module=module)
                self.chains.append(chain)
            families = _enabled_families(text)
            if families:
                self.method_security.setdefault(module, set()).update(families)

    # -- applicability ---------------------------------------------------------------------------
    def _visible(self, module: str, source_module: str) -> bool:
        if module == source_module:
            return True
        if source_module and module.startswith(source_module + "/"):
            return False  # a parent aggregator's code is not its children's classpath
        return module_depends_on(self.ctx, module, source_module)

    def _handler_rows(self, rel: str) -> list[dict]:
        if rel not in self._handlers:
            path = self.ctx.root / rel
            raw = self.ctx.text(path)
            self._handlers[rel] = handlers(without_comments(raw, path.suffix.lower())) if raw else []
        return self._handlers[rel]

    # -- per route -------------------------------------------------------------------------------
    def route(self, rel: str, method: str, path: str) -> dict | None:
        """Guard evidence for one route in a JVM handler file, or None when Spring Security says nothing."""
        if not rel or ("." + rel.rsplit(".", 1)[-1]).lower() not in JVM_SUFFIXES:
            return None
        module = build_module(self.ctx, rel)
        method = (method or "").upper()
        result: dict = {"guarded": False, "evidence": [], "unverified": [], "public_rule": None}

        families = set()
        for source_module, enabled in self.method_security.items():
            if self._visible(module, source_module):
                families |= enabled
        for row in handler_for(self._handler_rows(rel), method, path):
            for scope, block in (("method", row["annotations"]), ("class", row["class_annotations"])):
                for annotation in _METHOD_ANNOTATION.finditer(block):
                    name = annotation[1]
                    value = block[annotation.end():annotation.end() + 200]
                    if name == "PermitAll" or (name in ("PreAuthorize", "PostAuthorize")
                                               and re.match(r"\s*\(\s*\"\s*permitAll\s*\(\s*\)\s*\"", value)):
                        continue
                    if _FAMILY[name] in families:
                        result["guarded"] = True
                        result["evidence"].append(f"@{name} on the {scope} ({row['class']}.{row['name']})")
                    else:
                        result["unverified"].append(
                            f"@{name} on the {scope} is not enforced unless method security enables it "
                            "(@EnableMethodSecurity" + ("" if _FAMILY[name] == "prepost" else
                                                         f"({_FAMILY[name]}Enabled = true)") + "); none was found")
                if result["guarded"]:
                    break

        sample = _route_sample(path)
        visible = [chain for chain in self.chains if self._visible(module, chain["module"])]
        # A chain with a securityMatcher only handles requests it matches; check those first.
        ordered = ([chain for chain in visible if chain["scope"] and not chain.get("ignoring")]
                   + [chain for chain in visible if not chain["scope"]])
        ignoring = [chain for chain in visible if chain.get("ignoring")]
        for chain in ignoring:
            if _rule_matches(chain["rules"][0], method, sample):
                result["public_rule"] = f"{chain['file']}: {chain['rules'][0]['evidence']} (security filters skipped)"
                return result if result["guarded"] else dict(result, decided=True)
        for chain in ordered:
            if chain["scope"] and not any(ant_regex(p).match(sample) for p in chain["scope"]):
                continue
            for rule in chain["rules"]:
                if not _rule_matches(rule, method, sample):
                    continue
                where = f"{chain['file']}:{chain['line']}: {rule['evidence']}"
                if rule["decision"] in _PUBLIC:
                    result["public_rule"] = where
                else:
                    result["guarded"] = True
                    result["evidence"].append("Spring Security " + where)
                if chain["unresolved"] and rule["decision"] not in _PUBLIC:
                    result["unverified"].append("matchers with non-literal arguments precede or follow this rule: "
                                                + "; ".join(chain["unresolved"][:3]))
                result["decided"] = True
                return result
            break  # the first chain that handles the request decides it, even with no matching rule
        if result["guarded"]:
            result["decided"] = True
            return result
        if self._depends_on_spring_security(module) or visible:
            result["central_unresolved"] = True
            result["unverified"].append("Spring Security is on this module's classpath but no filter chain rule "
                                        "covering this route was resolved (shared/auto-configured chain or "
                                        "Spring Boot's default); verify the effective policy")
            return result
        return None if not result["unverified"] else result

    def _depends_on_spring_security(self, module: str) -> bool:
        directory = module
        while True:
            if _SPRING_SECURITY_DEP.search(module_text(self.ctx, directory)):
                return True
            if not directory:
                return False
            directory = directory.rsplit("/", 1)[0] if "/" in directory else ""


def _enabled_families(text: str) -> set:
    families = set()
    for match in re.finditer(r"@Enable(Reactive)?MethodSecurity\b(\s*\([^)]*\))?", text):
        args = match[2] or ""
        if not re.search(r"prePostEnabled\s*=\s*false", args):
            families.add("prepost")
        if re.search(r"securedEnabled\s*=\s*true", args):
            families.add("secured")
        if re.search(r"jsr250Enabled\s*=\s*true", args):
            families.add("jsr250")
    for match in re.finditer(r"@EnableGlobalMethodSecurity\b(\s*\([^)]*\))?", text):
        args = match[1] or ""
        for flag, family in (("prePostEnabled", "prepost"), ("securedEnabled", "secured"), ("jsr250Enabled", "jsr250")):
            if re.search(flag + r"\s*=\s*true", args):
                families.add(family)
    return families
