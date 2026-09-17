"""websec — CLI entry point.

Commands:
  websec run <repo> [--scan] [--out DIR]   full pipeline → FACTS.json + AGENT-BRIEFING.md + probes/
  websec recon <repo> [--out DIR]          recon only → FACTS.json
  websec doctor [<repo>]                    show which scanners are present / missing

Code-in, artifacts-out. No LLM, no server, no running app. Point your AI coding
agent at the generated AGENT-BRIEFING.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
import uuid
import sys
from pathlib import Path

from . import (__version__, baseline, briefing, calibration, constitution, diffscope, dynamic, feedback,
               findings, coverage, formats, fpfilter, inventory, probes, proof, recon, report, scanners)

_FEEDBACK_VERDICTS = feedback.VERDICTS
_FEEDBACK_SEVERITIES = feedback.SEVERITIES

MAX_SARIF_TOTAL_BYTES = 32 * 1024 * 1024


def _sarif_imports(paths, target, *, excludes=(), include_fixtures=False):
    """Bound cumulative expanded evidence, retaining honest failures for every requested input."""
    from . import sarif_ingest
    bundles, retained, exhausted = [], 0, False
    for path in paths:
        bundle = None if exhausted else sarif_ingest.load_report(Path(path).expanduser(), target,
                      excludes=excludes, include_fixtures=include_fixtures)
        size = len(json.dumps(bundle, ensure_ascii=True).encode("utf-8")) if bundle is not None else 0
        if exhausted or retained + size > MAX_SARIF_TOTAL_BYTES:
            original = bundle["report"] if bundle is not None else {}
            report = {key: original.get(key) for key in ("sha256", "bytes", "version")}
            report.update(path=str(Path(path).expanduser().absolute()), import_complete=False,
                          analysis_outcome=original.get("analysis_outcome", "unknown"), execution_complete=False,
                          source_freshness="unverified", tool_scope=[], scope={"aggregate_budget": MAX_SARIF_TOTAL_BYTES},
                          counts={"findings": 0, "observations": 0, "omitted": len((bundle or {}).get("findings", []))
                                  + len((bundle or {}).get("observations", []))},
                          gaps=[{"kind": "sarif_aggregate_limit", "execution": True,
                                 "detail": "Combined expanded SARIF evidence budget exceeded; this requested import was not retained."}],
                          limits={"aggregate_bytes": MAX_SARIF_TOTAL_BYTES},
                          source_references_read=False, commands_executed=False, references_fetched=False)
            bundle, exhausted = {"findings": [], "observations": [], "report": report}, True
        else:
            retained += size
        bundles.append(bundle)
    return bundles


def _resolve_target(raw: str) -> Path:
    p = Path(raw).expanduser().resolve()
    if not p.is_dir():
        sys.exit(f"error: target is not a directory: {p}")
    return p


def _maybe_nudge_websecignore(target: Path, ledger: dict, unified: dict | None, log) -> None:
    """One-line advisory when most findings sit in test/example/fixture code and no
    `.websec-ignore` exists yet — surfaces the suppression mechanism at the moment of need
    (DocGuard field report: the feature existed but was undiscoverable). Never auto-creates it."""
    from .extractors.base import is_script_file, is_test_file
    if (target / ".websec-ignore").is_file() or (Path.cwd() / ".websec-ignore").is_file():
        return
    locs = [f.get("location", "") for f in ledger.get("findings", []) or []]
    locs += [f.get("file", "") for f in ((unified or {}).get("all") or [])]
    locs = [x for x in locs if x]
    if len(locs) < 4:
        return
    fixture = sum(1 for x in locs if is_test_file(x) or is_script_file(x))
    if fixture and fixture >= 0.5 * len(locs):
        log(f"\n  ⓘ {fixture}/{len(locs)} findings are in test/example/fixture code. If those aren't "
            "your product,\n    add a .websec-ignore (path globs or `category:` / `fingerprint:` acks) "
            "— see the README\n    \"Scoping & suppression\" section, or narrow with --exclude.")


def _default_out(target: Path, out: str | None) -> Path:
    d = Path(out).expanduser().resolve() if out else Path.cwd() / "websec-out"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _new_run_dir(out: str | None) -> tuple:
    """Reserve below a real runs directory; publish latest only after artifacts exist.

    The explicitly selected base may resolve through an operator-provided alias.
    Nested runs symlinks are not an authorization to write somewhere else. This
    check does not make subsequent path-based writes race-proof against a process
    concurrently replacing the output tree.
    """
    import datetime
    base = (Path(out).expanduser() if out else Path.cwd() / "websec-out").resolve()
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    base.mkdir(parents=True, exist_ok=True)
    runs = base / "runs"
    try:
        info = runs.lstat()
    except FileNotFoundError:
        runs.mkdir(exist_ok=True)
        info = runs.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("output runs path must be a real directory, not a symlink or other file: " + str(runs))
    run = Path(tempfile.mkdtemp(prefix=stamp + "-", dir=runs))
    return run, run.name


_DIGESTED = ("FACTS.json", "coverage.json", "findings-ledger.json", "findings.envelope.json",
             "results.sarif", "findings.json", "repair-plans.json", "attack-surface.json",
             "REPORT.md", "AGENT-BRIEFING.md", "diff-scope.json", "sarif-imports.json")


def _now_stamp() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _artifact_digests(run: Path) -> dict:
    """sha256 of each artifact this run emitted, for integrity checking after the fact.

    Bounded and non-raising: an unreadable artifact records an error string rather than failing a
    run that has already completed its actual work."""
    out: dict = {}
    for name in _DIGESTED:
        path = run / name
        try:
            if not path.is_file():
                continue
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            out[name] = "sha256:" + digest.hexdigest()
        except Exception as error:
            out[name] = f"unreadable: {type(error).__name__}"
    return out


def _publish_run(run: Path) -> None:
    """Atomically replace the latest symlink; a failed run leaves its predecessor intact."""
    base = run.parent.parent
    temporary = base / (".latest-" + uuid.uuid4().hex)
    try:
        temporary.symlink_to(Path("runs") / run.name, target_is_directory=True)
        os.replace(temporary, base / "latest")
    finally:
        temporary.unlink(missing_ok=True)


def cmd_doctor(args) -> int:
    target = _resolve_target(args.target) if args.target else None
    langs = recon.detect_stack(target)["languages"] if target else None
    det = scanners.detect(langs)
    print(f"websec-validator v{__version__} — scanner check"
          + (f"  (stack: {', '.join(langs) or 'unknown'})" if langs else ""))
    print("\n  available:")
    for s in det["available"]:
        print(f"    ✓ {s['name']:20} {s['category']}")
    if not det["available"]:
        print("    (none on PATH)")
    print("\n  missing (optional — install for fuller coverage):")
    for s in det["missing"]:
        print(f"    · {s['name']:20} {s['category']:8} {s.get('install','')}")
    print("\n  Docker:", "present" if _which("docker") else "not found "
          "(used for reproducible scanner runs in a future release)")
    return 0


def cmd_recon(args) -> int:
    target = _resolve_target(args.target)
    out = _default_out(target, args.out)
    facts = recon.build_facts(target, __version__)
    recon.write_facts(facts, out / "FACTS.json")
    print(f"✓ FACTS.json → {out / 'FACTS.json'}")
    _print_facts_summary(facts)
    return 0


def _security_context_md(facts: dict, ledger: dict) -> str:
    """A compact, deterministic security-context block for injection into an agent's session — the
    attack surface at a glance so the agent (or a downstream LLM reviewer) starts pre-scoped."""
    st = facts.get("stack", {})
    rt = facts.get("routes", {})
    tg = rt.get("targeting", {})
    az = facts.get("authz", {})
    gs = az.get("guard_summary", {})
    tc = [t["key"] for t in facts.get("tenant", {}).get("candidates", [])][:3]
    unguarded = az.get("write_endpoints_without_visible_guard", []) or []
    sinks = (facts.get("surface", {}) or {}).get("sink_counts", {}) or {}
    top_sinks = ", ".join(f"{k}({v})" for k, v in list(sinks.items())[:6]) or "none"
    lines = [
        "## SECURITY CONTEXT (websec-validator — deterministic recon, no LLM)",
        f"- Stack: {', '.join(st.get('languages', [])) or '?'} · "
        f"{', '.join(st.get('frameworks', [])) or '?'} · datastores: {', '.join(st.get('datastores', [])) or '?'}",
        f"- Attack surface: {rt.get('count', 0)} route(s) · auth: {facts.get('auth', {}).get('scheme', '?')} · "
        f"tenant boundary candidate(s): {', '.join(tc) or 'none detected'}",
        f"- Access control: {gs.get('with_visible_guard', 0)} guarded · "
        f"**{gs.get('no_visible_guard', 0)} write endpoint(s) with NO visible guard**",
        f"- Targeting: IDOR={len(tg.get('idor_candidates', []))} SSRF={len(tg.get('ssrf_candidates', []))} "
        f"upload={len(tg.get('upload_candidates', []))} writes={len(tg.get('write_endpoints', []))}",
        f"- Code sinks (user-input-gated): {top_sinks}",
    ]
    if unguarded:
        lines.append("- ⚠ Missing-authz leads: " + "; ".join(str(u) for u in unguarded[:5]))
    if ledger.get("findings"):
        top = ledger["findings"][:5]
        lines.append("- Top recon findings: " + "; ".join(
            f"[{f['severity']}] {f['title'][:70]}" for f in top))
    lines.append(coverage.render_md(facts))
    lines.append("- When editing this repo: treat the unguarded write endpoints + IDOR/SSRF targets "
                 "as the highest-risk surface. Run `websec run . --scan` for the full briefing + probes.")
    return "\n".join(lines)


def cmd_emit_context(args) -> int:
    """Emit websec's recon as a Claude Code SessionStart `additionalContext` JSON envelope (stdout),
    so ANY agent starts a session with the deterministic attack-surface map already in context.
    Recon-only (no scanners) → fast enough for a session hook. `--markdown` prints the raw block."""
    target = _resolve_target(args.target)
    facts = recon.build_facts(target, __version__)
    ledger = findings.build_ledger(facts, None, None,
                                   findings.load_suppressions(target),
                                   findings.load_acknowledgements(target))
    block = _security_context_md(facts, ledger)
    if getattr(args, "markdown", False):
        print(block)
    else:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "SessionStart", "additionalContext": block}}))
    return 0


def cmd_run(args) -> int:
    if len(getattr(args, "sarif", []) or []) > 8:
        print("error: at most 8 explicit --sarif reports are supported per run", file=sys.stderr)
        return 2
    if getattr(args, "scanners", None) and not args.scan:
        print("error: --scanners requires --scan", file=sys.stderr)
        return 2
    if getattr(args, "scanners", None) and not any(key.strip() for key in args.scanners.split(",")):
        print("error: --scanners requires at least one scanner key", file=sys.stderr)
        return 2
    if getattr(args, "verify_secrets", False) and not args.scan:
        print("error: --verify-secrets requires --scan", file=sys.stderr)
        return 2
    target = _resolve_target(args.target)
    try:
        out, ts = _new_run_dir(args.out)
    except (OSError, ValueError) as error:
        print(f"error: cannot reserve output run: {error}", file=sys.stderr)
        return 2

    # In a machine-output mode (sarif/json) keep STDOUT pure for piping — route human progress to
    # stderr. `websec run app --format sarif > results.sarif` then Just Works in a pipeline.
    fmt = getattr(args, "format", "briefing")
    log = (lambda *a, **k: print(*a, file=sys.stderr, **k)) if fmt != "briefing" else print

    log(f"websec-validator v{__version__}  ·  target: {target}  ·  run {ts}\n")

    # 1. recon
    facts = recon.build_facts(target, __version__, args.exclude,
                              include_fixtures=getattr(args, "include_fixtures", False),
                              only=getattr(args, "only", None))
    langs = facts.get("stack", {}).get("languages", [])
    _print_facts_summary(facts, log)

    # 2. scanners: detect, optionally run
    det = scanners.detect(langs)
    scan_results = []
    unified = None
    if args.scan:
        log("\n  running available static scanners (read-only)…")
        only = [key.strip() for key in args.scanners.split(",") if key.strip()] if args.scanners else None
        scan_results = scanners.run_available(target, out, langs, excludes=args.exclude, only=only,
                                             verify_secrets=getattr(args, 'verify_secrets', False))
        for r in scan_results:
            tag = r.get("findings", r.get("status", "?"))
            log(f"    {r['name']}: {tag}")
        unified = scanners.normalize_findings(scan_results, out, target=target, excludes=args.exclude,
                                              include_fixtures=getattr(args, "include_fixtures", False))
        log(f"  → {unified['total']} de-duplicated findings "
            f"({unified['cross_tool_or_dup_merged']} merged) · {unified['by_severity']}")
        _hyg = []
        if unified.get('contamination_dropped'):
            _hyg.append(f"{unified['contamination_dropped']} dropped (skip-dir contamination)")
        if unified.get('user_excluded_dropped'):
            _hyg.append(f"{unified['user_excluded_dropped']} dropped (--exclude)")
        if unified.get('local_only_downgraded'):
            _hyg.append(f"{unified['local_only_downgraded']} downgraded (gitignored/local-only secret)")
        if unified.get('test_fixture_downgraded'):
            _hyg.append(f"{unified['test_fixture_downgraded']} downgraded (test/fixture secret → LOW)")
        if _hyg:
            log(f"    hygiene: {' · '.join(_hyg)}")
        _rx = unified.get('reachability') or {}
        if _rx.get('declared_only'):
            log(f"    reachability: {_rx.get('imported', 0)} imported · "
                f"{_rx['declared_only']} declared-only (import not observed; reachability unproven)")
        _ex = unified.get('exploitability') or {}
        if _ex.get('available') and (_ex.get('kev') or _ex.get('high_epss')):
            log(f"    exploitability: {_ex.get('kev', 0)} CISA-KEV (known-exploited) · "
                f"{_ex.get('high_epss', 0)} high-EPSS")
        elif _ex and not _ex.get('available') and unified.get('by_category', {}).get('sca'):
            log("    exploitability: EPSS/KEV snapshot unavailable or unverified — run websec intel refresh to "
                "prioritize CVEs by real-world exploit likelihood")
    else:
        log(f"\n  scanners available: {', '.join(s['name'] for s in det['available']) or 'none'}"
            "  (add --scan to execute them)")

    only = [key.strip() for key in args.scanners.split(",") if key.strip()] if args.scanners else None
    coverage.add_scanners(facts, det, scan_results, unified, scan=args.scan, only=only,
                          verify_secrets=getattr(args, "verify_secrets", False))
    imported = []
    if getattr(args, "sarif", None):
        imported = _sarif_imports(args.sarif, target, excludes=args.exclude or (),
                                 include_fixtures=getattr(args, "include_fixtures", False))
        coverage.add_imports(facts, [bundle["report"] for bundle in imported])
        unified = findings.merge_imports(unified, [row for bundle in imported for row in bundle["findings"]])
        (out / "sarif-imports.json").write_text(json.dumps(imported, indent=2))
        if not args.scan:
            (out / "findings.json").write_text(json.dumps(unified["all"], indent=2))
        log(f"  imported {len(imported)} SARIF report(s): {sum(len(bundle['findings']) for bundle in imported)} findings; source freshness unverified")
    facts["coverage"]["build_id"] = ts
    recon.write_facts(facts, out / "FACTS.json")
    (out / "coverage.json").write_text(json.dumps(facts["coverage"], indent=2))

    # 2c. SBOM (opt-in) — offline CycloneDX/SPDX via Trivy, alongside the other machine artifacts.
    sbom = None
    if getattr(args, "sbom", None):
        sbom = scanners.write_sbom(target, out, args.sbom, excludes=args.exclude)
        if sbom.get("available"):
            log(f"  SBOM ({sbom['format']}): {sbom['components']} components → {sbom['path']}")
        else:
            log(f"  SBOM skipped: {sbom.get('reason', 'unavailable')}")
            coverage.add_gap(facts, "sbom", sbom.get("reason", "unavailable"))

    # 2d. Attack-surface inventory — the ranked per-endpoint planning table (also rendered in §3a of
    # the briefing, and the substrate for the DAST-prediction + pentest-plan sections).
    inv = inventory.build(facts)
    (out / "attack-surface.json").write_text(json.dumps(inv, indent=2))
    _isum = inv.get("summary", {})
    if _isum.get("endpoints"):
        log(f"  attack surface: {_isum['endpoints']} endpoint(s) ranked · "
            f"{_isum.get('unguarded', 0)} unguarded ({_isum.get('unguarded_writes', 0)} writes) "
            f"→ attack-surface.json")

    # 3. probes: choose + stage
    chosen = probes.applicable(facts)
    manifest = probes.stage(chosen, out, facts)
    log(f"\n  staged {len([m for m in manifest if 'attack_class' in m])} tailored probe template(s) → {out / 'probes'}")

    # 4. traceable findings ledger (recon + static; dynamic merges in via `websec dynamic`)
    suppressions = findings.load_suppressions(target)
    acks = findings.load_acknowledgements(target)
    ledger = findings.build_ledger(facts, unified, None, suppressions, acks)
    ledger["coverage"] = facts["coverage"]
    ledger["target"] = facts["target"]
    ledger["build_id"] = ts
    baseline.annotate(ledger)          # stable per-finding fingerprints (baseline + SARIF tracking)
    if ledger.get("acknowledged_n"):
        log(f"  acknowledged: {ledger['acknowledged_n']} known finding(s) shown but not gating "
            "(fingerprint acks in .websec-ignore)")
    _maybe_nudge_websecignore(target, ledger, unified, log)

    # 4a. optional blast-radius enrichment from a graphify knowledge graph (opt-in, zero-dep). If the
    # repo has graphify-out/graph.json (or --graph is given), tag each finding with how much of the app
    # transitively depends on the vulnerable code. Wrapped so a bad/oversized graph never fails a run.
    graph_arg = getattr(args, "graph", None)
    graph_path = Path(graph_arg).expanduser() if graph_arg else None
    if graph_path or (target / "graphify-out" / "graph.json").exists():
        try:
            from . import graph_enrich
            graph_enrich.enrich_ledger(ledger, target, graph_path, excludes=args.exclude)
            ge = ledger.get("graph_enrichment")
            if ge and ge.get("available", True):
                log(f"\n  graph: {ge['mapped']} finding(s) mapped to {ge['nodes']} nodes · "
                    f"max blast-radius {ge['max_blast_radius']} (source: {ge['graph']})")
            if ge and not ge.get("available", True):
                coverage.add_gap(facts, "graph", ge.get("reason", "unavailable"), execution=bool(graph_path))
        except Exception as e:  # enrichment is best-effort — never fail the run over it
            coverage.add_gap(facts, "graph", type(e).__name__, execution=bool(graph_path))
            log(f"\n  graph: enrichment skipped ({type(e).__name__}: {e})")

    # 4a1. FP pre-pass: tag (never drop) findings a reviewer/LLM-reviewer would routinely filter,
    # so a downstream consumer can skip its own filtering pass.
    fp_counts = fpfilter.annotate(ledger, facts)
    if fp_counts.get("likely_filtered"):
        log(f"  pre-triage: {fp_counts['likely_filtered']} finding(s) tagged likely-filtered "
            f"(kept + reasoned, not dropped) · {fp_counts['kept']} high-signal")

    # 4a2. --diff: scope to what this branch/PR changed. Tags findings + emits exact hunk ranges so a
    # downstream reviewer (human or LLM) can validate that a finding sits on a CHANGED line.
    diff_scope = diff_counts = None
    if getattr(args, "diff", None):
        diff_scope = diffscope.compute(target, args.diff)
        diff_counts = diffscope.annotate(ledger, diff_scope)
        (out / "diff-scope.json").write_text(json.dumps(
            {"base": diff_scope.get("base"), "error": diff_scope.get("error"),
             "files": {f: [list(r) for r in rs] for f, rs in (diff_scope.get("files") or {}).items()},
             "counts": diff_counts}, indent=2))
        if diff_scope.get("error"):
            coverage.add_gap(facts, "diff", diff_scope["error"])
            log(f"  ⚠ --diff {args.diff}: {diff_scope['error']} — running UNSCOPED (whole repo)")
        else:
            log(f"  diff scope: {diff_counts['changed_files']} changed file(s) vs {diff_scope['base']} · "
                f"{diff_counts['in_changed_file']} finding(s) in changed files "
                f"({diff_counts['untouched']} pre-existing) → diff-scope.json")

    ledger["verification_context"] = {"application_id": getattr(args, "application_id", None) or str(target),
                                       "build_id": getattr(args, "build_id", None) or facts["coverage"]["analyzed_input_digest"],
                                       "source_digest": facts["coverage"]["analyzed_input_digest"]}
    # WHICH CHANGE this finding set describes. A SIBLING of verification_context, never merged into
    # it: repairs compares that object by strict dict equality, so an added key would invalidate
    # every repair plan emitted before this change.
    from . import attribution as _attribution
    ledger["attribution"] = _attribution.build(target, actor=getattr(args, "actor", None))
    # 4b. baseline / diff — only NEW findings gate CI when a baseline is supplied
    diff = None
    if getattr(args, "baseline", None):
        base_fps = baseline.load_baseline(Path(args.baseline).expanduser())
        for error in getattr(base_fps, "errors", []):
            coverage.add_gap(facts, "baseline", error)
        diff = baseline.diff(ledger, base_fps)
        log(f"\n  baseline: {diff['new_count']} new · {diff['unchanged_count']} unchanged · "
            f"{diff.get('no_longer_observed_count', 0)} no longer observed (vs {args.baseline})")

    # 4c. Evaluate the CI gate HERE, before any artifact is written, and record the verdict in the
    # ledger. Previously the gate ran after the artifacts were written and after the run was
    # published, so the verdict existed only as a process exit code: nothing in the run directory
    # said which gate ran, at what threshold, or whether it passed. An exit code is not evidence.
    _incomplete = (bool(getattr(args, "fail_on", None) or getattr(args, "require_complete", False))
                   and not facts["coverage"].get("execution_complete"))
    _scoped = bool(diff_scope and not diff_scope.get("error"))
    _gate_ledger = ledger
    if _scoped:
        # --diff narrows the gate to findings in CHANGED files (PR semantics: don't fail a PR on
        # pre-existing debt it didn't touch). Only when scoping actually succeeded.
        _gate_ledger = dict(ledger, findings=[f for f in ledger.get("findings", [])
                                              if f.get("diff_state") in {"in-changed-file", "in-changed-hunk"}])
    _gate = {"threshold": getattr(args, "fail_on", None),
             "require_complete": bool(getattr(args, "require_complete", False)),
             "new_only": bool(diff),
             "baseline": str(args.baseline) if getattr(args, "baseline", None) else None,
             "diff_scoped": _scoped,
             "diff_base": (diff_scope or {}).get("base") if _scoped else None,
             "execution_complete": bool(facts["coverage"].get("execution_complete"))}
    if _incomplete:
        _gate.update(verdict="incomplete", exit_code=2, count_at_or_above=None,
                     note="requested checks did not complete; the gate result is NOT a pass")
    elif getattr(args, "fail_on", None):
        _n = baseline.gate_count(_gate_ledger, args.fail_on, new_only=bool(diff))
        _gate.update(count_at_or_above=_n, verdict="fail" if _n else "pass", exit_code=1 if _n else 0)
    else:
        _gate.update(verdict="not-evaluated", exit_code=0, count_at_or_above=None,
                     note="no --fail-on was requested; this run gated nothing")
    # Enforcement is a server-side concern. Say so IN THE ARTIFACT, not only in the docs: a local
    # gate can be skipped with --no-verify, an uninstalled hook, or a deleted one.
    _gate["enforcement"] = ("advisory unless run as a required status check. A client-side gate is a "
                            "developer convenience, not a control: it cannot evidence that it ran for "
                            "every change.")
    ledger["gate"] = _gate

    recon.write_facts(facts, out / "FACTS.json")
    (out / "coverage.json").write_text(json.dumps(facts["coverage"], indent=2))
    (out / "findings-ledger.json").write_text(json.dumps(ledger, indent=2))
    from . import repairs
    (out / "repair-plans.json").write_text(json.dumps(repairs.build(ledger), indent=2))
    (out / "CONSTITUTION.md").write_text(constitution.render(constitution.build(facts, ledger)))
    if ledger["total"]:
        log(f"\n  ledger: {ledger['total']} finding(s) · {ledger['by_severity']} · confidence {ledger['by_confidence']}"
            + (f" · {ledger['suppressed']} suppressed" if ledger["suppressed"] else ""))

    # 5. briefing + comprehensive REPORT.md (immutable run record) + machine artifacts
    (out / "AGENT-BRIEFING.md").write_text(briefing.render(facts, det, scan_results, manifest, unified, ledger))
    (out / "REPORT.md").write_text(report.render(facts, det, scan_results, unified, manifest, ts, ledger))
    # SARIF is ALWAYS written — it's the enterprise/CI interchange artifact (GitHub Code Scanning etc.)
    sarif = formats.to_sarif(ledger, facts, __version__)
    (out / "results.sarif").write_text(json.dumps(sarif, indent=2))
    (out / "findings.envelope.json").write_text(json.dumps(formats.to_json(ledger, facts, __version__, ts), indent=2))
    # drop the full `all` finding list from the manifest — it's a duplicate of findings.json
    manifest_summary = {k: v for k, v in unified.items() if k != "all"} if unified else None
    (out / "manifest.json").write_text(json.dumps(
        {"facts": "FACTS.json", "coverage": "coverage.json", "scanners": det, "scan_results": scan_results,
         "sarif_imports": "sarif-imports.json" if imported else None,
         "findings_summary": manifest_summary, "ledger": {"total": ledger["total"], "by_severity": ledger["by_severity"]},
         "sarif": "results.sarif", "sbom": sbom, "attack_surface": "attack-surface.json",
         "attack_surface_summary": inv.get("summary", {}),
         "probes": manifest, "timestamp": ts,
         # The INPUT side was already content-addressed (analyzed_input_digest, per-file hashes),
         # but nothing hashed what we EMIT: the manifest listed filenames only, so a finding could
         # be deleted from findings-ledger.json in a text editor and no artifact would contradict
         # it. These digests make that edit detectable. They are integrity, NOT tamper-proofing:
         # anyone who can edit an artifact can recompute the manifest, so this is only meaningful
         # alongside an external copy (CI log, forge artifact store).
         "artifact_digests": _artifact_digests(out),
         "artifact_digests_note": ("sha256 of the artifacts emitted by this run, computed after they "
                                   "were written. Detects later edits; does not prove authorship. "
                                   "The manifest itself is not self-hashed.")}, indent=2))

    if facts["coverage"].get("execution_complete"):
        _publish_run(out)
    log(coverage.render_md(facts))
    log(f"\n✓ run {ts} saved (immutable — nothing overwritten):\n    {out}")
    log("    REPORT.md          — full historical record")
    log("    AGENT-BRIEFING.md  — hand this to your AI coding agent")
    log("    results.sarif      — SARIF 2.1.0 for CI / GitHub Code Scanning")
    if sbom and sbom.get("available"):
        log(f"    {sbom['path']}   — {sbom['format']} SBOM ({sbom['components']} components)")
    if facts["coverage"].get("execution_complete"):
        log(f"  latest → {out.parent.parent / 'latest'}    ·    add `websec-out/` to .gitignore")
    else:
        log(f"  partial attempt retained at {out}; latest completed scan unchanged")

    # emit the requested machine format on STDOUT (for piping); default 'briefing' emits nothing extra
    if fmt == "sarif":
        print(json.dumps(sarif, indent=2))
    elif fmt == "json":
        print(json.dumps(formats.to_json(ledger, facts, __version__, ts), indent=2))

    # 6. CI gate — the verdict was computed and RECORDED above, before artifacts were written. This
    # block only reports it and returns the exit code, so the artifact and the exit code cannot
    # disagree.
    if _gate["verdict"] == "incomplete":
        log("\n✗ requested security checks did not complete; partial artifacts saved (exit 2).")
        return 2
    if _gate["verdict"] == "fail":
        log(f"\n✗ --fail-on {args.fail_on}: {_gate['count_at_or_above']} finding(s) at or above threshold"
            + (" (new since baseline)" if diff else "")
            + (f" (in files changed vs {_gate['diff_base']})" if _gate["diff_scoped"] else "")
            + " — failing the build.")
        return 1
    if _gate["verdict"] == "pass":
        log(f"\n✓ --fail-on {args.fail_on}: no findings at or above threshold"
            + (" (new since baseline)" if diff else "") + ".")
    return 0


def cmd_dynamic(args) -> int:
    base = Path(args.out).expanduser().resolve() if args.out else Path.cwd() / "websec-out"
    # Resolve the previous complete run before reserving the dynamic run directory.
    facts_path = (Path(args.facts).expanduser() if args.facts else base / "latest" / "FACTS.json").resolve()
    if not facts_path.is_file():
        sys.exit(f"error: FACTS.json not found at {facts_path} — run `websec run <repo>` first (or pass --facts)")
    try:
        out, ts = _new_run_dir(args.out)
    except (OSError, ValueError) as error:
        print(f"error: cannot reserve output run: {error}", file=sys.stderr)
        return 2
    dyn: dict = {}

    if args.unauth:
        if not args.target:
            sys.exit("error: --unauth requires --target")
        if args.probe_writes and not dynamic.is_localhost(args.target):
            sys.exit("error: --probe-writes is localhost-only (it sends write verbs) — point --target at your sandbox")
        print(f"websec dynamic — STRICT read-only · UNAUTHENTICATED · GET-only  ·  run {ts}\n")
        dyn = dynamic.run_unauth(args.target, facts_path, out, probe_writes=args.probe_writes)
        u = dyn["unauth_reachability"]
        print(f"  target: {u['target']}  ·  → {u['summary']}")
        if u.get("warning"):
            print(f"\n  {u['warning']}\n")
        for r in u["results"]:
            mark = "🔓" if r["verdict"] == "OPEN-no-auth" else (" ·" if r["verdict"] == "protected" else "  ")
            print(f"    {mark} {str(r['status']):>4}  {r['verdict']:26} {r['path']}")
        ftb = dyn.get("forged_token_bypass", {})
        if ftb:
            print(f"\n  forged-token (unverified-signature) → {ftb['summary']}")
            for r in ftb.get("results", []):
                if r["verdict"] != "rejected":
                    print(f"    · {r['verdict']}  {r['baseline']}→{r['forged']}  {r['method']} {r['path']}  (via {r['via']})")
        if args.probe_writes:
            w = dyn["write_auth_enforcement"]
            print(f"\n  write-verb auth enforcement → {w['summary']}")
            if w.get("warning"):
                print(f"\n  {w['warning']}\n")
            for r in w["results"]:
                print(f"     · {str(r['status']):>4}  {r['verdict']:42} {r['method']} {r['path']}")
    elif args.config:
        cfg = Path(args.config).expanduser().resolve()
        if not cfg.is_file():
            sys.exit(f"error: config not found: {cfg}")
        print(f"websec dynamic — authenticated cross-tenant BOLA (read-only)  ·  run {ts}\n")
        dyn = dynamic.run_dynamic(cfg, facts_path, out)
        ct = dyn.get("cross_tenant_bola", {})
        if ct.get("error"):
            print("  ERROR:", ct["error"])
        else:
            print(f"  agentA {ct['agentA']['email']} (tenant {ct['agentA']['tenant']}) · "
                  f"agentB {ct['agentB']['email']} (tenant {ct['agentB']['tenant']})")
            print(f"  → {ct['summary']}")
        for lk in ct.get("leaks", []):
            print(f"     🚨 LEAK {lk['direction']} {lk['path']} → HTTP {lk['status']}")
    else:
        sys.exit("error: provide --config (authenticated cross-tenant) OR --unauth --target (read-only)")

    # merge dynamic evidence into the traceable ledger + write the immutable run report
    facts_dict = json.loads(facts_path.read_text())
    coverage.add_dynamic(facts_dict, dyn)
    _root = Path(facts_dict.get("target", "."))
    ledger = findings.build_ledger(facts_dict, None, dyn,
                                   findings.load_suppressions(_root),
                                   findings.load_acknowledgements(_root))
    ledger["coverage"] = facts_dict["coverage"]
    ledger["target"] = str(_root)
    ledger["build_id"] = ts
    ledger["verification_context"] = {
        "application_id": str(_root),
        "build_id": facts_dict["coverage"].get("analyzed_input_digest", ""),
        "source_digest": facts_dict["coverage"].get("analyzed_input_digest", ""),
    }
    (out / "findings-ledger.json").write_text(json.dumps(ledger, indent=2))
    (out / "CONSTITUTION.md").write_text(constitution.render(constitution.build(facts_dict, ledger)))
    (out / "REPORT.md").write_text(
        report.render(facts_dict, {"available": [], "missing": []}, [], None, [], ts, ledger))
    print(f"\n  ledger: {ledger['total']} finding(s) · {ledger['by_severity']} · confidence {ledger['by_confidence']}")

    # self-improving calibration: dynamic is an oracle — fold this run's CONFIRMED results
    # (executed-unauth / auth-enforced / cross-tenant leak) into the user-global local overlay
    samples = calibration.samples_from_dynamic(dyn)
    rec = calibration.record_samples(samples) if samples else None
    if rec:
        nr = sum(1 for s in samples if s["is_real"])
        print(f"  calibration: folded {len(samples)} confirmed sample(s) ({nr} real / {len(samples) - nr} FP) "
              f"into your local overlay → {rec['meta']['samples']} total; confidence now personalizes to your apps")

    recon.write_facts(facts_dict, out / "FACTS.json")
    (out / "coverage.json").write_text(json.dumps(facts_dict.get("coverage", {}), indent=2))
    if (facts_dict.get("coverage") or {}).get("execution_complete"):
        _publish_run(out)
    print(f"  ✓ run {ts} saved (immutable): {out}")
    if not (facts_dict.get("coverage") or {}).get("execution_complete"):
        print("  Requested checks incomplete; latest completed scan unchanged.")
        return 2
    return 1 if ledger["by_severity"].get("CRITICAL") else 0


def cmd_mcp(args) -> int:
    from . import mcp_server
    if getattr(args, "http", False):
        try:
            return mcp_server.serve_http(args.host, args.port, allowed_roots=getattr(args, "allow_root", None))
        except (ValueError, OSError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
    return mcp_server.serve()


def _load_json_artifact(path: str):
    from .extractors.base import read_artifact
    return json.loads(read_artifact(Path(path).expanduser()))


def cmd_repair_verify(args) -> int:
    """Validate supplied test evidence; never execute commands from artifacts."""
    from . import repairs
    try:
        plans = _load_json_artifact(args.plan)
        if isinstance(plans, list):
            selected = [p for p in plans if isinstance(p, dict) and p.get("plan_id") == args.plan_id]
            if args.plan_id is None and len(plans) == 1:
                selected = plans
            if len(selected) != 1:
                raise ValueError("select exactly one repair plan with --plan-id")
            plan = selected[0]
        else:
            plan = plans
        record = _load_json_artifact(args.record)
        rerun = _load_json_artifact(args.rerun)
        if not all(isinstance(data, dict) for data in (plan, record, rerun)):
            raise ValueError("plan, verification record and rerun must be JSON objects")
        result = repairs.validate_verification(plan, record, rerun, rerun.get("coverage") or {},
                                               evidence_root=Path(args.evidence_root).expanduser())
    except (OSError, ValueError, TypeError) as error:
        result = {"accepted": False, "state": "verification-rejected", "errors": [str(error)],
                  "tests_executed_by_websec": False}
    # The bound original/target repair evidence is the strongest thing websec produces, and it used
    # to exist only on stdout and as an exit code — nothing durable, nothing an assessor could read
    # later. `--out` persists it; _emit_json_result opens with "x", so a result can never overwrite
    # an input or prior evidence.
    result.setdefault("tests_executed_by_websec", False)
    result["verified_at"] = _now_stamp()
    try:
        _emit_json_result(result, getattr(args, "out", None))
    except FileExistsError:
        print(json.dumps(result, indent=2))
        print(f"\nrefusing to overwrite existing evidence at {args.out}", file=sys.stderr)
        return 2
    return 0 if result.get("accepted") else 2


def _emit_json_result(result: dict, output: str | None = None) -> None:
    content = json.dumps(result, indent=2)
    if output:
        destination = Path(output).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        # An explicit analysis result must never overwrite an input or prior evidence.
        with destination.open("x", encoding="utf-8") as stream:
            stream.write(content + "\n")
    print(content)


def cmd_gate(args) -> int:
    """Fast, scoped pass/fail for inside the agent loop. Writes nothing; never advances a baseline."""
    from . import gate as _gate
    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"error: target is not a directory: {target}", file=sys.stderr)
        return 2

    scope_source = "explicit"
    paths = list(getattr(args, "only", None) or [])
    if not paths:
        discovered = _gate.working_tree_paths(target)
        paths, scope_source = discovered["paths"], discovered["source"]
        if not paths:
            # Nothing changed is a PASS, but say which question was answered.
            print(_gate.to_json({"tool": "websec-validator", "command": "gate", "passed": True,
                                 "blocking_count": 0, "analyzed": [], "missed": [],
                                 "scope_source": scope_source,
                                 "scope_note": discovered.get("note", ""),
                                 "reason": "no changed files to analyze"}))
            return 0

    facts = recon.build_facts(target, __version__, getattr(args, "exclude", None), only=paths)
    ledger = findings.build_ledger(facts, None)
    result = _gate.verdict(ledger, facts, args.fail_on, scope_source=scope_source,
                           min_confidence=getattr(args, "min_confidence", "low"))

    if getattr(args, "format", "text") == "json":
        print(_gate.to_json(result))
    else:
        print(_gate.render_text(result))
    # 1 = blocking findings. Distinct from 2 (usage/target error) so a harness can tell a FAILED
    # check from a BROKEN one and must never treat a crash as a pass.
    return 0 if result["passed"] else 1


def cmd_capabilities(args) -> int:
    from .extractors.profiles import capabilities
    _emit_json_result(capabilities())
    return 0


def cmd_feedback(args) -> int:
    """Record an operator verdict on detector correctness. Local, offline, redacted."""
    import sys
    fb = feedback

    ledger_path = (Path(args.ledger).expanduser() if args.ledger
                   else Path(args.out or "websec-out") / "latest" / "findings-ledger.json").resolve()
    if not ledger_path.is_file():
        print(f"no ledger at {ledger_path}; run a scan first or pass --ledger", file=sys.stderr)
        return 2
    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"cannot read {ledger_path}: {exc}", file=sys.stderr)
        return 2

    envelope = {}
    envelope_path = ledger_path.parent / "findings.envelope.json"
    if envelope_path.is_file():
        try:
            envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            envelope = {}
    run_id = envelope.get("generated") or ledger_path.parent.name

    try:
        finding = fb.find_finding(ledger, args.fingerprint)
        record = fb.build_record(
            finding, verdict=args.verdict, reason=args.reason, envelope=envelope,
            run_id=run_id, expected_severity=args.expected_severity or "",
            include_snippet=bool(args.include_snippet))
    except fb.FeedbackError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    # --include-snippet can carry route, path and evidence prose out of the repository,
    # so it is never applied silently: the operator sees the exact record and confirms.
    # Fail closed when nobody can answer (CI), rather than defaulting to disclosure.
    if args.include_snippet and not args.yes:
        if not sys.stdin.isatty():
            print("--include-snippet needs --yes when stdin is not a terminal", file=sys.stderr)
            return 2
        print("This record will be written and included in the issue link:\n")
        print(json.dumps(record, indent=2, sort_keys=True))
        if input("\ninclude this context? [y/N] ").strip().lower() not in ("y", "yes"):
            print("aborted; nothing written", file=sys.stderr)
            return 2

    destination = Path(args.out or "websec-out").resolve() / fb.FEEDBACK_FILENAME
    try:
        fb.append(destination, record)
    except (fb.FeedbackError, OSError) as exc:
        print(f"cannot record feedback: {exc}", file=sys.stderr)
        return 2

    url = fb.issue_url(record)
    if getattr(args, "format", None) == "json":
        _emit_json_result({"recorded": str(destination), "record": record, "issue_url": url})
    else:
        print(f"recorded {record['verdict']} for {record['finding'].get('fingerprint')} "
              f"({record['redaction']}) → {destination}")
        print("\nnothing was sent. To report it upstream, open:")
        print(f"  {url}")
        print("\nTo silence this finding locally instead, add a `fingerprint:` line "
              "to .websec-ignore — feedback does not suppress.")
    return 0


def cmd_intel(args) -> int:
    from . import intel
    try:
        if args.action == "refresh":
            result = intel.refresh(args.cache_dir)
            code = 0 if (result.get("last_refresh") or {}).get("outcome") == "success" else 2
        elif args.action == "status":
            result, code = intel.status(args.cache_dir), 0
        else:
            ledger = _load_json_artifact(args.ledger)
            if (not isinstance(ledger, dict) or not isinstance(ledger.get("findings"), list)
                    or not all(isinstance(row, dict) for row in ledger["findings"])):
                raise ValueError("ledger must be a JSON object containing a findings list")
            result = intel.reassess(ledger, args.cache_dir)
            code = 0 if result["intel"].get("freshness") == "fresh" and not result.get("blocked_findings") else 2
        _emit_json_result(result, getattr(args, "out", None))
        return code
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"error": str(error)}, indent=2))
        return 2


def cmd_research(args) -> int:
    from . import research
    try:
        if args.action == "example":
            result, code = research.example(), 0
        elif args.action == "catalog":
            result, code = research.catalog(), 0
        elif getattr(args, "suite", None):
            if args.cases is not None:
                raise ValueError("--cases requires --proposal and cannot be used with --suite")
            result = research.evaluate_suite(args.suite)
            code = 0 if result.get("promotion_eligible") else 2
        else:
            document = _load_json_artifact(args.proposal)
            if args.cases is not None:
                proposal, cases = document, _load_json_artifact(args.cases)
            elif isinstance(document, dict):
                proposal, cases = document.get("proposal"), document.get("cases")
            else:
                raise ValueError("supply a proposal/cases bundle or --cases JSON")
            if not isinstance(proposal, dict) or not isinstance(cases, list):
                raise ValueError("proposal must be an object and cases must be an array")
            result = research.evaluate(proposal, cases)
            code = 0 if result.get("promotion_eligible") else 2
        _emit_json_result(result, args.out)
        return code
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"error": str(error)}, indent=2))
        return 2


def cmd_hooks(args) -> int:
    from . import hooks as _hooks
    path = Path(args.path).expanduser() if getattr(args, "path", None) else Path(".")
    try:
        if args.action == "install":
            print(_hooks.install(path, pre_push=args.pre_push))
        elif args.action == "uninstall":
            print(_hooks.uninstall(path))
        else:  # status
            print(_hooks.status(path))
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_install(args) -> int:
    from . import install as _install
    project_dir = Path(args.project_dir).expanduser() if args.project_dir else Path(".")
    if args.host == "status":
        print(_install.status(project_dir=project_dir, user=args.user))
        return 0
    try:
        msg = _install.install(args.host, project_dir=project_dir, user=args.user,
                               uninstall=args.uninstall)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(msg)
    return 0


def cmd_proof(args) -> int:
    from importlib import resources
    corpus_path = (Path(args.corpus).expanduser().resolve() if args.corpus
                   else Path(str(resources.files("websec_validator").joinpath("corpus.json"))))
    workdir = (Path(args.workdir).expanduser().resolve() if args.workdir
               else Path.home() / ".cache" / "websec-corpus")
    print(f"websec proof — recon coverage vs vuln-app corpus\n  corpus:  {corpus_path}\n  workdir: {workdir}\n")
    try:
        res = proof.run_proof(corpus_path, workdir)
    except (OSError, ValueError, TypeError) as error:
        print(f"  Proof could not complete: {type(error).__name__}: {error}")
        return 2
    for row in res["results"]:
        revision = row.get("revision_status", "unreported")
        actual = row.get("actual_revision")
        print(f"  {row['name']:12} — {row.get('status', 'unknown')} · revision {revision}" + (f" ({actual})" if actual else ""))
        if row.get("status") == "analyzed":
            print(f"    execution: {'complete' if row.get('execution_complete') is True else 'incomplete'} · "
                  f"{row.get('passed', 0)}/{row.get('total', 0)} evaluated checks · "
                  f"{row.get('unknown_checks', 0)} unknown checks · {row.get('unknown_labels', 0)} unknown truth labels")
        for check in row.get("checks", []):
            marker = "?" if check.get("pass") is None else "✓" if check["pass"] else "✗"
            print(f"       {marker} {check['check']:22} got={check.get('got')}")
        for error in row.get("execution_errors", []):
            print(f"       incomplete: {error}")
    aggregate = res["aggregate"]
    analyzed = aggregate.get("analyzed_apps", 0)
    completed = aggregate.get("completed_apps", sum(row.get("status") == "analyzed" and row.get("execution_complete") is True for row in res["results"]))
    incomplete = aggregate.get("incomplete_apps", analyzed - completed)
    unavailable = aggregate.get("unavailable_apps", aggregate["apps"] - analyzed)
    print(f"\n  Evaluated recon-check coverage: {aggregate.get('overall_coverage')} "
          f"({aggregate['checks_passed']}/{aggregate['checks_total']} evaluated checks)")
    print(f"  Applications: {completed} completed · {incomplete} incomplete · {unavailable} unavailable "
          f"({analyzed} analyzed / {aggregate['apps']} requested)")
    print(f"  Unknown: {aggregate.get('unknown_checks', 0)} checks · {aggregate.get('unknown_labels', 0)} truth labels "
          "(excluded from calibration; not false labels)")
    print("  NOTE: Recon surface checks are a proxy, not vulnerability precision or agent-lift evidence.")
    if incomplete or unavailable or aggregate.get("unknown_checks", 0) or not aggregate["checks_total"]:
        return 2
    return 1 if aggregate.get("failed_checks", aggregate["checks_total"] - aggregate["checks_passed"]) else 0


def cmd_calibrate(args) -> int:
    """Fit confidence calibration: run the recon ledger against the labeled vuln corpus,
    measure how often each (attack_class, label) bucket is a real documented vuln, and
    write calibration.json (shipped + applied at runtime by findings.build_ledger)."""
    from importlib import resources

    # --ingest-dast: close the loop with a REAL scan — a ZAP/Nuclei report confirms/refutes websec's
    # DAST-predictable findings (§4b) and folds the verdicts into your local overlay. Needs the ledger.
    if getattr(args, "ingest_dast", None):
        from . import dast_ingest
        rpt = Path(args.ingest_dast).expanduser().resolve()
        led_path = Path(args.ledger).expanduser().resolve() if getattr(args, "ledger", None) else None
        if not rpt.is_file():
            sys.exit(f"error: --ingest-dast report not found: {rpt}")
        if not led_path or not led_path.is_file():
            sys.exit("error: --ingest-dast needs --ledger <findings-ledger.json> to match against")
        report = json.loads(rpt.read_text())
        ledger = json.loads(led_path.read_text())
        res = dast_ingest.derive_labels(ledger, report)
        if not res["labels"]:
            print("websec calibrate --ingest-dast: no DAST-predictable findings in the ledger matched "
                  f"the scan (blind-spot findings skipped: {res['skipped_blind']}). Nothing to fold.")
            return 2
        rec = calibration.record_samples(res["labels"])
        if not rec:
            sys.exit("error: nothing ingested (local overlay not writable)")
        nc, nr, nu = len(res["confirmed"]), len(res["refuted"]), len(res.get("unjudged", []))
        print(f"websec calibrate --ingest-dast: the scan CONFIRMED {nc} finding(s) and REFUTED {nr} "
              f"(explicit location-scoped negative evidence); {nu} left UNJUDGED (this scan shows no "
              f"evidence it ran those rules — e.g. a passive-only baseline cannot test SQLi, so its "
              f"silence proves nothing); {res['skipped_blind']} blind-spot finding(s) unscored. "
              f"Folded {len(res['labels'])} sample(s) into {calibration.LOCAL_PATH} → "
              f"{rec['meta']['samples']} total; P(real) now personalizes to your app.")
        return 0

    # --ingest: fold a hand-labeled findings file into your LOCAL overlay (the manual real-repo path)
    if getattr(args, "ingest", None):
        src = Path(args.ingest).expanduser().resolve()
        if not src.is_file():
            sys.exit(f"error: --ingest file not found: {src}")
        data = json.loads(src.read_text())
        rows = data.get("findings", data) if isinstance(data, dict) else data
        labeled = [{**r, "attack_class": r.get("attack_class", ""), "confidence": r.get("confidence", "MEDIUM"),
                    "is_real": r.get("is_real") if isinstance(r.get("is_real"), bool) else None}
                   for r in rows if isinstance(r, dict)]
        rec = calibration.record_samples(labeled)
        if not rec:
            sys.exit("error: nothing ingested (empty file, or local overlay not writable)")
        verified = [s for s in labeled if s.get("evidence_verified") is True and s.get("sample_id")
                    and isinstance(s.get("provenance"), dict) and isinstance(s.get("is_real"), bool)]
        if not verified:
            print(f"websec calibrate --ingest: {len(labeled)} unverified/unknown rows retained for review; no measured samples added.")
            return 2
        nr = sum(1 for s in verified if s["is_real"] is True)
        print(f"websec calibrate --ingest: processed {len(verified)} evidence-backed sample(s) "
              f"({nr} real / {len(verified) - nr} FP) into {calibration.LOCAL_PATH} → {rec['meta']['samples']} total.")
        return 0

    corpus_path = (Path(args.corpus).expanduser().resolve() if args.corpus
                   else Path(str(resources.files("websec_validator").joinpath("corpus.json"))))
    workdir = (Path(args.workdir).expanduser().resolve() if args.workdir
               else Path.home() / ".cache" / "websec-corpus")
    out_path = (Path(args.out).expanduser().resolve() if args.out
                else Path(calibration.__file__).resolve().parent / "calibration.json")
    corpus = json.loads(corpus_path.read_text())
    workdir.mkdir(parents=True, exist_ok=True)
    print("websec calibrate — fitting confidence against the labeled vuln corpus")
    print(f"  corpus:  {corpus_path}\n  workdir: {workdir}\n  out:     {out_path}\n")

    labeled, used = [], []
    for entry in corpus:
        truth = entry.get("truth")
        if not truth:
            print(f"  {entry['name']:12} — no truth block, skipped")
            continue
        repo = proof._ensure_repo(entry, workdir)
        if not repo:
            print(f"  {entry['name']:12} — unavailable (clone failed / no local_path)")
            continue
        try:
            facts = recon.build_facts(repo, __version__)
            ledger = findings.build_ledger(facts, None, None, [])
        except Exception as e:
            print(f"  {entry['name']:12} — recon/ledger error: {e}")
            continue
        n_real = 0
        for f in ledger["findings"]:
            real = calibration.is_real(f.get("attack_class", ""), f.get("location", ""), truth)
            labeled.append({"attack_class": f.get("attack_class", ""),
                            "confidence": f["confidence"], "is_real": real})
            n_real += int(real is True)
        used.append(entry["name"])
        print(f"  {entry['name']:12} {len(ledger['findings'])} findings · {n_real} matched a documented vuln")

    if not labeled:
        print("\n  no labeled findings produced — is the corpus cloned? (needs network on first run)")
        return 1

    researched = {t.get("class") for entry in corpus for t in (entry.get("truth") or [])}
    table = calibration.fit(labeled, used, researched)
    print(f"  calibration labels: {table['meta']['n_total']} scored · {table['meta'].get('n_unknown', 0)} unknown")
    if not table["meta"]["n_total"]:
        print("No verified corpus labels matched; calibration was not replaced.")
        return 2
    out_path.write_text(json.dumps(table, indent=2) + "\n")
    print(f"\n  fitted {table['meta']['n_total']} findings across {len(used)} app(s) → {out_path}")
    for k, v in table["by_label"].items():
        print(f"    {k:7} {v['k']}/{v['n']} real · p={v['p']} · 95% CI {v['ci']}")
    print(f"\n  NOTE: {table['meta']['caveat']}.")
    print("  Per-finding estimates carry n + basis; wide CI / basis=prior ⇒ trust the debate, not the number.")
    return 0


def _which(b):
    import shutil
    return shutil.which(b)


def _print_facts_summary(facts: dict, log=print) -> None:
    if facts.get("files_truncated"):
        log(f"  ⚠ PARTIAL SCAN — hit the {facts.get('file_cap', '?')}-file cap; recon may be incomplete. "
            "Narrow with --exclude or scan a subdirectory.")
    st = facts.get("stack", {})
    rt = facts.get("routes", {})
    tg = rt.get("targeting", {})
    log(f"  stack:    {', '.join(st.get('languages', [])) or '?'}  ·  "
        f"frameworks: {', '.join(st.get('frameworks', [])) or '?'}  ·  "
        f"datastores: {', '.join(st.get('datastores', [])) or '?'}")
    log(f"  auth:     {facts.get('auth', {}).get('scheme', '?')}")
    tc = facts.get("tenant", {}).get("candidates", [])
    log(f"  tenant?:  {', '.join(t['key'] for t in tc) or 'none detected'}"
        + ("   ← confirm THE boundary" if tc else ""))
    log(f"  routes:   {rt.get('count', 0)} endpoints via {rt.get('engine', '?').split(' ')[0]}")
    if rt.get("fixture_excluded"):
        log(f"            {rt['fixture_excluded']} fixture/example endpoint(s) excluded "
            "(test/example code ≠ attack surface; --include-fixtures to analyze)")
    log(f"  targets:  IDOR={len(tg.get('idor_candidates', []))} "
        f"SSRF={len(tg.get('ssrf_candidates', []))} "
        f"upload={len(tg.get('upload_candidates', []))} "
        f"writes={len(tg.get('write_endpoints', []))}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="websec",
        description="Defensive, local-first security recon that briefs your AI coding agent — "
                    "read-only by default: it reads your own repo and writes a briefing, and never "
                    "touches a live app. Active probes are opt-in against a TEST instance you own.")
    p.add_argument("--version", action="version", version=f"websec-validator {__version__}")
    # metavar lists only the user-facing commands; recon/proof/calibrate still work but are
    # omitted (they get no `help=`, so argparse leaves them out of the listing entirely).
    sub = p.add_subparsers(dest="cmd", required=True,
                          metavar="{run,doctor,dynamic,mcp,capabilities,feedback,intel,research,repair-verify,install,hooks}")

    r = sub.add_parser("run", help="full pipeline → briefing + tailored probes")
    r.add_argument("target")
    r.add_argument("--scan", action="store_true", help="also execute available static scanners")
    r.add_argument("--sarif", action="append", metavar="REPORT", help="import an explicit offline SARIF 2.1.0 report (repeatable, maximum 8); source freshness unverified")
    r.add_argument("--out", help="output dir (default: ./websec-out)")
    r.add_argument("--exclude", action="append", metavar="PATH",
                   help="exclude a path/glob from recon + scanners (repeatable; e.g. --exclude 'docs/**')")
    r.add_argument("--include-fixtures", action="store_true", dest="include_fixtures",
                   help="treat test/example/fixture code as product code: fixture routes count as attack "
                        "surface and fixture secrets keep full severity (default: split out + demoted)")
    r.add_argument("--verify-secrets", action="store_true", dest="verify_secrets",
                   help="opt in to TruffleHog LIVE VERIFICATION of discovered secrets. ⚠ this sends "
                        "each candidate credential to its provider's API (a third party) to test if "
                        "it is live. Off by default; provider traffic is separate from public-feed refresh.")
    r.add_argument("--sbom", nargs="?", const="cyclonedx", choices=["cyclonedx", "spdx"], metavar="FMT",
                   help="also emit a Software Bill of Materials (default cyclonedx → sbom.cdx.json) via "
                        "Trivy — offline, for CI/compliance (SLSA, EO 14028)")
    r.add_argument("--scanners", metavar="A,B",
                   help="comma-separated subset of scanners to run with --scan (e.g. gitleaks,semgrep)")
    r.add_argument("--format", choices=["briefing", "sarif", "json"], default="briefing",
                   help="stdout format: briefing (human, default) | sarif (SARIF 2.1.0) | json (envelope). "
                        "results.sarif is ALWAYS written to the run dir regardless.")
    r.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], dest="fail_on",
                   help="exit 1 if any finding at/above this severity remains (CI gate). With --baseline, "
                        "new, changed and reopened findings count; incomplete execution exits 2.")
    r.add_argument("--require-complete", action="store_true", help="exit 2 when requested checks cannot complete")
    r.add_argument("--only", action="append", metavar="PATH",
                   help="narrow ANALYSIS to these files, repo-relative (repeatable). Unlike --diff, "
                        "which filters the report, this changes what is read and matched: ~13x faster "
                        "on a 320-file repo. The tree is still walked in full, so stack detection, "
                        "ignore policy and fixture classification are unchanged, and files are "
                        "analyzed IN PLACE. A requested path the walker never selected is reported as "
                        "MISSED, not as a clean result.")
    r.add_argument("--actor", metavar="WHO",
                   help="record who initiated this run (or $WEBSEC_ACTOR). SELF-ASSERTED: stored under "
                        "attribution.declared and labelled as not verified — a value the runner can set "
                        "to any string is a label, not audit evidence.")
    r.add_argument("--application-id", help="stable application identity for repair verification (default: target path)")
    r.add_argument("--build-id", help="reviewed build identity (default: analyzed input digest)")
    r.add_argument("--diff", metavar="REF",
                   help="scope to what changed vs REF (e.g. --diff main): tags findings "
                        "in-changed-file, emits exact hunk line ranges to diff-scope.json, and "
                        "narrows --fail-on to changed files (PR/CI review mode)")
    r.add_argument("--baseline", metavar="LEDGER.json",
                   help="prior ledger for new/unchanged/changed/reopened/no-longer-observed lifecycle")
    r.add_argument("--graph", metavar="GRAPH.json",
                   help="a graphify graph.json for blast-radius enrichment "
                        "(auto-detected at <target>/graphify-out/graph.json if present)")
    r.set_defaults(func=cmd_run)

    # recon/proof/calibrate are hidden from the main --help (argparse.SUPPRESS): recon is a
    # subset of `run`, and proof/calibrate are for developing the tool itself. They still work
    # if invoked explicitly — the user-facing surface is just `run` (+ the advanced `dynamic`).
    rc = sub.add_parser("recon")
    rc.add_argument("target")
    rc.add_argument("--out", help="output dir (default: ./websec-out)")
    rc.set_defaults(func=cmd_recon)

    d = sub.add_parser("doctor", help="show which scanners are installed")
    d.add_argument("target", nargs="?", help="optional repo to scope scanner relevance")
    d.set_defaults(func=cmd_doctor)

    ec = sub.add_parser("emit-context",
                        help="emit recon as a Claude Code SessionStart additionalContext JSON "
                             "envelope (pipe into a session hook so any agent starts pre-scoped)")
    ec.add_argument("target")
    ec.add_argument("--markdown", action="store_true",
                    help="print the raw ## SECURITY CONTEXT block instead of the JSON envelope")
    ec.set_defaults(func=cmd_emit_context)

    pf = sub.add_parser("proof")
    pf.add_argument("--corpus", help="corpus JSON (default: bundled)")
    pf.add_argument("--workdir", help="where to clone corpus apps (default: ~/.cache/websec-corpus)")
    pf.set_defaults(func=cmd_proof)

    cal = sub.add_parser("calibrate")
    cal.add_argument("--corpus", help="corpus JSON with `truth` blocks (default: bundled)")
    cal.add_argument("--workdir", help="where corpus apps are cloned (default: ~/.cache/websec-corpus)")
    cal.add_argument("--out", help="where to write calibration.json (default: bundled, next to the package)")
    cal.add_argument("--ingest", help="fold a hand-labeled findings JSON ({attack_class,confidence,is_real}) into your LOCAL overlay")
    cal.add_argument("--ingest-dast", dest="ingest_dast", metavar="REPORT.json",
                     help="close the loop with a real scan: a ZAP/Nuclei report confirms/refutes this "
                          "repo's DAST-predictable findings and folds the verdicts into calibration "
                          "(needs --ledger)")
    cal.add_argument("--ledger", metavar="findings-ledger.json",
                     help="the websec ledger the --ingest-dast report is matched against")
    cal.set_defaults(func=cmd_calibrate)

    dyn = sub.add_parser("dynamic", help="dynamic probes vs a LIVE target (read-only): cross-tenant BOLA (--config) or unauth reachability (--unauth)")
    dyn.add_argument("--config", help="dynamic config JSON (target + role creds) for authenticated cross-tenant BOLA")
    dyn.add_argument("--unauth", action="store_true", help="STRICT read-only: GET each data-read endpoint with NO auth (needs --target)")
    dyn.add_argument("--probe-writes", action="store_true", help="also test write-verb auth enforcement (LOCALHOST-only, non-destructive)")
    dyn.add_argument("--target", help="target base URL (for --unauth)")
    dyn.add_argument("--facts", help="FACTS.json from a prior run (default: ./websec-out/latest/FACTS.json)")
    dyn.add_argument("--out", help="output dir (default: ./websec-out)")
    dyn.set_defaults(func=cmd_dynamic)

    mc = sub.add_parser("mcp", help="typed recon tools over stdio or authenticated loopback HTTP")
    mc.add_argument("--http", action="store_true",
                    help="serve authenticated loopback HTTP (JSON-RPC POST) instead of stdio")
    mc.add_argument("--host", default="127.0.0.1",
                    help="HTTP bind host (default 127.0.0.1; loopback only; WEBSEC_MCP_TOKEN required)")
    mc.add_argument("--port", type=int, default=8733, help="HTTP port (default 8733)")
    mc.add_argument("--allow-root", action="append", metavar="PATH", help="allowed HTTP scan root (repeatable; default: startup directory)")
    mc.set_defaults(func=cmd_mcp)

    verify = sub.add_parser("repair-verify", help="validate offline repair evidence without executing tests")
    verify.add_argument("--plan", required=True, help="repair plan JSON or repair-plans.json")
    verify.add_argument("--plan-id", help="plan identifier when the artifact contains multiple plans")
    verify.add_argument("--record", required=True, help="operator-supplied verification record JSON")
    verify.add_argument("--rerun", required=True, help="findings ledger from the fixed build")
    verify.add_argument("--evidence-root", required=True, help="directory containing referenced test reports")
    verify.add_argument("--out", metavar="RESULT.json",
                        help="persist the verification result as a durable artifact (refuses to "
                             "overwrite an existing file)")
    verify.set_defaults(func=cmd_repair_verify)

    g = sub.add_parser("gate", help="fast scoped pass/fail on the files you just changed (agent-loop check)")
    g.add_argument("target", nargs="?", default=".")
    g.add_argument("--only", action="append", metavar="PATH",
                   help="analyze these files instead of the working-tree changes (repeatable)")
    g.add_argument("--fail-on", dest="fail_on", default="medium",
                   choices=["critical", "high", "medium", "low"],
                   help="block at or above this severity (default: medium — command injection and "
                        "SSRF on agent-written code are frequently MEDIUM, so a HIGH default would "
                        "miss the main case this check exists for)")
    g.add_argument("--min-confidence", dest="min_confidence", default="low",
                   choices=["low", "medium", "high"],
                   help="ignore findings below this calibrated confidence (default: low = no "
                        "filtering; in the loop a false block costs one turn, a miss ships)")
    g.add_argument("--format", choices=["text", "json"], default="text",
                   help="text (default) is what a harness feeds back to the model; json for tooling")
    g.add_argument("--exclude", action="append", metavar="PATH", help="exclude a path/glob")
    g.set_defaults(func=cmd_gate)

    capabilities = sub.add_parser("capabilities", help="show offline named security checks and profile limitations")
    capabilities.set_defaults(func=cmd_capabilities)

    fb_parser = sub.add_parser(
        "feedback", help="record an offline verdict that a finding is wrong (metadata-only by default)")
    fb_parser.add_argument("--fingerprint", required=True, help="fingerprint of the finding, from the ledger")
    fb_parser.add_argument("--verdict", required=True, choices=list(_FEEDBACK_VERDICTS),
                           help="false-positive: not a real issue · severity-wrong: real but misrated")
    fb_parser.add_argument("--reason", required=True, help="why the detector is wrong (max 1000 chars)")
    fb_parser.add_argument("--expected-severity", dest="expected_severity",
                           choices=list(_FEEDBACK_SEVERITIES), help="required with --verdict severity-wrong")
    fb_parser.add_argument("--ledger", help="findings-ledger.json (default: <out>/latest/findings-ledger.json)")
    fb_parser.add_argument("--include-snippet", action="store_true",
                           help="also include title, route, file and evidence; prompts before writing")
    fb_parser.add_argument("--yes", action="store_true", help="skip the --include-snippet prompt (for scripts)")
    fb_parser.add_argument("--out", help="output directory (default: websec-out)")
    fb_parser.add_argument("--format", choices=["text", "json"], default="text")
    fb_parser.set_defaults(func=cmd_feedback)

    intelligence = sub.add_parser("intel", help="explicit public threat-feed refresh and offline known-CVE reassessment")
    intel_actions = intelligence.add_subparsers(dest="action", required=True)
    for action in ("refresh", "status", "reassess"):
        item = intel_actions.add_parser(action)
        item.add_argument("--cache-dir", help="local intelligence snapshot directory")
        item.add_argument("--out", help="write JSON result to a new file (existing files refused)")
        if action == "reassess":
            item.add_argument("--ledger", required=True, help="existing findings ledger; input is never overwritten")
        item.set_defaults(func=cmd_intel)

    research = sub.add_parser("research", help="evaluate data-only proposals against shipped detectors offline")
    research_actions = research.add_subparsers(dest="action", required=True)
    for action in ("example", "catalog", "evaluate"):
        item = research_actions.add_parser(action)
        item.add_argument("--out", help="write JSON result to a new file (existing files refused)")
        if action == "evaluate":
            selection = item.add_mutually_exclusive_group(required=True)
            selection.add_argument("--proposal", help="proposal object or proposal/cases bundle JSON")
            from .research import SUITES
            selection.add_argument("--suite", choices=SUITES, help="evaluate every proposal in a shipped regression suite")
            item.add_argument("--cases", help="separate synthetic cases JSON when proposal is unbundled")
        item.set_defaults(func=cmd_research)

    from . import install as _install
    ins = sub.add_parser("install",
                         help="teach an AI coding agent to use websec (claude|codex|cursor|gemini|aider|generic)")
    ins.add_argument("host", choices=[*_install.HOSTS, "status"],
                     help="agent host to configure, or 'status' to list what's installed")
    ins.add_argument("--user", action="store_true",
                     help="install into your home dir (all repos) instead of this project")
    ins.add_argument("--project-dir", dest="project_dir",
                     help="project directory to install into (default: current dir)")
    ins.add_argument("--uninstall", action="store_true", help="remove the websec block/skill instead")
    ins.set_defaults(func=cmd_install)

    hk = sub.add_parser("hooks",
                        help="install a git guardrail hook (post-commit advisory or pre-push gate on NEW findings)")
    hk.add_argument("action", choices=["install", "uninstall", "status"])
    hk.add_argument("--pre-push", dest="pre_push", action="store_true",
                    help="install a blocking pre-push gate (--fail-on new findings) instead of the advisory post-commit hook")
    hk.add_argument("--path", help="repo directory (default: current dir)")
    hk.set_defaults(func=cmd_hooks)
    return p


_COMMANDS = {"run", "recon", "doctor", "emit-context", "proof", "dynamic", "calibrate", "mcp", "install", "hooks", "repair-verify", "capabilities", "intel", "research", "feedback", "gate"}


def main(argv=None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    parser = build_parser()
    if not argv:                      # bare `websec` → show help, don't error
        parser.print_help()
        return 0
    # bare `websec <path>` (no subcommand) ⇒ treat as `websec run <path>` — point-and-go
    if argv[0] not in _COMMANDS and not argv[0].startswith("-"):
        argv = ["run"] + argv
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
