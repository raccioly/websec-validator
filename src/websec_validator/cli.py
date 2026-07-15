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
import json
import sys
from pathlib import Path

from . import (__version__, baseline, briefing, calibration, constitution, dynamic, findings, formats,
               probes, proof, recon, report, scanners)


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
    """Create an immutable timestamped run dir and point `latest` at it. Returns (run_dir, ts).
    Every run is preserved — nothing is overwritten."""
    import datetime
    base = Path(out).expanduser().resolve() if out else Path.cwd() / "websec-out"
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run = base / "runs" / ts
    run.mkdir(parents=True, exist_ok=True)
    latest = base / "latest"
    try:
        if latest.is_symlink() or latest.exists():
            latest.unlink()
        latest.symlink_to(Path("runs") / ts, target_is_directory=True)
    except Exception:
        pass
    return run, ts


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


def cmd_run(args) -> int:
    target = _resolve_target(args.target)
    out, ts = _new_run_dir(args.out)

    # In a machine-output mode (sarif/json) keep STDOUT pure for piping — route human progress to
    # stderr. `websec run app --format sarif > results.sarif` then Just Works in a pipeline.
    fmt = getattr(args, "format", "briefing")
    log = (lambda *a, **k: print(*a, file=sys.stderr, **k)) if fmt != "briefing" else print

    log(f"websec-validator v{__version__}  ·  target: {target}  ·  run {ts}\n")

    # 1. recon
    facts = recon.build_facts(target, __version__, args.exclude,
                              include_fixtures=getattr(args, "include_fixtures", False))
    recon.write_facts(facts, out / "FACTS.json")
    langs = facts["stack"]["languages"]
    _print_facts_summary(facts, log)

    # 2. scanners: detect, optionally run
    det = scanners.detect(langs)
    scan_results = []
    unified = None
    if args.scan:
        log("\n  running available static scanners (read-only)…")
        only = args.scanners.split(",") if args.scanners else None
        scan_results = scanners.run_available(target, out, langs, excludes=args.exclude, only=only)
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
    else:
        log(f"\n  scanners available: {', '.join(s['name'] for s in det['available']) or 'none'}"
            "  (add --scan to execute them)")

    # 3. probes: choose + stage
    chosen = probes.applicable(facts)
    manifest = probes.stage(chosen, out, facts)
    log(f"\n  staged {len([m for m in manifest if 'attack_class' in m])} tailored probe template(s) → {out / 'probes'}")

    # 4. traceable findings ledger (recon + static; dynamic merges in via `websec dynamic`)
    suppressions = findings.load_suppressions(target)
    acks = findings.load_acknowledgements(target)
    ledger = findings.build_ledger(facts, unified, None, suppressions, acks)
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
            graph_enrich.enrich_ledger(ledger, target, graph_path)
            ge = ledger.get("graph_enrichment")
            if ge:
                log(f"\n  graph: {ge['mapped']} finding(s) mapped to {ge['nodes']} nodes · "
                    f"max blast-radius {ge['max_blast_radius']} (source: {ge['graph']})")
        except Exception as e:  # enrichment is best-effort — never fail the run over it
            log(f"\n  graph: enrichment skipped ({type(e).__name__}: {e})")

    # 4b. baseline / diff — only NEW findings gate CI when a baseline is supplied
    diff = None
    if getattr(args, "baseline", None):
        base_fps = baseline.load_baseline(Path(args.baseline).expanduser())
        diff = baseline.diff(ledger, base_fps)
        log(f"\n  baseline: {diff['new_count']} new · {diff['unchanged_count']} unchanged · "
            f"{diff['fixed_count']} fixed (vs {args.baseline})")

    (out / "findings-ledger.json").write_text(json.dumps(ledger, indent=2))
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
        {"facts": "FACTS.json", "scanners": det, "scan_results": scan_results,
         "findings_summary": manifest_summary, "ledger": {"total": ledger["total"], "by_severity": ledger["by_severity"]},
         "sarif": "results.sarif", "probes": manifest, "timestamp": ts}, indent=2))

    log(f"\n✓ run {ts} saved (immutable — nothing overwritten):\n    {out}")
    log("    REPORT.md          — full historical record")
    log("    AGENT-BRIEFING.md  — hand this to your AI coding agent")
    log("    results.sarif      — SARIF 2.1.0 for CI / GitHub Code Scanning")
    log(f"  latest → {out.parent.parent / 'latest'}    ·    add `websec-out/` to .gitignore")

    # emit the requested machine format on STDOUT (for piping); default 'briefing' emits nothing extra
    if fmt == "sarif":
        print(json.dumps(sarif, indent=2))
    elif fmt == "json":
        print(json.dumps(formats.to_json(ledger, facts, __version__, ts), indent=2))

    # 6. CI gate — exit non-zero if findings at/above --fail-on remain (only NEW ones when a baseline
    # is supplied). Default (no --fail-on) never fails the build.
    if getattr(args, "fail_on", None):
        n = baseline.gate_count(ledger, args.fail_on, new_only=bool(diff))
        if n:
            log(f"\n✗ --fail-on {args.fail_on}: {n} finding(s) at or above threshold"
                + (" (new since baseline)" if diff else "") + " — failing the build.")
            return 1
        log(f"\n✓ --fail-on {args.fail_on}: no findings at or above threshold"
            + (" (new since baseline)" if diff else "") + ".")
    return 0


def cmd_dynamic(args) -> int:
    base = Path(args.out).expanduser().resolve() if args.out else Path.cwd() / "websec-out"
    # resolve BEFORE _new_run_dir repoints `latest` (else the symlink moves under us)
    facts_path = (Path(args.facts).expanduser() if args.facts else base / "latest" / "FACTS.json").resolve()
    if not facts_path.is_file():
        sys.exit(f"error: FACTS.json not found at {facts_path} — run `websec run <repo>` first (or pass --facts)")
    out, ts = _new_run_dir(args.out)
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
                if r["verdict"] == "BYPASS":
                    print(f"    🚨 BYPASS  {r['baseline']}→{r['forged']}  {r['method']} {r['path']}  (via {r['via']})")
        if args.probe_writes:
            w = dyn["write_auth_enforcement"]
            print(f"\n  write-verb auth enforcement → {w['summary']}")
            if w.get("warning"):
                print(f"\n  {w['warning']}\n")
            for r in w["results"]:
                mark = "🔓" if r["verdict"] != "auth-enforced" and not r["verdict"].startswith("http-") else " ·"
                print(f"    {mark} {str(r['status']):>4}  {r['verdict']:42} {r['method']} {r['path']}")
    elif args.config:
        cfg = Path(args.config).expanduser().resolve()
        if not cfg.is_file():
            sys.exit(f"error: config not found: {cfg}")
        print(f"websec dynamic — authenticated cross-tenant BOLA (read-only)  ·  run {ts}\n")
        dyn = dynamic.run_dynamic(cfg, facts_path, out)
        ct = dyn.get("cross_tenant_bola", {})
        if ct.get("error"):
            print("  ERROR:", ct["error"])
            return 1
        print(f"  agentA {ct['agentA']['email']} (tenant {ct['agentA']['tenant']}) · "
              f"agentB {ct['agentB']['email']} (tenant {ct['agentB']['tenant']})")
        print(f"  → {ct['summary']}")
        for lk in ct.get("leaks", []):
            print(f"     🚨 LEAK {lk['direction']} {lk['path']} → HTTP {lk['status']}")
    else:
        sys.exit("error: provide --config (authenticated cross-tenant) OR --unauth --target (read-only)")

    # merge dynamic evidence into the traceable ledger + write the immutable run report
    facts_dict = json.loads(facts_path.read_text())
    _root = Path(facts_dict.get("target", "."))
    ledger = findings.build_ledger(facts_dict, None, dyn,
                                   findings.load_suppressions(_root),
                                   findings.load_acknowledgements(_root))
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

    print(f"  ✓ run {ts} saved (immutable): {out}")
    return 1 if ledger["by_severity"].get("CRITICAL") else 0


def cmd_mcp(args) -> int:
    from . import mcp_server
    if getattr(args, "http", False):
        return mcp_server.serve_http(args.host, args.port)
    return mcp_server.serve()


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
    res = proof.run_proof(corpus_path, workdir)
    for r in res["results"]:
        if r.get("score") is None:
            print(f"  {r['name']:12} — {r.get('status', 'no checks')}")
            continue
        print(f"  {r['name']:12} {r['passed']}/{r['total']} checks · {r.get('endpoints', '?')} endpoints · {r.get('vulns', '')[:55]}")
        for c in r.get("checks", []):
            print(f"       {'✓' if c['pass'] else '✗'} {c['check']:22} got={c['got']}")
    agg = res["aggregate"]
    print(f"\n  OVERALL recon coverage: {agg.get('overall_coverage')} "
          f"({agg['checks_passed']}/{agg['checks_total']} checks, {agg['apps']} apps)")
    print("  NOTE: PROXY metric (does recon surface the known-vuln surface?). The full agent-lift")
    print("  kill-criterion is the manual A/B in corpus/PROOF-PROTOCOL.md.")
    return 0


def cmd_calibrate(args) -> int:
    """Fit confidence calibration: run the recon ledger against the labeled vuln corpus,
    measure how often each (attack_class, label) bucket is a real documented vuln, and
    write calibration.json (shipped + applied at runtime by findings.build_ledger)."""
    from importlib import resources

    # --ingest: fold a hand-labeled findings file into your LOCAL overlay (the manual real-repo path)
    if getattr(args, "ingest", None):
        src = Path(args.ingest).expanduser().resolve()
        if not src.is_file():
            sys.exit(f"error: --ingest file not found: {src}")
        data = json.loads(src.read_text())
        rows = data.get("findings", data) if isinstance(data, dict) else data
        labeled = [{"attack_class": r.get("attack_class", ""), "confidence": r.get("confidence", "MEDIUM"),
                    "is_real": bool(r.get("is_real"))} for r in rows]
        rec = calibration.record_samples(labeled)
        if not rec:
            sys.exit("error: nothing ingested (empty file, or local overlay not writable)")
        nr = sum(1 for s in labeled if s["is_real"])
        print(f"websec calibrate --ingest: folded {len(labeled)} hand-labeled sample(s) "
              f"({nr} real / {len(labeled) - nr} FP) into {calibration.LOCAL_PATH} → {rec['meta']['samples']} total.")
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
            n_real += int(real)
        used.append(entry["name"])
        print(f"  {entry['name']:12} {len(ledger['findings'])} findings · {n_real} matched a documented vuln")

    if not labeled:
        print("\n  no labeled findings produced — is the corpus cloned? (needs network on first run)")
        return 1

    researched = {t.get("class") for entry in corpus for t in (entry.get("truth") or [])}
    table = calibration.fit(labeled, used, researched)
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
    sub = p.add_subparsers(dest="cmd", required=True, metavar="{run,doctor,dynamic,mcp,install,hooks}")

    r = sub.add_parser("run", help="full pipeline → briefing + tailored probes")
    r.add_argument("target")
    r.add_argument("--scan", action="store_true", help="also execute available static scanners")
    r.add_argument("--out", help="output dir (default: ./websec-out)")
    r.add_argument("--exclude", action="append", metavar="PATH",
                   help="exclude a path/glob from recon + scanners (repeatable; e.g. --exclude 'docs/**')")
    r.add_argument("--include-fixtures", action="store_true", dest="include_fixtures",
                   help="treat test/example/fixture code as product code: fixture routes count as attack "
                        "surface and fixture secrets keep full severity (default: split out + demoted)")
    r.add_argument("--scanners", metavar="A,B",
                   help="comma-separated subset of scanners to run with --scan (e.g. gitleaks,semgrep)")
    r.add_argument("--format", choices=["briefing", "sarif", "json"], default="briefing",
                   help="stdout format: briefing (human, default) | sarif (SARIF 2.1.0) | json (envelope). "
                        "results.sarif is ALWAYS written to the run dir regardless.")
    r.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], dest="fail_on",
                   help="exit 1 if any finding at/above this severity remains (CI gate). With --baseline, "
                        "only NEW findings count.")
    r.add_argument("--baseline", metavar="LEDGER.json",
                   help="a prior findings-ledger.json — mark findings new/unchanged/fixed and gate only on NEW")
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

    pf = sub.add_parser("proof")
    pf.add_argument("--corpus", help="corpus JSON (default: bundled)")
    pf.add_argument("--workdir", help="where to clone corpus apps (default: ~/.cache/websec-corpus)")
    pf.set_defaults(func=cmd_proof)

    cal = sub.add_parser("calibrate")
    cal.add_argument("--corpus", help="corpus JSON with `truth` blocks (default: bundled)")
    cal.add_argument("--workdir", help="where corpus apps are cloned (default: ~/.cache/websec-corpus)")
    cal.add_argument("--out", help="where to write calibration.json (default: bundled, next to the package)")
    cal.add_argument("--ingest", help="fold a hand-labeled findings JSON ({attack_class,confidence,is_real}) into your LOCAL overlay")
    cal.set_defaults(func=cmd_calibrate)

    dyn = sub.add_parser("dynamic", help="dynamic probes vs a LIVE target (read-only): cross-tenant BOLA (--config) or unauth reachability (--unauth)")
    dyn.add_argument("--config", help="dynamic config JSON (target + role creds) for authenticated cross-tenant BOLA")
    dyn.add_argument("--unauth", action="store_true", help="STRICT read-only: GET each data-read endpoint with NO auth (needs --target)")
    dyn.add_argument("--probe-writes", action="store_true", help="also test write-verb auth enforcement (LOCALHOST-only, non-destructive)")
    dyn.add_argument("--target", help="target base URL (for --unauth)")
    dyn.add_argument("--facts", help="FACTS.json from a prior run (default: ./websec-out/FACTS.json)")
    dyn.add_argument("--out", help="output dir (default: ./websec-out)")
    dyn.set_defaults(func=cmd_dynamic)

    mc = sub.add_parser("mcp", help="run as an MCP server (typed recon tools for any MCP client): stdio, or --http for a team-shared URL")
    mc.add_argument("--http", action="store_true",
                    help="serve over HTTP (JSON-RPC POST) instead of stdio — one URL for a team (stdlib only)")
    mc.add_argument("--host", default="127.0.0.1",
                    help="HTTP bind host (default 127.0.0.1; use 0.0.0.0 to expose on a TRUSTED network only)")
    mc.add_argument("--port", type=int, default=8733, help="HTTP port (default 8733)")
    mc.set_defaults(func=cmd_mcp)

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


_COMMANDS = {"run", "recon", "doctor", "proof", "dynamic", "calibrate", "mcp", "install", "hooks"}


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
