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

from . import __version__, briefing, dynamic, probes, proof, recon, report, scanners


def _resolve_target(raw: str) -> Path:
    p = Path(raw).expanduser().resolve()
    if not p.is_dir():
        sys.exit(f"error: target is not a directory: {p}")
    return p


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

    print(f"websec-validator v{__version__}  ·  target: {target}  ·  run {ts}\n")

    # 1. recon
    facts = recon.build_facts(target, __version__)
    recon.write_facts(facts, out / "FACTS.json")
    langs = facts["stack"]["languages"]
    _print_facts_summary(facts)

    # 2. scanners: detect, optionally run
    det = scanners.detect(langs)
    scan_results = []
    unified = None
    if args.scan:
        print("\n  running available static scanners (read-only)…")
        scan_results = scanners.run_available(target, out, langs)
        for r in scan_results:
            tag = r.get("findings", r.get("status", "?"))
            print(f"    {r['name']}: {tag}")
        unified = scanners.normalize_findings(scan_results, out)
        print(f"  → {unified['total']} de-duplicated findings "
              f"({unified['cross_tool_or_dup_merged']} merged) · {unified['by_severity']}")
    else:
        print(f"\n  scanners available: {', '.join(s['name'] for s in det['available']) or 'none'}"
              "  (add --scan to execute them)")

    # 3. probes: choose + stage
    chosen = probes.applicable(facts)
    manifest = probes.stage(chosen, out)
    print(f"\n  staged {len([m for m in manifest if 'attack_class' in m])} tailored probe template(s) → {out / 'probes'}")

    # 4. briefing + comprehensive REPORT.md (immutable run record)
    (out / "AGENT-BRIEFING.md").write_text(briefing.render(facts, det, scan_results, manifest, unified))
    (out / "REPORT.md").write_text(report.render(facts, det, scan_results, unified, manifest, ts))
    (out / "manifest.json").write_text(json.dumps(
        {"facts": "FACTS.json", "scanners": det, "scan_results": scan_results,
         "findings_summary": unified, "probes": manifest, "timestamp": ts}, indent=2))

    print(f"\n✓ run {ts} saved (immutable — nothing overwritten):\n    {out}")
    print("    REPORT.md          — full historical record")
    print("    AGENT-BRIEFING.md  — hand this to your AI coding agent")
    print(f"  latest → {out.parent.parent / 'latest'}    ·    add `websec-out/` to .gitignore")
    return 0


def cmd_dynamic(args) -> int:
    out = Path(args.out).expanduser().resolve() if args.out else Path.cwd() / "websec-out"
    out.mkdir(parents=True, exist_ok=True)
    facts = Path(args.facts).expanduser().resolve() if args.facts else out / "FACTS.json"
    if not facts.is_file():
        sys.exit(f"error: FACTS.json not found at {facts} — run `websec run <repo>` first (or pass --facts)")

    if args.unauth:
        if not args.target:
            sys.exit("error: --unauth requires --target")
        if args.probe_writes and not dynamic.is_localhost(args.target):
            sys.exit("error: --probe-writes is localhost-only (it sends write verbs) — point --target at your sandbox")
        print("websec dynamic — STRICT read-only · UNAUTHENTICATED · GET-only (side-effecting paths skipped)\n")
        full = dynamic.run_unauth(args.target, facts, out, probe_writes=args.probe_writes)
        u = full["unauth_reachability"]
        print(f"  target: {u['target']}")
        print(f"  skipped {len(u['skipped_side_effecting'])} side-effecting GET(s) (cron/generate/etc.)")
        print(f"  → {u['summary']}\n")
        for r in u["results"]:
            mark = "🔓" if r["verdict"] == "OPEN-no-auth" else (" ·" if r["verdict"] == "protected" else "  ")
            print(f"    {mark} {str(r['status']):>4}  {r['verdict']:26} {r['path']}  ({r['bytes']}b)")
        if args.probe_writes:
            w = full["write_auth_enforcement"]
            print(f"\n  --- write-verb auth enforcement (localhost, non-destructive) ---")
            print(f"  → {w['summary']}\n")
            for r in w["results"]:
                mark = "🔓" if r["verdict"] != "auth-enforced" and not r["verdict"].startswith("http-") else " ·"
                print(f"    {mark} {str(r['status']):>4}  {r['verdict']:42} {r['method']} {r['path']}")
        print(f"\n  details: {out / 'dynamic-unauth-findings.json'}")
        return 0

    if not args.config:
        sys.exit("error: provide --config (authenticated cross-tenant) OR --unauth --target (read-only)")
    cfg = Path(args.config).expanduser().resolve()
    if not cfg.is_file():
        sys.exit(f"error: config not found: {cfg}")
    print("websec dynamic — authenticated, READ-ONLY v1 (cross-tenant BOLA on GET endpoints)\n")
    res = dynamic.run_dynamic(cfg, facts, out)
    ct = res.get("cross_tenant_bola", {})
    if ct.get("error"):
        print("  ERROR:", ct["error"])
        return 1
    print(f"  agentA: {ct['agentA']['email']}  (tenant {ct['agentA']['tenant']})")
    print(f"  agentB: {ct['agentB']['email']}  (tenant {ct['agentB']['tenant']})")
    print(f"  tested {ct['endpoints_tested']} tenant-scoped GET endpoint(s) · {ct['checks']} cross-tenant checks")
    print(f"  → {ct['summary']}")
    for lk in ct.get("leaks", []):
        print(f"     🚨 LEAK {lk['direction']} {lk['path']} → HTTP {lk['status']}")
    print(f"\n  details: {out / 'dynamic-findings.json'}")
    return 1 if ct.get("leaks") else 0


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


def _which(b):
    import shutil
    return shutil.which(b)


def _print_facts_summary(facts: dict) -> None:
    st = facts.get("stack", {})
    rt = facts.get("routes", {})
    tg = rt.get("targeting", {})
    print(f"  stack:    {', '.join(st.get('languages', [])) or '?'}  ·  "
          f"frameworks: {', '.join(st.get('frameworks', [])) or '?'}  ·  "
          f"datastores: {', '.join(st.get('datastores', [])) or '?'}")
    print(f"  auth:     {facts.get('auth', {}).get('scheme', '?')}")
    tc = facts.get("tenant", {}).get("candidates", [])
    print(f"  tenant?:  {', '.join(t['key'] for t in tc) or 'none detected'}"
          + ("   ← confirm THE boundary" if tc else ""))
    print(f"  routes:   {rt.get('count', 0)} endpoints via {rt.get('engine', '?').split(' ')[0]}")
    print(f"  targets:  IDOR={len(tg.get('idor_candidates', []))} "
          f"SSRF={len(tg.get('ssrf_candidates', []))} "
          f"upload={len(tg.get('upload_candidates', []))} "
          f"writes={len(tg.get('write_endpoints', []))}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="websec",
        description="Local-first security recon that briefs your AI coding agent.")
    p.add_argument("--version", action="version", version=f"websec-validator {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="full pipeline → briefing + tailored probes")
    r.add_argument("target")
    r.add_argument("--scan", action="store_true", help="also execute available static scanners")
    r.add_argument("--out", help="output dir (default: ./websec-out)")
    r.set_defaults(func=cmd_run)

    rc = sub.add_parser("recon", help="recon only → FACTS.json")
    rc.add_argument("target")
    rc.add_argument("--out", help="output dir (default: ./websec-out)")
    rc.set_defaults(func=cmd_recon)

    d = sub.add_parser("doctor", help="show which scanners are installed")
    d.add_argument("target", nargs="?", help="optional repo to scope scanner relevance")
    d.set_defaults(func=cmd_doctor)

    pf = sub.add_parser("proof", help="score recon coverage against a known-vuln-app corpus")
    pf.add_argument("--corpus", help="corpus JSON (default: bundled)")
    pf.add_argument("--workdir", help="where to clone corpus apps (default: ~/.cache/websec-corpus)")
    pf.set_defaults(func=cmd_proof)

    dyn = sub.add_parser("dynamic", help="dynamic probes vs a LIVE target (read-only): cross-tenant BOLA (--config) or unauth reachability (--unauth)")
    dyn.add_argument("--config", help="dynamic config JSON (target + role creds) for authenticated cross-tenant BOLA")
    dyn.add_argument("--unauth", action="store_true", help="STRICT read-only: GET each data-read endpoint with NO auth (needs --target)")
    dyn.add_argument("--probe-writes", action="store_true", help="also test write-verb auth enforcement (LOCALHOST-only, non-destructive)")
    dyn.add_argument("--target", help="target base URL (for --unauth)")
    dyn.add_argument("--facts", help="FACTS.json from a prior run (default: ./websec-out/FACTS.json)")
    dyn.add_argument("--out", help="output dir (default: ./websec-out)")
    dyn.set_defaults(func=cmd_dynamic)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
