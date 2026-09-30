"""Authored-pair precision: run the repository's paired fixtures and score the detector on them.

A PAIR is a vulnerable variant that must produce a given attack class, and a sanitized twin that
must not. Both halves are labels: the positive says "this must fire" (is_real=True), the negative
says "this must not" (a finding here is a false positive, is_real=False).

WHY THIS IS SEPARATE FROM `calibration.fit`: these cases were written by the same people who wrote
the detectors, so they measure whether the rule still handles what it was BUILT to handle. That is
regression evidence, and it is valuable — but it is not the rate at which a finding in a real
repository turns out to be a real vulnerability. Merging the two would make P(real) look better by
importing the author's own coverage. The numbers therefore live in their own file with their own
basis and caveat, reported beside the measured table and never summed into it.

Pairs are declared as data (`pairs.json`), not discovered by scanning test files: a harness that
inferred labels from test code would silently relabel itself whenever a test was edited.
"""
from __future__ import annotations

import json
import tempfile
from importlib import resources
from pathlib import Path, PurePosixPath

PAIRS_FILENAME = "pairs.json"


def load_pairs(path: Path | None = None) -> list:
    """Read the declared pair manifest. Missing or malformed → empty, never a guess."""
    try:
        if path is not None:
            return json.loads(Path(path).read_text())
        return json.loads(resources.files("websec_validator").joinpath(PAIRS_FILENAME).read_text())
    except Exception:
        return []


def _findings_for(source: str, filename: str, extractor_name: str) -> set:
    """Run one extractor over one synthetic file and return the attack classes it reported."""
    from .extractors.base import RepoContext
    from . import extractors as _ex

    cls = _fixture_type(filename, extractor_name)
    _fixture_source(source)
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / filename
        target.resolve().relative_to(root.resolve())
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
        ctx = RepoContext(root)
        result = cls().extract(ctx, {"stack": {"datastores": ["postgres"]}}) or {}
    classes = set()
    for row in result.get("findings", []) or []:
        for key in ("attack_class", "kind"):
            if row.get(key):
                classes.add(row[key])
    for key in result.get("sinks", []) or []:
        classes.add(key)
    for key in (result.get("sink_counts", {}) or {}):
        classes.add(key)
    return classes


def _fixture_type(filename, extractor_name):
    from .extractors import REGISTRY
    if (not isinstance(filename, str) or not filename or len(filename) > 1024
            or "\\" in filename or ":" in filename or "\x00" in filename
            or PurePosixPath(filename).is_absolute()
            or any(p == ".." or p.casefold() == ".local" for p in PurePosixPath(filename).parts)):
        raise ValueError("fixture file must be a safe relative path")
    allowed = {type(item).__name__: type(item) for item in REGISTRY}
    if not isinstance(extractor_name, str) or extractor_name not in allowed:
        raise ValueError("unknown fixture extractor")
    return allowed[extractor_name]


def _fixture_source(source):
    if not isinstance(source, str) or not source or len(source.encode()) > 2_000_000:
        raise ValueError("fixture source must be bounded nonempty text")


def evaluate(pairs: list) -> dict:
    """Score every pair. Returns {"labels": [...], "errors": [...], "skipped": int}.

    Each label is a `calibration.fit_synthetic` row. A pair whose extractor cannot be resolved is an
    ERROR, not a silent pass — a harness that scores nothing must not report a perfect table.
    """
    labels, errors = [], []
    if not isinstance(pairs, list) or len(pairs) > 1000:
        return {"labels": [], "errors": [{"pair": "?", "error": "invalid pair manifest"}], "pairs": 0}
    # Validate the entire imported manifest before materializing even its first fixture.
    for pair in pairs:
        try:
            if not isinstance(pair, dict) or not all(pair.get(k) for k in ("attack_class", "confidence", "extractor")):
                raise ValueError("incomplete pair declaration")
            _fixture_type(pair.get("file", "app.ts"), pair["extractor"])
            for variant in ("vulnerable", "control"):
                if not pair.get(variant):
                    raise ValueError(f"missing {variant} variant")
                _fixture_source(pair[variant])
        except (ValueError, TypeError) as exc:
            errors.append({"pair": pair.get("id", "?") if isinstance(pair, dict) else "?", "error": str(exc)})
    if errors:
        return {"labels": [], "errors": errors, "pairs": len(pairs)}
    for pair in pairs or []:
        cls = pair.get("attack_class")
        conf = pair.get("confidence")
        extractor = pair.get("extractor")
        if not (cls and conf and extractor):
            errors.append({"pair": pair.get("id", "?"), "error": "incomplete pair declaration"})
            continue
        for variant, expect_fires in (("vulnerable", True), ("control", False)):
            source = pair.get(variant)
            if not source:
                errors.append({"pair": pair.get("id", "?"), "error": f"missing {variant} variant"})
                continue
            try:
                fired = cls in _findings_for(source, pair.get("file", "app.ts"), extractor)
            except Exception as exc:                      # a crashing detector is evidence too
                errors.append({"pair": pair.get("id", "?"), "variant": variant, "error": str(exc)})
                continue
            # The label is whether the detector got this case RIGHT, expressed as is_real so the
            # cell means the same thing as in the measured table: "a reported finding was correct".
            # Positive variant: fired ⇒ a correct report. Control: fired ⇒ a false positive.
            if expect_fires:
                if fired:
                    labels.append({"attack_class": cls, "confidence": conf, "is_real": True,
                                   "sample_id": f"pair:{pair.get('id')}:vulnerable"})
                else:
                    # A miss produces no finding at all, so it is not a precision label — it is a
                    # recall failure. Recorded as an error so it cannot be mistaken for precision.
                    errors.append({"pair": pair.get("id", "?"), "variant": "vulnerable",
                                   "error": f"detector did not report {cls} on the vulnerable variant "
                                            "(recall gap; not scored as precision)"})
            elif fired:
                labels.append({"attack_class": cls, "confidence": conf, "is_real": False,
                               "sample_id": f"pair:{pair.get('id')}:control"})
            # control that correctly stayed silent produces NO finding, so there is nothing to score:
            # precision is about reports that happened, and a silent control made none.
    return {"labels": labels, "errors": errors, "pairs": len(pairs or [])}
