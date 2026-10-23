#!/usr/bin/env python3
"""Validate R2 case traceability; this does not certify workflow execution."""

import argparse
from datetime import datetime, timezone
import math
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


LEGACY_SHA256 = "987e7384fd6b698f783f95bfe6e48b57d05fa0fbd56500dfc110a83ee72abefd"
POINTER_KINDS = {"source", "test", "candidate_source", "candidate_test", "planned_test", "fixture", "baseline", "gap", "dependency", "legacy_evidence"}
PROGRESS_STATUSES = {"PARTIALLY_IMPLEMENTED", "PARTIALLY_VERIFIED", "IMPLEMENTED_VERIFIED_LOCAL", "QA_VERIFIED", "UAT_READY", "ACCEPTED", "FAILED"}
EXECUTED_KINDS = {"source_execution", "native_execution", "qa_execution", "human_uat"}
WORK_ORDER_START = "<!-- OSMAP_ACTIVE_WORK_ORDER -->"
WORK_ORDER_END = "<!-- /OSMAP_ACTIVE_WORK_ORDER -->"
DELIVERY_STAGES = {"implementation", "source_tests", "native_tests", "deployed_qa", "independent_review", "recovery"}
DELIVERY_ROLES = {"project_manager", "scrum_lead", "developers", "qa", "security_review", "technical_writer"}
R4_PROPOSAL_SHA256 = "55bb148960599b9dc33fc777b9299d11f201312bab7434521e78d1ee7af29ac8"
R4_PROFILE = "maint/ux/s04_01_r4_scope.json"
R4_SUPPLEMENT = "docs/UX_PLAN_AMENDMENT_R4.md"
R4_PROPOSAL = "docs/UX_PLAN_AMENDMENT_R4_PROPOSED.md"
R4_FOLLOWUPS = {
    "OSMAP-UX/F1": {"R2-11-005"},
    "OSMAP-UX/F2": {"R2-11-012", "R2-16-007"},
    "OSMAP-UX/F3": {"R2-01-028"},
    "OSMAP-UX/F4": {"R2-01-029"},
    "OSMAP-UX/F5": {"R2-01-030"},
    "OSMAP-UX/F6": {"R2-01-026", "R2-01-027"},
    "OSMAP-UX/F7": {"R2-11-024"},
    "OSMAP-UX/F8": {"R2-11-025"},
    "OSMAP-UX/F9": {"R2-11-026"},
}
R4_DEPENDENCIES = {"OSMAP-UX/F1": [], "OSMAP-UX/F2": ["S02-03"], "OSMAP-UX/F3": [],
    "OSMAP-UX/F4": [], "OSMAP-UX/F5": [], "OSMAP-UX/F6": ["S08-01"],
    "OSMAP-UX/F7": ["S04-02"], "OSMAP-UX/F8": [], "OSMAP-UX/F9": ["S04-03", "S04-04"]}


def r4_scope(matrix, repo):
    """Pinned supplement/profile consistency only; signatures are checked externally."""
    root = repo.resolve()
    require(len(matrix["cases"]) == 110 and semantic_hash(matrix["cases"]) == LEGACY_SHA256,
            "R4 must preserve all110 immutable legacy cases")
    require(len(matrix["approved_control_cases"]) == 403 and len({row["id"] for row in matrix["approved_control_cases"]}) == 403,
            "R4 must preserve all403 approved obligations")
    entries = {}
    for line in (root / "docs/UX_PLAN_SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        require(match is not None, "invalid R4 plan manifest line")
        digest, relative = match.groups()
        require(relative not in entries, "duplicate R4 plan manifest path")
        entries[relative] = digest
    inputs = {}
    for relative in (R4_PROFILE, R4_SUPPLEMENT, R4_PROPOSAL):
        target = (root / relative).resolve(strict=True)
        require(target.is_relative_to(root) and target.is_file(), "R4 input outside repository")
        inputs[relative] = target.read_bytes()
        require(entries.get(relative) == hashlib.sha256(inputs[relative]).hexdigest(), "R4 input missing or changed in plan manifest")
    require(hashlib.sha256(inputs[R4_PROPOSAL]).hexdigest() == R4_PROPOSAL_SHA256, "R4 approved proposal SHA256 mismatch")
    profile = json.loads(inputs[R4_PROFILE])
    fields = {"schema_version", "revision", "slice", "approved_proposal_sha256", "accepted_supplement", "historical_proposal", "original_plan_anchor", "prior_execution_anchor", "core_control_ids", "required_followups", "completion_label"}
    require(isinstance(profile, dict) and set(profile) == fields and type(profile.get("schema_version")) is int and profile["schema_version"] == 1,
            "R4 scope profile exact fields/version required")
    require(profile["revision"] == "R4" and profile["slice"] == "S04-01"
            and profile["approved_proposal_sha256"] == R4_PROPOSAL_SHA256
            and profile["accepted_supplement"] == R4_SUPPLEMENT and profile["historical_proposal"] == R4_PROPOSAL
            and profile["original_plan_anchor"] == "6b3ce8fff27ca3dabf87039d54098bd9967a2e42"
            and profile["prior_execution_anchor"] == "f2a117c17dbd93b634f9914c5608473dc682d8e0"
            and profile["completion_label"] == "S04-01 complete (R4 narrowed scope)", "unapproved R4 scope identity")
    proposal_core = set(re.findall(r"^\| `((?:UX\d{2}-\d{3}|R2-\d{2}-\d{3}))` \|", inputs[R4_PROPOSAL].decode(), re.MULTILINE))
    core = profile["core_control_ids"]
    require(isinstance(core, list) and len(core) == len(set(core)) == 46 and set(core) == proposal_core,
            "R4 core must preserve the exact 46 approved proposal IDs")
    followups = profile["required_followups"]
    require(isinstance(followups, list) and len(followups) == 9, "nine required R4 followups required")
    found, retained = set(), set()
    for item in followups:
        require(isinstance(item, dict) and set(item) == {"id", "owner", "sprint", "required", "control_ids", "dependency_slices"}, "R4 followup exact fields required")
        identifier, controls = item["id"], item["control_ids"]
        require(identifier in R4_FOLLOWUPS and identifier not in found and item["owner"] == "epic-integration/root"
                and item["sprint"] == "S04" and item["required"] is True, "R4 followup identity/required owner changed")
        require(isinstance(controls, list) and len(controls) == len(set(controls))
                and set(controls) == R4_FOLLOWUPS[identifier] and not retained.intersection(controls), "R4 followup controls omitted/duplicated/changed")
        require(item["dependency_slices"] == R4_DEPENDENCIES[identifier], "R4 dependency slices changed")
        found.add(identifier); retained.update(controls)
    original = {row["id"] for key in ("cases", "approved_control_cases") for row in matrix[key] if "S04-01" in row["owning_slices"]}
    require(found == set(R4_FOLLOWUPS) and len(retained) == 11 and not set(core).intersection(retained)
            and len(original) == 57 and set(core) | retained == original, "R4 scope must retain disjoint 46+11 original 57 obligations")
    return set(core), retained


def validate_closure(matrix, scope, repo=None):
    """Row-level closure refusal only; this is not sprint, release or evidence QA."""
    require(scope in {"S04", "EPIC"}, "unknown closure scope")
    root = repo if repo is not None else Path(__file__).resolve().parents[2]
    report = validate(matrix, json.loads((root / "maint/ux/approved_pages.json").read_text()),
                      (root / "docs/UX_FULL_FUNCTIONAL_SLICES.md").read_text(), root)
    rows = matrix["approved_control_cases"]
    require(len(rows) == 403 and len({row["id"] for row in rows}) == 403, "closure requires all403 original approved rows")
    required_followups = set().union(*R4_FOLLOWUPS.values())
    by_id = {row["id"]: row for row in rows}
    require(required_followups <= set(by_id), "closure omits required R4 followup controls")
    required = rows if scope == "EPIC" else [row for row in rows if any(owner.startswith("S04-") for owner in row["owning_slices"]) or row["id"] in required_followups]
    unfinished = [row["id"] for row in required if row["result"]["status"] != "ACCEPTED"]
    require(not unfinished, scope + " closure requires ACCEPTED original controls including all11 required followups: " + ", ".join(unfinished))
    return {**report, "closure_scope": scope, "accepted_row_count": len(required), "closure_claim": "row consistency only; no sprint/release QA or evidence truth inferred"}


def semantic_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def text(value):
    return isinstance(value, str) and bool(value.strip())


def active_work_order(ledger):
    require(ledger.count(WORK_ORDER_START) == ledger.count(WORK_ORDER_END) == 1,
            "exactly one active work order is required")
    block = ledger.split(WORK_ORDER_START, 1)[1].split(WORK_ORDER_END, 1)[0].strip()
    require(block.startswith("```json\n") and block.endswith("\n```"), "active work order must be JSON")
    return json.loads(block[len("```json\n"):-len("\n```")])


def work_order_changed_paths(repo, baseline):
    require(isinstance(baseline, str) and re.fullmatch(r"[0-9a-f]{40,64}", baseline),
            "stable work-order admission baseline required")
    subprocess.run(["git", "merge-base", "--is-ancestor", baseline, "HEAD"], cwd=repo,
                   check=True, capture_output=True)
    changed = subprocess.check_output(["git", "diff", "--name-only", "-z", baseline, "--"], cwd=repo)
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=repo)
    return {path.decode("utf-8") for path in (changed + untracked).split(b"\0") if path}


def validate_accountability(order, outcome_ids, pre_action=False):
    """Declared accountability only; references do not prove their evidence."""
    record = order.get("accountability")
    require(isinstance(record, dict), "functional delivery accountability required")
    owners = {owner for values in order["roles"].values() for owner in values}
    independent = set(order["roles"]["qa"] + order["roles"]["security_review"])
    require(text(record.get("functional_exit")) and record.get("owner") in owners,
            "one functional exit and named accountable owner required")
    require(record.get("elapsed_scope") == "wall_clock" and text(record.get("history_reference")),
            "wall-clock scope and retained attempt history required; no compute-cost inference")

    def elapsed(item):
        status, seconds = item.get("elapsed_status"), item.get("elapsed_seconds")
        require("elapsed_seconds" in item and status in {"MEASURED", "UNKNOWN", "UNMEASURED"}, "explicit elapsed measurement status required")
        require((status == "MEASURED" and type(seconds) in (int, float)
                 and math.isfinite(seconds) and seconds >= 0)
                or (status != "MEASURED" and seconds is None), "elapsed wall-clock measurement contradicts status")

    investigation = record.get("investigation")
    require(isinstance(investigation, dict) and investigation.get("owner") in owners,
            "named bounded investigation required")
    seconds = investigation.get("timebox_seconds")
    require(type(seconds) is int and 1 <= seconds <= 14400, "bounded investigation timebox required")
    started = investigation.get("started_at")
    require(isinstance(started, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", started),
            "investigation started_at UTC required")
    began = datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    elapsed(investigation)
    observed = (datetime.now(timezone.utc) - began).total_seconds() if pre_action else None
    require(observed is None or observed >= 0, "investigation start cannot be in the future")
    if (investigation["elapsed_status"] == "MEASURED" and investigation["elapsed_seconds"] > seconds
            or observed is not None and observed > seconds):
        require(text(investigation.get("overrun_reference")), "expired investigation needs recorded reassessment/disposition")

    attempts = record.get("attempts")
    require(isinstance(attempts, list), "chronological retained attempts required")
    failures, identifiers, last = {}, set(), {}

    def attempt(item, planned=False):
        require(isinstance(item, dict) and text(item.get("id")) and item["id"] not in identifiers,
                "unique attempt ID required")
        boundary, owner = item.get("boundary"), item.get("owner")
        require(text(boundary) and boundary in outcome_ids and owner in owners, "stable functional outcome boundary and owner required")
        require(item.get("scope") in {"FIXTURE", "PRODUCT_DELIVERY"}, "fixture versus product delivery scope required")
        adoption = item.get("adoption")
        require(adoption in {"PRE_ADOPTION", "CURRENT"} and (not planned or adoption == "CURRENT"),
                "explicit attempt adoption scope required")
        if not planned:
            require(item.get("result") in {"PASS", "FAIL", "UNKNOWN"} and text(item.get("reference")),
                    "settled attempt result and retained reference required")
            elapsed(item)
        prior = failures.get(boundary, [])
        if adoption == "CURRENT":
            require(isinstance(item.get("source_revision"), str)
                    and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", item["source_revision"]),
                    "exact current source revision required")
            review = item.get("success_chain_review", {})
            require(isinstance(review, dict) and review.get("reviewer") in independent
                    and review.get("reviewer") != owner and text(review.get("reference"))
                    and isinstance(review.get("covers"), list) and len(review["covers"]) == 3
                    and set(review["covers"]) == {"producer", "cleanup", "consumer"},
                    "independent successful producer/cleanup/consumer review required")
            require(text(item.get("change_reference")), "failed boundary retry needs concrete changed-action reference")
            previous = last.get(boundary)
            if previous is not None and previous["result"] in {"FAIL", "UNKNOWN"}:
                require(item.get("source_revision") != previous.get("source_revision")
                        or item["change_reference"] != previous.get("change_reference"), "unchanged failed-boundary retry refused")
            reassessment = item.get("reassessment")
            if len(prior) >= 2 or reassessment is not None:
                reassessment = reassessment if reassessment is not None else {}
                reviewers = reassessment.get("reviewers", []) if isinstance(reassessment, dict) else []
                require(isinstance(reviewers, list) and all(text(name) for name in reviewers)
                        and len(set(reviewers)) >= 2 and all(name in owners for name in reviewers) and owner in reviewers
                        and any(name != owner and name in independent for name in reviewers)
                        and text(reassessment.get("reference")) and text(reassessment.get("next_action"))
                        and isinstance(reassessment.get("failed_attempt_ids"), list)
                        and len(reassessment["failed_attempt_ids"]) == len(prior)
                        and set(reassessment["failed_attempt_ids"]) == set(prior),
                        "two failed attempts require combined independent reassessment of same functional boundary")
                # A completed combined review acknowledges this window's IDs;
                # history remains intact and new failures start the next window.
                failures[boundary] = []
        identifiers.add(item["id"])
        if not planned:
            last[boundary] = item
            if item["result"] in {"FAIL", "UNKNOWN"}:
                failures.setdefault(boundary, []).append(item["id"])

    current_seen = False
    for item in attempts:
        require(isinstance(item, dict), "chronological retained attempt objects required")
        require(not current_seen or item.get("adoption") != "PRE_ADOPTION",
                "pre-adoption history must precede current attempts")
        current_seen |= item.get("adoption") == "CURRENT"
        attempt(item)
    next_attempt = record.get("next_attempt")
    require(not pre_action or isinstance(next_attempt, dict), "pre-action requires exact next attempt record")
    if next_attempt is not None:
        attempt(next_attempt, planned=True)


def validate_slice_contract(order, outcome_ids, repo):
    """Validate declared design/test structure, not evidence truth or execution."""
    contract = order.get("slice_contract")
    fields = {"version", "slice", "specification", "design", "tests", "engineering_exit", "human_exit"}
    require(isinstance(contract, dict) and set(contract) == fields
            and type(contract.get("version")) is int and contract["version"] == 1,
            "slice contract version1 and exact fields required")
    require(contract["slice"] == order["slice"], "slice contract must match active slice")

    def concrete(value):
        return text(value) and not re.fullmatch(
            r"(?:tbd|todo|pending|none|n/?a|not (?:yet )?specified|(?:control )?(?:works?|pass(?:es)?|success|available|implemented))[.!]?",
            value.strip(), re.IGNORECASE)

    specification = contract["specification"]
    require(isinstance(specification, dict) and set(specification) == {"path", "sha256"}
            and text(specification["path"]) and isinstance(specification["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", specification["sha256"]),
            "slice specification path and exact SHA256 required")
    relative = Path(specification["path"])
    require(not relative.is_absolute() and relative.parts and relative.parts[0] == "docs" and ".." not in relative.parts,
            "slice specification must be a relative docs path without escape")
    root = repo.resolve()
    try:
        target = (root / relative).resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("slice specification missing or outside repository docs") from None
    require(target.is_relative_to(root / "docs") and target.is_file(),
            "slice specification missing or outside repository docs")
    require(hashlib.sha256(target.read_bytes()).hexdigest() == specification["sha256"],
            "slice specification SHA256 mismatch")
    design = contract["design"]
    require(isinstance(design, dict) and set(design) == {"journey", "frontend", "backend", "interfaces",
            "persistence", "security", "failure_recovery"} and all(concrete(value) for value in design.values()),
            "concrete slice design fields required")
    require(all(concrete(contract[key]) for key in ("engineering_exit", "human_exit")),
            "concrete engineering and human exits required")
    tests = contract["tests"]
    require(isinstance(tests, list) and tests, "planned slice tests required")
    owners = {owner for values in order["roles"].values() for owner in values}
    independent = set(order["roles"].get("qa", []) + order["roles"].get("security_review", []))
    identifiers, positive, negative = set(), set(), set()
    nonhuman, human = [], []
    test_fields = {"id", "outcome_ids", "kind", "level", "prerequisites", "action", "expected",
                   "preserved", "owner", "reviewer", "status", "evidence"}
    for test in tests:
        require(isinstance(test, dict) and set(test) == test_fields, "exact planned slice test fields required")
        require(text(test["id"]) and test["id"] not in identifiers, "unique slice test ID required")
        identifiers.add(test["id"])
        mapped = test["outcome_ids"]
        require(isinstance(mapped, list) and mapped and all(text(value) for value in mapped)
                and len(mapped) == len(set(mapped)) and set(mapped) <= outcome_ids,
                "slice test has missing, duplicate or unmapped outcome IDs")
        require(test["kind"] in {"positive", "negative", "recovery", "usability"}
                and test["level"] in {"source", "native", "deployed", "human"}, "slice test kind/level required")
        require(all(concrete(test[key]) for key in ("prerequisites", "action", "expected", "preserved")),
                "concrete slice test prerequisites/action/expected/preserved required")
        require(test["owner"] in owners and test["reviewer"] in independent and test["owner"] != test["reviewer"],
                "named slice test owner and independent reviewer required")
        status, evidence = test["status"], test["evidence"]
        require(status in {"NOT_RUN", "PASS", "FAIL", "PARTIAL"} and isinstance(evidence, list)
                and all(text(reference) for reference in evidence), "slice test status/evidence references required")
        require((status == "NOT_RUN" and not evidence) or (status != "NOT_RUN" and evidence),
                "NOT_RUN cannot carry execution evidence; PASS/FAIL/PARTIAL require retained evidence")
        if test["level"] != "human":
            if test["kind"] == "positive":
                positive.update(mapped)
            if test["kind"] == "negative":
                negative.update(mapped)
        (human if test["level"] == "human" else nonhuman).append(test)
    require(positive == negative == outcome_ids, "positive and negative nonhuman slice test coverage required for every outcome")
    require(nonhuman and human, "planned engineering and human slice tests required")
    state = order["state"]
    if state in {"ENGINEERING_COMPLETE", "UAT_READY", "ACCEPTED"}:
        require(all(test["status"] == "PASS" for test in nonhuman),
                "required nonhuman slice tests must PASS before engineering closure or UAT readiness")
    if state == "ACCEPTED":
        require(all(test["status"] == "PASS" for test in human), "required human slice tests must PASS before acceptance")
        acceptance = order.get("human_acceptance", {})
        require(acceptance.get("status") == "PASS" and text(acceptance.get("reference")),
                "existing human acceptance flag and evidence required")


def validate_execution_contract(order, outcome_ids, pre_action=False, attempt_id=None):
    """Bind the declared S04-02 action, not evidence truth or arbitrary shell use."""
    contract = order.get("execution_contract")
    require(isinstance(contract, dict) and set(contract) == {"version", "environment", "gaps", "recipes", "budget", "planned_action"}
            and type(contract.get("version")) is int and contract["version"] == 1,
            "S04-02 execution contract version1 and exact fields required")
    now = datetime.now(timezone.utc)

    def utc(value):
        require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value),
                "execution contract requires explicit UTC times")
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    def paths(values):
        require(isinstance(values, list) and values and len(values) == len(set(values))
                and all(text(value) and value in order["allowed_paths"] for value in values),
                "execution recipe/gap paths must stay within active allowed paths")

    def evidence(value, required=False):
        if value is None:
            require(not required, "PASS execution authority requires pinned metadata evidence")
            return
        require(isinstance(value, dict) and set(value) == {"path", "sha256"} and text(value["path"])
                and isinstance(value["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]),
                "execution metadata evidence requires path and exact SHA256")
        if pre_action:
            target = Path(value["path"])
            require(target.is_absolute() and target.is_file() and not target.is_symlink(),
                    "execution metadata evidence must be an existing absolute nonsymlink file")
            require(hashlib.sha256(target.read_bytes()).hexdigest() == value["sha256"],
                    "execution metadata evidence SHA256 mismatch")

    environments = contract["environment"]
    require(isinstance(environments, list) and environments, "named execution environments required")
    env = {}
    for item in environments:
        require(isinstance(item, dict) and set(item) == {"id", "host", "address", "status", "software", "observed_at", "evidence"}
                and text(item["id"]) and item["id"] not in env and item["id"] != "local"
                and text(item["host"]) and text(item["address"]) and item["status"] in {"PASS", "PENDING"},
                "unique execution environment identity/status required")
        software = item["software"]
        require(isinstance(software, dict) and all(text(name) and text(version) for name, version in software.items()),
                "execution software facts must be explicit observed versions")
        if item["observed_at"] is not None:
            observed = utc(item["observed_at"])
            require(not pre_action or observed <= now, "execution observation cannot be in the future")
        require(item["status"] != "PASS" or software and item["observed_at"] is not None,
                "PASS environment requires observed software and timestamp")
        evidence(item["evidence"], item["status"] == "PASS")
        env[item["id"]] = item

    test_ids = {test["id"] for test in order["slice_contract"]["tests"]}
    gaps, recipes = {}, {}
    require(isinstance(contract["gaps"], list) and contract["gaps"], "demonstrated execution gaps required")
    for item in contract["gaps"]:
        require(isinstance(item, dict) and set(item) == {"id", "outcome_ids", "test_ids", "allowed_paths", "reference"}
                and text(item["id"]) and item["id"] not in gaps and text(item["reference"]),
                "unique demonstrated gap and retained reference required")
        for key, permitted in (("outcome_ids", outcome_ids), ("test_ids", test_ids)):
            values = item[key]
            require(isinstance(values, list) and values and len(values) == len(set(values)) and set(values) <= permitted,
                    "execution gap must link existing outcomes and slice tests")
        paths(item["allowed_paths"])
        gaps[item["id"]] = item
    require(isinstance(contract["recipes"], list) and contract["recipes"], "fixed execution recipes required")
    for item in contract["recipes"]:
        require(isinstance(item, dict) and set(item) == {"id", "kind", "environment_ids", "gap_ids", "test_ids", "allowed_paths", "operations", "expected", "prerequisites"}
                and text(item["id"]) and item["id"] not in recipes
                and item["kind"] in {"SOURCE", "DISCOVERY", "NATIVE", "INSTALL"} and text(item["expected"]),
                "unique fixed execution recipe/kind and expected result required")
        for key, permitted, nonempty in (("environment_ids", set(env), item["kind"] != "SOURCE"),
                ("gap_ids", set(gaps), True), ("test_ids", test_ids, True)):
            values = item[key]
            require(isinstance(values, list) and (values or not nonempty)
                    and len(values) == len(set(values)) and set(values) <= permitted,
                    "execution recipe has missing or unplanned environment/gap/test linkage")
        paths(item["allowed_paths"])
        mapped = [gaps[identifier] for identifier in item["gap_ids"]]
        require(set(item["allowed_paths"]) <= set().union(*(set(gap["allowed_paths"]) for gap in mapped))
                and set(item["test_ids"]) <= set().union(*(set(gap["test_ids"]) for gap in mapped)),
                "execution recipe exceeds its demonstrated gaps")
        require(isinstance(item["operations"], list) and item["operations"], "fixed operation commands required")
        for operation in item["operations"]:
            require(isinstance(operation, dict) and set(operation) == {"target_id", "program", "arguments", "privilege"}
                    and operation["target_id"] in {"local", *item["environment_ids"]}
                    and text(operation["program"]) and Path(operation["program"]).is_absolute()
                    and ".." not in Path(operation["program"]).parts
                    and operation["privilege"] in {"user", "root"}
                    and isinstance(operation["arguments"], list)
                    and all(isinstance(arg, str) and not any(char in arg for char in "\0\r\n") for arg in operation["arguments"]),
                    "fixed operation requires exact target, absolute program, arguments and privilege")
        prerequisites = item["prerequisites"]
        require(isinstance(prerequisites, list), "explicit execution prerequisites required")
        seen = set()
        for prerequisite in prerequisites:
            require(isinstance(prerequisite, dict) and set(prerequisite) == {"id", "status", "evidence"}
                    and text(prerequisite["id"]) and prerequisite["id"] not in seen
                    and prerequisite["status"] in {"PASS", "PENDING", "FAIL", "UNKNOWN"},
                    "unique execution prerequisite/status required")
            evidence(prerequisite["evidence"], prerequisite["status"] == "PASS")
            seen.add(prerequisite["id"])
        recipes[item["id"]] = item

    budget = contract["budget"]
    owners = {owner for values in order["roles"].values() for owner in values}
    require(isinstance(budget, dict) and set(budget) == {"objective", "owner", "started_at", "deadline_at", "allowance_seconds", "consumed_seconds", "history_reference"}
            and budget["objective"] == "S04-02" and budget["owner"] in owners and text(budget["history_reference"]),
            "stable slice objective, cumulative budget owner and retained history required")
    started, deadline = utc(budget["started_at"]), utc(budget["deadline_at"])
    allowance, consumed = budget["allowance_seconds"], budget["consumed_seconds"]
    require(type(allowance) is int and allowance > 0 and type(consumed) in (int, float)
            and math.isfinite(consumed) and consumed >= 0 and deadline > started,
            "valid historical execution accounting required")
    action = contract["planned_action"]
    require(action is not None or not pre_action, "pre-action requires a planned execution action")
    if action is None:
        return
    action_fields = {"attempt_id", "recipe_id", "source_revision", "not_after", "max_seconds"}
    require(isinstance(action, dict) and action_fields <= set(action)
            and set(action) <= action_fields | {"operator_expires_at"}
            and text(action["attempt_id"]) and action["recipe_id"] in recipes
            and isinstance(action["source_revision"], str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", action["source_revision"])
            and type(action["max_seconds"]) is int and action["max_seconds"] > 0,
            "exact planned execution action, recipe, source and bounded duration required")
    # These clocks remain historical accounting. Direct operator authority is
    # not invalidated merely because wall-clock or idle time passed.
    utc(action["not_after"])
    operator_expiry = utc(action["operator_expires_at"]) if "operator_expires_at" in action else None
    if pre_action:
        require(operator_expiry is None
                or (operator_expiry - datetime.now(timezone.utc)).total_seconds() >= action["max_seconds"],
                "explicit operator expiration cannot accommodate action and cleanup")
        require(order["state"] == "IN_PROGRESS", "pre-action requires IN_PROGRESS; paused or blocked dispatch refused")
        require(text(attempt_id) and attempt_id == action["attempt_id"], "pre-action requires matching --attempt-id")
        next_attempt = order["accountability"].get("next_attempt", {})
        require(isinstance(next_attempt, dict) and next_attempt.get("id") == attempt_id
                and next_attempt.get("source_revision") == action["source_revision"],
                "execution action must match exact accountability attempt and source")
        recipe = recipes[action["recipe_id"]]
        require(all(item["status"] == "PASS" for item in recipe["prerequisites"]),
                "planned execution prerequisites have not passed")
        if recipe["kind"] in {"NATIVE", "INSTALL"}:
            require(all(env[identifier]["status"] == "PASS" for identifier in recipe["environment_ids"]),
                    "native/install requires authoritative PASS environment metadata")


def validate_pre_action(order, attempt_id):
    """Check only the dispatch facts this declaration can mechanically prove."""
    require(isinstance(order, dict) and order.get("version") == 1 and order.get("slice") == "S04-02",
            "pre-action requires the active S04-02 work order")
    require(order.get("state") == "IN_PROGRESS",
            "pre-action requires IN_PROGRESS; paused or blocked dispatch refused")
    contract = order.get("execution_contract")
    require(isinstance(contract, dict) and contract.get("version") == 1,
            "pre-action requires execution contract version1")
    action = contract.get("planned_action")
    required = {"attempt_id", "recipe_id", "source_revision", "not_after", "max_seconds"}
    require(isinstance(action, dict) and required <= set(action)
            and set(action) <= required | {"operator_expires_at"}
            and text(action.get("attempt_id")) and action["attempt_id"] == attempt_id
            and isinstance(action.get("source_revision"), str)
            and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", action["source_revision"])
            and type(action.get("max_seconds")) is int and action["max_seconds"] > 0,
            "pre-action requires matching bounded action and exact source")

    # not_after is retained historical accounting. Only an expiry explicitly
    # attributed to the operator is an admission condition.
    if "operator_expires_at" in action:
        value = action["operator_expires_at"]
        require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value),
                "explicit operator expiration must be UTC")
        expiry = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        require((expiry - datetime.now(timezone.utc)).total_seconds() >= action["max_seconds"],
                "explicit operator expiration cannot accommodate action and cleanup")

    next_attempt = order.get("accountability", {}).get("next_attempt")
    require(isinstance(next_attempt, dict)
            and next_attempt.get("id") == action["attempt_id"]
            and next_attempt.get("source_revision") == action["source_revision"],
            "planned action must match the exact next attempt and source")

    environments = contract.get("environment")
    require(isinstance(environments, list), "pre-action requires declared environments")
    environment_status = {}
    for item in environments:
        require(isinstance(item, dict) and text(item.get("id"))
                and item["id"] not in environment_status
                and item.get("status") in {"PASS", "PENDING"},
                "pre-action environment identity/status invalid")
        environment_status[item["id"]] = item["status"]

    recipes = contract.get("recipes")
    require(isinstance(recipes, list), "pre-action requires declared recipes")
    matches = [recipe for recipe in recipes
               if isinstance(recipe, dict) and recipe.get("id") == action.get("recipe_id")]
    require(len(matches) == 1, "pre-action recipe is missing or ambiguous")
    recipe = matches[0]
    require(recipe.get("kind") in {"SOURCE", "DISCOVERY", "NATIVE", "INSTALL"}
            and isinstance(recipe.get("environment_ids"), list)
            and len(recipe["environment_ids"]) == len(set(recipe["environment_ids"]))
            and set(recipe["environment_ids"]) <= set(environment_status),
            "pre-action recipe kind or environments invalid")
    operations = recipe.get("operations")
    require(isinstance(operations, list) and operations, "pre-action requires fixed operations")
    targets = {"local", *recipe["environment_ids"]}
    for operation in operations:
        require(isinstance(operation, dict)
                and set(operation) == {"target_id", "program", "arguments", "privilege"}
                and operation["target_id"] in targets
                and text(operation["program"]) and Path(operation["program"]).is_absolute()
                and ".." not in Path(operation["program"]).parts
                and operation["privilege"] in {"user", "root"}
                and isinstance(operation["arguments"], list)
                and all(isinstance(value, str) and not any(char in value for char in "\0\r\n")
                        for value in operation["arguments"]),
                "pre-action operation must bind exact target, program and arguments")
    prerequisites = recipe.get("prerequisites")
    require(isinstance(prerequisites, list)
            and all(isinstance(item, dict) and item.get("status") == "PASS" for item in prerequisites),
            "pre-action recipe prerequisites have not passed")
    if recipe["kind"] in {"NATIVE", "INSTALL"}:
        require(recipe["environment_ids"]
                and all(environment_status[name] == "PASS" for name in recipe["environment_ids"]),
                "native/install requires PASS target environment")
    return {"active_slice": "S04-02", "state": order["state"],
            "attempt_id": action["attempt_id"],
            "claim": "planned-action consistency only; not authority, evidence truth or product acceptance"}


def validate_work_order(order, matrix, catalogue, changed_paths, pre_action=False, repo=None, attempt_id=None):
    require(isinstance(order, dict) and order.get("version") == 1, "invalid active work order")
    slices = dict(re.findall(r"^\| (S\d{2}-\d{2}) \| ([^|]+) \|", catalogue, re.MULTILINE))
    parent = order.get("slice")
    require(parent in slices and order.get("original_requirement") == slices[parent].strip(),
            "active scope must preserve an original slice requirement")
    expected = {row["id"] for key in ("cases", "approved_control_cases") for row in matrix[key]
                if parent in row["owning_slices"]}
    revision = order.get("scope_revision")
    if revision is not None:
        require(revision == "R4" and parent == "S04-01", "unapproved work-order scope revision")
        expected, _ = r4_scope(matrix, repo if repo is not None else Path(__file__).resolve().parents[2])
    roles = order.get("roles")
    require(isinstance(roles, dict) and set(roles) == DELIVERY_ROLES, "six named role owners required")
    require(all(isinstance(owners, list) and owners and all(text(owner) for owner in owners)
                for owners in roles.values()), "named role owner missing")
    require(text(order.get("integration_owner")) and text(order.get("next_action")), "integration owner and next action required")
    allowed = order.get("allowed_paths")
    require(isinstance(allowed, list) and allowed and all(text(path) and not Path(path).is_absolute()
            and ".." not in Path(path).parts and not any(c in path for c in "*?[]") for path in allowed),
            "explicit repository-relative allowed paths required")
    require(not set(changed_paths) - set(allowed), "changed paths outside active work order: " +
            ", ".join(sorted(set(changed_paths) - set(allowed))))
    state = order.get("state")
    require(state in {"IN_PROGRESS", "BLOCKED", "PAUSED", "ENGINEERING_COMPLETE", "UAT_READY", "ACCEPTED"},
            "invalid work-order state; checkpoints cannot park or close work")
    require(not pre_action or state == "IN_PROGRESS", "pre-action requires IN_PROGRESS; paused or blocked dispatch refused")
    if parent == "S11-04" and state in {"ENGINEERING_COMPLETE", "UAT_READY", "ACCEPTED"}:
        validate_closure(matrix, "EPIC", repo)
    if state == "PAUSED":
        directive = order.get("operator_pause", {})
        require(directive.get("actor") == "operator" and text(directive.get("reference")), "only explicit operator direction may pause work")
    if state == "BLOCKED":
        require(text(order.get("blocker")) and text(order.get("independent_next_action")),
                "concrete blocker and independent next action required")
    outcomes = order.get("outcomes")
    require(isinstance(outcomes, list) and outcomes, "functional outcomes required")
    ids = [item.get("id") for item in outcomes if isinstance(item, dict)]
    require(len(ids) == len(outcomes) and all(text(item) for item in ids) and len(set(ids)) == len(ids), "unique outcome IDs required")
    covered = set()
    all_pass = True
    for outcome in outcomes:
        require(text(outcome.get("owner")) and any(outcome["owner"] in owners for owners in roles.values()), "named outcome owner required")
        require(all(text(outcome.get(key)) for key in ("frontend_backend_outcome", "essential_qa", "next_action")), "concrete outcome, QA and next action required")
        obligations = outcome.get("requirement_ids")
        require(isinstance(obligations, list) and obligations and set(obligations) <= expected, "outcome contains unmapped scope")
        if revision == "R4":
            require(len(obligations) == len(set(obligations)) and not covered.intersection(obligations), "duplicate R4 work-order obligation")
        covered.update(obligations)
        dependencies = outcome.get("dependencies")
        require(isinstance(dependencies, list), "technical dependencies required (empty allowed)")
        for dependency in dependencies:
            require(isinstance(dependency, dict) and all(text(dependency.get(key)) for key in ("owner", "condition", "next_action"))
                    and dependency.get("status") in {"PASS", "PENDING", "FAIL", "UNKNOWN"}, "named concrete dependency required")
        stages = outcome.get("stages")
        require(isinstance(stages, dict) and set(stages) == DELIVERY_STAGES and
                all(status in {"PASS", "PENDING", "FAIL", "UNKNOWN"} for status in stages.values()), "required delivery stages must remain explicit")
        evidence = outcome.get("evidence")
        require(isinstance(evidence, list) and all(isinstance(item, dict) and item.get("stage") in DELIVERY_STAGES
                and text(item.get("reference")) for item in evidence), "stage evidence references required")
        require(all(status != "PASS" or any(item["stage"] == stage for item in evidence)
                    for stage, status in stages.items()), "PASS stage lacks scoped evidence")
        all_pass &= all(status == "PASS" for status in stages.values()) and all(item["status"] == "PASS" for item in dependencies)
    require(covered == expected, "all original mapped obligations must remain in active scope")
    validate_accountability(order, set(ids), pre_action)
    if state in {"ENGINEERING_COMPLETE", "UAT_READY", "ACCEPTED"}:
        require(all_pass, "unfinished or failed required scope cannot close or become UAT ready")
        if revision == "R4":
            root = repo if repo is not None else Path(__file__).resolve().parents[2]
            validate(matrix, json.loads((root / "maint/ux/approved_pages.json").read_text()), catalogue, root)
            permitted = {"ACCEPTED"} if state == "ACCEPTED" else {"QA_VERIFIED", "UAT_READY", "ACCEPTED"}
            require(all(row["result"]["status"] in permitted for row in matrix["approved_control_cases"] if row["id"] in expected),
                    "R4 core approved-control results must meet the actual closure stage; PARTIAL/BLOCKED cannot close")
    human = order.get("human_acceptance", {})
    require(human.get("status") in {"PENDING", "PASS", "FAIL"}, "human acceptance must remain separate")
    if state == "ACCEPTED":
        require(human["status"] == "PASS" and text(human.get("reference")), "human acceptance evidence required for accepted slice")
    validate_slice_contract(order, set(ids), repo if repo is not None else Path(__file__).resolve().parents[2])
    if parent == "S04-02":
        validate_execution_contract(order, set(ids), pre_action, attempt_id)
    return {"active_slice": parent, "required_obligations": len(expected), "state": state,
            "claim": "declaration/scope consistency only; no evidence truth or functional acceptance inferred"}


def validate(matrix, inventory, catalogue, repo):
    require(isinstance(matrix, dict) and isinstance(inventory, dict), "matrix/inventory must be objects")
    legacy = matrix.get("cases")
    require(isinstance(legacy, list) and len(legacy) == 110, "110 legacy cases must remain")
    require(semantic_hash(legacy) == LEGACY_SHA256, "legacy case content/status/evidence changed")
    legacy_ids = {row["id"] for row in legacy}
    slices = set(re.findall(r"^\| (S\d{2}-\d{2}) \|", catalogue, re.MULTILINE))
    expected = {}
    pages = inventory.get("pages")
    require(isinstance(pages, list) and len(pages) == 27, "27 approved pages required")
    for page in pages:
        for control in page["controls"]:
            require(control["id"] not in expected, "duplicate approved inventory ID")
            expected[control["id"]] = (page, control)
    require(len(expected) == 403, "403 exact approved controls required")
    rows = matrix.get("approved_control_cases")
    require(isinstance(rows, list), "approved_control_cases must be a list")
    ids = [row.get("id") for row in rows if isinstance(row, dict)]
    require(len(ids) == len(rows) and all(text(item) for item in ids), "case IDs must be strings")
    require(len(ids) == len(set(ids)), "duplicate approved case ID")
    require(set(ids) == set(expected), "missing or unmapped approved case ID")
    for row in rows:
        identifier = row["id"]
        page, control = expected[identifier]
        require(row.get("page_id") == page["id"], identifier + ": wrong page")
        require(row.get("reference_control") == control["label"], identifier + ": altered reference label")
        owners = row.get("owning_slices")
        require(isinstance(owners, list) and owners and all(text(owner) for owner in owners), identifier + ": missing owners")
        require(len(owners) == len(set(owners)) and set(owners) <= slices, identifier + ": unknown/duplicate owner")
        require(bool(set(owners) & set(page["owning_slices"])), identifier + ": no approved page owner")
        for name, fields in (("positive", ("setup", "action", "expected")), ("negative", ("setup", "action", "expected", "preserved"))):
            scenario = row.get(name)
            require(isinstance(scenario, dict) and set(scenario) == set(fields), identifier + ": invalid " + name + " fields")
            require(all(text(scenario[field]) for field in fields), identifier + ": empty " + name + " expectation")
            outcome = scenario["expected"].strip()
            require(outcome != control["label"] and not re.fullmatch(r"(?:control )?(?:works?|passes?|success|available|implemented)[.!]?", outcome, re.IGNORECASE), identifier + ": generic expectation")
        links = row.get("legacy_case_ids")
        require(isinstance(links, list) and all(text(item) for item in links) and len(links) == len(set(links)) and set(links) <= legacy_ids, identifier + ": invalid legacy links")
        pointers = row.get("pointers")
        require(isinstance(pointers, list) and pointers, identifier + ": missing provenance pointers")
        for pointer in pointers:
            require(isinstance(pointer, dict) and set(pointer) == {"kind", "path", "scope"}, identifier + ": invalid pointer fields")
            require(text(pointer["kind"]) and pointer["kind"] in POINTER_KINDS and text(pointer["path"]) and text(pointer["scope"]), identifier + ": invalid pointer meaning")
            if pointer["kind"] in {"source", "test", "candidate_source", "candidate_test"}:
                path = (repo / pointer["path"]).resolve()
                require(path.is_relative_to(repo.resolve()) and path.is_file(), identifier + ": source/test pointer missing or outside repository")
        result = row.get("result")
        require(isinstance(result, dict) and set(result) == {"status", "executed", "evidence"}, identifier + ": invalid result fields")
        require(type(result["executed"]) is bool and isinstance(result["evidence"], list), identifier + ": invalid execution/evidence type")
        if result["status"] == "NOT_YET_ACCEPTED":
            require(not result["executed"] and not result["evidence"], identifier + ": planned case cannot claim execution")
        elif result["status"] == "BLOCKED":
            require(not result["executed"] and result["evidence"], identifier + ": blocked case requires non-execution evidence")
            for evidence in result["evidence"]:
                require(isinstance(evidence, dict) and set(evidence) == {"kind", "path", "scope"}, identifier + ": invalid blocked evidence")
                require(text(evidence["kind"]) and evidence["kind"] in {"dependency", "gap"} and text(evidence["path"]) and text(evidence["scope"]), identifier + ": blocked evidence must describe a dependency or gap")
        else:
            require(text(result["status"]) and result["status"] in PROGRESS_STATUSES and result["executed"] and result["evidence"], identifier + ": false or unsupported progress claim")
            for evidence in result["evidence"]:
                require(isinstance(evidence, dict) and set(evidence) == {"kind", "path", "scope"}, identifier + ": invalid executed evidence")
                require(text(evidence["kind"]) and evidence["kind"] in EXECUTED_KINDS and text(evidence["path"]) and text(evidence["scope"]), identifier + ": planned pointer is not executed evidence")
            require(result["status"] != "ACCEPTED" or any(item["kind"] == "human_uat" for item in result["evidence"]), identifier + ": human acceptance reference required")
    return {"legacy_cases": len(legacy), "approved_pages": len(pages), "approved_cases": len(rows), "claim": "traceability only; evidence truth and workflow success require independent review"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--work-order-only", action="store_true")
    parser.add_argument("--pre-action", action="store_true", help="check planned action/source/recipe consistency before dispatch; not an authority decision")
    parser.add_argument("--attempt-id", help="bind S04-02 pre-action to its exact planned attempt")
    parser.add_argument("--closure-scope", choices=("S04", "EPIC"), help="require accepted original rows, including required R4 followups; not a sprint/release QA certificate")
    args = parser.parse_args()
    repo = args.repo.resolve()
    try:
        order = active_work_order((repo / "docs/UX_EXECUTION_LEDGER.md").read_text())
        if args.pre_action:
            require(args.closure_scope is None, "pre-action cannot make a closure claim")
            result = validate_pre_action(order, args.attempt_id)
        else:
            matrix = json.loads((repo / "maint/ux/acceptance.json").read_text())
            catalogue = (repo / "docs/UX_FULL_FUNCTIONAL_SLICES.md").read_text()
            result = validate_work_order(order, matrix, catalogue,
                    work_order_changed_paths(repo, order.get("source_baseline")), repo=repo)
            if args.closure_scope:
                result = {**result, **validate_closure(matrix, args.closure_scope, repo)}
            elif not args.work_order_only:
                result = {**result, **validate(matrix, json.loads((repo / "maint/ux/approved_pages.json").read_text()), catalogue, repo)}
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        print("acceptance traceability refused: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
