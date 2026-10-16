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


def validate_work_order(order, matrix, catalogue, changed_paths, pre_action=False):
    require(isinstance(order, dict) and order.get("version") == 1, "invalid active work order")
    slices = dict(re.findall(r"^\| (S\d{2}-\d{2}) \| ([^|]+) \|", catalogue, re.MULTILINE))
    parent = order.get("slice")
    require(parent in slices and order.get("original_requirement") == slices[parent].strip(),
            "active scope must preserve an original slice requirement")
    expected = {row["id"] for key in ("cases", "approved_control_cases") for row in matrix[key]
                if parent in row["owning_slices"]}
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
    human = order.get("human_acceptance", {})
    require(human.get("status") in {"PENDING", "PASS", "FAIL"}, "human acceptance must remain separate")
    if state == "ACCEPTED":
        require(human["status"] == "PASS" and text(human.get("reference")), "human acceptance evidence required for accepted slice")
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
    parser.add_argument("--pre-action", action="store_true", help="validate the recorded next expensive/native attempt before dispatch")
    args = parser.parse_args()
    repo = args.repo.resolve()
    try:
        matrix = json.loads((repo / "maint/ux/acceptance.json").read_text())
        catalogue = (repo / "docs/UX_FULL_FUNCTIONAL_SLICES.md").read_text()
        order = active_work_order((repo / "docs/UX_EXECUTION_LEDGER.md").read_text())
        result = validate_work_order(order, matrix, catalogue, work_order_changed_paths(repo, order.get("source_baseline")), pre_action=args.pre_action)
        if not args.work_order_only:
            result = {**result, **validate(matrix, json.loads((repo / "maint/ux/approved_pages.json").read_text()), catalogue, repo)}
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        print("acceptance traceability refused: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
