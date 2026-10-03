#!/usr/bin/env python3
"""Validate R2 case traceability; this does not certify workflow execution."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


LEGACY_SHA256 = "987e7384fd6b698f783f95bfe6e48b57d05fa0fbd56500dfc110a83ee72abefd"
POINTER_KINDS = {"source", "test", "candidate_source", "candidate_test", "planned_test", "fixture", "baseline", "gap", "dependency", "legacy_evidence"}
PROGRESS_STATUSES = {"PARTIALLY_IMPLEMENTED", "PARTIALLY_VERIFIED", "IMPLEMENTED_VERIFIED_LOCAL", "QA_VERIFIED", "UAT_READY", "ACCEPTED"}
EXECUTED_KINDS = {"source_execution", "native_execution", "qa_execution", "human_uat"}


def semantic_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def text(value):
    return isinstance(value, str) and bool(value.strip())


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
    args = parser.parse_args()
    repo = args.repo.resolve()
    try:
        result = validate(json.loads((repo / "maint/ux/acceptance.json").read_text()), json.loads((repo / "maint/ux/approved_pages.json").read_text()), (repo / "docs/UX_FULL_FUNCTIONAL_SLICES.md").read_text(), repo)
    except (ValueError, KeyError, TypeError, OSError) as error:
        print("acceptance traceability refused: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
