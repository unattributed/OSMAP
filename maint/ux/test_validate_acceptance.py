#!/usr/bin/env python3
"""Counterexamples for R2 traceability, not tests of the mail application."""

import copy
import json
from pathlib import Path
import unittest

from validate_acceptance import validate


REPO = Path(__file__).resolve().parents[2]


class TraceabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = json.loads((REPO / "maint/ux/acceptance.json").read_text())
        cls.pending_matrix = copy.deepcopy(cls.matrix)
        for row in cls.pending_matrix["approved_control_cases"]:
            row["result"] = {"status": "NOT_YET_ACCEPTED", "executed": False, "evidence": []}
        cls.inventory = json.loads((REPO / "maint/ux/approved_pages.json").read_text())
        cls.catalogue = (REPO / "docs/UX_FULL_FUNCTIONAL_SLICES.md").read_text()

    def run_check(self, matrix):
        return validate(matrix, self.inventory, self.catalogue, REPO)

    def refused(self, mutate, message):
        candidate = copy.deepcopy(self.pending_matrix)
        mutate(candidate)
        with self.assertRaisesRegex(ValueError, message):
            self.run_check(candidate)

    def test_real_design_is_complete_but_not_execution(self):
        report = self.run_check(self.matrix)
        self.assertEqual((report["legacy_cases"], report["approved_cases"]), (110, 403))

    def test_evidence_linked_progress_remains_possible(self):
        candidate = copy.deepcopy(self.pending_matrix)
        candidate["approved_control_cases"][0]["result"] = {
            "status": "IMPLEMENTED_VERIFIED_LOCAL", "executed": True,
            "evidence": [{"kind": "source_execution", "path": "synthetic-test-reference", "scope": "validator counterexample only; not an application result"}],
        }
        self.assertEqual(self.run_check(candidate)["approved_cases"], 403)

    def test_missing_control(self):
        self.refused(lambda m: m["approved_control_cases"].pop(), "missing or unmapped")

    def test_duplicate_control(self):
        self.refused(lambda m: m["approved_control_cases"].append(copy.deepcopy(m["approved_control_cases"][0])), "duplicate approved")

    def test_extra_control(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(id="R2-99-999"), "missing or unmapped")

    def test_wrong_page(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(page_id="PAGE-27"), "wrong page")

    def test_changed_requirement(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(reference_control="different requirement"), "altered reference")

    def test_unknown_slice(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(owning_slices=["S99-99"]), "unknown/duplicate owner")

    def test_valid_but_unrelated_slice(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(owning_slices=["S11-04"]), "no approved page owner")

    def test_missing_negative_preservation(self):
        self.refused(lambda m: m["approved_control_cases"][0]["negative"].pop("preserved"), "invalid negative fields")

    def test_generic_positive(self):
        self.refused(lambda m: m["approved_control_cases"][0]["positive"].update(expected="Control works."), "generic expectation")

    def test_unknown_legacy_link(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(legacy_case_ids=["UX00-999"]), "invalid legacy links")

    def test_untyped_pointer(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(pointers=["src/http_ui.rs"]), "invalid pointer fields")

    def test_source_pointer_outside_repository(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(pointers=[{"kind": "source", "path": "../not-a-source-file", "scope": "inspected source"}]), "outside repository")

    def test_false_pass_on_unexecuted_case(self):
        self.refused(lambda m: m["approved_control_cases"][0]["result"].update(status="IMPLEMENTED_VERIFIED_LOCAL"), "false or unsupported progress")

    def test_planned_pointer_cannot_be_executed_evidence(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(result={"status": "IMPLEMENTED_VERIFIED_LOCAL", "executed": True, "evidence": [{"kind": "planned_test", "path": "future-test", "scope": "not run"}]}), "planned pointer")

    def test_source_execution_is_not_human_acceptance(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(result={"status": "ACCEPTED", "executed": True, "evidence": [{"kind": "source_execution", "path": "retained-test-result", "scope": "source only"}]}), "human acceptance reference")

    def test_claimed_execution_with_planned_status(self):
        self.refused(lambda m: m["approved_control_cases"][0]["result"].update(executed=True), "planned case cannot")

    def test_legacy_result_cannot_be_rewritten(self):
        self.refused(lambda m: m["cases"][0].update(status="NOT_YET_ACCEPTED"), "legacy case content")


if __name__ == "__main__":
    unittest.main()
