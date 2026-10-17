#!/usr/bin/env python3
"""Counterexamples for R2 traceability, not tests of the mail application."""

import copy
import hashlib
import tempfile
import json
from pathlib import Path
import unittest
from datetime import datetime, timedelta, timezone

from validate_acceptance import (active_work_order, validate, validate_work_order, validate_slice_contract,
    r4_scope, validate_closure, R4_PROFILE, R4_SUPPLEMENT, R4_PROPOSAL, R4_FOLLOWUPS)


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

    def test_executed_failure_is_recordable_without_acceptance(self):
        candidate = copy.deepcopy(self.pending_matrix)
        candidate["approved_control_cases"][0]["result"] = {
            "status": "FAILED", "executed": True,
            "evidence": [{"kind": "native_execution", "path": "synthetic-failed-result", "scope": "validator counterexample only; required assertion failed"}],
        }
        self.assertEqual(self.run_check(candidate)["approved_cases"], 403)
        candidate["approved_control_cases"][0]["result"]["executed"] = False
        with self.assertRaisesRegex(ValueError, "false or unsupported progress"):
            self.run_check(candidate)

    def test_failure_cannot_use_planned_test_as_execution(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(result={"status": "FAILED", "executed": True, "evidence": [{"kind": "planned_test", "path": "future-test", "scope": "not run"}]}), "planned pointer")

    def test_blocked_dependency_is_recordable_without_execution(self):
        candidate = copy.deepcopy(self.pending_matrix)
        candidate["approved_control_cases"][0]["result"] = {
            "status": "BLOCKED", "executed": False,
            "evidence": [{"kind": "dependency", "path": "synthetic-dependency-reference", "scope": "validator counterexample only; prerequisite missing"}],
        }
        self.assertEqual(self.run_check(candidate)["approved_cases"], 403)
        candidate["approved_control_cases"][0]["result"]["executed"] = True
        with self.assertRaisesRegex(ValueError, "blocked case requires non-execution"):
            self.run_check(candidate)

    def test_blocked_case_cannot_hide_an_executed_result(self):
        self.refused(lambda m: m["approved_control_cases"][0].update(result={"status": "BLOCKED", "executed": False, "evidence": [{"kind": "native_execution", "path": "actual-result", "scope": "must retain actual execution as FAILED or partial"}]}), "blocked evidence must describe")


class WorkOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.order = active_work_order((REPO / "docs/UX_EXECUTION_LEDGER.md").read_text())
        cls.matrix = json.loads((REPO / "maint/ux/acceptance.json").read_text())
        cls.catalogue = (REPO / "docs/UX_FULL_FUNCTIONAL_SLICES.md").read_text()

    def check(self, order, changed=()):
        return validate_work_order(order, self.matrix, self.catalogue, changed)

    def test_valid_active_work_order_does_not_claim_human_acceptance(self):
        order = copy.deepcopy(self.order)
        order["state"] = "IN_PROGRESS"
        order["human_acceptance"] = {"status": "PENDING"}
        self.assertEqual(self.check(order)["active_slice"], order["slice"])

    def test_invalid_scope_and_undeclared_file_are_refused(self):
        order = copy.deepcopy(self.order)
        order["slice"] = "S99-99"
        with self.assertRaisesRegex(ValueError, "original slice"):
            self.check(order)
        with self.assertRaisesRegex(ValueError, "outside active work order"):
            self.check(self.order, ["src/unassigned-product-change.rs"])
        order = copy.deepcopy(self.order)
        missing = order["outcomes"][0]["requirement_ids"][0]
        for outcome in order["outcomes"]:
            outcome["requirement_ids"] = [identifier for identifier in outcome["requirement_ids"] if identifier != missing]
        order["outcomes"] = [outcome for outcome in order["outcomes"] if outcome["requirement_ids"]]
        with self.assertRaisesRegex(ValueError, "all original mapped obligations"):
            self.check(order)

    def test_unfinished_or_failed_scope_cannot_close(self):
        for state in ("ENGINEERING_COMPLETE", "UAT_READY", "ACCEPTED"):
            order = copy.deepcopy(self.order)
            order["state"] = state
            order["outcomes"][0]["stages"]["deployed_qa"] = "FAIL"
            with self.subTest(state=state), self.assertRaisesRegex(ValueError, "unfinished or failed"):
                self.check(order)

    def test_missing_owner_is_refused(self):
        order = copy.deepcopy(self.order)
        order["roles"]["qa"] = []
        with self.assertRaisesRegex(ValueError, "owner missing"):
            self.check(order)
        order = copy.deepcopy(self.order)
        order["outcomes"][0]["owner"] = "unassigned"
        with self.assertRaisesRegex(ValueError, "outcome owner"):
            self.check(order)

    def test_agent_cannot_park_or_pause_active_work(self):
        for state in ("PARKED", "PAUSED"):
            order = copy.deepcopy(self.order)
            order.pop("operator_pause", None)
            order["state"] = state
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.check(order)
        order["operator_pause"] = {"actor": "operator", "reference": "synthetic explicit pause"}
        self.assertEqual(self.check(order)["state"], "PAUSED")


class AccountabilityTests(unittest.TestCase):
    """Synthetic declarations exercise structure, never historical compliance."""
    @classmethod
    def setUpClass(cls):
        cls.base = active_work_order((REPO / "docs/UX_EXECUTION_LEDGER.md").read_text())
        cls.matrix = json.loads((REPO / "maint/ux/acceptance.json").read_text())
        cls.catalogue = (REPO / "docs/UX_FULL_FUNCTIONAL_SLICES.md").read_text()

    def order(self):
        order = copy.deepcopy(self.base)
        owner = order["integration_owner"]
        reviewer = next(name for name in order["roles"]["security_review"] if name != owner)
        boundary = order["outcomes"][0]["id"]
        historical = [dict(id=name, boundary=boundary, owner=owner, scope="FIXTURE",
            adoption="PRE_ADOPTION", result="FAIL", elapsed_status="UNKNOWN",
            elapsed_seconds=None, reference="synthetic retained pre-adoption fact") for name in ("old1", "old2")]
        planned = dict(id="next", boundary=boundary, owner=owner, scope="FIXTURE", adoption="CURRENT",
            source_revision="a" * 40, change_reference="synthetic frozen changed fixture",
            success_chain_review=dict(reviewer=reviewer, reference="synthetic independent whole-path review",
                covers=["producer", "cleanup", "consumer"]),
            reassessment=dict(reviewers=[owner, reviewer], reference="synthetic combined failure review",
                failed_attempt_ids=["old1", "old2"], next_action="execute the reviewed changed action"))
        order["accountability"] = dict(functional_exit="synthetic complete password user journey", owner=owner,
            elapsed_scope="wall_clock", history_reference="synthetic retained chronological history",
            investigation=dict(owner=owner, started_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                timebox_seconds=1800, elapsed_status="UNMEASURED", elapsed_seconds=None),
            attempts=historical, next_attempt=planned)
        return order

    def check(self, order, pre_action=True):
        return validate_work_order(order, self.matrix, self.catalogue, (), pre_action=pre_action)

    def test_valid_history_and_current_pre_action_preserve_unknown_elapsed(self):
        order = self.order()
        self.assertIn("no evidence truth", self.check(order)["claim"])
        action = order["accountability"]["next_attempt"]
        action.update(result="PASS", elapsed_status="MEASURED", elapsed_seconds=12.5, reference="synthetic measured wall-clock action")
        order["accountability"]["attempts"].append(action)
        order["accountability"]["next_attempt"] = None
        self.check(order, pre_action=False)
        with self.assertRaisesRegex(ValueError, "exact next attempt"):
            self.check(order)
        following = copy.deepcopy(action)
        following.update(id="product-after-reviewed-fixture", scope="PRODUCT_DELIVERY")
        for key in ("result", "elapsed_status", "elapsed_seconds", "reference", "reassessment"):
            following.pop(key)
        order["accountability"]["next_attempt"] = following
        self.check(order)
        # New failures accumulate in a new window without erasing history.
        action["result"] = "FAIL"
        following["change_reference"] = "synthetic newly changed action"
        self.check(order)
        following.update(result="FAIL", elapsed_status="UNKNOWN", elapsed_seconds=None,
            reference="synthetic second new-window failure")
        order["accountability"]["attempts"].append(following)
        third = copy.deepcopy(following)
        third.update(id="third-new-window-action", change_reference="synthetic third changed action")
        for key in ("result", "elapsed_status", "elapsed_seconds", "reference"):
            third.pop(key)
        order["accountability"]["next_attempt"] = third
        with self.assertRaisesRegex(ValueError, "two failed attempts"):
            self.check(order)

    def test_missing_accountability_or_success_chain_review_refuses(self):
        order = self.order();del order["accountability"]
        with self.assertRaisesRegex(ValueError, "accountability"):
            self.check(order)
        for edit in (lambda a: a.pop("success_chain_review"),
                lambda a: a["success_chain_review"].update(covers=["producer", "consumer"]),
                lambda a: a["success_chain_review"].update(reviewer=a["owner"])):
            order = self.order();edit(order["accountability"]["next_attempt"])
            with self.assertRaisesRegex(ValueError, "producer/cleanup/consumer"):
                self.check(order)

    def test_missing_change_and_unchanged_failed_retry_refuse(self):
        order = self.order();del order["accountability"]["next_attempt"]["change_reference"]
        with self.assertRaisesRegex(ValueError, "changed-action"):
            self.check(order)
        order = self.order();record = order["accountability"]
        previous = copy.deepcopy(record["next_attempt"])
        previous.update(id="failed-current", result="FAIL", reference="synthetic current failure",
            elapsed_status="UNMEASURED", elapsed_seconds=None)
        record["attempts"].append(previous)
        record["next_attempt"].pop("reassessment")
        with self.assertRaisesRegex(ValueError, "unchanged failed-boundary"):
            self.check(order)

    def test_two_failures_require_combined_independent_reassessment(self):
        for edit in (lambda a: a.pop("reassessment"),
                lambda a: a["reassessment"].update(failed_attempt_ids=["old2"]),
                lambda a: a["reassessment"].update(reviewers=[a["owner"]])):
            order = self.order();edit(order["accountability"]["next_attempt"])
            with self.assertRaisesRegex(ValueError, "two failed attempts"):
                self.check(order)

    def test_successor_rename_does_not_reset_stable_boundary(self):
        order = self.order();action = order["accountability"]["next_attempt"]
        action.update(id="different-package-successor99", change_reference="renamed package with changed source")
        del action["reassessment"]
        with self.assertRaisesRegex(ValueError, "two failed attempts"):
            self.check(order)
        action["boundary"] = "different-package-successor99"
        with self.assertRaisesRegex(ValueError, "stable functional outcome"):
            self.check(order)

    def test_timebox_and_explicit_wall_clock_measurement_refuse_contradictions(self):
        for edit, message in ((lambda a: a.update(elapsed_scope="compute_cost"), "wall-clock scope"),
                (lambda a: a["investigation"].update(timebox_seconds=0), "bounded investigation timebox"),
                (lambda a: a["investigation"].update(started_at="yesterday"), "started_at UTC"),
                (lambda a: a["attempts"][0].update(elapsed_seconds=122.497), "contradicts status")):
            order = self.order();edit(order["accountability"])
            with self.assertRaisesRegex(ValueError, message):self.check(order)
        order = self.order();window = order["accountability"]["investigation"]
        window["started_at"] = (datetime.now(timezone.utc)-timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaisesRegex(ValueError, "expired investigation"):
            self.check(order)
        window["overrun_reference"] = "synthetic explicit bounded-investigation reassessment/disposition"
        self.check(order)


class SliceContractTests(unittest.TestCase):
    """Synthetic slice declarations exercise structure, not product acceptance."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="osmap-slice-contract-")
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        (self.repo / "docs").mkdir()
        self.specification = self.repo / "docs/slice.md"
        self.specification.write_text("Public synthetic specification for validator counterexamples.\n")
        self.outcomes = {"password-change", "preserve-bob"}
        design = {key: "Declared concrete " + key + " behavior for the synthetic password workflow."
                  for key in ("journey", "frontend", "backend", "interfaces", "persistence", "security", "failure_recovery")}
        tests = []
        for kind, level in (("positive", "native"), ("negative", "deployed"), ("usability", "human")):
            tests.append(dict(id=kind, outcome_ids=sorted(self.outcomes), kind=kind, level=level,
                prerequisites="Create only the two isolated synthetic accounts before this declared action.",
                action="Submit one own-account request through the declared password route.",
                expected="Alice changes once while Bob retains his existing epoch and session.",
                preserved="Bob credential row and unrelated mail remain byte-identical.",
                owner="developer", reviewer="reviewer", status="NOT_RUN", evidence=[]))
        self.order = dict(slice="S04-02", state="IN_PROGRESS", roles={"developers": ["developer"],
            "security_review": ["reviewer"], "technical_writer": ["writer"]}, human_acceptance=dict(status="PENDING"),
            slice_contract=dict(version=1, slice="S04-02", specification=dict(path="docs/slice.md",
                sha256=hashlib.sha256(self.specification.read_bytes()).hexdigest()), design=design, tests=tests,
                engineering_exit="All required actual agent-owned password and preservation checks pass.",
                human_exit="Operator independently accepts the completed own-account password journey."))

    def check(self, order):
        return validate_slice_contract(order, self.outcomes, self.repo)

    def test_planned_contract_and_explicit_failure_do_not_claim_execution(self):
        self.check(self.order)
        for status in ("FAIL", "PARTIAL"):
            order = copy.deepcopy(self.order)
            order["slice_contract"]["tests"][0].update(status=status, evidence=["synthetic retained failed result"])
            self.check(order)

    def test_missing_unmapped_or_generic_plan_declarations_refuse(self):
        edits = [
            (lambda o: o.pop("slice_contract"), "slice contract"),
            (lambda o: o["slice_contract"].pop("specification"), "exact fields"),
            (lambda o: o["slice_contract"].update(slice="S05-01"), "match active slice"),
            (lambda o: o["slice_contract"]["design"].pop("backend"), "concrete slice design"),
            (lambda o: o["slice_contract"]["design"].update(security="TBD"), "concrete slice design"),
            (lambda o: o["slice_contract"].update(tests=[]), "planned slice tests"),
            (lambda o: o["slice_contract"]["tests"][0].update(outcome_ids=["unmapped"]), "unmapped outcome"),
            (lambda o: o["slice_contract"]["tests"][1].update(outcome_ids=["password-change"]), "every outcome"),
            (lambda o: o["slice_contract"]["tests"][1].update(id="positive"), "unique slice test"),
            (lambda o: o["slice_contract"]["tests"][0].pop("expected"), "exact planned slice test"),
            (lambda o: o["slice_contract"]["tests"][0].update(expected=""), "concrete slice test"),
            (lambda o: o["slice_contract"]["tests"][0].update(expected="Control works."), "concrete slice test"),
            (lambda o: o["slice_contract"]["tests"][0].update(expected="pass"), "concrete slice test"),
            (lambda o: o["slice_contract"]["tests"][0].update(expected="works"), "concrete slice test"),
            (lambda o: o["slice_contract"]["specification"].update(sha256="0" * 64), "SHA256 mismatch"),
        ]
        for edit, message in edits:
            order = copy.deepcopy(self.order); edit(order)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.check(order)

    def test_specification_cannot_escape_docs_or_disappear(self):
        outside = self.repo / "outside.md"; outside.write_text("public outside-docs fixture")
        (self.repo / "docs/escape.md").symlink_to(outside)
        for path in ("../outside.md", ".", str(self.specification), "outside.md", "docs/missing.md", "docs/escape.md"):
            order = copy.deepcopy(self.order); order["slice_contract"]["specification"]["path"] = path
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "slice specification"):
                self.check(order)

    def test_execution_evidence_and_independent_named_review_are_required(self):
        edits = [
            (dict(status="NOT_RUN", evidence=["synthetic claimed execution"]), "NOT_RUN"),
            (dict(status="PASS", evidence=[]), "retained evidence"),
            (dict(status="FAIL", evidence=[]), "retained evidence"),
            (dict(status="PARTIAL", evidence=[]), "retained evidence"),
            (dict(status="PASS", evidence=[""]), "evidence references"),
            (dict(reviewer="developer"), "independent reviewer"),
            (dict(reviewer="writer"), "independent reviewer"),
            (dict(owner="unassigned"), "named slice test owner"),
        ]
        for changes, message in edits:
            order = copy.deepcopy(self.order); order["slice_contract"]["tests"][0].update(changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, message):
                self.check(order)

    def test_engineering_and_human_closure_cannot_skip_required_tests(self):
        human_only = copy.deepcopy(self.order)
        human_only["state"] = "ENGINEERING_COMPLETE"
        human_only["slice_contract"]["tests"][0]["level"] = "human"
        human_only["slice_contract"]["tests"][1].update(status="PASS", evidence=["synthetic negative result"])
        with self.assertRaisesRegex(ValueError, "nonhuman slice test coverage"):
            self.check(human_only)
        for state in ("ENGINEERING_COMPLETE", "UAT_READY", "ACCEPTED"):
            order = copy.deepcopy(self.order); order["state"] = state
            with self.subTest(state=state), self.assertRaisesRegex(ValueError, "nonhuman slice tests"):
                self.check(order)
        order = copy.deepcopy(self.order)
        for test in order["slice_contract"]["tests"]:
            if test["level"] != "human":
                test.update(status="PASS", evidence=["synthetic engineering result only"])
        for state in ("ENGINEERING_COMPLETE", "UAT_READY"):
            order["state"] = state; self.check(order)
        order["state"] = "ACCEPTED"
        with self.assertRaisesRegex(ValueError, "human slice tests"):
            self.check(order)
        order["slice_contract"]["tests"][-1].update(status="PASS", evidence=["synthetic human result"])
        with self.assertRaisesRegex(ValueError, "human acceptance flag"):
            self.check(order)
        order["human_acceptance"] = dict(status="PASS", reference="synthetic operator acceptance only")
        self.check(order)


class R4ScopeTests(unittest.TestCase):
    """Synthetic scope/closure declarations; no application acceptance is created."""
    @classmethod
    def setUpClass(cls):
        cls.matrix = json.loads((REPO / "maint/ux/acceptance.json").read_text())
        cls.catalogue = (REPO / "docs/UX_FULL_FUNCTIONAL_SLICES.md").read_text()
        cls.base = active_work_order((REPO / "docs/UX_EXECUTION_LEDGER.md").read_text())
        cls.core, cls.followups = r4_scope(cls.matrix, REPO)
        cls.original = cls.core | cls.followups

    def order(self, narrowed=True, state="IN_PROGRESS"):
        order = copy.deepcopy(self.base)
        order["state"] = state
        order.pop("operator_pause", None)
        if narrowed:
            order["scope_revision"] = "R4"
        else:
            order.pop("scope_revision", None)
        # One current functional outcome is retained; only its declared map changes.
        self.assertEqual(len(order["outcomes"]), 1)
        order["outcomes"][0]["requirement_ids"] = sorted(self.core if narrowed else self.original)
        return order

    def check(self, order, matrix=None):
        return validate_work_order(order, matrix if matrix is not None else self.matrix, self.catalogue, (), repo=REPO)

    def fixture(self):
        scratch = tempfile.TemporaryDirectory(prefix="osmap-r4-scope-")
        self.addCleanup(scratch.cleanup)
        repo = Path(scratch.name)
        for relative in (R4_PROFILE, R4_SUPPLEMENT, R4_PROPOSAL, "docs/UX_PLAN_SHA256SUMS"):
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((REPO / relative).read_bytes())
        return repo

    def rewrite_profile(self, repo, mutate):
        path = repo / R4_PROFILE
        profile = json.loads(path.read_text()); mutate(profile)
        path.write_text(json.dumps(profile, sort_keys=True) + "\n")
        manifest = repo / "docs/UX_PLAN_SHA256SUMS"
        lines = manifest.read_text().splitlines()
        manifest.write_text("\n".join(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + R4_PROFILE
            if line.endswith("  " + R4_PROFILE) else line for line in lines) + "\n")

    def complete_declarations(self, order):
        for outcome in order["outcomes"]:
            outcome["stages"] = {stage: "PASS" for stage in outcome["stages"]}
            outcome["evidence"] = [{"stage": stage, "reference": "synthetic declaration only, not product evidence"} for stage in outcome["stages"]]
            for dependency in outcome["dependencies"]: dependency["status"] = "PASS"
        for test in order["slice_contract"]["tests"]:
            test["status"] = "PASS"
            test["evidence"] = ["synthetic declaration only, not executed application QA"]
        order["human_acceptance"] = {"status": "PASS", "reference": "synthetic human-evidence shape only"}

    def accepted_matrix(self):
        matrix = copy.deepcopy(self.matrix)
        for row in matrix["approved_control_cases"]:
            row["result"] = {"status": "ACCEPTED", "executed": True,
                "evidence": [{"kind": "human_uat", "path": "synthetic-counterexample", "scope": "shape test only; no actual human result or application acceptance"}]}
        return matrix

    def test_default_original57_and_explicit_approved46_keep_followups_open(self):
        self.assertEqual(self.check(self.order(False))["required_obligations"], 57)
        self.assertEqual(self.check(self.order())["required_obligations"], 46)
        rows = {row["id"]: row for row in self.matrix["approved_control_cases"]}
        self.assertEqual(len(self.followups), 11)
        self.assertTrue(all(rows[identifier]["result"]["status"] == "BLOCKED" for identifier in self.followups))
        # No result, original expectation or owner history is modified by the overlay.
        before = copy.deepcopy(self.matrix)
        r4_scope(self.matrix, REPO)
        self.assertEqual(self.matrix, before)

    def test_unapproved_unknown_and_unmanifested_scope_refused(self):
        order = self.order(); order["scope_revision"] = "R5"
        with self.assertRaisesRegex(ValueError, "unapproved.*scope revision"): self.check(order)
        order.pop("scope_revision")
        with self.assertRaisesRegex(ValueError, "all original mapped"): self.check(order)
        repo = self.fixture()
        manifest = repo / "docs/UX_PLAN_SHA256SUMS"
        manifest.write_text("\n".join(line for line in manifest.read_text().splitlines() if not line.endswith(R4_SUPPLEMENT)) + "\n")
        with self.assertRaisesRegex(ValueError, "missing or changed"): r4_scope(self.matrix, repo)

    def test_omitted_duplicate_and_reassigned_scope_cannot_be_repinned(self):
        edits = [lambda p: p["core_control_ids"].pop(),
                 lambda p: p["core_control_ids"].append(p["core_control_ids"][0]),
                 lambda p: p["required_followups"].pop(),
                 lambda p: p["required_followups"].append(copy.deepcopy(p["required_followups"][0])),
                 lambda p: p["required_followups"][0].update(required=False),
                 lambda p: p["required_followups"][0].update(owner="unassigned"),
                 lambda p: p["required_followups"][5].update(dependency_slices=[]),
                 lambda p: p["required_followups"][0]["control_ids"].append(p["required_followups"][0]["control_ids"][0]),
                 lambda p: p["core_control_ids"].__setitem__(0, "R2-11-005")]
        for edit in edits:
            with self.subTest(edit=edit):
                repo = self.fixture(); self.rewrite_profile(repo, edit)
                with self.assertRaises(ValueError): r4_scope(self.matrix, repo)
        order = self.order(); order["outcomes"][0]["requirement_ids"].append(order["outcomes"][0]["requirement_ids"][0])
        with self.assertRaisesRegex(ValueError, "duplicate R4"): self.check(order)
        order = self.order(); order["outcomes"][0]["requirement_ids"].pop()
        with self.assertRaisesRegex(ValueError, "all original mapped"): self.check(order)

    def test_changed_approved_proposal_or_supplement_refused(self):
        for relative in (R4_PROPOSAL, R4_SUPPLEMENT):
            repo = self.fixture()
            with (repo / relative).open("ab") as file: file.write(b"changed\n")
            with self.assertRaisesRegex(ValueError, "missing or changed"): r4_scope(self.matrix, repo)
        repo = self.fixture()
        path = repo / R4_PROPOSAL; path.write_bytes(path.read_bytes() + b"changed\n")
        manifest = repo / "docs/UX_PLAN_SHA256SUMS"
        manifest.write_text("\n".join(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + R4_PROPOSAL if line.endswith("  " + R4_PROPOSAL) else line for line in manifest.read_text().splitlines()) + "\n")
        with self.assertRaisesRegex(ValueError, "approved proposal SHA256"): r4_scope(self.matrix, repo)

    def test_partial_core_cannot_close_even_when_stage_flags_claim_pass(self):
        for state in ("ENGINEERING_COMPLETE", "UAT_READY", "ACCEPTED"):
            order = self.order(state=state); self.complete_declarations(order)
            with self.subTest(state=state), self.assertRaisesRegex(ValueError, "actual closure stage"): self.check(order)
        matrix = self.accepted_matrix()
        approved_core = [row for row in matrix["approved_control_cases"] if row["id"] in self.core]
        self.assertEqual(len(approved_core), 43)
        for row in approved_core: row["result"]["status"] = "QA_VERIFIED"
        order = self.order(state="ENGINEERING_COMPLETE"); self.complete_declarations(order)
        self.assertEqual(self.check(order, matrix)["required_obligations"], 46)
        order["state"] = "ACCEPTED"
        with self.assertRaisesRegex(ValueError, "actual closure stage"): self.check(order, matrix)

    def test_s04_epic_and_s11_closure_cannot_drop_required11(self):
        for scope in ("S04", "EPIC"):
            with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, "closure requires ACCEPTED"): validate_closure(self.matrix, scope, REPO)
        matrix = self.accepted_matrix()
        for scope in ("S04", "EPIC"):
            self.assertIn("no sprint/release QA", validate_closure(matrix, scope, REPO)["closure_claim"])
        identifier = next(iter(self.followups))
        row = next(row for row in matrix["approved_control_cases"] if row["id"] == identifier)
        row["result"] = copy.deepcopy(next(row for row in self.matrix["approved_control_cases"] if row["id"] == identifier)["result"])
        for scope in ("S04", "EPIC"):
            with self.assertRaisesRegex(ValueError, identifier): validate_closure(matrix, scope, REPO)
        order = self.order(False, "ENGINEERING_COMPLETE"); self.complete_declarations(order)
        order["slice"] = "S11-04"
        import re
        order["original_requirement"] = dict(re.findall(r"^\| (S\d{2}-\d{2}) \| ([^|]+) \|", self.catalogue, re.MULTILINE))["S11-04"].strip()
        order["outcomes"][0]["requirement_ids"] = [row["id"] for key in ("cases", "approved_control_cases") for row in matrix[key] if "S11-04" in row["owning_slices"]]
        with self.assertRaisesRegex(ValueError, "EPIC closure requires ACCEPTED"): self.check(order, matrix)
        # ACCEPTED without actual execution/human-evidence shape also refuses.
        matrix = self.accepted_matrix(); matrix["approved_control_cases"][0]["result"]["evidence"] = []
        with self.assertRaisesRegex(ValueError, "unsupported progress"): validate_closure(matrix, "EPIC", REPO)


if __name__ == "__main__":
    unittest.main()
