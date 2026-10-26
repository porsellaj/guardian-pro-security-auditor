"""Pruebas del almacenamiento, comparación y plan de acción de Guardian Pro."""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import guardian_workspace as workspace


def device(device_id="dev_test_01", name="TEST-PC"):
    return {"id": device_id, "name": name, "os": "Windows 11 Pro"}


def check(name, status, severity="info", recommendation="", can_fix=False, fix_action=""):
    return {
        "name": name,
        "status": status,
        "severity": severity,
        "recommendation": recommendation,
        "can_fix": can_fix,
        "fix_action": fix_action,
    }


def iso(minutes_ago=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")


class WorkspaceTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.store = workspace.GuardianWorkspace(self.base)

    def save(self, checks, when=None, device_data=None):
        return self.store.save_audit(
            checks,
            device_data or device(),
            collected_at=when or iso(),
        )


class HistoryTests(WorkspaceTestCase):
    def test_save_and_load_history(self):
        record = self.save([
            check("Firewall de Windows", "finding", "high", "Habilitar firewall", True, "firewall_enable_all"),
            check("Microsoft Defender", "ok", "info", "Activo"),
        ])
        self.assertEqual(record["schema"], workspace.SCHEMA_AUDIT)
        self.assertEqual(record["summary"], {"ok": 1, "finding": 1, "unverifiable": 0, "error": 0})
        loaded = self.store.load_history()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["audit_id"], record["audit_id"])

    def test_history_persists_across_instances(self):
        record = self.save([check("Firewall de Windows", "ok")])
        second = workspace.GuardianWorkspace(self.base)
        loaded = second.load_history()
        self.assertEqual([item["audit_id"] for item in loaded], [record["audit_id"]])

    def test_atomic_write_leaves_no_temporary_files(self):
        self.save([check("Firewall de Windows", "ok")])
        names = [path.name for path in self.base.iterdir()]
        self.assertIn("history.json", names)
        self.assertFalse([name for name in names if ".tmp-" in name])

    def test_corrupt_history_is_preserved_before_new_write(self):
        self.store.history_path.write_text("{esto no es json", encoding="utf-8")
        corrupt_store = workspace.GuardianWorkspace(self.base)
        self.assertEqual(corrupt_store.load_history(), [])
        self.assertTrue(corrupt_store.warnings)
        corrupt_store.save_audit([check("Firewall de Windows", "ok")], device())
        backups = list(self.base.glob("history.corrupt-*.json"))
        self.assertEqual(len(backups), 1)
        self.assertIn("esto no es json", backups[0].read_text(encoding="utf-8"))
        self.assertEqual(len(workspace.GuardianWorkspace(self.base).load_history()), 1)

    def test_invalid_records_are_skipped_and_preserved(self):
        record = workspace.build_audit_record([check("Firewall de Windows", "ok")], device())
        broken = dict(record)
        broken["audit_id"] = "audit_broken"
        broken["summary"] = {"ok": 0, "finding": 0, "unverifiable": 0, "error": 0}
        self.store.history_path.write_text(json.dumps({
            "schema": workspace.SCHEMA_HISTORY,
            "schema_version": 1,
            "audits": [record, broken],
        }), encoding="utf-8")
        loaded = self.store.load_history()
        self.assertEqual(len(loaded), 1)
        self.assertTrue(self.store.warnings)
        self.store.save_audit([check("Microsoft Defender", "ok")], device())
        self.assertTrue(list(self.base.glob("history.corrupt-*.json")))

    def test_history_limit_keeps_newest(self):
        with patch.object(workspace, "MAX_AUDITS", 3):
            for index in range(5):
                self.save(
                    [check("Firewall de Windows", "ok")],
                    when=iso(10 - index),
                )
        loaded = self.store.load_history()
        self.assertEqual(len(loaded), 3)
        self.assertEqual(loaded[-1]["audit_id"], self.store.load_history()[-1]["audit_id"])

    def test_history_does_not_store_evidence_or_paths(self):
        record = self.save([check(
            "Análisis de nombres de archivo",
            "finding",
            "low",
            r"Revise C:\Users\Ana\passwords.txt",
        )])
        text = json.dumps(record)
        self.assertNotIn("passwords.txt", text)
        self.assertNotIn(r"C:\Users", text)
        self.assertNotIn("evidence", text)


class ComparisonTests(WorkspaceTestCase):
    def test_new_persistent_resolved_and_unverifiable(self):
        previous = workspace.build_audit_record([
            check("Firewall de Windows", "finding", "high"),
            check("Microsoft Defender", "finding", "high"),
            check("Escritorio Remoto (RDP)", "ok"),
            check("Análisis de nombres de archivo", "finding", "low"),
        ], device(), collected_at=iso(20), audit_id="audit_previous")
        current = workspace.build_audit_record([
            check("Firewall de Windows", "ok"),
            check("Microsoft Defender", "finding", "high"),
            check("Escritorio Remoto (RDP)", "unverifiable"),
            check("Análisis de nombres de archivo", "ok"),
        ], device(), collected_at=iso(1), audit_id="audit_current")
        comparison = workspace.compare_audits(previous, current)
        self.assertEqual([item["check_id"] for item in comparison["resolved"]], ["firewall", "file_names"])
        self.assertEqual([item["check_id"] for item in comparison["persistent"]], ["defender"])
        self.assertEqual([item["check_id"] for item in comparison["unverifiable"]], ["rdp"])
        self.assertEqual(comparison["summary"]["new"], 0)

    def test_error_after_ok_is_not_resolved(self):
        previous = workspace.build_audit_record([
            check("Firewall de Windows", "ok"),
        ], device(), collected_at=iso(5), audit_id="audit_ok")
        current = workspace.build_audit_record([
            check("Firewall de Windows", "error", "high"),
        ], device(), collected_at=iso(1), audit_id="audit_error")
        comparison = workspace.compare_audits(previous, current)
        self.assertEqual(comparison["summary"]["resolved"], 0)
        self.assertEqual(comparison["summary"]["unverifiable"], 1)
        self.assertEqual(comparison["summary"]["regressed"], 1)

    def test_missing_previous_is_not_a_resolution(self):
        current = workspace.build_audit_record([
            check("Firewall de Windows", "ok"),
        ], device(), collected_at=iso(1), audit_id="audit_current")
        comparison = workspace.compare_check_lists([], current["checks"])
        self.assertEqual(comparison["summary"]["resolved"], 0)

    def test_previous_finding_absent_is_not_evaluated(self):
        previous = workspace.build_audit_record([
            check("Firewall de Windows", "finding", "high"),
        ], device(), collected_at=iso(5), audit_id="audit_previous")
        current = workspace.build_audit_record([
            check("Microsoft Defender", "ok"),
        ], device(), collected_at=iso(1), audit_id="audit_current")
        comparison = workspace.compare_audits(previous, current)
        self.assertEqual(comparison["summary"]["not_evaluated"], 1)
        self.assertEqual(comparison["summary"]["resolved"], 0)

    def test_saved_audit_contains_comparison(self):
        first = self.save([check("Firewall de Windows", "finding", "high")], when=iso(5))
        second = self.save([check("Firewall de Windows", "ok")], when=iso(1))
        self.assertEqual(second["comparison"]["previous_audit_id"], first["audit_id"])
        self.assertEqual(second["comparison"]["summary"]["resolved"], 1)


class ReportTests(WorkspaceTestCase):
    def test_export_uses_public_schema_without_evidence(self):
        record = workspace.build_audit_record([
            check(
                "Análisis de nombres de archivo", "finding", "low",
                r"Revise C:\Users\Ana\passwords.txt y confirme el acceso.",
            )
        ], device(), collected_at=iso(), audit_id="audit_export")
        report = workspace.report_from_audit(record)
        self.assertEqual(report["schema"], workspace.SCHEMA_REPORT)
        text = json.dumps(report)
        self.assertNotIn("passwords.txt", text)
        self.assertNotIn(r"C:\Users", text)
        self.assertNotIn("comparison", report)
        workspace.validate_report(report)

    def test_import_sanitizes_path_like_names(self):
        report = workspace.report_from_audit(workspace.build_audit_record([
            check("Firewall de Windows", "ok"),
        ], device(), collected_at=iso(), audit_id="audit_sanitize_name"))
        report["device"]["name"] = r"C:\Users\Ana\private"
        report["checks"][0]["name"] = r"C:\Users\Ana\secret.txt"
        report["checks"][0]["recommendation"] = r"Revise C:\Users\Ana\secret.txt"
        validated = workspace.validate_report(report)
        text = json.dumps(validated)
        self.assertNotIn(r"C:\Users", text)
        self.assertNotIn("secret.txt", text)

    def test_duplicate_check_ids_are_rejected(self):
        report = workspace.report_from_audit(workspace.build_audit_record([
            check("Firewall de Windows", "ok"),
        ], device(), collected_at=iso(), audit_id="audit_duplicate_check"))
        duplicate = dict(report["checks"][0])
        report["checks"].append(duplicate)
        with self.assertRaises(workspace.WorkspaceError):
            workspace.validate_report(report)

    def test_export_writes_valid_json(self):
        record = workspace.build_audit_record([
            check("Firewall de Windows", "ok"),
        ], device(), collected_at=iso(), audit_id="audit_export_file")
        target = self.base / "report.json"
        self.store.write_report(record, target)
        payload = json.loads(target.read_text(encoding="utf-8"))
        workspace.validate_report(payload)

    def test_invalid_status_is_rejected(self):
        report = workspace.report_from_audit(workspace.build_audit_record([
            check("Firewall de Windows", "ok"),
        ], device(), collected_at=iso(), audit_id="audit_invalid"))
        report["checks"][0]["status"] = "perfecto"
        with self.assertRaises(workspace.WorkspaceError):
            workspace.validate_report(report)

    def test_unknown_schema_and_version_are_rejected(self):
        report = workspace.report_from_audit(workspace.build_audit_record([
            check("Firewall de Windows", "ok"),
        ], device(), collected_at=iso(), audit_id="audit_schema"))
        changed = dict(report)
        changed["schema"] = "otro.schema"
        with self.assertRaises(workspace.WorkspaceError):
            workspace.validate_report(changed)
        changed = dict(report)
        changed["schema_version"] = 99
        with self.assertRaises(workspace.WorkspaceError):
            workspace.validate_report(changed)

    def test_summary_mismatch_is_rejected(self):
        report = workspace.report_from_audit(workspace.build_audit_record([
            check("Firewall de Windows", "ok"),
        ], device(), collected_at=iso(), audit_id="audit_summary"))
        report["summary"]["finding"] = 1
        with self.assertRaises(workspace.WorkspaceError):
            workspace.validate_report(report)

    def test_unknown_fields_are_rejected(self):
        report = workspace.report_from_audit(workspace.build_audit_record([
            check("Firewall de Windows", "ok"),
        ], device(), collected_at=iso(), audit_id="audit_unknown"))
        report["ruta_local"] = r"C:\secreto"
        with self.assertRaises(workspace.WorkspaceError):
            workspace.validate_report(report)

    def test_oversized_file_is_rejected(self):
        target = self.base / "grande.json"
        target.write_text("x" * (workspace.MAX_REPORT_BYTES + 1), encoding="utf-8")
        with self.assertRaises(workspace.WorkspaceError):
            self.store.read_report_file(target)

    def test_malformed_file_is_rejected(self):
        target = self.base / "roto.json"
        target.write_text("{no json", encoding="utf-8")
        with self.assertRaises(workspace.WorkspaceError):
            self.store.read_report_file(target)

    def test_read_valid_report_file(self):
        record = workspace.build_audit_record([
            check("Firewall de Windows", "ok"),
        ], device(), collected_at=iso(), audit_id="audit_file")
        target = self.base / "valid.json"
        self.store.write_report(record, target)
        loaded = self.store.read_report_file(target)
        self.assertEqual(loaded["audit_id"], "audit_file")


class ImportTests(WorkspaceTestCase):
    def report(self, device_id, name, when, audit_id, status="finding"):
        return workspace.report_from_audit(workspace.build_audit_record([
            check("Firewall de Windows", status, "high" if status == "finding" else "info"),
        ], device(device_id, name), collected_at=when, audit_id=audit_id))

    def test_multiple_devices_and_duplicate_and_older(self):
        first = self.report("dev_a", "PC-A", iso(30), "audit_a_1")
        second = self.report("dev_b", "PC-B", iso(20), "audit_b_1")
        duplicate = dict(first)
        older = self.report("dev_a", "PC-A", iso(90), "audit_a_0")
        results = self.store.add_imported_reports([first, second, duplicate, older])
        self.assertEqual([item["outcome"] for item in results], ["new", "new", "duplicate", "older"])
        self.assertEqual(len(self.store.load_fleet()), 3)

    def test_import_is_persistent(self):
        self.store.add_imported_reports([self.report("dev_a", "PC-A", iso(1), "audit_a")])
        second = workspace.GuardianWorkspace(self.base)
        self.assertEqual(len(second.load_fleet()), 1)

    def test_invalid_report_does_not_cancel_valid_import(self):
        valid = self.report("dev_a", "PC-A", iso(1), "audit_valid")
        invalid = {"schema": "guardian.report"}
        results = self.store.add_imported_reports([invalid, valid])
        self.assertEqual([item["outcome"] for item in results], ["invalid", "new"])
        self.assertEqual(len(self.store.load_fleet()), 1)

    def test_import_does_not_execute_anything(self):
        report = self.report("dev_a", "PC-A", iso(1), "audit_safe")
        with patch("subprocess.run") as run, patch("os.system") as system:
            self.store.add_imported_reports([report])
        run.assert_not_called()
        system.assert_not_called()

    def test_fleet_overview_compares_two_reports_for_same_device(self):
        older = self.report("dev_a", "PC-A", iso(20), "audit_a_old", "finding")
        newer = self.report("dev_a", "PC-A", iso(1), "audit_a_new", "ok")
        overview = workspace.fleet_overview([older, newer])
        self.assertEqual(len(overview), 1)
        self.assertEqual(overview[0]["latest"]["audit_id"], "audit_a_new")
        self.assertEqual(overview[0]["comparison"]["summary"]["resolved"], 1)

    def test_fleet_overview_sorts_high_findings_first(self):
        low = self.report("dev_low", "PC-LOW", iso(1), "audit_low", "unverifiable")
        high = self.report("dev_high", "PC-HIGH", iso(5), "audit_high", "finding")
        overview = workspace.fleet_overview([low, high])
        self.assertEqual(overview[0]["device"]["id"], "dev_high")
        self.assertEqual(overview[0]["high_findings"], 1)
        self.assertEqual(overview[1]["review_items"], 1)


class PlanTests(unittest.TestCase):
    def test_plan_is_deterministic_and_explained(self):
        checks = [
            check("Análisis de nombres de archivo", "finding", "low"),
            check("Escritorio Remoto (RDP)", "unverifiable"),
            check("Microsoft Defender", "finding", "high"),
            check("Firewall de Windows", "finding", "high", can_fix=True, fix_action="firewall_enable_all"),
        ]
        first = workspace.build_action_plan(checks, allow_repair=True)
        second = workspace.build_action_plan(list(reversed(checks)), allow_repair=True)
        self.assertEqual([item["check_id"] for item in first], [item["check_id"] for item in second])
        self.assertEqual(first[0]["check_id"], "firewall")
        self.assertTrue(first[0]["can_repair"])
        for item in first:
            self.assertTrue(item["what"])
            self.assertTrue(item["why"])
            self.assertTrue(item["next_step"])
            self.assertTrue(item["verification"])

    def test_defender_is_always_manual(self):
        plan = workspace.build_action_plan([
            check("Microsoft Defender", "finding", "high", can_fix=True, fix_action="defender_enable_rtp")
        ], allow_repair=True)
        self.assertFalse(plan[0]["can_repair"])
        self.assertTrue(plan[0]["manual"])
        self.assertEqual(plan[0]["action_kind"], "manual")

    def test_imported_and_demo_plans_cannot_repair(self):
        checks = [check(
            "Firewall de Windows", "finding", "high",
            can_fix=True, fix_action="firewall_enable_all",
        )]
        for source in ("imported", "demo", "history"):
            plan = workspace.build_action_plan(checks, allow_repair=False, source=source)
            self.assertFalse(plan[0]["can_repair"])
            self.assertEqual(plan[0]["source"], source)

    def test_errors_are_review_items_not_ok(self):
        plan = workspace.build_action_plan([
            check("Firewall de Windows", "error", "high"),
            check("Microsoft Defender", "ok"),
        ])
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["status"], "error")
        self.assertFalse(plan[0]["can_repair"])
        self.assertIn("No se pudo confirmar", plan[0]["what"])


class DemoAndSanitizeTests(unittest.TestCase):
    def test_demo_has_three_devices_and_valid_schema(self):
        audits = workspace.generate_demo_audits()
        self.assertEqual(len({audit["device"]["id"] for audit in audits}), 3)
        for audit in audits:
            workspace.validate_audit_record(audit)
        self.assertEqual(len(audits), 4)

    def test_demo_contains_confirmed_improvement(self):
        audits = workspace.generate_demo_audits()
        latest = next(a for a in audits if a["audit_id"] == "demo-audit-admin-03-new")
        self.assertIn("comparison", latest)
        self.assertEqual(latest["comparison"]["summary"]["resolved"], 1)

    def test_demo_is_not_persisted(self):
        with tempfile.TemporaryDirectory() as td:
            store = workspace.GuardianWorkspace(td)
            workspace.generate_demo_audits()
            self.assertEqual(store.load_history(), [])
            self.assertEqual(store.load_fleet(), [])

    def test_sanitize_redacts_windows_and_unc_paths(self):
        text = workspace.sanitize_text(
            r"Revise C:\Users\Ana\passwords.txt y \\servidor\share\datos.csv"
        )
        self.assertNotIn("passwords.txt", text)
        self.assertNotIn("datos.csv", text)
        self.assertIn("[ruta omitida]", text)

    def test_text_limits_are_applied(self):
        value = workspace.sanitize_text("x" * 1000)
        self.assertLessEqual(len(value), workspace.MAX_TEXT_LENGTH)


if __name__ == "__main__":
    unittest.main(verbosity=2)
