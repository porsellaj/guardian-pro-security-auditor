"""Pruebas de regresión de Guardian Pro.

Se ejecutan con:
    python -m unittest -v

No ejecutan reparaciones reales ni modifican firewall, Defender, RDP o el
registro. Las funciones que dependen de PowerShell se sustituyen por mocks.
"""

import json
import os
import queue
import tempfile
import threading
import time
import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

import Guardian


class GuardianGuiTestCase(unittest.TestCase):
    """Base con una instancia real de la interfaz, sin mainloop."""

    def setUp(self):
        self.app = Guardian.GuardianProMaster()
        self.app.withdraw()
        self.app.update_idletasks()
        self.addCleanup(self._destroy_app)

    def _destroy_app(self):
        try:
            self.app.audit_in_progress = False
            self.app.repair_in_progress = False
            # Cancelar callbacks pendientes de CustomTkinter para que no se
            # ejecuten sobre una ventana ya destruida al pasar al siguiente test.
            try:
                for after_id in self.app.tk.call("after", "info"):
                    self.app.after_cancel(after_id)
            except Exception:
                pass
            self.app.destroy()
        except Exception:
            pass

    def drain_queue(self):
        events = []
        while True:
            try:
                events.append(self.app.result_queue.get_nowait())
            except queue.Empty:
                break
        return events

    def scan(self, path):
        self.app.selected_path = path
        self.app._check_sensitive_files()
        return self.drain_queue()

    def single_result(self, events):
        results = [data for kind, data in events if kind == "result"]
        self.assertEqual(len(results), 1, f"Se esperaba un resultado y hay {len(results)}")
        return results[0]

    def wait_for_audit(self, timeout=5):
        deadline = time.time() + timeout
        while self.app.audit_in_progress and time.time() < deadline:
            self.app.update()
            time.sleep(0.01)
        self.app.update()
        self.assertFalse(self.app.audit_in_progress, "La auditoría no terminó a tiempo")

    def start_audit_with_results(self, results):
        """Ejecuta una auditoría real de UI con comprobaciones simuladas."""
        pending = list(results)

        def put_one():
            if pending:
                self.app.result_queue.put(("result", pending.pop(0)))

        patches = [
            patch.object(self.app, "_check_firewall", new=put_one),
            patch.object(self.app, "_check_defender", new=put_one),
            patch.object(self.app, "_check_rdp", new=put_one),
            patch.object(self.app, "_check_sensitive_files", new=put_one),
        ]
        for patcher in patches:
            patcher.start()
        try:
            self.app.iniciar_auditoria()
            self.wait_for_audit()
        finally:
            for patcher in reversed(patches):
                patcher.stop()

    @staticmethod
    def touch(path, content=""):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)


class FileScanTests(GuardianGuiTestCase):
    def test_accessible_tree_without_matches(self):
        with tempfile.TemporaryDirectory() as td:
            self.touch(os.path.join(td, "notas.txt"))
            events = self.scan(td)
            result = self.single_result(events)
            self.assertEqual(result.status, "ok")
            self.assertIn("Sin coincidencias", result.evidence)
            self.assertEqual([data for kind, data in events if kind == "file_finding"], [])

    def test_filename_match_is_reported(self):
        with tempfile.TemporaryDirectory() as td:
            self.touch(os.path.join(td, "password.txt"))
            events = self.scan(td)
            result = self.single_result(events)
            self.assertEqual(result.status, "finding")
            findings = [data for kind, data in events if kind == "file_finding"]
            self.assertEqual(len(findings), 1)
            self.assertTrue(findings[0].endswith("password.txt"))

    def test_excluded_directory_is_not_traversed(self):
        with tempfile.TemporaryDirectory() as td:
            self.touch(os.path.join(td, "notas.txt"))
            self.touch(os.path.join(td, "node_modules", "password.txt"))
            self.touch(os.path.join(td, "normal", "password.txt"))

            events = self.scan(td)
            result = self.single_result(events)
            findings = [data for kind, data in events if kind == "file_finding"]

            self.assertEqual(result.status, "finding")
            self.assertEqual(len(findings), 1)
            self.assertIn("normal", findings[0])
            self.assertNotIn("node_modules", findings[0])
            self.assertIn("Revisados: 2 archivos", result.evidence)

    def test_root_missing_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            missing = os.path.join(td, "no_existe")
            events = self.scan(missing)
            result = self.single_result(events)
            self.assertEqual(result.status, "error")
            self.assertIn("no existe", result.evidence.lower())

    def test_root_file_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            file_path = os.path.join(td, "archivo.txt")
            self.touch(file_path)
            events = self.scan(file_path)
            result = self.single_result(events)
            self.assertEqual(result.status, "error")
            self.assertIn("no es un directorio", result.evidence.lower())

    def test_root_inaccessible_is_unverifiable(self):
        with tempfile.TemporaryDirectory() as td:
            real_stat = os.stat
            target = os.path.abspath(td)

            def fake_stat(path, *args, **kwargs):
                if os.path.abspath(path) == target:
                    raise PermissionError(13, "Acceso denegado", path)
                return real_stat(path, *args, **kwargs)

            with patch("Guardian.os.stat", side_effect=fake_stat):
                events = self.scan(td)

            result = self.single_result(events)
            self.assertEqual(result.status, "unverifiable")
            self.assertIn("permisos", result.evidence.lower())

    def test_walk_error_with_match_is_partial_finding(self):
        with tempfile.TemporaryDirectory() as td:
            self.touch(os.path.join(td, "password.txt"))

            def fake_walk(path, topdown=True, onerror=None, followlinks=False):
                self.assertTrue(topdown)
                self.assertFalse(followlinks)
                self.assertIsNotNone(onerror)
                onerror(PermissionError(13, "Acceso denegado", os.path.join(path, "bloqueado")))
                yield path, [], ["password.txt"]

            with patch("Guardian.os.walk", side_effect=fake_walk):
                events = self.scan(td)

            result = self.single_result(events)
            self.assertEqual(result.status, "finding")
            self.assertIn("1 directorio(s) no recorrido(s)", result.evidence)
            self.assertIn("Análisis parcial", result.evidence)
            self.assertEqual(len([d for k, d in events if k == "file_finding"]), 1)

    def test_walk_error_without_match_is_unverifiable(self):
        with tempfile.TemporaryDirectory() as td:
            self.touch(os.path.join(td, "notas.txt"))

            def fake_walk(path, topdown=True, onerror=None, followlinks=False):
                onerror(PermissionError(13, "Acceso denegado", os.path.join(path, "bloqueado")))
                yield path, [], ["notas.txt"]

            with patch("Guardian.os.walk", side_effect=fake_walk):
                events = self.scan(td)

            result = self.single_result(events)
            self.assertEqual(result.status, "unverifiable")
            self.assertIn("Sin coincidencias en lo revisado", result.evidence)
            self.assertIn("1 directorio(s) no recorrido(s)", result.evidence)

    def test_file_access_error_does_not_stop_scan(self):
        with tempfile.TemporaryDirectory() as td:
            blocked = os.path.join(td, "password.txt")
            self.touch(blocked)
            self.touch(os.path.join(td, "notas.txt"))
            real_stat = os.stat
            target = os.path.abspath(blocked)

            def fake_stat(path, *args, **kwargs):
                if os.path.abspath(path) == target:
                    raise PermissionError(13, "Acceso denegado", path)
                return real_stat(path, *args, **kwargs)

            with patch("Guardian.os.stat", side_effect=fake_stat):
                events = self.scan(td)

            result = self.single_result(events)
            self.assertEqual(result.status, "finding")
            self.assertIn("1 archivo(s) con acceso no verificado", result.evidence)
            self.assertIn("Análisis parcial", result.evidence)
            self.assertEqual(len([d for k, d in events if k == "file_finding"]), 1)

    def test_file_access_error_without_match_is_unverifiable(self):
        with tempfile.TemporaryDirectory() as td:
            blocked = os.path.join(td, "notas.txt")
            self.touch(blocked)
            real_stat = os.stat
            target = os.path.abspath(blocked)

            def fake_stat(path, *args, **kwargs):
                if os.path.abspath(path) == target:
                    raise PermissionError(13, "Acceso denegado", path)
                return real_stat(path, *args, **kwargs)

            with patch("Guardian.os.stat", side_effect=fake_stat):
                events = self.scan(td)

            result = self.single_result(events)
            self.assertEqual(result.status, "unverifiable")
            self.assertIn("1 archivo(s) con acceso no verificado", result.evidence)

    def test_walk_receives_onerror_and_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            with patch("Guardian.os.walk", return_value=iter([])) as walk:
                events = self.scan(td)

            kwargs = walk.call_args.kwargs
            self.assertIn("onerror", kwargs)
            self.assertTrue(callable(kwargs["onerror"]))
            self.assertFalse(kwargs["followlinks"])
            self.assertEqual(self.single_result(events).status, "ok")

    def test_audit_final_state_with_real_file_scan(self):
        with tempfile.TemporaryDirectory() as td:
            self.touch(os.path.join(td, "password.txt"))
            self.app.selected_path = td

            def put(result):
                def _put():
                    self.app.result_queue.put(("result", result))
                return _put

            with patch.object(self.app, "_check_firewall", new=put(Guardian.CheckResult("Firewall", "ok", "ok"))), \
                 patch.object(self.app, "_check_defender", new=put(Guardian.CheckResult("Defender", "ok", "ok"))), \
                 patch.object(self.app, "_check_rdp", new=put(Guardian.CheckResult("RDP", "ok", "ok"))):
                self.app.iniciar_auditoria()
                self.wait_for_audit()

            self.assertEqual(len(self.app.check_results), 4)
            self.assertFalse(self.app.audit_in_progress)
            self.assertAlmostEqual(self.app.progress_bar.get(), 1.0)
            self.assertEqual(str(self.app.btn_audit.cget("state")), "normal")
            self.assertEqual(str(self.app.btn_new_audit.cget("state")), "normal")

            file_results = [r for r in self.app.check_results if r.name == "Análisis de nombres de archivo"]
            self.assertEqual(len(file_results), 1)
            self.assertEqual(file_results[0].status, "finding")
            self.assertTrue(any("password.txt" in path for path in self.app.sensitive_files))


class StateTests(GuardianGuiTestCase):
    def test_reset_audit_state_clears_all_audit_data(self):
        self.app.check_results = [
            Guardian.CheckResult("A", "ok"),
            Guardian.CheckResult("B", "finding"),
        ]
        self.app.repair_actions = [Guardian.RepairAction("Vieja", "d", "c")]
        self.app.repair_actions_to_run = list(self.app.repair_actions)
        self.app.sensitive_files = ["viejo.txt"]
        self.app.audit_timestamp = "ayer"
        self.app._update_summary_counts()
        self.app.result_queue.put(("stale", None))

        self.app._reset_audit_state()

        self.assertEqual(self.app.check_results, [])
        self.assertEqual(self.app.repair_actions, [])
        self.assertEqual(self.app.repair_actions_to_run, [])
        self.assertEqual(self.app.sensitive_files, [])
        self.assertEqual(self.app.audit_timestamp, "")
        for key in ("ok", "finding", "unverifiable", "error"):
            self.assertEqual(str(self.app.summary_labels[key].cget("text")), "0")
        with self.assertRaises(queue.Empty):
            self.app.result_queue.get_nowait()

    def test_two_consecutive_audits_do_not_inherit_state(self):
        first = [
            Guardian.CheckResult("Primera correcta", "ok"),
            Guardian.CheckResult("Primer hallazgo", "finding", can_fix=True, fix_action="firewall_enable_all"),
            Guardian.CheckResult("Primera incierta", "unverifiable"),
            Guardian.CheckResult("Primer error", "error"),
        ]
        self.start_audit_with_results(first)
        self.app.repair_actions.append(Guardian.RepairAction("Historial", "d", "c"))
        self.app.sensitive_files.append("viejo.txt")

        second = [
            Guardian.CheckResult("Segunda correcta", "ok"),
            Guardian.CheckResult("Segundo hallazgo", "finding"),
            Guardian.CheckResult("Segunda incierta", "unverifiable"),
            Guardian.CheckResult("Segundo error", "error"),
        ]
        self.start_audit_with_results(second)

        self.assertEqual([r.name for r in self.app.check_results], [r.name for r in second])
        self.assertEqual(self.app.repair_actions, [])
        self.assertEqual(self.app.repair_actions_to_run, [])
        self.assertEqual(self.app.sensitive_files, [])
        self.assertNotEqual(self.app.audit_timestamp, "")
        for key in ("ok", "finding", "unverifiable", "error"):
            self.assertEqual(str(self.app.summary_labels[key].cget("text")), "1")
        self.assertEqual(str(self.app.btn_new_audit.cget("state")), "normal")

    def test_repair_dialog_preserves_previous_history(self):
        self.app.check_results = [
            Guardian.CheckResult(
                "Firewall", "finding", can_fix=True, fix_action="firewall_enable_all"
            )
        ]
        old = Guardian.RepairAction("Antigua", "d", "c")
        old.attempted = True
        old.success = True
        old.verified = True
        old.verification_status = "verified"
        self.app.repair_actions = [old]

        with patch.object(self.app, "_is_admin", return_value=True), \
             patch("Guardian.messagebox.askyesno", return_value=False), \
             patch("Guardian.messagebox.showinfo"), \
             patch("Guardian.messagebox.showwarning"), \
             patch("Guardian.threading.Thread") as thread_cls, \
             patch.object(self.app, "after") as after:
            self.app.mostrar_dialogo_reparacion()

        self.assertIn(old, self.app.repair_actions)
        self.assertEqual(len(self.app.repair_actions), 2)
        self.assertTrue(self.app.repair_actions[1].skipped)
        self.assertEqual(self.app.repair_actions[1].verification_status, "skipped")
        self.assertEqual(len(self.app.check_results), 1)
        self.assertFalse(self.app.repair_in_progress)
        thread_cls.assert_not_called()
        after.assert_not_called()

    def test_nueva_auditoria_is_blocked_during_active_operations(self):
        result = Guardian.CheckResult("Viejo", "ok")
        action = Guardian.RepairAction("Vieja", "d", "c")
        self.app.check_results = [result]
        self.app.repair_actions = [action]

        self.app.audit_in_progress = True
        self.app.nueva_auditoria()
        self.assertTrue(self.app.audit_in_progress)
        self.assertEqual(self.app.check_results, [result])
        self.assertEqual(self.app.repair_actions, [action])

        self.app.audit_in_progress = False
        self.app.repair_in_progress = True
        self.app.nueva_auditoria()
        self.assertTrue(self.app.repair_in_progress)
        self.assertEqual(self.app.check_results, [result])
        self.assertEqual(self.app.repair_actions, [action])
        self.app.repair_in_progress = False

    def test_repair_dialog_is_blocked_during_audit(self):
        self.app.check_results = [
            Guardian.CheckResult("Firewall", "finding", can_fix=True, fix_action="firewall_enable_all")
        ]
        self.app.audit_in_progress = True
        with patch("Guardian.messagebox.showinfo") as info:
            self.app.mostrar_dialogo_reparacion()
        info.assert_not_called()
        self.assertEqual(self.app.repair_actions, [])
        self.app.audit_in_progress = False

    def test_failed_audit_can_be_followed_by_another(self):
        def boom():
            raise RuntimeError("fallo simulado")

        with patch.object(self.app, "_check_firewall", new=boom):
            self.app.iniciar_auditoria()
            self.wait_for_audit()

        self.assertFalse(self.app.audit_in_progress)
        self.assertEqual(self.app.check_results, [])
        self.assertEqual(str(self.app.btn_audit.cget("state")), "normal")
        self.assertEqual(str(self.app.btn_report.cget("state")), "disabled")

        second = [
            Guardian.CheckResult("Correcta", "ok"),
            Guardian.CheckResult("Hallazgo", "finding"),
            Guardian.CheckResult("Incierta", "unverifiable"),
            Guardian.CheckResult("Error", "error"),
        ]
        self.start_audit_with_results(second)
        self.assertEqual([r.name for r in self.app.check_results], [r.name for r in second])
        self.assertFalse(self.app.audit_in_progress)

    def test_start_audit_resets_immediately_and_disables_new_audit(self):
        self.app.check_results = [Guardian.CheckResult("Viejo", "ok")]
        self.app.repair_actions = [Guardian.RepairAction("Vieja", "d", "c")]
        self.app.sensitive_files = ["viejo.txt"]
        self.app._update_summary_counts()

        started = threading.Event()
        release = threading.Event()

        def blocking_check():
            started.set()
            release.wait(2)
            self.app.result_queue.put(("result", Guardian.CheckResult("Firewall", "ok")))

        def noop():
            pass

        with patch.object(self.app, "_check_firewall", new=blocking_check), \
             patch.object(self.app, "_check_defender", new=noop), \
             patch.object(self.app, "_check_rdp", new=noop), \
             patch.object(self.app, "_check_sensitive_files", new=noop):
            try:
                self.app.iniciar_auditoria()
                self.assertTrue(started.wait(2), "El worker no llegó a iniciarse")
                self.assertEqual(self.app.check_results, [])
                self.assertEqual(self.app.repair_actions, [])
                self.assertEqual(self.app.sensitive_files, [])
                for key in ("ok", "finding", "unverifiable", "error"):
                    self.assertEqual(str(self.app.summary_labels[key].cget("text")), "0")
                self.assertTrue(self.app.audit_in_progress)
                self.assertEqual(str(self.app.btn_new_audit.cget("state")), "disabled")
            finally:
                release.set()
            self.wait_for_audit()

        self.assertFalse(self.app.audit_in_progress)
        self.assertEqual(str(self.app.btn_new_audit.cget("state")), "normal")


class RenderTests(GuardianGuiTestCase):
    def tags_for(self, status, severity="info"):
        self.app._clear_results()
        self.app._render_result(Guardian.CheckResult(
            "Prueba", status, "evidencia", severity, "recomendación"
        ))
        return {
            tag: bool(self.app.txt_results.tag_ranges(tag))
            for tag in ("ok", "finding", "unverifiable", "error")
        }

    def test_ok_is_green(self):
        tags = self.tags_for("ok", "info")
        self.assertTrue(tags["ok"])
        self.assertFalse(tags["finding"])
        self.assertFalse(tags["unverifiable"])
        self.assertFalse(tags["error"])

    def test_finding_is_not_ok(self):
        tags = self.tags_for("finding", "low")
        self.assertTrue(tags["finding"])
        self.assertFalse(tags["ok"])

    def test_unverifiable_with_info_is_not_ok(self):
        tags = self.tags_for("unverifiable", "info")
        self.assertTrue(tags["unverifiable"])
        self.assertFalse(tags["ok"])

    def test_error_with_info_is_not_ok(self):
        tags = self.tags_for("error", "info")
        self.assertTrue(tags["error"])
        self.assertFalse(tags["ok"])

    def test_unverifiable_with_high_severity_is_not_ok(self):
        tags = self.tags_for("unverifiable", "high")
        self.assertTrue(tags["unverifiable"])
        self.assertFalse(tags["ok"])
        self.assertFalse(tags["finding"])

    def test_error_with_high_severity_is_not_ok(self):
        tags = self.tags_for("error", "high")
        self.assertTrue(tags["error"])
        self.assertFalse(tags["ok"])
        self.assertFalse(tags["finding"])

    def test_unknown_status_is_error_not_ok(self):
        tags = self.tags_for("desconocido", "info")
        self.assertTrue(tags["error"])
        self.assertFalse(tags["ok"])

    def test_ok_with_high_severity_remains_ok(self):
        tags = self.tags_for("ok", "high")
        self.assertTrue(tags["ok"])
        self.assertFalse(tags["finding"])


class RepairRegressionTests(GuardianGuiTestCase):
    @staticmethod
    def cp(stdout="", returncode=0, stderr=""):
        return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)

    def verify_with(self, action, responses):
        def fake_run(cmd, **kwargs):
            script = cmd[-1] if isinstance(cmd, (list, tuple)) else str(cmd)
            for needle, response in responses:
                if needle in script:
                    return response
            raise AssertionError(f"Comando inesperado: {script}")

        with patch("Guardian.subprocess.run", side_effect=fake_run):
            return self.app._verify_repair(action)

    @staticmethod
    def firewall_json(domain=1, private=1, public=1):
        return json.dumps([
            {"Name": "Domain", "Enabled": domain},
            {"Name": "Private", "Enabled": private},
            {"Name": "Public", "Enabled": public},
        ])

    def test_dispatch_uses_action_type_not_command_substring(self):
        action = Guardian.RepairAction(
            "RDP", "d", "Set-NetFirewallProfile -All -Enabled True",
            action_type="rdp_disable"
        )
        action.success = True
        verification = self.verify_with(action, [
            ("Get-ItemProperty", self.cp("0")),
            ("Get-NetFirewallProfile", self.cp(self.firewall_json())),
            ("Get-NetFirewallRule", self.cp("[]")),
        ])
        self.assertEqual(verification.status, "unverified")

    def test_firewall_action_uses_firewall_verification(self):
        action = Guardian.RepairAction(
            "Firewall", "d", "Disable-NetFirewallRule -DisplayName 'x'",
            action_type="firewall_enable_all"
        )
        action.success = True
        verification = self.verify_with(action, [
            ("Get-NetFirewallProfile", self.cp(self.firewall_json())),
            ("Get-NetFirewallRule", self.cp("[]")),
        ])
        self.assertEqual(verification.status, "verified")

    def test_firewall_requires_all_profiles_enabled(self):
        action = Guardian.RepairAction("Firewall", "d", "c", action_type="firewall_enable_all")
        action.success = True
        verification = self.verify_with(action, [
            ("Get-NetFirewallProfile", self.cp(self.firewall_json(public=0))),
        ])
        self.assertEqual(verification.status, "unverified")

    def test_firewall_not_configured_is_unverified(self):
        action = Guardian.RepairAction("Firewall", "d", "c", action_type="firewall_enable_all")
        action.success = True
        verification = self.verify_with(action, [
            ("Get-NetFirewallProfile", self.cp(self.firewall_json(domain=2))),
        ])
        self.assertEqual(verification.status, "unverified")

    def test_firewall_unknown_enum_is_error(self):
        action = Guardian.RepairAction("Firewall", "d", "c", action_type="firewall_enable_all")
        action.success = True
        verification = self.verify_with(action, [
            ("Get-NetFirewallProfile", self.cp(self.firewall_json(domain=3))),
        ])
        self.assertEqual(verification.status, "error")

    def test_firewall_command_failure_is_error(self):
        action = Guardian.RepairAction("Firewall", "d", "c", action_type="firewall_enable_all")
        action.success = True
        verification = self.verify_with(action, [
            ("Get-NetFirewallProfile", self.cp("", returncode=1, stderr="fallo")),
        ])
        self.assertEqual(verification.status, "error")

    def test_defender_requires_exact_true(self):
        action = Guardian.RepairAction("Defender", "d", "c", action_type="defender_enable_rtp")
        action.success = True
        self.assertEqual(
            self.verify_with(action, [("Get-MpComputerStatus", self.cp("True"))]).status,
            "verified"
        )
        self.assertEqual(
            self.verify_with(action, [("Get-MpComputerStatus", self.cp("False"))]).status,
            "unverified"
        )
        self.assertEqual(
            self.verify_with(action, [("Get-MpComputerStatus", self.cp(""))]).status,
            "error"
        )

    def test_rdp_requires_registry_and_firewall_rules(self):
        action = Guardian.RepairAction("RDP", "d", "c", action_type="rdp_disable")
        action.success = True
        verified = self.verify_with(action, [
            ("Get-ItemProperty", self.cp("1")),
            ("Get-NetFirewallRule", self.cp(json.dumps([{"DisplayName": "RDP", "Enabled": 2}]))),
        ])
        self.assertEqual(verified.status, "verified")

        registry_enabled = self.verify_with(action, [
            ("Get-ItemProperty", self.cp("0")),
        ])
        self.assertEqual(registry_enabled.status, "unverified")

        rule_enabled = self.verify_with(action, [
            ("Get-ItemProperty", self.cp("1")),
            ("Get-NetFirewallRule", self.cp(json.dumps([{"DisplayName": "RDP", "Enabled": 1}]))),
        ])
        self.assertEqual(rule_enabled.status, "unverified")

        rule_error = self.verify_with(action, [
            ("Get-ItemProperty", self.cp("1")),
            ("Get-NetFirewallRule", self.cp("", returncode=1, stderr="fallo")),
        ])
        self.assertEqual(rule_error.status, "error")

    def run_rdp_check(self, registry_value, port_open):
        def fake_run(cmd, **kwargs):
            script = cmd[-1] if isinstance(cmd, (list, tuple)) else str(cmd)
            if "Get-ItemProperty" in script:
                return self.cp(registry_value)
            if "Get-NetFirewallRule" in script:
                return self.cp(json.dumps([{"DisplayName": "RDP", "Enabled": 2}]))
            raise AssertionError(f"Comando inesperado: {script}")

        class FakeSocket:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, value):
                pass

            def connect_ex(self, address):
                return 0 if port_open else 1

        with patch("Guardian.subprocess.run", side_effect=fake_run), \
             patch("Guardian.socket.socket", FakeSocket):
            self.app._check_rdp()
        events = self.drain_queue()
        return self.single_result(events)

    def test_rdp_repair_not_offered_from_open_port_alone(self):
        result = self.run_rdp_check("1", port_open=True)
        self.assertEqual(result.status, "unverifiable")
        self.assertFalse(result.can_fix)
        self.assertIn("fDenyTSConnections=1", result.evidence)
        self.assertIn("ABIERTO", result.evidence)

    def test_rdp_repair_offered_when_registry_confirms_enabled(self):
        result = self.run_rdp_check("0", port_open=True)
        self.assertEqual(result.status, "finding")
        self.assertTrue(result.can_fix)
        self.assertEqual(result.fix_action, "rdp_disable")
        self.assertIn("fDenyTSConnections=0", result.evidence)

    def test_unknown_repair_type_is_error(self):
        action = Guardian.RepairAction("Otro", "d", "c", action_type="otro")
        action.success = True
        self.assertEqual(self.app._verify_repair(action).status, "error")

    def test_permission_denied_is_not_executed(self):
        action = Guardian.RepairAction(
            "Firewall", "d", "c", requires_admin=True, action_type="firewall_enable_all"
        )
        with patch("Guardian.messagebox.askyesno") as ask:
            selected = self.app._seleccionar_acciones([action], is_admin=False)
        self.assertEqual(selected, [])
        self.assertTrue(action.skipped)
        self.assertEqual(action.verification_status, "permission_denied")
        ask.assert_not_called()

    def test_user_rejection_is_skipped(self):
        action = Guardian.RepairAction(
            "Firewall", "d", "c", requires_admin=True, action_type="firewall_enable_all"
        )
        with patch("Guardian.messagebox.askyesno", return_value=False):
            selected = self.app._seleccionar_acciones([action], is_admin=True)
        self.assertEqual(selected, [])
        self.assertTrue(action.skipped)
        self.assertEqual(action.verification_status, "skipped")

    def test_worker_rechecks_admin_before_executing(self):
        action = Guardian.RepairAction(
            "Firewall", "d", "c", requires_admin=True, action_type="firewall_enable_all"
        )
        action.selected = True
        self.app.repair_actions = [action]
        self.app.repair_actions_to_run = [action]
        with patch.object(self.app, "_is_admin", return_value=False), \
             patch("Guardian.subprocess.run") as run:
            self.app._worker_reparar()
        self.assertFalse(action.attempted)
        self.assertTrue(action.skipped)
        self.assertEqual(action.verification_status, "permission_denied")
        run.assert_not_called()

    def test_worker_executes_only_current_batch_and_verifies(self):
        old = Guardian.RepairAction("Vieja", "d", "viejo", action_type="firewall_enable_all")
        old.selected = True
        new = Guardian.RepairAction(
            "Nueva", "d", "nuevo", requires_admin=True, action_type="firewall_enable_all"
        )
        new.selected = True
        self.app.repair_actions = [old, new]
        self.app.repair_actions_to_run = [new]

        with patch.object(self.app, "_is_admin", return_value=True), \
             patch("Guardian.subprocess.run", return_value=self.cp()) as run, \
             patch.object(self.app, "_verify_repair",
                          return_value=Guardian.RepairVerification("verified", "ok")):
            self.app._worker_reparar()

        self.assertFalse(old.attempted)
        self.assertTrue(new.attempted)
        self.assertTrue(new.success)
        self.assertTrue(new.verified)
        self.assertEqual(new.verification_status, "verified")
        self.assertEqual(run.call_count, 1)

    def test_failed_action_is_not_verified(self):
        action = Guardian.RepairAction(
            "Firewall", "d", "c", requires_admin=True, action_type="firewall_enable_all"
        )
        action.selected = True
        self.app.repair_actions = [action]
        self.app.repair_actions_to_run = [action]
        with patch.object(self.app, "_is_admin", return_value=True), \
             patch("Guardian.subprocess.run", return_value=self.cp(returncode=1, stderr="fallo")), \
             patch.object(self.app, "_verify_repair") as verify:
            self.app._worker_reparar()
        self.assertTrue(action.attempted)
        self.assertFalse(action.success)
        self.assertFalse(action.verified)
        self.assertEqual(action.verification_status, "not_checked")
        verify.assert_not_called()


class PdfTests(GuardianGuiTestCase):
    def test_pdf_contains_scope_statuses_history_and_privacy_note(self):
        self.app.selected_path = r"C:\Datos\GuardianPrueba"
        self.app.audit_timestamp = "24/10/2026 12:00:00"
        self.app.check_results = [
            Guardian.CheckResult("Correcta", "ok", "todo bien", "info", "nada"),
            Guardian.CheckResult("Hallazgo", "finding", "hallazgo", "high", "revisar"),
            Guardian.CheckResult(
                "Incierta", "unverifiable",
                "Revisados: 2 | Sin coincidencias en lo revisado | Análisis parcial: 1 directorio(s) no recorrido(s)",
                "info", "revisar permisos"
            ),
            Guardian.CheckResult("Error", "error", "fallo de consulta", "info", "revisar"),
        ]
        self.app.sensitive_files = [r"C:\Datos\passwords.txt"]

        verified = Guardian.RepairAction("Verificada", "d", "cmd1", action_type="firewall_enable_all")
        verified.attempted = True
        verified.success = True
        verified.verified = True
        verified.verification_status = "verified"
        verified.verification_evidence = "evidencia verificada"

        unverified = Guardian.RepairAction("No verificada", "d", "cmd2", action_type="firewall_enable_all")
        unverified.attempted = True
        unverified.success = True
        unverified.verification_status = "unverified"
        unverified.verification_evidence = "evidencia insuficiente"

        verror = Guardian.RepairAction("Error de verificación", "d", "cmd3", action_type="firewall_enable_all")
        verror.attempted = True
        verror.success = True
        verror.verification_status = "error"
        verror.verification_evidence = "fallo de verificación"

        failed = Guardian.RepairAction("Fallida", "d", "cmd4", action_type="firewall_enable_all")
        failed.attempted = True
        failed.success = False
        failed.error = "fallo de ejecución"

        skipped = Guardian.RepairAction("Omitida", "d", "cmd5", action_type="firewall_enable_all")
        skipped.skipped = True
        skipped.verification_status = "skipped"
        skipped.skip_reason = "Omitida por el usuario"

        denied = Guardian.RepairAction("Sin permisos", "d", "cmd6", action_type="firewall_enable_all")
        denied.skipped = True
        denied.verification_status = "permission_denied"
        denied.skip_reason = "Requiere permisos de administrador"

        self.app.repair_actions = [verified, unverified, verror, failed, skipped, denied]

        with tempfile.TemporaryDirectory() as td:
            output = os.path.join(td, "informe.pdf")
            real_fpdf = Guardian.FPDF

            def factory(*args, **kwargs):
                pdf = real_fpdf(*args, **kwargs)
                pdf.set_compression(False)
                return pdf

            with patch("Guardian.FPDF", side_effect=factory), \
                 patch("Guardian.filedialog.asksaveasfilename", return_value=output), \
                 patch("Guardian.messagebox.showinfo") as info, \
                 patch("Guardian.messagebox.showerror") as error:
                self.app.crear_pdf()

            info.assert_called_once()
            error.assert_not_called()
            with open(output, "rb") as handle:
                data = handle.read()

        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertGreater(len(data), 1000)
        for needle in (
            b"Alcance",
            b"GuardianPrueba",
            b"NO VERIFICABLE",
            b"HALLAZGO",
            b"ERROR",
            b"EJECUTADA Y VERIFICADA",
            b"EJECUTADA, NO VERIFICADA",
            b"VERIFICACI",
            b"CON ERROR",
            b"FALLIDA",
            b"OMITIDA POR EL USUARIO",
            b"NO EJECUTADA \\(SIN PERMISOS\\)",
            b"PRIVACIDAD",
            b"parcial",
            b"solo nombres, no contenido",
        ):
            self.assertIn(needle, data, f"Falta en el PDF: {needle!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
