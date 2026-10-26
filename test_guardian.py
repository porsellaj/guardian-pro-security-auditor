"""Pruebas de regresión de Guardian Pro.

Se ejecutan con:
    python -m unittest -v

No ejecutan reparaciones reales ni modifican firewall, Defender, RDP o el
registro. Las funciones que dependen de PowerShell se sustituyen por mocks.
"""

import json
import os
import queue
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

import Guardian
import guardian_workspace as workspace


class GuardianGuiTestCase(unittest.TestCase):
    """Base con una instancia real de la interfaz, sin mainloop."""

    def setUp(self):
        self.workspace_temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace_temp.cleanup)
        self.app = Guardian.GuardianProMaster(
            workspace_dir=self.workspace_temp.name,
            device_identity={
                "id": "dev_test_suite",
                "name": "TEST-PC",
                "os": "Windows 11 Pro",
            },
        )
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

    @staticmethod
    def create_directory_link(link, target):
        """Crea un enlace de directorio y devuelve el tipo creado.

        Intenta primero un enlace simbólico. En Windows, si el entorno no
        concede ese privilegio, usa una junction mediante `mklink /J`.
        Devuelve "" si el entorno no permite crear ninguno de los dos.
        """
        try:
            os.symlink(target, link, target_is_directory=True)
            return "symlink"
        except (OSError, NotImplementedError):
            pass

        if os.name == "nt":
            try:
                result = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", link, target],
                    capture_output=True,
                    text=True,
                )
            except OSError:
                return ""
            if result.returncode == 0 and os.path.exists(link):
                return "junction"
        return ""


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

    def test_descendant_link_to_outside_is_excluded_and_reported(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            self.touch(os.path.join(root, "notas.txt"))
            self.touch(os.path.join(outside, "password.txt"))
            link = os.path.join(root, "enlace_externo")
            if not self.create_directory_link(link, outside):
                self.skipTest("El entorno no permite crear enlaces simbólicos ni junctions")

            events = self.scan(root)
            result = self.single_result(events)
            findings = [data for kind, data in events if kind == "file_finding"]

            self.assertEqual(findings, [])
            self.assertEqual(result.status, "unverifiable")
            self.assertIn("enlace(s)/punto(s) de reanálisis excluido(s)", result.evidence)
            self.assertIn("no se puede confirmar", result.recommendation.lower())
            self.assertIn("ámbito autorizado", result.recommendation)

    def test_descendant_link_to_protected_root_is_excluded(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as protected:
            self.touch(os.path.join(root, "notas.txt"))
            self.touch(os.path.join(protected, "password.txt"))
            link = os.path.join(root, "enlace_protegido")
            if not self.create_directory_link(link, protected):
                self.skipTest("El entorno no permite crear enlaces simbólicos ni junctions")

            with patch.dict("Guardian.os.environ", {"ProgramData": protected}, clear=False):
                events = self.scan(root)

            result = self.single_result(events)
            findings = [data for kind, data in events if kind == "file_finding"]

            self.assertEqual(findings, [])
            self.assertEqual(result.status, "unverifiable")
            self.assertIn("enlace(s)/punto(s) de reanálisis excluido(s)", result.evidence)

    def test_walk_outside_authorized_scope_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            self.touch(os.path.join(root, "notas.txt"))
            self.touch(os.path.join(outside, "password.txt"))

            def fake_walk(path, topdown=True, onerror=None, followlinks=False):
                yield path, [], ["notas.txt"]
                yield outside, [], ["password.txt"]

            with patch("Guardian.os.walk", side_effect=fake_walk):
                events = self.scan(root)

            result = self.single_result(events)
            findings = [data for kind, data in events if kind == "file_finding"]

            self.assertEqual(findings, [])
            self.assertEqual(result.status, "unverifiable")
            self.assertIn("fuera del ámbito autorizado", result.evidence)

    def test_selected_link_to_valid_user_folder_is_scanned_by_real_path(self):
        with tempfile.TemporaryDirectory() as parent:
            target = os.path.join(parent, "destino")
            os.mkdir(target)
            self.touch(os.path.join(target, "password.txt"))
            link = os.path.join(parent, "acceso_valido")
            if not self.create_directory_link(link, target):
                self.skipTest("El entorno no permite crear enlaces simbólicos ni junctions")

            events = self.scan(link)
            result = self.single_result(events)
            findings = [data for kind, data in events if kind == "file_finding"]

            self.assertEqual(result.status, "finding")
            self.assertEqual(len(findings), 1)
            self.assertTrue(findings[0].lower().startswith(os.path.realpath(target).lower()))

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


class ProtectedPathTests(GuardianGuiTestCase):
    PROTECTED_ENV = {
        "SystemRoot": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "ProgramFiles": r"C:\Program Files",
        "ProgramFiles(x86)": r"C:\Program Files (x86)",
        "ProgramW6432": r"C:\Program Files",
        "ProgramData": r"C:\ProgramData",
    }

    def test_system_and_program_paths_are_rejected(self):
        with patch.dict("Guardian.os.environ", self.PROTECTED_ENV, clear=False):
            for path in (
                r"C:\Windows",
                r"C:\Windows\System32",
                r"C:\Program Files\Aplicacion",
                r"C:\Program Files (x86)\Aplicacion",
                r"C:\ProgramData\Aplicacion",
            ):
                with self.subTest(path=path):
                    reason = self.app._protected_scan_reason(path)
                    self.assertTrue(reason)
                    self.assertTrue(any(word in reason.lower() for word in ("carpeta", "directorio")))

    def test_drive_root_is_rejected_but_not_all_its_subfolders(self):
        with patch.dict("Guardian.os.environ", self.PROTECTED_ENV, clear=False):
            self.assertIn("unidad", self.app._protected_scan_reason("C:\\"))
            self.assertEqual(self.app._protected_scan_reason(r"C:\Users\Persona"), "")

    def test_similar_prefix_is_not_blocked(self):
        with patch.dict("Guardian.os.environ", self.PROTECTED_ENV, clear=False):
            self.assertEqual(self.app._protected_scan_reason(r"C:\WindowsBackup"), "")
            self.assertEqual(self.app._protected_scan_reason(r"C:\Program Files Backup"), "")
            self.assertEqual(self.app._protected_scan_reason(r"C:\ProgramDataBackup"), "")

    def test_protected_path_comparison_is_case_insensitive(self):
        with patch.dict("Guardian.os.environ", self.PROTECTED_ENV, clear=False):
            self.assertTrue(self.app._protected_scan_reason(r"c:\windows\system32"))
            self.assertTrue(self.app._protected_scan_reason(r"C:/PROGRAM FILES/App"))

    def test_dot_segments_and_mixed_separators_resolve_to_protected(self):
        with patch.dict("Guardian.os.environ", self.PROTECTED_ENV, clear=False):
            for path in (
                r"C:\Windows\System32\..",
                r"C:/Windows/./System32/../",
                r"C:\WINDOWS\System32\Temp\..",
            ):
                with self.subTest(path=path):
                    self.assertTrue(self.app._protected_scan_reason(path, strict=True))

    def test_real_path_resolving_to_protected_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            protected = os.path.join(td, "DatosProtegidos")
            os.mkdir(protected)
            link = os.path.join(td, "acceso_protegido")
            if not self.create_directory_link(link, protected):
                self.skipTest("El entorno no permite crear enlaces simbólicos ni junctions")

            with patch.dict("Guardian.os.environ", {"ProgramData": protected}, clear=False), \
                 patch("Guardian.os.walk") as walk, \
                 patch("Guardian.os.stat") as stat, \
                 patch("Guardian.os.scandir") as scandir:
                events = self.scan(link)

            walk.assert_not_called()
            stat.assert_not_called()
            scandir.assert_not_called()
            result = self.single_result(events)
            self.assertEqual(result.status, "error")
            self.assertIn("Ruta bloqueada", result.evidence)
            self.assertIn("directorio de datos de sistema", result.evidence)
            self.assertEqual([d for k, d in events if k == "file_finding"], [])

    def test_link_to_windows_root_is_rejected_before_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            windows_root = os.environ.get("SystemRoot", r"C:\Windows")
            link = os.path.join(td, "acceso_windows")
            if not self.create_directory_link(link, windows_root):
                self.skipTest("El entorno no permite crear enlaces simbólicos ni junctions")

            with patch("Guardian.os.walk") as walk, \
                 patch("Guardian.os.stat") as stat, \
                 patch("Guardian.os.scandir") as scandir:
                events = self.scan(link)

            walk.assert_not_called()
            stat.assert_not_called()
            scandir.assert_not_called()
            result = self.single_result(events)
            self.assertEqual(result.status, "error")
            self.assertIn("Ruta bloqueada", result.evidence)
            self.assertIn("carpeta del sistema", result.evidence)

    def test_similar_prefix_real_directory_remains_scanable(self):
        with tempfile.TemporaryDirectory() as td:
            system = os.path.join(td, "Windows")
            backup = os.path.join(td, "WindowsBackup")
            os.mkdir(system)
            os.mkdir(backup)
            self.touch(os.path.join(backup, "password.txt"))

            with patch.dict("Guardian.os.environ", {"SystemRoot": system, "WINDIR": system}, clear=False):
                self.assertEqual(self.app._protected_scan_reason(backup, strict=True), "")
                events = self.scan(backup)

            result = self.single_result(events)
            findings = [data for kind, data in events if kind == "file_finding"]
            self.assertEqual(result.status, "finding")
            self.assertEqual(len(findings), 1)
            self.assertIn("WindowsBackup", findings[0])

    def test_unc_share_root_is_rejected_but_descendant_is_not(self):
        def fake_realpath(path, *, strict=False):
            return os.fspath(path)

        with patch("Guardian.os.path.realpath", side_effect=fake_realpath), \
             patch.dict("Guardian.os.environ", self.PROTECTED_ENV, clear=False):
            reason = self.app._protected_scan_reason(r"\\servidor\recurso")
            self.assertTrue(reason)
            self.assertIn("recurso de red", reason)
            self.assertEqual(
                self.app._protected_scan_reason(r"\\servidor\recurso\carpeta"),
                ""
            )
            self.assertTrue(
                self.app._protected_scan_reason(r"\\?\UNC\servidor\recurso")
            )
            self.assertEqual(
                self.app._protected_scan_reason(r"\\?\UNC\servidor\recurso\carpeta"),
                ""
            )

    def test_extended_paths_are_recognized_and_device_volumes_fail_closed(self):
        def fake_realpath(path, *, strict=False):
            return os.fspath(path)

        with patch("Guardian.os.path.realpath", side_effect=fake_realpath), \
             patch.dict("Guardian.os.environ", self.PROTECTED_ENV, clear=False):
            self.assertTrue(self.app._protected_scan_reason(r"\\?\C:\Windows"))
            self.assertTrue(self.app._protected_scan_reason(r"\\.\C:\Windows"))
            self.assertEqual(
                self.app._normalize_path_for_compare(r"\\?\Volume{abc}\Windows"),
                ""
            )
            self.assertEqual(
                self.app._normalize_path_for_compare(r"\\.\Volume{abc}\Windows"),
                ""
            )
            self.assertTrue(
                self.app._protected_scan_reason(r"\\?\Volume{abc}\Windows", strict=True)
            )

    def test_path_resolution_error_fails_safely_before_walk(self):
        with tempfile.TemporaryDirectory() as td:
            self.touch(os.path.join(td, "notas.txt"))
            target = os.path.abspath(td)
            real_realpath = os.path.realpath

            def fake_realpath(path, *, strict=False):
                if os.path.normcase(os.path.abspath(path)) == os.path.normcase(target):
                    raise OSError("fallo simulado de resolución")
                return real_realpath(path, strict=strict)

            with patch("Guardian.os.path.realpath", side_effect=fake_realpath), \
                 patch("Guardian.os.walk") as walk, \
                 patch("Guardian.os.scandir") as scandir:
                events = self.scan(td)

            walk.assert_not_called()
            scandir.assert_not_called()
            result = self.single_result(events)
            self.assertEqual(result.status, "error")
            self.assertIn("No se pudo resolver", result.evidence)
            self.assertIn("vuelva a iniciar", result.recommendation.lower())
            self.assertEqual([d for k, d in events if k == "file_finding"], [])

    def test_folder_dialog_rejects_unresolvable_selection(self):
        original = self.app.selected_path
        with tempfile.TemporaryDirectory() as td:
            missing = os.path.join(td, "no_existe")
            with patch("Guardian.filedialog.askdirectory", return_value=missing), \
                 patch("Guardian.messagebox.showwarning") as warning:
                self.app.elegir_carpeta()

        self.assertEqual(self.app.selected_path, original)
        warning.assert_called_once()
        self.assertIn("no pudo resolver", warning.call_args.args[1].lower())

    def test_folder_dialog_stores_canonical_path(self):
        with tempfile.TemporaryDirectory() as td:
            with patch("Guardian.filedialog.askdirectory", return_value=td), \
                 patch("Guardian.messagebox.showwarning") as warning:
                self.app.elegir_carpeta()

            warning.assert_not_called()
            self.assertEqual(
                os.path.normcase(self.app.selected_path),
                os.path.normcase(os.path.realpath(td, strict=True))
            )

    def test_protected_root_is_blocked_before_walk_or_stat(self):
        with patch.dict("Guardian.os.environ", self.PROTECTED_ENV, clear=False), \
             patch("Guardian.os.walk") as walk, \
             patch("Guardian.os.stat") as stat, \
             patch("Guardian.os.scandir") as scandir:
            events = self.scan(r"C:\Windows")

        walk.assert_not_called()
        stat.assert_not_called()
        scandir.assert_not_called()
        result = self.single_result(events)
        self.assertEqual(result.status, "error")
        self.assertIn("Ruta bloqueada", result.evidence)
        self.assertIn("carpeta del sistema", result.evidence)
        self.assertIn("Seleccione una carpeta de usuario", result.recommendation)
        self.assertEqual([d for k, d in events if k == "file_finding"], [])

    def test_folder_dialog_rejects_protected_selection(self):
        original = self.app.selected_path
        with patch.dict("Guardian.os.environ", self.PROTECTED_ENV, clear=False), \
             patch("Guardian.filedialog.askdirectory", return_value=r"C:\Windows"), \
             patch("Guardian.messagebox.showwarning") as warning:
            self.app.elegir_carpeta()

        self.assertEqual(self.app.selected_path, original)
        warning.assert_called_once()
        self.assertIn("C:\\Windows", warning.call_args.args[1])

    def test_blocked_audit_clears_old_findings_and_restores_ui(self):
        self.app.selected_path = r"C:\Windows"
        self.app.check_results = [Guardian.CheckResult("Viejo", "finding")]
        self.app.sensitive_files = ["viejo.txt"]
        self.app._update_summary_counts()

        def put(result):
            def _put():
                self.app.result_queue.put(("result", result))
            return _put

        with patch.dict("Guardian.os.environ", self.PROTECTED_ENV, clear=False), \
             patch.object(self.app, "_check_firewall", new=put(Guardian.CheckResult("Firewall", "ok"))), \
             patch.object(self.app, "_check_defender", new=put(Guardian.CheckResult("Defender", "ok"))), \
             patch.object(self.app, "_check_rdp", new=put(Guardian.CheckResult("RDP", "ok"))), \
             patch("Guardian.os.walk") as walk, \
             patch("Guardian.os.stat") as stat, \
             patch("Guardian.os.scandir") as scandir:
            self.app.iniciar_auditoria()
            self.wait_for_audit()

        walk.assert_not_called()
        stat.assert_not_called()
        scandir.assert_not_called()
        self.assertEqual(self.app.sensitive_files, [])
        self.assertFalse(self.app.audit_in_progress)
        self.assertEqual(str(self.app.btn_audit.cget("state")), "normal")
        self.assertEqual(str(self.app.btn_new_audit.cget("state")), "normal")
        file_results = [r for r in self.app.check_results if r.name == "Análisis de nombres de archivo"]
        self.assertEqual(len(file_results), 1)
        self.assertEqual(file_results[0].status, "error")
        self.assertIn("Ruta bloqueada", file_results[0].evidence)


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
        self.app.pre_repair_results = [Guardian.CheckResult("Inicial", "finding")]
        self.app.pre_repair_sensitive_files = ["inicial.txt"]
        self.app.pre_repair_timestamp = "antes"
        self.app.pre_repair_path = r"C:\Datos"
        self.app.pre_repair_context_captured = True
        self.app.post_repair_audit_attempted = True
        self.app._update_summary_counts()
        self.app.result_queue.put(("stale", None))

        self.app._reset_audit_state()

        self.assertEqual(self.app.check_results, [])
        self.assertEqual(self.app.repair_actions, [])
        self.assertEqual(self.app.repair_actions_to_run, [])
        self.assertEqual(self.app.sensitive_files, [])
        self.assertEqual(self.app.audit_timestamp, "")
        self.assertEqual(self.app.pre_repair_results, [])
        self.assertEqual(self.app.pre_repair_sensitive_files, [])
        self.assertEqual(self.app.pre_repair_timestamp, "")
        self.assertEqual(self.app.pre_repair_path, "")
        self.assertFalse(self.app.pre_repair_context_captured)
        self.assertFalse(self.app.post_repair_audit_attempted)
        for key in ("ok", "finding", "unverifiable", "error"):
            self.assertEqual(str(self.app.summary_labels[key].cget("text")), "0")
        with self.assertRaises(queue.Empty):
            self.app.result_queue.get_nowait()

    def test_capture_repair_context_is_an_independent_copy(self):
        original = Guardian.CheckResult(
            "Firewall", "finding", "estado inicial", "high", "revisar",
            can_fix=True, fix_action="firewall_enable_all"
        )
        self.app.check_results = [original]
        self.app.sensitive_files = ["inicial.txt"]
        self.app.audit_timestamp = "inicial"
        self.app.selected_path = r"C:\Datos"

        self.app._capture_repair_context()
        original.status = "ok"
        original.evidence = "mutado después"

        self.assertTrue(self.app.pre_repair_context_captured)
        self.assertEqual(self.app.pre_repair_results[0].status, "finding")
        self.assertEqual(self.app.pre_repair_results[0].evidence, "estado inicial")
        self.assertEqual(self.app.pre_repair_sensitive_files, ["inicial.txt"])
        self.assertEqual(self.app.pre_repair_timestamp, "inicial")
        self.assertEqual(self.app.pre_repair_path, r"C:\Datos")

    def test_preserved_reaudit_keeps_context_and_history(self):
        self.app.check_results = [
            Guardian.CheckResult(
                "Firewall", "finding", "inicial", can_fix=True,
                fix_action="firewall_enable_all"
            )
        ]
        self.app.repair_actions = [Guardian.RepairAction("Acción", "d", "c")]
        self.app._capture_repair_context()

        self.app.nueva_auditoria(preserve_repair_context=True)

        self.assertTrue(self.app.pre_repair_context_captured)
        self.assertTrue(self.app.post_repair_audit_attempted)
        self.assertEqual(len(self.app.pre_repair_results), 1)
        self.assertEqual(len(self.app.repair_actions), 1)
        self.assertEqual(self.app.check_results, [])
        self.assertEqual(self.app.sensitive_files, [])

        self.app.nueva_auditoria()
        self.assertFalse(self.app.pre_repair_context_captured)
        self.assertFalse(self.app.post_repair_audit_attempted)
        self.assertEqual(self.app.pre_repair_results, [])
        self.assertEqual(self.app.repair_actions, [])

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

    def test_defender_finding_does_not_disable_other_repairs(self):
        defender = Guardian.CheckResult(
            "Microsoft Defender", "finding", "Protección desactivada", "high",
            Guardian.GuardianProMaster.DEFENDER_MANUAL_INTRO,
            manual_guidance=Guardian.GuardianProMaster.DEFENDER_MANUAL_DETAILS
        )
        self.start_audit_with_results([defender])
        self.assertEqual(str(self.app.btn_repair.cget("state")), "disabled")

        firewall = Guardian.CheckResult(
            "Firewall de Windows", "finding", can_fix=True,
            fix_action="firewall_enable_all"
        )
        self.start_audit_with_results([defender, firewall])
        self.assertEqual(str(self.app.btn_repair.cget("state")), "normal")

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

    def test_unresolvable_path_audit_can_be_followed_by_another(self):
        with tempfile.TemporaryDirectory() as td:
            self.touch(os.path.join(td, "notas.txt"))
            target = os.path.abspath(td)
            real_realpath = os.path.realpath

            def fake_realpath(path, *, strict=False):
                if os.path.normcase(os.path.abspath(path)) == os.path.normcase(target):
                    raise OSError("fallo simulado de resolución")
                return real_realpath(path, strict=strict)

            def put(result):
                def _put():
                    self.app.result_queue.put(("result", result))
                return _put

            self.app.selected_path = td
            with patch("Guardian.os.path.realpath", side_effect=fake_realpath), \
                 patch.object(self.app, "_check_firewall", new=put(Guardian.CheckResult("Firewall", "ok", "ok"))), \
                 patch.object(self.app, "_check_defender", new=put(Guardian.CheckResult("Defender", "ok", "ok"))), \
                 patch.object(self.app, "_check_rdp", new=put(Guardian.CheckResult("RDP", "ok", "ok"))):
                self.app.iniciar_auditoria()
                self.wait_for_audit()

            self.assertFalse(self.app.audit_in_progress)
            file_results = [r for r in self.app.check_results if r.name == "Análisis de nombres de archivo"]
            self.assertEqual(len(file_results), 1)
            self.assertEqual(file_results[0].status, "error")
            self.assertIn("No se pudo resolver", file_results[0].evidence)
            self.assertEqual(str(self.app.btn_new_audit.cget("state")), "normal")

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

    def test_defender_manual_guidance_is_visible_in_ui(self):
        self.app._clear_results()
        self.app._render_result(Guardian.CheckResult(
            "Microsoft Defender", "finding",
            "Protección en tiempo real: Deshabilitada", "high",
            Guardian.GuardianProMaster.DEFENDER_MANUAL_INTRO,
            manual_guidance=Guardian.GuardianProMaster.DEFENDER_MANUAL_DETAILS
        ))
        text = self.app.txt_results.get("1.0", "end")
        for needle in (
            "Requiere intervención manual",
            "Seguridad de Windows",
            "Administrar la configuración",
            "Protección en tiempo real",
            "Protección contra alteraciones",
            "nueva auditoría",
        ):
            self.assertIn(needle, text)

    def test_active_defender_ui_does_not_show_manual_guide(self):
        self.app._clear_results()
        self.app._render_result(Guardian.CheckResult(
            "Microsoft Defender", "ok",
            "Protección en tiempo real: Habilitada", "info",
            "La protección en tiempo real está activa."
        ))
        text = self.app.txt_results.get("1.0", "end")
        self.assertNotIn("Seguridad de Windows", text)
        self.assertNotIn("intervención manual", text)


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

    @staticmethod
    def defender_json(realtime=True, tamper=False, antivirus=True,
                      mode="Normal", preference=False):
        return json.dumps({
            "RealTimeProtectionEnabled": realtime,
            "IsTamperProtected": tamper,
            "AntivirusEnabled": antivirus,
            "AMRunningMode": mode,
            "DisableRealtimeMonitoring": preference,
        })

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

    def test_defender_active_is_ok_without_manual_guidance(self):
        status = json.loads(self.defender_json(realtime=True))
        with patch.object(self.app, "_query_defender_status", return_value=status):
            self.app._check_defender()
        result = self.single_result(self.drain_queue())
        self.assertEqual(result.status, "ok")
        self.assertFalse(result.can_fix)
        self.assertEqual(result.fix_action, "")
        self.assertEqual(result.manual_guidance, "")
        self.assertIn("Protección en tiempo real: Habilitada", result.evidence)
        self.assertNotIn("Seguridad de Windows", result.recommendation)

    def test_defender_disabled_is_finding_with_manual_guidance(self):
        status = json.loads(self.defender_json(realtime=False, tamper=True))
        with patch.object(self.app, "_query_defender_status", return_value=status):
            self.app._check_defender()
        result = self.single_result(self.drain_queue())

        self.assertEqual(result.status, "finding")
        self.assertFalse(result.can_fix)
        self.assertEqual(result.fix_action, "")
        self.assertIn("Deshabilitada", result.evidence)
        self.assertIn("Tamper Protection: Activada", result.evidence)
        self.assertIn("Requiere intervención manual", result.recommendation)
        self.assertIn("Seguridad de Windows", result.recommendation)
        self.assertNotIn("reparación automática", result.recommendation.lower())

        for step in (
            "1. Abre el menú Inicio.",
            "2. Busca y abre 'Seguridad de Windows'",
            "3. Entra en 'Protección antivirus y contra amenazas'",
            "4. En 'Configuración de protección antivirus y contra amenazas'",
            "5. Busca 'Protección en tiempo real'",
            "6. Regresa a Guardian y ejecuta una nueva auditoría",
        ):
            self.assertIn(step, result.manual_guidance)
        self.assertIn("Protección contra alteraciones", result.manual_guidance)
        self.assertIn("directiva de administración", result.manual_guidance)
        self.assertIn("No intentes eludir esas restricciones", result.manual_guidance)

    def test_defender_query_error_is_not_confirmed_finding(self):
        cases = (
            (TimeoutExpired(cmd="powershell", timeout=15), "error"),
            (RuntimeError("PowerShell no disponible"), "unverifiable"),
        )
        for error, expected in cases:
            with self.subTest(expected=expected):
                with patch.object(self.app, "_query_defender_status", side_effect=error):
                    self.app._check_defender()
                result = self.single_result(self.drain_queue())
                self.assertEqual(result.status, expected)
                self.assertNotIn(result.status, ("ok", "finding"))
                self.assertFalse(result.can_fix)

    def test_defender_finding_does_not_create_repair_action(self):
        self.app.check_results = [
            Guardian.CheckResult(
                "Microsoft Defender", "finding", "Protección desactivada", "high",
                Guardian.GuardianProMaster.DEFENDER_MANUAL_INTRO,
                manual_guidance=Guardian.GuardianProMaster.DEFENDER_MANUAL_DETAILS
            )
        ]
        self.assertEqual(self.app._build_repair_actions(), [])

        # Tampoco debe revivir la acción antigua si un resultado legado la conserva.
        self.app.check_results = [
            Guardian.CheckResult(
                "Microsoft Defender", "finding", can_fix=True,
                fix_action="defender_enable_rtp"
            )
        ]
        self.assertEqual(self.app._build_repair_actions(), [])

    def test_repair_selection_cannot_execute_defender_change(self):
        self.app.check_results = [
            Guardian.CheckResult(
                "Microsoft Defender", "finding", "Protección desactivada", "high",
                Guardian.GuardianProMaster.DEFENDER_MANUAL_INTRO,
                manual_guidance=Guardian.GuardianProMaster.DEFENDER_MANUAL_DETAILS
            ),
            Guardian.CheckResult(
                "Firewall de Windows", "finding", can_fix=True,
                fix_action="firewall_enable_all"
            ),
            Guardian.CheckResult(
                "Escritorio Remoto (RDP)", "finding", can_fix=True,
                fix_action="rdp_disable"
            ),
        ]
        actions = self.app._build_repair_actions()
        self.assertEqual(
            [action.action_type for action in actions],
            ["firewall_enable_all", "rdp_disable"]
        )
        for action in actions:
            self.assertNotIn("Set-MpPreference", action.command)
            self.assertNotIn("DisableRealtimeMonitoring", action.command)
            self.assertNotIn("RealTimeProtection", action.command)

        with patch("Guardian.messagebox.askyesno", return_value=True):
            selected = self.app._seleccionar_acciones(actions, is_admin=True)
        self.assertEqual(selected, actions)
        self.assertTrue(all(a.action_type != "defender_enable_rtp" for a in selected))

    def test_firewall_repair_does_not_mark_defender_fixed(self):
        defender = Guardian.CheckResult(
            "Microsoft Defender", "finding", "Protección desactivada", "high",
            Guardian.GuardianProMaster.DEFENDER_MANUAL_INTRO,
            manual_guidance=Guardian.GuardianProMaster.DEFENDER_MANUAL_DETAILS
        )
        firewall = Guardian.CheckResult(
            "Firewall de Windows", "finding", can_fix=True,
            fix_action="firewall_enable_all"
        )
        self.app.check_results = [defender, firewall]
        actions = self.app._build_repair_actions()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].action_type, "firewall_enable_all")
        self.app.repair_actions = list(actions)
        self.app.repair_actions_to_run = list(actions)

        with patch.object(self.app, "_is_admin", return_value=True), \
             patch("Guardian.subprocess.run", return_value=self.cp()), \
             patch.object(self.app, "_verify_repair",
                          return_value=Guardian.RepairVerification("verified", "ok")):
            self.app._worker_reparar()

        self.assertTrue(actions[0].attempted)
        self.assertTrue(actions[0].verified)
        self.assertEqual(defender.status, "finding")
        self.assertFalse(defender.can_fix)
        self.assertEqual(self.app.repair_actions, actions)
        self.assertFalse(any(a.name == "Microsoft Defender" for a in self.app.repair_actions))

        # La misma separación se aplica a RDP: solo se construye su acción.
        self.app.check_results = [
            defender,
            Guardian.CheckResult(
                "Escritorio Remoto (RDP)", "finding", can_fix=True,
                fix_action="rdp_disable"
            ),
        ]
        rdp_actions = self.app._build_repair_actions()
        self.assertEqual([a.action_type for a in rdp_actions], ["rdp_disable"])
        self.assertFalse(any(a.name == "Microsoft Defender" for a in rdp_actions))

    def test_source_has_no_automatic_defender_repair_command(self):
        with open(Guardian.__file__, encoding="utf-8") as handle:
            source = handle.read()
        self.assertNotIn("Set-MpPreference", source)
        self.assertNotIn("defender_enable_rtp", source)

    def test_firewall_and_rdp_actions_remain_available(self):
        self.app.check_results = [
            Guardian.CheckResult(
                "Firewall de Windows", "finding", can_fix=True,
                fix_action="firewall_enable_all"
            ),
            Guardian.CheckResult(
                "Escritorio Remoto (RDP)", "finding", can_fix=True,
                fix_action="rdp_disable"
            ),
        ]
        actions = self.app._build_repair_actions()
        self.assertEqual(
            [action.action_type for action in actions],
            ["firewall_enable_all", "rdp_disable"]
        )
        self.assertTrue(all(action.requires_admin for action in actions))

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
    @staticmethod
    def defender_finding(evidence="Protección en tiempo real: Deshabilitada"):
        return Guardian.CheckResult(
            "Microsoft Defender", "finding", evidence, "high",
            Guardian.GuardianProMaster.DEFENDER_MANUAL_INTRO,
            manual_guidance=Guardian.GuardianProMaster.DEFENDER_MANUAL_DETAILS
        )

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

    def test_pdf_represents_path_resolution_error_and_link_exclusion(self):
        self.app.selected_path = r"C:\Datos\Prueba"
        self.app.audit_timestamp = "25/10/2026 10:00:00"
        self.app.check_results = [
            Guardian.CheckResult(
                "Análisis de nombres de archivo", "error",
                r"No se pudo resolver la ruta seleccionada de forma segura: C:\Datos\Enlace",
                "info",
                "Seleccione una carpeta de usuario o una carpeta de pruebas y vuelva a iniciar la auditoría."
            ),
            Guardian.CheckResult(
                "Análisis de nombres de archivo", "unverifiable",
                "Revisados: 3 archivos | Sin coincidencias en lo revisado | "
                "Análisis parcial: 1 enlace(s)/punto(s) de reanálisis excluido(s)",
                "info",
                "No se puede confirmar la ausencia de nombres sensibles. Los enlaces se "
                "excluyeron para no salir del ámbito autorizado."
            ),
        ]

        data = self._render_current_pdf()

        for needle in (
            b"ERROR",
            b"NO VERIFICABLE",
            b"No se pudo resolver",
            b"enlace",
            b"excluido",
            b"autorizado",
        ):
            self.assertIn(needle, data, f"Falta en el PDF: {needle!r}")

    def _render_current_pdf(self):
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
                return handle.read()

    def test_pdf_defender_finding_includes_manual_activation_section(self):
        self.app.selected_path = r"C:\Datos\Prueba"
        self.app.audit_timestamp = "25/10/2026 10:00:00"
        self.app.check_results = [self.defender_finding()]

        data = self._render_current_pdf()

        for needle in (
            b"ACTIVACI",
            b"MANUAL DE MICROSOFT DEFENDER",
            b"Seguridad de Windows",
            b"Administrar la configuraci",
            b"Protecci",
            b"tiempo real",
            b"nueva auditor",
            b"Protecci",
            b"alteraciones",
            b"directiva de administraci",
            b"no modifica autom",
        ):
            self.assertIn(needle, data, f"Falta en la guía manual del PDF: {needle!r}")
        self.assertNotIn(b"Set-MpPreference", data)

    def test_pdf_active_defender_has_no_manual_activation_section(self):
        self.app.selected_path = r"C:\Datos\Prueba"
        self.app.audit_timestamp = "25/10/2026 10:00:00"
        self.app.check_results = [
            Guardian.CheckResult(
                "Microsoft Defender", "ok",
                "Protección en tiempo real: Habilitada", "info",
                "La protección en tiempo real está activa."
            )
        ]

        data = self._render_current_pdf()

        self.assertNotIn(b"ACTIVACI", data)
        self.assertNotIn(b"Seguridad de Windows", data)

    def test_pdf_manual_activation_is_not_attributed_to_guardian(self):
        self.app.selected_path = r"C:\Datos\Prueba"
        self.app.audit_timestamp = "25/10/2026 10:05:00"
        self.app.pre_repair_context_captured = True
        self.app.pre_repair_path = r"C:\Datos\Prueba"
        self.app.pre_repair_timestamp = "25/10/2026 10:00:00"
        self.app.pre_repair_results = [self.defender_finding()]
        self.app.pre_repair_sensitive_files = []
        self.app.repair_actions = []
        self.app.post_repair_audit_attempted = True
        self.app.check_results = [
            Guardian.CheckResult(
                "Microsoft Defender", "ok",
                "Protección en tiempo real: Habilitada", "info",
                "La protección en tiempo real está activa."
            )
        ]

        data = self._render_current_pdf()

        self.assertIn(b"ACTIVACI", data)
        self.assertIn(b"Estado posterior", data)
        self.assertIn(b"Habilitada", data)
        self.assertNotIn(b"Guardian activ", data)
        self.assertNotIn(b"Set-MpPreference", data)
        self.assertNotIn(b"defender_enable_rtp", data)

    def test_pdf_firewall_repair_keeps_defender_manual_guidance(self):
        self.app.selected_path = r"C:\Datos\Prueba"
        self.app.audit_timestamp = "25/10/2026 10:05:00"
        self.app.pre_repair_context_captured = True
        self.app.pre_repair_path = r"C:\Datos\Prueba"
        self.app.pre_repair_timestamp = "25/10/2026 10:00:00"
        self.app.pre_repair_results = [
            self.defender_finding(),
            Guardian.CheckResult(
                "Firewall de Windows", "finding", "Firewall desactivado", "high",
                "Activar firewall", can_fix=True, fix_action="firewall_enable_all"
            ),
        ]
        self.app.pre_repair_sensitive_files = []
        firewall = Guardian.RepairAction(
            "Habilitar firewall", "d", "Set-NetFirewallProfile -All -Enabled True",
            action_type="firewall_enable_all"
        )
        firewall.attempted = True
        firewall.success = True
        firewall.verified = True
        firewall.verification_status = "verified"
        firewall.verification_evidence = "Tres perfiles habilitados"
        self.app.repair_actions = [firewall]
        self.app.post_repair_audit_attempted = True
        self.app.check_results = [
            self.defender_finding("Protección en tiempo real: Deshabilitada"),
            Guardian.CheckResult(
                "Firewall de Windows", "ok", "Tres perfiles habilitados", "info", "Nada"
            ),
        ]

        data = self._render_current_pdf()

        for needle in (
            b"ACTIVACI",
            b"MANUAL DE MICROSOFT DEFENDER",
            b"Seguridad de Windows",
            b"Habilitar firewall",
            b"EJECUTADA Y VERIFICADA",
            b"Estado posterior",
            b"Deshabilitada",
        ):
            self.assertIn(needle, data, f"Falta en el PDF tras reparar firewall: {needle!r}")
        self.assertNotIn(b"Set-MpPreference", data)

    def test_pdf_repair_cycle_contains_initial_actions_and_post_state(self):
        self.app.selected_path = r"C:\Datos\Prueba"
        self.app.audit_timestamp = "25/10/2026 10:05:00"
        self.app.pre_repair_context_captured = True
        self.app.pre_repair_path = r"C:\Datos\Prueba"
        self.app.pre_repair_timestamp = "25/10/2026 10:00:00"
        self.app.pre_repair_results = [
            Guardian.CheckResult(
                "Firewall", "finding", "Firewall desactivado", "high", "Activar firewall"
            )
        ]
        self.app.pre_repair_sensitive_files = []
        action = Guardian.RepairAction(
            "Habilitar firewall", "d", "Set-NetFirewallProfile -All -Enabled True",
            action_type="firewall_enable_all"
        )
        action.attempted = True
        action.success = True
        action.verified = True
        action.verification_status = "verified"
        action.verification_evidence = "Tres perfiles habilitados"
        self.app.repair_actions = [action]
        self.app.post_repair_audit_attempted = True
        self.app.check_results = [
            Guardian.CheckResult("Firewall", "ok", "Tres perfiles habilitados", "info", "Nada")
        ]

        data = self._render_current_pdf()

        for needle in (
            b"Estado inicial",
            b"Firewall desactivado",
            b"HALLAZGO",
            b"Acciones de correcci",
            b"EJECUTADA Y VERIFICADA",
            b"Estado posterior",
            b"OK",
            b"Auditor",
            b"Reauditor",
        ):
            self.assertIn(needle, data, f"Falta en el PDF del ciclo: {needle!r}")

    def test_pdf_failed_repair_without_reaudit_does_not_claim_resolution(self):
        self.app.selected_path = r"C:\Datos\Prueba"
        self.app.pre_repair_context_captured = True
        self.app.pre_repair_path = r"C:\Datos\Prueba"
        self.app.pre_repair_timestamp = "25/10/2026 10:00:00"
        self.app.pre_repair_results = [
            self.defender_finding(),
            Guardian.CheckResult(
                "Firewall de Windows", "finding", "Firewall desactivado", "high",
                "Activar firewall", can_fix=True, fix_action="firewall_enable_all"
            ),
        ]
        self.app.pre_repair_sensitive_files = []
        failed = Guardian.RepairAction(
            "Habilitar firewall", "d", "Set-NetFirewallProfile -All -Enabled True",
            action_type="firewall_enable_all"
        )
        failed.attempted = True
        failed.success = False
        failed.error = "Comando bloqueado"
        failed.verification_status = "not_checked"
        self.app.repair_actions = [failed]
        self.app.post_repair_audit_attempted = False
        self.app.check_results = []

        data = self._render_current_pdf()

        self.assertIn(b"Estado inicial", data)
        self.assertIn(b"Firewall desactivado", data)
        self.assertIn(b"HALLAZGO", data)
        self.assertIn(b"FALLIDA", data)
        self.assertIn(b"ACTIVACI", data)
        self.assertIn(b"MANUAL DE MICROSOFT DEFENDER", data)
        self.assertIn(b"No se realiz", data)
        self.assertIn(b"no est", data)
        self.assertNotIn(b"EJECUTADA Y VERIFICADA", data)
        self.assertNotIn(b"Set-MpPreference", data)

    def test_pdf_failed_repair_with_reaudit_keeps_finding(self):
        self.app.selected_path = r"C:\Datos\Prueba"
        self.app.audit_timestamp = "25/10/2026 10:05:00"
        self.app.pre_repair_context_captured = True
        self.app.pre_repair_path = r"C:\Datos\Prueba"
        self.app.pre_repair_timestamp = "25/10/2026 10:00:00"
        self.app.pre_repair_results = [
            self.defender_finding(),
            Guardian.CheckResult(
                "Firewall de Windows", "finding", "Firewall desactivado", "high",
                "Activar firewall", can_fix=True, fix_action="firewall_enable_all"
            ),
        ]
        self.app.pre_repair_sensitive_files = []
        failed = Guardian.RepairAction(
            "Habilitar firewall", "d", "Set-NetFirewallProfile -All -Enabled True",
            action_type="firewall_enable_all"
        )
        failed.attempted = True
        failed.success = False
        failed.error = "Comando bloqueado"
        failed.verification_status = "not_checked"
        self.app.repair_actions = [failed]
        self.app.post_repair_audit_attempted = True
        self.app.check_results = [
            self.defender_finding("Protección en tiempo real: Deshabilitada"),
            Guardian.CheckResult(
                "Firewall de Windows", "finding", "Firewall sigue desactivado", "high",
                "Revisar manualmente"
            ),
        ]

        data = self._render_current_pdf()

        self.assertIn(b"Estado inicial", data)
        self.assertIn(b"Firewall desactivado", data)
        self.assertIn(b"FALLIDA", data)
        self.assertIn(b"Estado posterior", data)
        self.assertIn(b"Firewall sigue desactivado", data)
        self.assertIn(b"ACTIVACI", data)
        self.assertIn(b"MANUAL DE MICROSOFT DEFENDER", data)
        self.assertNotIn(b"EJECUTADA Y VERIFICADA", data)
        self.assertNotIn(b"Set-MpPreference", data)

    def test_new_audit_pdf_does_not_include_previous_repair_cycle(self):
        self.app.pre_repair_context_captured = True
        self.app.pre_repair_results = [
            Guardian.CheckResult("Viejo", "finding", "evidencia_inicial_unica")
        ]
        self.app.pre_repair_timestamp = "antes"
        self.app.pre_repair_path = r"C:\Viejo"
        self.app.repair_actions = [
            Guardian.RepairAction("Accion vieja", "d", "cmd")
        ]
        self.app.post_repair_audit_attempted = True
        self.app.audit_timestamp = "nueva"
        self.app.selected_path = r"C:\Nueva"
        self.app.check_results = [
            Guardian.CheckResult("Nuevo", "ok", "evidencia_nueva_unica")
        ]
        self.app._reset_audit_state()
        self.app.audit_timestamp = "nueva"
        self.app.selected_path = r"C:\Nueva"
        self.app.check_results = [
            Guardian.CheckResult("Nuevo", "ok", "evidencia_nueva_unica")
        ]

        data = self._render_current_pdf()

        self.assertIn(b"evidencia_nueva_unica", data)
        self.assertNotIn(b"evidencia_inicial_unica", data)
        self.assertNotIn(b"Accion vieja", data)
        self.assertFalse(self.app.pre_repair_context_captured)

    def test_finish_repairs_requests_preserving_reaudit(self):
        action = Guardian.RepairAction("Accion", "d", "cmd")
        action.attempted = True
        self.app.repair_actions_to_run = [action]
        self.app.repair_in_progress = True
        self.app.check_results = [Guardian.CheckResult("Firewall", "finding")]

        with patch("Guardian.messagebox.askyesno", return_value=True), \
             patch.object(self.app, "nueva_auditoria") as new_audit:
            self.app._finish_repairs()

        new_audit.assert_called_once_with(auto_start=True, preserve_repair_context=True)


class OperationsCenterTests(GuardianGuiTestCase):
    """Integración de las vistas nuevas con el ciclo de auditoría existente."""

    def wait_for_import(self, timeout=6):
        deadline = time.time() + timeout
        while self.app.import_in_progress and time.time() < deadline:
            self.app.update()
            time.sleep(0.01)
        self.app.update()
        self.assertFalse(self.app.import_in_progress, "La importación no terminó a tiempo")

    @staticmethod
    def make_report(device_id, name, status, when, audit_id):
        record = workspace.build_audit_record(
            [{
                "name": "Firewall de Windows",
                "status": status,
                "severity": "high" if status == "finding" else "info",
                "recommendation": "Habilite el firewall y vuelva a auditar.",
            }],
            {"id": device_id, "name": name, "os": "Windows 11 Pro"},
            collected_at=when,
            audit_id=audit_id,
        )
        return workspace.report_from_audit(record)

    @staticmethod
    def write_report(path, report):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False)

    def render_pdf(self):
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
            self.assertFalse(error.called, error.call_args)
            with open(output, "rb") as handle:
                return handle.read()

    def test_operations_center_views_and_legacy_controls_exist(self):
        self.assertIn("overview", self.app.views)
        self.assertIn("action", self.app.views)
        self.assertIn("history", self.app.views)
        self.assertIn("fleet", self.app.views)
        self.assertIn("audit", self.app.views)
        for key in ("ok", "finding", "unverifiable", "error"):
            self.assertIn(key, self.app.summary_labels)
        for name in (
            "btn_audit", "btn_repair", "btn_report", "btn_new_audit",
            "btn_select_folder", "btn_export_json", "btn_import_json",
            "btn_demo_toggle", "txt_results", "lbl_progress", "progress_bar",
        ):
            self.assertTrue(hasattr(self.app, name), name)
        self.app.show_view("fleet")
        self.assertEqual(self.app.current_view, "fleet")
        self.assertEqual(str(self.app.header_title.cget("text")), "Vista de equipos")
        self.app.show_view("overview")

    def test_finished_audits_are_saved_and_compared(self):
        first = Guardian.CheckResult(
            "Firewall de Windows", "finding", "perfil público desactivado", "high",
            "Habilite el firewall.", can_fix=True, fix_action="firewall_enable_all",
        )
        second = Guardian.CheckResult(
            "Firewall de Windows", "ok", "todos los perfiles activos", "info",
            "Mantener la configuración.",
        )
        self.start_audit_with_results([first])
        self.assertEqual(len(self.app.history), 1)
        self.assertIsNotNone(self.app.current_audit_record)
        self.assertEqual(
            self.app.current_audit_record["checks"][0]["check_id"], "firewall"
        )

        self.start_audit_with_results([second])
        self.assertEqual(len(self.app.history), 2)
        comparison = self.app.current_audit_record.get("comparison")
        self.assertIsNotNone(comparison)
        self.assertEqual(comparison["summary"]["resolved"], 1)
        self.app.show_view("history")
        self.app.update_idletasks()

    def test_demo_is_in_memory_and_disables_real_actions(self):
        history_before = len(self.app.history)
        self.app._toggle_demo()
        self.assertTrue(self.app.demo_mode)
        self.assertEqual(len(self.app.demo_audits), 4)
        self.assertEqual(
            len({record["device"]["id"] for record in self.app.demo_audits}), 3
        )
        self.assertTrue(self.app.demo_banner.grid_info())
        self.assertEqual(str(self.app.btn_audit.cget("state")), "disabled")
        self.assertEqual(str(self.app.btn_repair.cget("state")), "disabled")
        self.assertEqual(str(self.app.btn_report.cget("state")), "disabled")
        self.assertEqual(str(self.app.btn_export_json.cget("state")), "disabled")
        self.assertEqual(str(self.app.btn_import_json.cget("state")), "disabled")
        self.assertFalse(self.app._current_action_context()[2])
        self.app._focus_on_record(self.app.demo_audits[-1], "demo")
        self.assertEqual(self.app.current_view, "action")
        self.assertEqual(str(self.app.btn_repair.cget("state")), "disabled")

        self.app._toggle_demo()
        self.assertFalse(self.app.demo_mode)
        self.assertEqual(self.app.demo_audits, [])
        self.assertEqual(len(self.app.history), history_before)
        self.assertFalse(self.app.demo_banner.grid_info())
        self.assertEqual(str(self.app.btn_audit.cget("state")), "normal")

    def test_import_async_adds_reports_and_detects_duplicates(self):
        with tempfile.TemporaryDirectory() as td:
            first = self.make_report(
                "dev_import_a", "IMPORT-A", "finding",
                (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec="seconds"),
                "audit_import_a",
            )
            second = self.make_report(
                "dev_import_b", "IMPORT-B", "ok",
                (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(timespec="seconds"),
                "audit_import_b",
            )
            path_a = os.path.join(td, "a.json")
            path_b = os.path.join(td, "b.json")
            self.write_report(path_a, first)
            self.write_report(path_b, second)

            with patch("Guardian.filedialog.askopenfilenames", return_value=(path_a, path_b)), \
                 patch("Guardian.messagebox.showinfo"):
                self.app._start_import()
                self.wait_for_import()
            self.assertEqual(len(self.app.fleet_reports), 2)
            self.assertTrue(any("nuevo" in message for message in self.app.import_messages))
            self.assertEqual(self.app.current_view, "fleet")

            with patch("Guardian.filedialog.askopenfilenames", return_value=(path_a,)), \
                 patch("Guardian.messagebox.showinfo"):
                self.app._start_import()
                self.wait_for_import()
            self.assertEqual(len(self.app.fleet_reports), 2)
            self.assertTrue(any("duplicado" in message for message in self.app.import_messages))

    def test_imported_report_plan_is_read_only(self):
        report = self.make_report(
            "dev_readonly", "READONLY", "finding",
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "audit_readonly",
        )
        self.app.focus_record = report
        self.app.focus_source = "imported"
        self.app._refresh_action_view()
        self.app._refresh_sidebar_state()
        self.assertFalse(self.app._current_action_context()[2])
        self.assertEqual(str(self.app.btn_repair.cget("state")), "disabled")
        plan = workspace.build_action_plan(report["checks"], allow_repair=False)
        self.assertTrue(plan)
        self.assertFalse(any(item["can_repair"] for item in plan))

    def test_export_requires_confirmation_and_excludes_paths(self):
        record = workspace.build_audit_record(
            [{
                "name": "Análisis de nombres de archivo",
                "status": "finding",
                "severity": "low",
                "recommendation": r"Revise C:\Users\Ana\passwords.txt",
            }],
            {"id": "dev_export", "name": "EXPORT-PC", "os": "Windows 11 Pro"},
            collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            audit_id="audit_export_ui",
        )
        self.app.current_audit_record = record
        with patch("Guardian.messagebox.askokcancel", return_value=False) as confirm, \
             patch("Guardian.filedialog.asksaveasfilename") as save:
            self.app._export_current_report()
        confirm.assert_called_once()
        save.assert_not_called()

        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "export.json")
            with patch("Guardian.messagebox.askokcancel", return_value=True), \
                 patch("Guardian.filedialog.asksaveasfilename", return_value=target), \
                 patch("Guardian.messagebox.showinfo"):
                self.app._export_current_report()
            with open(target, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            workspace.validate_report(payload)
            text = json.dumps(payload)
            self.assertNotIn("passwords.txt", text)
            self.assertNotIn(r"C:\Users", text)

    def test_storage_failure_does_not_break_audit_or_pdf(self):
        result = Guardian.CheckResult(
            "Firewall de Windows", "finding", "evidencia", "high",
            "Habilite el firewall.", can_fix=True, fix_action="firewall_enable_all",
        )
        with patch.object(
            self.app.workspace, "save_audit",
            side_effect=workspace.WorkspaceError("fallo simulado"),
        ):
            self.start_audit_with_results([result])
        self.assertEqual(self.app.history, [])
        self.assertIsNotNone(self.app.current_audit_record)
        self.assertIn("fallo simulado", self.app.storage_warning)
        self.assertFalse(self.app.audit_in_progress)

    def test_pdf_executive_summary_is_first_and_honest_without_history(self):
        self.app.audit_timestamp = "24/10/2026 12:00:00"
        self.app.current_audit_record = None
        self.app.check_results = [
            Guardian.CheckResult(
                "Firewall de Windows", "finding", "perfil desactivado", "high",
                "Habilite el firewall.",
            ),
            Guardian.CheckResult(
                "Microsoft Defender", "ok", "protección activa", "info",
                "Mantener.",
            ),
        ]
        data = self.render_pdf()
        self.assertIn(b"Resumen ejecutivo", data)
        self.assertIn(b"Dispositivo evaluado", data)
        self.assertIn(b"No hay una auditor", data)
        self.assertLess(data.find(b"Resumen ejecutivo"), data.find(b"Hallazgos"))

    def test_pdf_executive_summary_uses_saved_comparison(self):
        self.app.workspace.save_audit(
            [{
                "name": "Firewall de Windows", "status": "finding",
                "severity": "high", "recommendation": "Habilite el firewall.",
            }],
            self.app.device_identity,
            collected_at=(datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec="seconds"),
        )
        current = self.app.workspace.save_audit(
            [{
                "name": "Firewall de Windows", "status": "ok",
                "severity": "info", "recommendation": "Mantener.",
            }],
            self.app.device_identity,
            collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        self.app.current_audit_record = current
        self.app.audit_timestamp = "24/10/2026 12:00:00"
        self.app.check_results = [
            Guardian.CheckResult("Firewall de Windows", "ok", "activo", "info", "Mantener.")
        ]
        data = self.render_pdf()
        self.assertIn(b"Resumen ejecutivo", data)
        self.assertIn(b"Resueltos confirmados", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
