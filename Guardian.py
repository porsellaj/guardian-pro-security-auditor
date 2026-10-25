import os
import stat
import subprocess
import threading
import socket
import queue
import sys
import json
from datetime import datetime
from tkinter import messagebox, filedialog
import customtkinter as ctk
from fpdf import FPDF

# Configuración visual
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class CheckResult:
    """Resultado de una comprobación individual."""
    def __init__(self, name: str, status: str, evidence: str = "", severity: str = "info",
                 recommendation: str = "", can_fix: bool = False, fix_action: str = ""):
        self.name = name
        self.status = status  # "ok", "finding", "error", "unverifiable"
        self.evidence = evidence
        self.severity = severity  # "high", "medium", "low", "info"
        self.recommendation = recommendation
        self.can_fix = can_fix
        self.fix_action = fix_action


class RepairAction:
    """Acción de reparación propuesta, ejecutada u omitida."""
    def __init__(self, name: str, description: str, command: str, requires_admin: bool = False,
                 action_type: str = "", warning: str = ""):
        self.name = name
        self.description = description
        self.command = command
        self.requires_admin = requires_admin
        self.action_type = action_type
        self.warning = warning
        self.selected = False
        self.attempted = False
        self.skipped = False
        self.skip_reason = ""
        self.success = False
        self.output = ""
        self.error = ""
        self.verified = False
        self.verification_status = "not_checked"  # verified, unverified, error, skipped, permission_denied
        self.verification_evidence = ""

    def result_label(self) -> str:
        """Etiqueta inequívoca para el informe y la interfaz."""
        if self.verification_status == "permission_denied":
            return "NO EJECUTADA (SIN PERMISOS)"
        if self.skipped:
            return "OMITIDA POR EL USUARIO"
        if not self.attempted:
            return "NO EJECUTADA"
        if self.success and self.verified:
            return "EJECUTADA Y VERIFICADA"
        if self.success and self.verification_status == "error":
            return "EJECUTADA, VERIFICACIÓN CON ERROR"
        if self.success:
            return "EJECUTADA, NO VERIFICADA"
        return "FALLIDA"

    def display_status(self) -> tuple[str, str]:
        """Devuelve (texto, tag de color) para el área de resultados."""
        if self.verification_status == "permission_denied":
            return ("⛔ NO EJECUTADA (SIN PERMISOS)", "dim")
        if self.skipped:
            return ("— OMITIDA", "dim")
        if not self.attempted:
            return ("— NO EJECUTADA", "dim")
        if self.success and self.verified:
            return ("✓ VERIFICADA", "ok")
        if self.success and self.verification_status == "error":
            return ("⚠ EJECUTADA, VERIFICACIÓN CON ERROR", "unverifiable")
        if self.success:
            return ("⚠ EJECUTADA, NO VERIFICADA", "unverifiable")
        return ("✗ FALLIDA", "error")


class RepairVerification:
    """Resultado de la comprobación posterior de una reparación."""
    def __init__(self, status: str, evidence: str):
        self.status = status  # "verified", "unverified", "error", "not_checked"
        self.evidence = evidence


class GuardianProMaster(ctk.CTk):
    RDP_FIREWALL_GROUP = "@FirewallAPI.dll,-28752"

    def __init__(self):
        super().__init__()
        self.title("Guardian Pro — Windows Security Check")
        self.geometry("1100x750")
        self.minsize(900, 650)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Estado de la auditoría
        self.check_results = []
        self.repair_actions = []
        self.repair_actions_to_run = []
        self.sensitive_files = []
        self.selected_path = os.path.expanduser("~")
        self.audit_timestamp = ""
        self.audit_in_progress = False
        self.repair_in_progress = False
        self.worker_thread = None
        self.result_queue = queue.Queue()

        self.setup_ui()

    def setup_ui(self):
        # --- SIDEBAR ---
        self.sidebar = ctk.CTkFrame(self, width=300, fg_color="#1A1C1E", corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        self.lbl_title = ctk.CTkLabel(self.sidebar, text="GUARDIAN PRO", font=("Segoe UI", 28, "bold"), text_color="#3498db")
        self.lbl_title.place(relx=0.5, y=80, anchor="center")

        self.lbl_subtitle = ctk.CTkLabel(self.sidebar, text="Windows Security Check", font=("Segoe UI", 11), text_color="#888888")
        self.lbl_subtitle.place(relx=0.5, y=115, anchor="center")

        btn_style = {"height": 48, "corner_radius": 10, "font": ("Segoe UI", 12, "bold")}

        self.btn_select_folder = ctk.CTkButton(self.sidebar, text="📂  Seleccionar carpeta", command=self.elegir_carpeta, **btn_style)
        self.btn_select_folder.place(relx=0.5, y=200, anchor="center", relwidth=0.85)

        self.btn_audit = ctk.CTkButton(self.sidebar, text="🔍  Iniciar auditoría", fg_color="#27AE60", hover_color="#2ECC71", command=self.iniciar_auditoria, **btn_style)
        self.btn_audit.place(relx=0.5, y=270, anchor="center", relwidth=0.85)

        self.btn_repair = ctk.CTkButton(self.sidebar, text="🛠️  Reparar hallazgos", fg_color="#E67E22", hover_color="#D35400", command=self.mostrar_dialogo_reparacion, state="disabled", **btn_style)
        self.btn_repair.place(relx=0.5, y=340, anchor="center", relwidth=0.85)

        self.btn_report = ctk.CTkButton(self.sidebar, text="📄  Generar informe PDF", fg_color="#2980B9", hover_color="#3498DB", command=self.crear_pdf, state="disabled", **btn_style)
        self.btn_report.place(relx=0.5, y=410, anchor="center", relwidth=0.85)

        self.btn_new_audit = ctk.CTkButton(self.sidebar, text="🔄  Nueva auditoría", fg_color="#555555", hover_color="#666666", command=self.nueva_auditoria, **btn_style)
        self.btn_new_audit.place(relx=0.5, y=480, anchor="center", relwidth=0.85)

        # --- PANEL PRINCIPAL ---
        self.main_view = ctk.CTkFrame(self, fg_color="#0F1112", corner_radius=20)
        self.main_view.grid(row=0, column=1, padx=30, pady=30, sticky="nsew")
        self.main_view.grid_rowconfigure(3, weight=1)
        self.main_view.grid_columnconfigure(0, weight=1)

        # Header con resumen
        self.header_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=30, pady=(30, 10), sticky="ew")
        self.header_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.summary_labels = {}
        for i, (key, label_text, color) in enumerate([
            ("ok", "Correctas", "#27AE60"),
            ("finding", "Hallazgos", "#E74C3C"),
            ("unverifiable", "No verificables", "#F39C12"),
            ("error", "Errores", "#E74C3C")
        ]):
            frame = ctk.CTkFrame(self.header_frame, fg_color="#1A1C1E", corner_radius=10)
            frame.grid(row=0, column=i, padx=5, sticky="ew")
            ctk.CTkLabel(frame, text="0", font=("Segoe UI", 28, "bold"), text_color=color).pack(pady=(10, 0))
            ctk.CTkLabel(frame, text=label_text, font=("Segoe UI", 10), text_color="#ABB2B9").pack(pady=(0, 10))
            self.summary_labels[key] = frame.winfo_children()[0]

        # Barra de progreso
        self.progress_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        self.progress_frame.grid(row=1, column=0, padx=30, pady=5, sticky="ew")
        self.progress_frame.grid_columnconfigure(0, weight=1)

        self.lbl_progress = ctk.CTkLabel(self.progress_frame, text="Listo para iniciar", font=("Segoe UI", 11), text_color="#ABB2B9")
        self.lbl_progress.grid(row=0, column=0, sticky="w")

        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, height=8, progress_color="#3498db")
        self.progress_bar.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        self.progress_bar.set(0)

        # Área de resultados (treeview estilo)
        self.results_frame = ctk.CTkFrame(self.main_view, fg_color="#161616", corner_radius=10, border_width=1, border_color="#333333")
        self.results_frame.grid(row=3, column=0, padx=30, pady=(10, 20), sticky="nsew")
        self.results_frame.grid_rowconfigure(0, weight=1)
        self.results_frame.grid_columnconfigure(0, weight=1)

        # Usamos un textbox con formato para simular tabla
        self.txt_results = ctk.CTkTextbox(self.results_frame, fg_color="#161616", text_color="#E0E0E0",
                                           border_width=0, font=("Consolas", 11), corner_radius=10,
                                           wrap="none")
        self.txt_results.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.txt_results.configure(state="disabled")

        # Configurar tags para colores
        self.txt_results.tag_config("ok", foreground="#27AE60")
        self.txt_results.tag_config("finding", foreground="#E74C3C")
        self.txt_results.tag_config("unverifiable", foreground="#F39C12")
        self.txt_results.tag_config("error", foreground="#E74C3C")
        self.txt_results.tag_config("header", foreground="#3498DB")
        self.txt_results.tag_config("dim", foreground="#777777")

    def elegir_carpeta(self):
        ruta = filedialog.askdirectory(initialdir=self.selected_path, title="Seleccionar carpeta para análisis de nombres de archivo")
        if ruta:
            self.selected_path = ruta
            self._append_log(f"[SISTEMA] Carpeta seleccionada: {ruta}")

    def _append_log(self, text: str, tag: str | None = None):
        """Añade texto al área de resultados (siempre desde el hilo principal)."""
        self.txt_results.configure(state="normal")
        try:
            if tag:
                self.txt_results.insert("end", text + "\n", tag)
            else:
                self.txt_results.insert("end", text + "\n")
            self.txt_results.see("end")
        except Exception as exc:
            # Un fallo al pintar un mensaje no debe detener la auditoría.
            print(f"[Guardian] No se pudo registrar el mensaje: {exc}", file=sys.stderr)
        finally:
            self.txt_results.configure(state="disabled")

    def _clear_results(self):
        self.txt_results.configure(state="normal")
        self.txt_results.delete("1.0", "end")
        self.txt_results.configure(state="disabled")

    def _update_summary_counts(self):
        counts = {"ok": 0, "finding": 0, "unverifiable": 0, "error": 0}
        for r in self.check_results:
            if r.status in counts:
                counts[r.status] += 1
        for key, label in self.summary_labels.items():
            label.configure(text=str(counts.get(key, 0)))

    def _reset_audit_state(self):
        """Inicializa de forma única el estado de una auditoría nueva.

        No toca `audit_in_progress` ni `repair_in_progress`: el ciclo de vida
        de una operación activa lo controlan el worker y sus finalizadores.
        """
        self.check_results = []
        self.repair_actions = []
        self.repair_actions_to_run = []
        self.sensitive_files = []
        self.audit_timestamp = ""
        # Evitar que eventos de una operación anterior se interpreten como
        # resultados de la auditoría nueva. Solo se llama sin operaciones activas.
        while True:
            try:
                self.result_queue.get_nowait()
            except queue.Empty:
                break
        self._update_summary_counts()

    # ==================== UTILIDADES DE ESTADO ====================

    @staticmethod
    def _is_admin() -> bool:
        """Comprueba el token de administrador sin intentar elevar privilegios."""
        if os.name != "nt":
            return False
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception as exc:
            print(f"[Guardian] No se pudo comprobar el privilegio de administrador: {exc}", file=sys.stderr)
            return False

    @staticmethod
    def _enabled_state(value) -> str:
        """Interpreta explícitamente los valores de Enabled de PowerShell.

        Perfiles de firewall: True/1 = habilitado; False/0 = deshabilitado;
        2 = NotConfigured. Reglas de firewall: True/1 = habilitada;
        False/2 = deshabilitada. Cualquier otro valor es desconocido.
        No se usa la verdad simple de Python para valores numéricos.
        """
        if isinstance(value, bool):
            return "enabled" if value else "disabled"
        if isinstance(value, int):
            if value == 1:
                return "enabled"
            if value == 0:
                return "disabled"
            if value == 2:
                return "not_configured"
            return "unknown"
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1"}:
                return "enabled"
            if normalized in {"false", "0"}:
                return "disabled"
            if normalized in {"2", "notconfigured", "not configured"}:
                return "not_configured"
        return "unknown"

    def _parse_firewall_profiles(self, stdout: str) -> dict:
        """Valida la salida JSON de los tres perfiles del firewall.

        Exige Domain, Private y Public, sin duplicados ni valores de enum
        desconocidos. Lanza ValueError si la evidencia no es concluyente.
        """
        text = (stdout or "").strip()
        if not text:
            raise ValueError("salida vacía")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON inválido: {exc}") from exc

        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list) or not data:
            raise ValueError("la consulta no devolvió perfiles")

        required = ("Domain", "Private", "Public")
        profiles = {}
        for item in data:
            if not isinstance(item, dict):
                raise ValueError("formato de perfil inesperado")
            name = item.get("Name")
            if name not in required:
                raise ValueError(f"perfil inesperado: {name!r}")
            if name in profiles:
                raise ValueError(f"perfil duplicado: {name}")
            state = self._enabled_state(item.get("Enabled"))
            if state == "unknown":
                raise ValueError(f"valor de Enabled inesperado para {name}: {item.get('Enabled')!r}")
            profiles[name] = state

        missing = [name for name in required if name not in profiles]
        if missing:
            raise ValueError(f"faltan perfiles: {', '.join(missing)}")
        return profiles

    @staticmethod
    def _firewall_profiles_evidence(profiles: dict) -> str:
        labels = {"enabled": "Habilitado", "disabled": "Deshabilitado", "not_configured": "No configurado"}
        return "; ".join(
            f"{name}: {labels.get(profiles[name], profiles[name])}"
            for name in ("Domain", "Private", "Public")
        )

    def _query_firewall_profiles(self) -> dict:
        """Consulta estricta del estado de los tres perfiles del firewall."""
        cmd = [
            "powershell", "-NoProfile", "-Command",
            "Get-NetFirewallProfile -Profile Domain,Private,Public | Select-Object Name,Enabled | ConvertTo-Json -Compress"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, encoding='utf-8', errors='ignore')
        if proc.returncode != 0:
            detail = proc.stderr.strip() or "sin detalle"
            raise RuntimeError(f"PowerShell falló (código {proc.returncode}): {detail}")
        return self._parse_firewall_profiles(proc.stdout)

    def _query_rdp_firewall_rules(self) -> list:
        """Consulta las reglas RDP por su Group independiente del idioma.

        No usa DisplayGroup ni nombres visibles localizados. Una consulta
        correcta sin reglas devuelve una lista vacía; un error de consulta
        lanza una excepción y nunca se interpreta como ausencia de reglas.
        """
        script = (
            "Get-NetFirewallRule -ErrorAction Stop | "
            "Where-Object { $_.Group -eq '" + self.RDP_FIREWALL_GROUP + "' } | "
            "Select-Object DisplayName,Group,Enabled | ConvertTo-Json -Compress"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=15, encoding='utf-8', errors='ignore'
        )
        if proc.returncode != 0:
            detail = proc.stderr.strip() or "sin detalle"
            raise RuntimeError(f"PowerShell falló (código {proc.returncode}): {detail}")

        text = proc.stdout.strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON de reglas inválido: {exc}") from exc
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            raise ValueError("formato de reglas inesperado")

        rules = []
        for item in data:
            if not isinstance(item, dict):
                raise ValueError("regla con formato inesperado")
            state = self._enabled_state(item.get("Enabled"))
            if state == "unknown":
                raise ValueError(f"valor de Enabled inesperado en regla RDP: {item.get('Enabled')!r}")
            rules.append({
                "name": item.get("DisplayName") or "Regla sin nombre",
                "state": state,
            })
        return rules

    @staticmethod
    def _rdp_firewall_evidence(rules: list) -> str:
        if not rules:
            return "Reglas de firewall RDP: no se encontraron reglas en el grupo (consulta correcta)"
        enabled = [r["name"] for r in rules if r["state"] == "enabled"]
        disabled_count = len(rules) - len(enabled)
        detail = f"Reglas de firewall RDP: {len(enabled)} habilitadas, {disabled_count} no habilitadas (total {len(rules)})"
        if enabled:
            shown = ", ".join(enabled[:3])
            if len(enabled) > 3:
                shown += f" y {len(enabled) - 3} más"
            detail += f" | Habilitadas: {shown}"
        return detail

    def iniciar_auditoria(self):
        if self.audit_in_progress or self.repair_in_progress:
            return

        # Inicializar el estado antes de marcar la operación como activa. Si el
        # reset falla, no dejamos la auditoría bloqueada.
        self._reset_audit_state()
        self.audit_in_progress = True

        try:
            self.audit_timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            self.btn_audit.configure(state="disabled", text="⏳  Auditando...")
            self.btn_repair.configure(state="disabled")
            self.btn_report.configure(state="disabled")
            self.btn_new_audit.configure(state="disabled")
            self.btn_select_folder.configure(state="disabled")
            self.progress_bar.set(0)
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start()
            self.lbl_progress.configure(text="Ejecutando comprobaciones...")

            self._clear_results()
            self._append_log(f"=== Guardian Pro — Auditoría iniciada: {self.audit_timestamp} ===")
            self._append_log(f"Alcance de análisis de archivos: {self.selected_path}")
            self._append_log("")

            # Programar el polling antes de arrancar el worker: si el hilo no
            # puede iniciarse, el estado se restaura y no queda bloqueado.
            self.after(100, self._poll_results)
            self.worker_thread = threading.Thread(target=self._worker_auditar, daemon=True)
            self.worker_thread.start()
        except Exception as exc:
            self.audit_in_progress = False
            self.audit_timestamp = ""
            self.progress_bar.stop()
            self.progress_bar.configure(mode="determinate")
            self.progress_bar.set(0)
            self.lbl_progress.configure(text="No se pudo iniciar la auditoría")
            self.btn_audit.configure(state="normal", text="🔍  Iniciar auditoría")
            self.btn_repair.configure(state="disabled")
            self.btn_report.configure(state="disabled")
            self.btn_new_audit.configure(state="normal")
            self.btn_select_folder.configure(state="normal")
            messagebox.showerror("Guardian Pro", f"No se pudo iniciar la auditoría:\n{exc}")

    def _worker_auditar(self):
        """Ejecuta todas las comprobaciones en hilo secundario y envía resultados a la cola."""
        try:
            # 1. Firewall
            self.result_queue.put(("progress", "Comprobando firewall de Windows..."))
            self._check_firewall()

            # 2. Microsoft Defender
            self.result_queue.put(("progress", "Comprobando Microsoft Defender..."))
            self._check_defender()

            # 3. RDP
            self.result_queue.put(("progress", "Comprobando configuración RDP..."))
            self._check_rdp()

            # 4. Archivos sensibles
            self.result_queue.put(("progress", "Analizando nombres de archivo..."))
            self._check_sensitive_files()

        except Exception as e:
            print(f"[Guardian] Error en auditoría: {e}", file=sys.stderr)
            self.result_queue.put(("error", f"Error inesperado en auditoría: {e}"))
        finally:
            # Un único evento terminal, también ante excepciones.
            self.result_queue.put(("done", None))

    def _poll_results(self):
        """Consulta la cola de resultados y actualiza UI desde el hilo principal."""
        try:
            while True:
                msg_type, data = self.result_queue.get_nowait()
                try:
                    if msg_type == "progress":
                        self.lbl_progress.configure(text=data)
                    elif msg_type == "result":
                        self.check_results.append(data)
                        self._render_result(data)
                        self._update_summary_counts()
                    elif msg_type == "file_finding":
                        self.sensitive_files.append(data)
                        self._append_log(f"  [RIESGO] {data}", "finding")
                    elif msg_type == "error":
                        self._append_log(f"[ERROR] {data}", "error")
                    elif msg_type == "done":
                        self._finish_audit()
                        return
                except Exception as exc:
                    # No dejamos que un evento defectuoso detenga el polling.
                    print(f"[Guardian] Error procesando evento '{msg_type}': {exc}", file=sys.stderr)
        except queue.Empty:
            pass
        except Exception as exc:
            print(f"[Guardian] Error en el bucle de resultados: {exc}", file=sys.stderr)

        if self.audit_in_progress:
            self.after(100, self._poll_results)

    def _finish_audit(self):
        # Marcar el fin antes de tocar widgets: si alguno falla, no se reprograma el polling.
        self.audit_in_progress = False
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1)
        self.lbl_progress.configure(text="Auditoría completada")

        self.btn_audit.configure(state="normal", text="🔍  Iniciar auditoría")
        self.btn_select_folder.configure(state="normal")
        self.btn_report.configure(state="normal" if self.check_results else "disabled")
        self.btn_new_audit.configure(state="normal")

        # Habilitar reparación solo si hay hallazgos reparables
        fixable = any(r.can_fix for r in self.check_results)
        self.btn_repair.configure(state="normal" if fixable else "disabled")

        self._append_log("")
        self._append_log("=== Auditoría finalizada ===")

    def _render_result(self, result: CheckResult):
        status_icon = {
            "ok": "✓",
            "finding": "⚠",
            "unverifiable": "?",
            "error": "✗"
        }.get(result.status, "•")

        # El color depende primero del estado real. La severidad no puede
        # convertir un error o una comprobación no verificable en un OK verde.
        status_color = {
            "ok": "ok",
            "finding": "finding",
            "unverifiable": "unverifiable",
            "error": "error"
        }.get(result.status, "error")

        self.txt_results.configure(state="normal")
        self.txt_results.insert("end", f"  {status_icon} ", status_color)
        self.txt_results.insert("end", f"{result.name}: ", status_color)
        self.txt_results.insert("end", f"{result.evidence}\n", "dim")
        if result.recommendation:
            self.txt_results.insert("end", f"      → {result.recommendation}\n", "dim")
        self.txt_results.see("end")
        self.txt_results.configure(state="disabled")

    # ==================== COMPROBACIONES ====================

    def _check_firewall(self):
        """Comprueba el estado de los tres perfiles del firewall."""
        try:
            profiles = self._query_firewall_profiles()
            evidence = self._firewall_profiles_evidence(profiles)
            all_enabled = all(state == "enabled" for state in profiles.values())

            if all_enabled:
                self.result_queue.put(("result", CheckResult(
                    name="Firewall de Windows",
                    status="ok",
                    evidence=evidence,
                    severity="info",
                    recommendation="El firewall está activo en todos los perfiles."
                )))
            else:
                self.result_queue.put(("result", CheckResult(
                    name="Firewall de Windows",
                    status="finding",
                    evidence=evidence,
                    severity="high",
                    recommendation="Habilite el firewall en los perfiles desactivados.",
                    can_fix=True,
                    fix_action="firewall_enable_all"
                )))

        except subprocess.TimeoutExpired:
            self.result_queue.put(("result", CheckResult(
                name="Firewall de Windows",
                status="error",
                evidence="Timeout al consultar el firewall (15s)",
                severity="info",
                recommendation="Verifique manualmente con 'Get-NetFirewallProfile' en PowerShell."
            )))
        except Exception as e:
            self.result_queue.put(("result", CheckResult(
                name="Firewall de Windows",
                status="unverifiable",
                evidence=f"No se pudo consultar: {e}",
                severity="info",
                recommendation="Ejecute la aplicación como administrador o verifique manualmente."
            )))

    def _check_defender(self):
        """Comprueba la protección en tiempo real de Microsoft Defender."""
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "(Get-MpComputerStatus).RealTimeProtectionEnabled"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, encoding='utf-8', errors='ignore')

            if proc.returncode != 0:
                raise RuntimeError(f"PowerShell falló (código {proc.returncode}): {proc.stderr.strip()}")

            output = proc.stdout.strip()
            if output.lower() == "true":
                self.result_queue.put(("result", CheckResult(
                    name="Microsoft Defender",
                    status="ok",
                    evidence="Protección en tiempo real: Habilitada",
                    severity="info",
                    recommendation="La protección en tiempo real está activa."
                )))
            elif output.lower() == "false":
                self.result_queue.put(("result", CheckResult(
                    name="Microsoft Defender",
                    status="finding",
                    evidence="Protección en tiempo real: Deshabilitada",
                    severity="high",
                    recommendation="Active la protección en tiempo real de Windows Defender.",
                    can_fix=True,
                    fix_action="defender_enable_rtp"
                )))
            else:
                raise ValueError(f"Respuesta inesperada: {output}")

        except subprocess.TimeoutExpired:
            self.result_queue.put(("result", CheckResult(
                name="Microsoft Defender",
                status="error",
                evidence="Timeout al consultar Defender (15s)",
                severity="info",
                recommendation="Verifique manualmente con 'Get-MpComputerStatus' en PowerShell."
            )))
        except Exception as e:
            self.result_queue.put(("result", CheckResult(
                name="Microsoft Defender",
                status="unverifiable",
                evidence=f"No se pudo consultar: {e}",
                severity="info",
                recommendation="Puede que Defender no esté instalado o no haya permisos. Verifique en Seguridad de Windows."
            )))

    def _check_rdp(self):
        """Comprueba registro RDP, puerto local y reglas de firewall.

        El puerto 3389 abierto es solo una señal: no confirma que RDP esté
        habilitado ni que esté expuesto a Internet. Solo se ofrece la
        reparación RDP si el registro confirma fDenyTSConnections=0.
        """
        # 1. Registro: es la evidencia principal del estado de RDP.
        reg_status = "unknown"
        reg_evidence = ""
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "(Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore')
            if proc.returncode != 0:
                detail = proc.stderr.strip() or "sin detalle"
                reg_evidence = f"Registro: no se pudo consultar (código {proc.returncode}): {detail}"
            else:
                val = proc.stdout.strip()
                if val == "1":
                    reg_status = "disabled"
                    reg_evidence = "Registro: fDenyTSConnections=1 (RDP deshabilitado)"
                elif val == "0":
                    reg_status = "enabled"
                    reg_evidence = "Registro: fDenyTSConnections=0 (RDP habilitado)"
                else:
                    reg_evidence = f"Registro: valor inesperado o ausente ({val!r})"
        except subprocess.TimeoutExpired:
            reg_evidence = "Registro: timeout al consultar (10s)"
        except Exception as e:
            reg_evidence = f"Registro: error de consulta: {e}"

        # 2. Puerto local: señal adicional, nunca prueba suficiente.
        port_open = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex(('127.0.0.1', 3389)) == 0:
                    port_open = True
        except Exception:
            pass

        port_evidence = (
            "Puerto 3389 local: ABIERTO (puede ser otro servicio; no confirma RDP ni exposición a Internet)"
            if port_open else "Puerto 3389 local: CERRADO"
        )

        # 3. Reglas RDP por Group, independiente del nombre visible localizado.
        fw_status = "error"
        fw_evidence = ""
        try:
            rules = self._query_rdp_firewall_rules()
            fw_evidence = self._rdp_firewall_evidence(rules)
            if not rules:
                fw_status = "none"
            elif any(r["state"] == "enabled" for r in rules):
                fw_status = "enabled"
            else:
                fw_status = "disabled"
        except subprocess.TimeoutExpired:
            fw_evidence = "Reglas de firewall RDP: timeout al consultar (15s)"
        except Exception as e:
            fw_evidence = f"Reglas de firewall RDP: no se pudo verificar: {e}"

        full_evidence = " | ".join(p for p in (reg_evidence, port_evidence, fw_evidence) if p)

        if reg_status == "enabled":
            # RDP confirmado en el registro: se puede ofrecer la reparación.
            self.result_queue.put(("result", CheckResult(
                name="Escritorio Remoto (RDP)",
                status="finding",
                evidence=full_evidence,
                severity="medium",
                recommendation="RDP está habilitado en el registro. Si no lo usa, deshabilítelo y revise las reglas de firewall RDP.",
                can_fix=True,
                fix_action="rdp_disable"
            )))
        elif reg_status == "disabled":
            # RDP deshabilitado: el puerto abierto no justifica ofrecer la reparación.
            if fw_status == "error":
                status = "unverifiable"
                recommendation = "RDP está deshabilitado en el registro, pero no se pudo verificar el firewall. No se ofrece reparación RDP."
            elif fw_status == "enabled":
                status = "unverifiable"
                recommendation = "RDP está deshabilitado en el registro, pero hay reglas de firewall RDP habilitadas. Revise si son necesarias; no se ofrece reparación RDP."
            elif port_open:
                status = "unverifiable"
                recommendation = "El registro indica RDP deshabilitado, pero el puerto 3389 local está abierto. Puede ser otro servicio; investigue manualmente. No se ofrece reparación RDP."
            else:
                status = "ok"
                recommendation = "RDP está deshabilitado en el registro y no hay reglas RDP habilitadas."
            self.result_queue.put(("result", CheckResult(
                name="Escritorio Remoto (RDP)",
                status=status,
                evidence=full_evidence,
                severity="info",
                recommendation=recommendation
            )))
        else:
            self.result_queue.put(("result", CheckResult(
                name="Escritorio Remoto (RDP)",
                status="unverifiable",
                evidence=full_evidence,
                severity="info",
                recommendation="No se pudo confirmar el estado de RDP en el registro. No se ofrece reparación automática; verifique manualmente."
            )))

    def _check_sensitive_files(self):
        """Busca palabras sensibles en nombres de archivo (no en contenido)."""
        exts = {".txt", ".pdf", ".env", ".docx", ".xlsx", ".csv", ".json", ".xml", ".ini", ".config"}
        keywords = {"pass", "clave", "banco", "nomina", "password", "secret", "token", "credential", "key", "pwd"}

        # Directorios a excluir (modificamos dirs in-place para que os.walk no los recorra)
        exclude_dirs = {"appdata", "windows", "program files", "program files (x86)", "programdata",
                        "node_modules", ".git", ".vs", "__pycache__", "temp", "tmp"}

        scanned = 0
        matches = 0
        walk_errors = []
        file_errors = []
        root_path = self.selected_path

        def publish_result(status, evidence, recommendation, severity="info"):
            self.result_queue.put(("result", CheckResult(
                name="Análisis de nombres de archivo",
                status=status,
                evidence=evidence,
                severity=severity,
                recommendation=recommendation,
                can_fix=False
            )))

        # Validar la raíz antes de recorrer: distingue ruta inexistente,
        # archivo en lugar de carpeta y falta de permisos.
        if not root_path:
            publish_result(
                "error",
                "No se seleccionó una carpeta para el análisis de nombres.",
                "Seleccione una carpeta válida."
            )
            return

        try:
            root_info = os.stat(root_path)
        except FileNotFoundError:
            publish_result(
                "error",
                f"La ruta seleccionada no existe: {root_path}",
                "Seleccione una carpeta existente."
            )
            return
        except PermissionError as exc:
            publish_result(
                "unverifiable",
                f"No se pudo acceder a la raíz por permisos: {root_path} ({exc})",
                "Ejecute Guardian Pro como administrador o seleccione una carpeta accesible."
            )
            return
        except OSError as exc:
            publish_result(
                "error",
                f"No se pudo comprobar la raíz: {root_path} ({exc})",
                "Verifique la ruta y los permisos de la carpeta seleccionada."
            )
            return

        if not stat.S_ISDIR(root_info.st_mode):
            publish_result(
                "error",
                f"La ruta seleccionada no es un directorio: {root_path}",
                "Seleccione una carpeta, no un archivo."
            )
            return

        try:
            # Abrir y cerrar el directorio comprueba el acceso sin leer nombres
            # ni contenidos de archivos.
            with os.scandir(root_path):
                pass
        except PermissionError as exc:
            publish_result(
                "unverifiable",
                f"No se pudo abrir la raíz por permisos: {root_path} ({exc})",
                "Ejecute Guardian Pro como administrador o seleccione una carpeta accesible."
            )
            return
        except OSError as exc:
            publish_result(
                "error",
                f"No se pudo abrir la raíz: {root_path} ({exc})",
                "Verifique la ruta y los permisos de la carpeta seleccionada."
            )
            return

        def on_walk_error(exc):
            """Acumula errores de recorrido sin detener el resto del árbol."""
            error_path = getattr(exc, "filename", None) or root_path
            walk_errors.append((error_path, exc))

        try:
            for current_root, dirs, files in os.walk(
                root_path, topdown=True, onerror=on_walk_error, followlinks=False
            ):
                # Excluir directorios modificando la lista in-place. Con
                # topdown=True esto impide que os.walk descienda a ellos.
                dirs[:] = [d for d in dirs if d.lower() not in exclude_dirs and not d.startswith('.')]

                for file in files:
                    scanned += 1
                    file_path = os.path.join(current_root, file)

                    # Solo se consultan metadatos para detectar archivos que no
                    # se pueden ni siquiera inspeccionar por nombre. No se abre
                    # ni se modifica su contenido.
                    try:
                        os.stat(file_path, follow_symlinks=False)
                    except OSError as exc:
                        file_errors.append((file_path, exc))

                    file_lower = file.lower()
                    if any(file_lower.endswith(e) for e in exts):
                        if any(k in file_lower for k in keywords):
                            self.result_queue.put(("file_finding", file_path))
                            matches += 1

                    # Actualizar progreso cada 500 archivos
                    if scanned % 500 == 0:
                        self.result_queue.put(("progress", f"Analizando archivos... ({scanned} revisados, {matches} coincidencias)"))

        except Exception as exc:
            accumulated = []
            if walk_errors:
                accumulated.append(f"{len(walk_errors)} directorio(s) no recorrido(s)")
            if file_errors:
                accumulated.append(f"{len(file_errors)} archivo(s) con acceso no verificado")
            evidence = f"Error durante el recorrido: {exc} | Revisados: {scanned} | Coincidencias: {matches}"
            if accumulated:
                evidence += " | " + "; ".join(accumulated)
            publish_result(
                "error",
                evidence,
                "Verifique la ruta y los permisos. El análisis puede estar incompleto."
            )
            return

        error_parts = []
        if walk_errors:
            error_parts.append(f"{len(walk_errors)} directorio(s) no recorrido(s)")
        if file_errors:
            error_parts.append(f"{len(file_errors)} archivo(s) con acceso no verificado")
        error_summary = "; ".join(error_parts)
        partial = bool(error_parts)

        if matches > 0:
            evidence = f"Revisados: {scanned} archivos | Coincidencias: {matches} archivos con palabras sensibles en el nombre"
            if partial:
                evidence += f" | Análisis parcial: {error_summary}"
            recommendation = (
                "Revise los archivos listados. La presencia de palabras sensibles en el nombre "
                "no confirma una filtración. Solo se examinaron nombres, no el contenido."
            )
            if partial:
                recommendation += " El análisis fue parcial; revise también los directorios o archivos no accesibles."
            publish_result(
                "finding",
                evidence,
                recommendation,
                severity="low"
            )
        elif partial:
            publish_result(
                "unverifiable",
                f"Revisados: {scanned} archivos | Sin coincidencias en lo revisado | Análisis parcial: {error_summary}",
                "No se puede confirmar la ausencia de nombres sensibles: hubo directorios o archivos "
                "que no se pudieron revisar. Solo se examinaron nombres, no el contenido. "
                "Ejecute Guardian Pro como administrador o seleccione una carpeta accesible."
            )
        else:
            publish_result(
                "ok",
                f"Revisados: {scanned} archivos | Sin coincidencias",
                "No se encontraron nombres de archivo con palabras sensibles en el ámbito seleccionado. "
                "Solo se examinaron nombres, no el contenido."
            )

    # ==================== REPARACIONES ====================

    def _build_repair_actions(self) -> list:
        """Construye acciones con tipo explícito, aviso y requisito de admin."""
        actions = []
        for r in self.check_results:
            if not r.can_fix:
                continue

            if r.fix_action == "firewall_enable_all":
                actions.append(RepairAction(
                    name="Habilitar firewall en todos los perfiles",
                    description="Activa el firewall de Windows en los perfiles Domain, Private y Public.",
                    command="Set-NetFirewallProfile -All -Enabled True",
                    requires_admin=True,
                    action_type="firewall_enable_all",
                    warning="Puede bloquear aplicaciones o servicios que dependan de reglas de firewall existentes."
                ))
            elif r.fix_action == "defender_enable_rtp":
                actions.append(RepairAction(
                    name="Activar protección en tiempo real de Defender",
                    description="Habilita la protección en tiempo real de Microsoft Defender.",
                    command="Set-MpPreference -DisableRealtimeMonitoring 0",
                    requires_admin=True,
                    action_type="defender_enable_rtp",
                    warning="Puede afectar el rendimiento. Requiere que Microsoft Defender esté instalado y disponible."
                ))
            elif r.fix_action == "rdp_disable":
                rdp_command = (
                    "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                    "-Name 'fDenyTSConnections' -Value 1 -ErrorAction Stop; "
                    "Get-NetFirewallRule -ErrorAction Stop | "
                    "Where-Object { $_.Group -eq '" + self.RDP_FIREWALL_GROUP + "' } | "
                    "Disable-NetFirewallRule -ErrorAction Stop"
                )
                actions.append(RepairAction(
                    name="Deshabilitar Escritorio Remoto (RDP)",
                    description=(
                        "Establece fDenyTSConnections=1 y deshabilita las reglas de firewall "
                        "del grupo RDP identificado por @FirewallAPI.dll,-28752."
                    ),
                    command=rdp_command,
                    requires_admin=True,
                    action_type="rdp_disable",
                    warning=(
                        "Puede interrumpir sesiones de Escritorio Remoto activas y bloquear "
                        "accesos remotos legítimos. No la ejecute si depende de RDP."
                    )
                ))
        return actions

    def _confirmar_accion(self, action: RepairAction) -> bool:
        """Confirmación específica con cambio, comando, efectos y privilegios."""
        effects = action.warning or "Puede cambiar la configuración de seguridad del sistema."
        msg = (
            f"Reparación: {action.name}\n\n"
            f"Qué cambiará:\n{action.description}\n\n"
            f"Comando:\n{action.command}\n\n"
            f"Posibles efectos adversos:\n{effects}\n\n"
            f"Requiere administrador: {'Sí' if action.requires_admin else 'No'}\n\n"
            "¿Ejecutar esta reparación?"
        )
        return messagebox.askyesno(f"Confirmar reparación: {action.name}", msg, icon="warning")

    def _seleccionar_acciones(self, actions: list, is_admin: bool) -> list:
        """Selecciona acciones por confirmación individual y comprueba privilegios."""
        selected = []
        for action in actions:
            if action.requires_admin and not is_admin:
                action.skipped = True
                action.verification_status = "permission_denied"
                action.skip_reason = "Requiere permisos de administrador"
                continue
            if not self._confirmar_accion(action):
                action.skipped = True
                action.verification_status = "skipped"
                action.skip_reason = "Omitida por el usuario"
                continue
            action.selected = True
            selected.append(action)
        return selected

    def mostrar_dialogo_reparacion(self):
        """Construye acciones, pide confirmación individual y ejecuta las aceptadas."""
        if self.audit_in_progress or self.repair_in_progress:
            return

        actions = self._build_repair_actions()
        if not actions:
            messagebox.showinfo("Guardian Pro", "No hay hallazgos que puedan repararse automáticamente.")
            return

        # Preservar el historial de esta auditoría: abrir el diálogo no debe
        # borrar acciones ya registradas. Solo se ejecuta el lote nuevo.
        self.repair_actions.extend(actions)
        self.repair_actions_to_run = []

        is_admin = self._is_admin()
        admin_actions = [a for a in actions if a.requires_admin]
        if admin_actions and not is_admin:
            names = "\n".join(f"- {a.name}" for a in admin_actions)
            messagebox.showwarning(
                "Permisos insuficientes",
                "Las siguientes reparaciones requieren permisos de administrador y no se ejecutarán:\n\n"
                f"{names}\n\n"
                "Inicie Guardian Pro como administrador para ejecutarlas. "
                "No se intentará elevar privilegios automáticamente."
            )

        selected = self._seleccionar_acciones(actions, is_admin)
        if not selected:
            self._append_log("No se ejecutó ninguna reparación.", "dim")
            for action in actions:
                self._append_log(f"  — {action.name}: {action.skip_reason or 'no ejecutada'}", "dim")
            messagebox.showinfo("Guardian Pro", "No se ejecutó ninguna reparación.")
            return

        for action in actions:
            if not action.selected:
                self._append_log(f"  — OMITIDA: {action.name} ({action.skip_reason})", "dim")

        self.repair_actions_to_run = selected

        # Ejecutar solo las acciones aceptadas, en hilo secundario.
        self.repair_in_progress = True
        self.btn_repair.configure(state="disabled", text="⏳  Reparando...")
        self.btn_audit.configure(state="disabled")
        self.btn_new_audit.configure(state="disabled")
        self.btn_report.configure(state="disabled")
        self.btn_select_folder.configure(state="disabled")
        self.lbl_progress.configure(text="Ejecutando reparaciones...")
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()

        repair_thread = threading.Thread(target=self._worker_reparar, daemon=True)
        try:
            self.after(100, lambda: self._poll_repairs(repair_thread))
            repair_thread.start()
        except Exception as exc:
            # Si el hilo no llega a arrancar, restaurar el estado sin simular
            # que una reparación sigue activa.
            self._finish_repairs()
            messagebox.showerror("Guardian Pro", f"No se pudo iniciar la reparación:\n{exc}")

    def _worker_reparar(self):
        """Ejecuta una sola vez las acciones seleccionadas y publica su resultado."""
        try:
            selected_actions = list(self.repair_actions_to_run)
            for action in selected_actions:
                # Defensa adicional: no ejecutar si el privilegio cambió desde la selección.
                if action.requires_admin and not self._is_admin():
                    action.skipped = True
                    action.verification_status = "permission_denied"
                    action.skip_reason = "Requiere permisos de administrador"
                    self.result_queue.put(("repair_result", action))
                    continue

                self.result_queue.put(("repair_progress", f"Ejecutando: {action.name}..."))
                action.attempted = True

                try:
                    cmd = ["powershell", "-NoProfile", "-Command", action.command]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, encoding='utf-8', errors='ignore')
                    action.output = proc.stdout.strip()
                    action.error = proc.stderr.strip()
                    action.success = (proc.returncode == 0)

                except subprocess.TimeoutExpired:
                    action.success = False
                    action.error = "Timeout (30s)"
                except Exception as e:
                    action.success = False
                    action.error = str(e)

                if action.success:
                    self.result_queue.put(("repair_progress", f"Verificando: {action.name}..."))
                    try:
                        verification = self._verify_repair(action)
                    except Exception as e:
                        verification = RepairVerification("error", f"Error al verificar: {e}")
                    action.verified = verification.status == "verified"
                    action.verification_status = verification.status
                    action.verification_evidence = verification.evidence
                else:
                    action.verified = False
                    action.verification_status = "not_checked"
                    action.verification_evidence = "No se verificó porque la ejecución del comando falló."

                self.result_queue.put(("repair_result", action))
        except Exception as e:
            print(f"[Guardian] Error en reparación: {e}", file=sys.stderr)
            self.result_queue.put(("repair_error", f"Error inesperado en reparación: {e}"))
        finally:
            # Un único evento terminal, también ante excepciones.
            self.result_queue.put(("repair_done", None))

    def _verify_repair(self, action: RepairAction) -> RepairVerification:
        """Comprueba el estado real posterior con criterios explícitos por tipo.

        firewall_enable_all: consulta con código 0, JSON válido con Domain,
        Private y Public, y los tres con Enabled=True/1. 0/False y 2
        (NotConfigured) no cuentan como habilitado; un enum desconocido es error.

        defender_enable_rtp: consulta con código 0 y
        RealTimeProtectionEnabled=True.

        rdp_disable: consulta con código 0 de fDenyTSConnections=1 y consulta
        con código 0 de reglas RDP por Group sin ninguna Enabled=True/1. 2
        cuenta como deshabilitada. Cualquier error de consulta es error.
        """
        if not action.success:
            return RepairVerification("not_checked", "No se verificó porque la ejecución del comando falló.")

        try:
            if action.action_type == "firewall_enable_all":
                profiles = self._query_firewall_profiles()
                evidence = self._firewall_profiles_evidence(profiles)
                if all(state == "enabled" for state in profiles.values()):
                    return RepairVerification("verified", evidence)
                return RepairVerification("unverified", evidence)

            if action.action_type == "defender_enable_rtp":
                cmd = [
                    "powershell", "-NoProfile", "-Command",
                    "(Get-MpComputerStatus).RealTimeProtectionEnabled"
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore')
                if proc.returncode != 0:
                    detail = proc.stderr.strip() or "sin detalle"
                    return RepairVerification("error", f"PowerShell falló (código {proc.returncode}): {detail}")
                value = proc.stdout.strip().lower()
                if value == "true":
                    return RepairVerification("verified", "RealTimeProtectionEnabled=True")
                if value == "false":
                    return RepairVerification("unverified", "RealTimeProtectionEnabled=False")
                return RepairVerification("error", f"Respuesta inesperada: {value!r}")

            if action.action_type == "rdp_disable":
                cmd = [
                    "powershell", "-NoProfile", "-Command",
                    "(Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections"
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore')
                if proc.returncode != 0:
                    detail = proc.stderr.strip() or "sin detalle"
                    return RepairVerification("error", f"Registro: PowerShell falló (código {proc.returncode}): {detail}")
                value = proc.stdout.strip()
                if value != "1":
                    if value == "0":
                        return RepairVerification("unverified", "Registro: fDenyTSConnections=0 (RDP sigue habilitado)")
                    return RepairVerification("error", f"Registro: valor inesperado o ausente ({value!r})")

                rules = self._query_rdp_firewall_rules()
                evidence = f"Registro: fDenyTSConnections=1 | {self._rdp_firewall_evidence(rules)}"
                if any(r["state"] == "enabled" for r in rules):
                    return RepairVerification("unverified", evidence)
                return RepairVerification("verified", evidence)

            return RepairVerification("error", f"Tipo de reparación no reconocido: {action.action_type!r}")
        except subprocess.TimeoutExpired as exc:
            return RepairVerification("error", f"Timeout al verificar: {exc}")
        except Exception as exc:
            return RepairVerification("error", f"No se pudo verificar: {exc}")

    def _poll_repairs(self, thread):
        try:
            while True:
                msg_type, data = self.result_queue.get_nowait()
                try:
                    if msg_type == "repair_progress":
                        self.lbl_progress.configure(text=data)
                    elif msg_type == "repair_result":
                        action = data
                        status, color = action.display_status()
                        self._append_log(f"  {status} - {action.name}", color)
                        if action.skip_reason:
                            self._append_log(f"      Motivo: {action.skip_reason}", "dim")
                        if action.verification_evidence:
                            self._append_log(f"      Verificación: {action.verification_evidence}", "dim")
                        if action.error:
                            self._append_log(f"      Detalle: {action.error}", "dim")
                    elif msg_type == "repair_error":
                        self._append_log(f"[ERROR] {data}", "error")
                    elif msg_type == "repair_done":
                        self._finish_repairs()
                        return
                except Exception as exc:
                    # No dejamos que un evento defectuoso detenga el polling.
                    print(f"[Guardian] Error procesando evento '{msg_type}': {exc}", file=sys.stderr)
        except queue.Empty:
            pass
        except Exception as exc:
            print(f"[Guardian] Error en el bucle de reparaciones: {exc}", file=sys.stderr)

        if thread.is_alive():
            self.after(100, lambda: self._poll_repairs(thread))
        else:
            self._finish_repairs()

    def _finish_repairs(self):
        # Evitar finalizaciones duplicadas si el hilo termina y el evento ya se procesó.
        if not self.repair_in_progress:
            return
        self.repair_in_progress = False
        current_actions = list(self.repair_actions_to_run)
        self.repair_actions_to_run = []
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1)
        self.lbl_progress.configure(text="Reparaciones finalizadas")
        fixable = any(r.can_fix for r in self.check_results)
        self.btn_repair.configure(
            state="normal" if fixable else "disabled",
            text="🛠️  Reparar hallazgos"
        )
        self.btn_audit.configure(state="normal")
        self.btn_new_audit.configure(state="normal")
        self.btn_report.configure(state="normal" if self.check_results else "disabled")
        self.btn_select_folder.configure(state="normal")

        # Re-escanear solo si al menos una acción del lote actual llegó a ejecutarse.
        if any(a.attempted for a in current_actions):
            if messagebox.askyesno("Guardian Pro", "Reparaciones completadas. ¿Desea realizar una nueva auditoría para verificar los cambios?"):
                self.nueva_auditoria(auto_start=True)

    # ==================== INFORME PDF ====================

    @staticmethod
    def _pdf_safe(text) -> str:
        """Adapta texto a las fuentes core (latin-1) conservando tildes y eñes."""
        replacements = {
            "\u2014": "-", "\u2013": "-", "\u2018": "'", "\u2019": "'",
            "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u2022": "-",
            "\u00a0": " ",
        }
        value = str(text)
        for old, new in replacements.items():
            value = value.replace(old, new)
        return value.encode("latin-1", "replace").decode("latin-1")

    @staticmethod
    def _pdf_multicell(pdf, text, height=5):
        """Escribe un bloque de texto desde el margen izquierdo del PDF."""
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, height, text)

    def crear_pdf(self):
        if not self.check_results:
            messagebox.showwarning("Guardian Pro", "No hay resultados de auditoría para generar el informe.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            initialfile=f"Guardian_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            title="Guardar informe PDF"
        )
        if not path:
            return

        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_auto_page_break(auto=True, margin=20)

            # Encabezado
            pdf.set_fill_color(30, 60, 110)
            pdf.rect(0, 0, 210, 35, 'F')
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", 'B', 18)
            pdf.ln(8)
            pdf.cell(0, 10, self._pdf_safe("Guardian Pro — Informe de Seguridad"), ln=True, align='C')
            pdf.set_font("Helvetica", '', 10)
            pdf.cell(0, 6, self._pdf_safe(f"Generado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"), ln=True, align='C')
            pdf.cell(0, 6, self._pdf_safe(f"Auditoría: {self.audit_timestamp}"), ln=True, align='C')
            pdf.ln(10)

            # Resumen
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", 'B', 13)
            pdf.cell(0, 8, self._pdf_safe("1. Resumen de comprobaciones"), ln=True)
            pdf.set_font("Helvetica", '', 10)

            # Alcance explícito del análisis de archivos.
            self._pdf_multicell(pdf, self._pdf_safe(
                f"  Alcance del análisis de archivos: {self.selected_path or 'No seleccionado'}"
            ), 5)
            self._pdf_multicell(pdf, self._pdf_safe(
                "  El alcance indica la carpeta seleccionada. Si la comprobación de archivos reporta "
                "errores de acceso o de recorrido, el análisis no cubrió la carpeta completa."
            ), 5)
            pdf.ln(2)

            counts = {"ok": 0, "finding": 0, "unverifiable": 0, "error": 0}
            for r in self.check_results:
                if r.status in counts:
                    counts[r.status] += 1

            pdf.cell(0, 6, self._pdf_safe(f"  Correctas: {counts['ok']}"), ln=True)
            pdf.set_text_color(200, 0, 0)
            pdf.cell(0, 6, self._pdf_safe(f"  Hallazgos: {counts['finding']}"), ln=True)
            pdf.set_text_color(200, 150, 0)
            pdf.cell(0, 6, self._pdf_safe(f"  No verificables: {counts['unverifiable']}"), ln=True)
            pdf.set_text_color(200, 0, 0)
            pdf.cell(0, 6, self._pdf_safe(f"  Errores: {counts['error']}"), ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(4)

            # Detalle de comprobaciones
            pdf.set_font("Helvetica", 'B', 13)
            pdf.cell(0, 8, self._pdf_safe("2. Detalle de comprobaciones"), ln=True)
            pdf.ln(2)

            for r in self.check_results:
                pdf.set_font("Helvetica", 'B', 10)
                status_text = {"ok": "OK", "finding": "HALLAZGO", "unverifiable": "NO VERIFICABLE", "error": "ERROR"}.get(r.status, r.status.upper())
                pdf.cell(0, 6, self._pdf_safe(f"{r.name} — {status_text}"), ln=True)

                pdf.set_font("Helvetica", '', 9)
                pdf.set_text_color(80, 80, 80)
                # Todo el texto se adapta a la fuente core del PDF.
                self._pdf_multicell(pdf, self._pdf_safe(f"  Evidencia: {r.evidence}"), 5)
                if r.recommendation:
                    self._pdf_multicell(pdf, self._pdf_safe(f"  Recomendación: {r.recommendation}"), 5)
                pdf.set_text_color(0, 0, 0)
                pdf.ln(3)

            # Reparaciones ejecutadas y acciones omitidas
            repair_history = [
                a for a in self.repair_actions
                if a.attempted or a.skipped or a.selected or a.verification_status == "permission_denied"
            ]
            if repair_history:
                pdf.ln(2)
                pdf.set_font("Helvetica", 'B', 13)
                pdf.cell(0, 8, self._pdf_safe("3. Reparaciones y acciones omitidas"), ln=True)
                pdf.ln(2)

                for a in repair_history:
                    pdf.set_font("Helvetica", 'B', 10)
                    pdf.cell(0, 6, self._pdf_safe(f"{a.name} — {a.result_label()}"), ln=True)
                    pdf.set_font("Helvetica", '', 9)
                    pdf.set_text_color(80, 80, 80)
                    command_label = "Comando" if a.attempted else "Comando propuesto"
                    self._pdf_multicell(pdf, self._pdf_safe(f"  {command_label}: {a.command}"), 5)
                    if a.skip_reason:
                        self._pdf_multicell(pdf, self._pdf_safe(f"  Motivo: {a.skip_reason}"), 5)
                    if a.output:
                        self._pdf_multicell(pdf, self._pdf_safe(f"  Salida: {a.output}"), 5)
                    if a.error:
                        self._pdf_multicell(pdf, self._pdf_safe(f"  Error: {a.error}"), 5)
                    if a.verification_evidence:
                        self._pdf_multicell(pdf, self._pdf_safe(f"  Verificación: {a.verification_evidence}"), 5)
                    pdf.set_text_color(0, 0, 0)
                    pdf.ln(3)

            # Archivos sensibles
            if self.sensitive_files:
                pdf.ln(2)
                pdf.set_font("Helvetica", 'B', 13)
                pdf.cell(0, 8, self._pdf_safe("4. Archivos con nombres sensibles (solo nombres, no contenido)"), ln=True)
                pdf.ln(2)
                pdf.set_font("Helvetica", '', 8)
                pdf.set_text_color(80, 80, 80)
                for f in self.sensitive_files[:50]:  # Limitar a 50 para no saturar
                    self._pdf_multicell(pdf, self._pdf_safe(f"  > {f}"), 4.5)
                if len(self.sensitive_files) > 50:
                    self._pdf_multicell(pdf, self._pdf_safe(f"  ... y {len(self.sensitive_files) - 50} archivos más."), 4.5)
                pdf.set_text_color(0, 0, 0)

            # Pie de página con privacidad y advertencia
            pdf.ln(6)
            pdf.set_font("Helvetica", 'I', 8)
            pdf.set_text_color(120, 120, 120)
            self._pdf_multicell(pdf, self._pdf_safe(
                "PRIVACIDAD: este informe puede contener rutas locales, nombres de archivo u otros "
                "datos que revelen información del usuario. Revíselo antes de compartirlo."), 4.5)
            pdf.ln(2)
            self._pdf_multicell(pdf, self._pdf_safe(
                "ADVERTENCIA: Guardian Pro es una herramienta educativa de comprobación básica. "
                "Sus resultados no constituyen una evaluación profesional de seguridad ni garantizan "
                "la ausencia de vulnerabilidades. Las reparaciones automatizadas deben revisarse "
                "manualmente. Úselo bajo su propia responsabilidad."), 4.5)

            pdf.output(path)
            messagebox.showinfo("Guardian Pro", f"Informe guardado en:\n{path}")

        except Exception as e:
            messagebox.showerror("Error", f"No se pudo generar el PDF:\n{e}")

    # ==================== ESTADO Y LIMPIEZA ====================

    def nueva_auditoria(self, auto_start=False):
        """Resetea el estado para una nueva auditoría."""
        if self.audit_in_progress or self.repair_in_progress:
            return
        self._reset_audit_state()
        self._clear_results()
        self.progress_bar.set(0)
        self.progress_bar.configure(mode="determinate")
        self.lbl_progress.configure(text="Listo para iniciar")
        self.btn_audit.configure(state="normal", text="🔍  Iniciar auditoría")
        self.btn_repair.configure(state="disabled")
        self.btn_report.configure(state="disabled")
        self.btn_new_audit.configure(state="normal")
        self.btn_select_folder.configure(state="normal")
        self._append_log("=== Guardian Pro — Nueva auditoría ===")
        self._append_log(f"Carpeta seleccionada: {self.selected_path}")
        self._append_log("")

        if auto_start:
            self.iniciar_auditoria()


if __name__ == "__main__":
    app = GuardianProMaster()
    app.mainloop()