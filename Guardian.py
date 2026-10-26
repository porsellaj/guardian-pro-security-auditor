import copy
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

import guardian_workspace as workspace

# Configuración visual
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

COLORS = {
    "bg": "#0B1220",
    "sidebar": "#08101C",
    "panel": "#111C2E",
    "panel_alt": "#16243A",
    "border": "#26354A",
    "text": "#EDF2F7",
    "muted": "#9BAAC0",
    "accent": "#31C9B0",
    "accent_hover": "#45DCC5",
    "blue": "#6AA7FF",
    "warning": "#F5B95C",
    "error": "#F07575",
    "success": "#31C9B0",
    "demo_bg": "#3A2A12",
    "demo_border": "#8A6220",
}

FONT = "Segoe UI"


class CheckResult:
    """Resultado de una comprobación individual."""
    def __init__(self, name: str, status: str, evidence: str = "", severity: str = "info",
                 recommendation: str = "", can_fix: bool = False, fix_action: str = "",
                 manual_guidance: str = ""):
        self.name = name
        self.status = status  # "ok", "finding", "error", "unverifiable"
        self.evidence = evidence
        self.severity = severity  # "high", "medium", "low", "info"
        self.recommendation = recommendation
        self.can_fix = can_fix
        self.fix_action = fix_action
        self.manual_guidance = manual_guidance


class RepairAction:
    """Acción de reparación propuesta, ejecutada u omitida."""
    def __init__(self, name: str, description: str, command: str, requires_admin: bool = False,
                 action_type: str = "", warning: str = "", manual_guidance: str = ""):
        self.name = name
        self.description = description
        self.command = command
        self.requires_admin = requires_admin
        self.action_type = action_type
        self.warning = warning
        self.manual_guidance = manual_guidance
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
    DEFENDER_MANUAL_TITLE = "ACTIVACIÓN MANUAL DE MICROSOFT DEFENDER"
    DEFENDER_MANUAL_INTRO = (
        "Requiere intervención manual. Guardian no modifica automáticamente la "
        "configuración de la protección en tiempo real de Microsoft Defender. "
        "Actívala manualmente desde Seguridad de Windows y vuelve a ejecutar el "
        "análisis para comprobar el resultado."
    )
    DEFENDER_MANUAL_STEPS = (
        "1. Abre el menú Inicio.\n"
        "2. Busca y abre 'Seguridad de Windows' (Windows Security).\n"
        "3. Entra en 'Protección antivirus y contra amenazas' "
        "(Virus & threat protection).\n"
        "4. En 'Configuración de protección antivirus y contra amenazas', "
        "selecciona 'Administrar la configuración' (Manage settings).\n"
        "5. Busca 'Protección en tiempo real' (Real-time protection) y cambia "
        "el interruptor a 'Activado' (On).\n"
        "6. Regresa a Guardian y ejecuta una nueva auditoría para verificar el estado."
    )
    DEFENDER_MANUAL_NOTE = (
        "Si el interruptor está deshabilitado, no permite cambios o vuelve a "
        "apagarse, Windows puede estar aplicando Protección contra alteraciones "
        "(Tamper Protection), una directiva de administración u otra configuración "
        "de antivirus. No intentes eludir esas restricciones desde Guardian. "
        "Consulta la configuración de Seguridad de Windows o al administrador "
        "responsable del dispositivo."
    )
    DEFENDER_MANUAL_DETAILS = DEFENDER_MANUAL_STEPS + "\n\n" + DEFENDER_MANUAL_NOTE

    def __init__(self, workspace_dir=None, device_identity=None):
        super().__init__()
        self.title("Guardian Pro — Operations Center")
        self.geometry("1240x800")
        self.minsize(1020, 680)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Estado de la auditoría
        self.check_results = []
        self.repair_actions = []
        self.repair_actions_to_run = []
        self.sensitive_files = []
        self.pre_repair_results = []
        self.pre_repair_sensitive_files = []
        self.pre_repair_timestamp = ""
        self.pre_repair_path = ""
        self.pre_repair_context_captured = False
        self.post_repair_audit_attempted = False
        self.selected_path = os.path.expanduser("~")
        self.audit_timestamp = ""
        self.audit_in_progress = False
        self.repair_in_progress = False
        self.worker_thread = None
        self.result_queue = queue.Queue()

        # Estado del Operations Center
        self.workspace = workspace.GuardianWorkspace(workspace_dir)
        self.device_identity = device_identity or workspace.get_device_identity()
        self.history = []
        self.fleet_reports = []
        self.current_audit_record = None
        self.demo_mode = False
        self.demo_audits = []
        self.focus_record = None
        self.focus_source = ""
        self.history_selection = ""
        self.current_view = "overview"
        self.storage_warning = ""
        self.import_queue = queue.Queue()
        self.import_in_progress = False
        self.import_messages = []
        self.nav_buttons = {}
        self._load_workspace_data()

        self.setup_ui()
        self.show_view("overview")
        self._refresh_all_views()

    def _load_workspace_data(self):
        """Carga historial y flota sin impedir que la aplicación arranque."""
        try:
            self.history = self.workspace.load_history()
            self.fleet_reports = self.workspace.load_fleet()
        except Exception as exc:
            self.history = []
            self.fleet_reports = []
            self.storage_warning = f"No se pudo cargar el almacenamiento local: {exc}"
        warnings = list(getattr(self.workspace, "warnings", []))
        if warnings:
            self.storage_warning = warnings[-1]

    def setup_ui(self):
        # --- SIDEBAR ---
        self.grid_columnconfigure(0, weight=0, minsize=232)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=232, fg_color=COLORS["sidebar"], corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0, weight=1)
        self.sidebar.grid_rowconfigure(2, weight=1)

        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, padx=18, pady=(24, 14), sticky="ew")
        self.lbl_title = ctk.CTkLabel(
            brand, text="GUARDIAN PRO", font=(FONT, 21, "bold"),
            text_color=COLORS["text"], anchor="w",
        )
        self.lbl_title.pack(anchor="w")
        self.lbl_subtitle = ctk.CTkLabel(
            brand, text="OPERATIONS CENTER", font=(FONT, 9, "bold"),
            text_color=COLORS["accent"], anchor="w",
        )
        self.lbl_subtitle.pack(anchor="w", pady=(2, 0))
        ctk.CTkLabel(
            brand, text="Diagnóstico y seguimiento Windows",
            font=(FONT, 10), text_color=COLORS["muted"], anchor="w",
        ).pack(anchor="w", pady=(8, 0))

        nav = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        nav.grid(row=1, column=0, padx=12, pady=(4, 8), sticky="ew")
        nav.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            nav, text="NAVEGACIÓN", font=(FONT, 9, "bold"),
            text_color=COLORS["muted"], anchor="w",
        ).grid(row=0, column=0, padx=8, pady=(0, 6), sticky="w")
        for row, (key, text) in enumerate([
            ("overview", "Resumen ejecutivo"),
            ("action", "Plan de acción"),
            ("history", "Historial"),
            ("fleet", "Vista de equipos"),
        ], start=1):
            button = ctk.CTkButton(
                nav, text=text, anchor="w", height=38, corner_radius=8,
                font=(FONT, 12), fg_color="transparent", hover_color=COLORS["panel_alt"],
                text_color=COLORS["muted"], command=lambda k=key: self.show_view(k),
            )
            button.grid(row=row, column=0, sticky="ew", pady=2)
            self.nav_buttons[key] = button

        ops = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        ops.grid(row=3, column=0, padx=12, pady=(8, 8), sticky="ew")
        ops.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            ops, text="OPERACIONES", font=(FONT, 9, "bold"),
            text_color=COLORS["muted"], anchor="w",
        ).grid(row=0, column=0, padx=8, pady=(0, 6), sticky="w")

        self.btn_select_folder = ctk.CTkButton(
            ops, text="Seleccionar carpeta", height=32, corner_radius=8,
            font=(FONT, 11), fg_color=COLORS["panel_alt"], hover_color=COLORS["border"],
            text_color=COLORS["text"], command=self._select_folder_and_show_audit,
        )
        self.btn_select_folder.grid(row=1, column=0, sticky="ew", pady=2)
        self.btn_audit = ctk.CTkButton(
            ops, text="Iniciar auditoría", height=34, corner_radius=8,
            font=(FONT, 11, "bold"), fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"], text_color="#06201C",
            command=self._start_audit_from_ui,
        )
        self.btn_audit.grid(row=2, column=0, sticky="ew", pady=(4, 2))
        self.btn_repair = ctk.CTkButton(
            ops, text="Reparar hallazgos", height=32, corner_radius=8,
            font=(FONT, 11), fg_color=COLORS["panel_alt"], hover_color="#A56A28",
            text_color=COLORS["muted"], command=self._on_repair_button,
            state="disabled",
        )
        self.btn_repair.grid(row=3, column=0, sticky="ew", pady=2)
        self.btn_report = ctk.CTkButton(
            ops, text="Generar informe PDF", height=32, corner_radius=8,
            font=(FONT, 11), fg_color=COLORS["panel_alt"], hover_color="#2B6098",
            text_color=COLORS["muted"], command=self._on_report_button,
            state="disabled",
        )
        self.btn_report.grid(row=4, column=0, sticky="ew", pady=2)
        self.btn_new_audit = ctk.CTkButton(
            ops, text="Nueva auditoría", height=32, corner_radius=8,
            font=(FONT, 11), fg_color=COLORS["panel_alt"], hover_color=COLORS["border"],
            text_color=COLORS["text"], command=self._new_audit_from_ui,
        )
        self.btn_new_audit.grid(row=5, column=0, sticky="ew", pady=2)

        footer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        footer.grid(row=4, column=0, padx=18, pady=(8, 18), sticky="ew")
        self.sidebar_device_label = ctk.CTkLabel(
            footer, text="", font=(FONT, 10, "bold"),
            text_color=COLORS["text"], anchor="w", justify="left",
        )
        self.sidebar_device_label.pack(anchor="w")
        self.sidebar_os_label = ctk.CTkLabel(
            footer, text="", font=(FONT, 9), text_color=COLORS["muted"],
            anchor="w", justify="left",
        )
        self.sidebar_os_label.pack(anchor="w", pady=(1, 0))
        self.sidebar_demo_label = ctk.CTkLabel(
            footer, text="DEMO — DATOS FICTICIOS", font=(FONT, 9, "bold"),
            text_color=COLORS["warning"], anchor="w",
        )
        self.sidebar_demo_label.pack(anchor="w", pady=(6, 0))

        # --- PANEL PRINCIPAL ---
        self.main_view = ctk.CTkFrame(self, fg_color=COLORS["bg"], corner_radius=0)
        self.main_view.grid(row=0, column=1, sticky="nsew")
        self.main_view.grid_columnconfigure(0, weight=1)
        self.main_view.grid_rowconfigure(2, weight=1)

        self.header_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=28, pady=(22, 10), sticky="ew")
        self.header_frame.grid_columnconfigure(0, weight=1)

        header_left = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        header_left.grid(row=0, column=0, sticky="w")
        self.header_title = ctk.CTkLabel(
            header_left, text="Resumen ejecutivo", font=(FONT, 24, "bold"),
            text_color=COLORS["text"], anchor="w",
        )
        self.header_title.pack(anchor="w")
        self.header_subtitle = ctk.CTkLabel(
            header_left, text="", font=(FONT, 11), text_color=COLORS["muted"],
            anchor="w", justify="left", wraplength=430,
        )
        self.header_subtitle.pack(anchor="w", pady=(3, 0))

        header_actions = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        header_actions.grid(row=0, column=1, sticky="e")
        self.lbl_header_status = ctk.CTkLabel(
            header_actions, text="Sin auditorías", font=(FONT, 10, "bold"),
            text_color=COLORS["muted"],
        )
        self.lbl_header_status.grid(row=0, column=0, columnspan=3, sticky="e", pady=(0, 6))
        self.btn_export_json = ctk.CTkButton(
            header_actions, text="Exportar JSON", width=112, height=30,
            corner_radius=8, font=(FONT, 10), fg_color=COLORS["panel_alt"],
            hover_color=COLORS["border"], text_color=COLORS["muted"],
            command=self._export_current_report, state="disabled",
        )
        self.btn_export_json.grid(row=1, column=0, padx=(0, 6))
        self.btn_import_json = ctk.CTkButton(
            header_actions, text="Importar informes", width=124, height=30,
            corner_radius=8, font=(FONT, 10), fg_color=COLORS["panel_alt"],
            hover_color=COLORS["border"], text_color=COLORS["text"],
            command=self._start_import,
        )
        self.btn_import_json.grid(row=1, column=1, padx=(0, 6))
        self.btn_demo_toggle = ctk.CTkButton(
            header_actions, text="Modo demo", width=104, height=30,
            corner_radius=8, font=(FONT, 10, "bold"), fg_color="#6B4B1E",
            hover_color="#876026", command=self._toggle_demo,
        )
        self.btn_demo_toggle.grid(row=1, column=2)

        self.demo_banner = ctk.CTkFrame(
            self.main_view, fg_color=COLORS["demo_bg"], corner_radius=8,
            border_width=1, border_color=COLORS["demo_border"],
        )
        self.demo_banner.grid(row=1, column=0, padx=28, pady=(0, 8), sticky="ew")
        ctk.CTkLabel(
            self.demo_banner,
            text="DEMO — DATOS FICTICIOS · Esta vista no representa equipos reales y no se guarda en el historial.",
            font=(FONT, 10, "bold"), text_color=COLORS["warning"], anchor="w",
        ).pack(anchor="w", padx=12, pady=7)
        self.demo_banner.grid_remove()

        self.content_area = ctk.CTkFrame(self.main_view, fg_color="transparent")
        self.content_area.grid(row=2, column=0, padx=28, pady=(0, 4), sticky="nsew")
        self.content_area.grid_rowconfigure(0, weight=1)
        self.content_area.grid_columnconfigure(0, weight=1)
        self.views = {}
        self._build_overview_view()
        self._build_action_view()
        self._build_history_view()
        self._build_fleet_view()
        self._build_audit_view()

        self.progress_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        self.progress_frame.grid(row=3, column=0, padx=28, pady=(2, 16), sticky="ew")
        self.progress_frame.grid_columnconfigure(0, weight=1)
        self.lbl_progress = ctk.CTkLabel(
            self.progress_frame, text="Listo para iniciar", font=(FONT, 10),
            text_color=COLORS["muted"],
        )
        self.lbl_progress.grid(row=0, column=0, sticky="w")
        self.progress_bar = ctk.CTkProgressBar(
            self.progress_frame, height=6, progress_color=COLORS["accent"],
        )
        self.progress_bar.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        self.progress_bar.set(0)

    # ==================== COMPONENTES VISUALES ====================

    def _card(self, parent, **kwargs):
        options = {
            "fg_color": COLORS["panel"],
            "corner_radius": 12,
            "border_width": 1,
            "border_color": COLORS["border"],
        }
        options.update(kwargs)
        return ctk.CTkFrame(parent, **options)

    def _make_view(self, key):
        frame = ctk.CTkFrame(self.content_area, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        self.views[key] = frame
        return frame

    def _scroll(self, parent):
        return ctk.CTkScrollableFrame(
            parent, fg_color="transparent", corner_radius=0,
            label_text="", scrollbar_button_color=COLORS["border"],
            scrollbar_button_hover_color=COLORS["accent"],
        )

    def _clear_children(self, frame):
        for child in frame.winfo_children():
            child.destroy()

    def _section_label(self, parent, text):
        return ctk.CTkLabel(
            parent, text=text, font=(FONT, 11, "bold"),
            text_color=COLORS["text"], anchor="w",
        )

    def _muted_label(self, parent, text, wraplength=620):
        return ctk.CTkLabel(
            parent, text=text, font=(FONT, 10), text_color=COLORS["muted"],
            anchor="w", justify="left", wraplength=wraplength,
        )

    def _badge(self, parent, text, color, bg=None):
        return ctk.CTkLabel(
            parent, text=text, font=(FONT, 9, "bold"),
            text_color=color, fg_color=bg or COLORS["panel_alt"],
            corner_radius=6, padx=8, pady=3,
        )

    def _empty_state(self, parent, title, body, action_text=None, command=None):
        card = self._card(parent)
        card.pack(fill="x", pady=(8, 12))
        ctk.CTkLabel(
            card, text=title, font=(FONT, 18, "bold"),
            text_color=COLORS["text"], anchor="w",
        ).pack(anchor="w", padx=22, pady=(22, 6))
        self._muted_label(card, body, wraplength=720).pack(
            anchor="w", padx=22, pady=(0, 14)
        )
        if action_text and command:
            ctk.CTkButton(
                card, text=action_text, height=34, corner_radius=8,
                font=(FONT, 11, "bold"), fg_color=COLORS["accent"],
                hover_color=COLORS["accent_hover"], text_color="#06201C",
                command=command,
            ).pack(anchor="w", padx=22, pady=(0, 22))
        return card

    def _build_overview_view(self):
        frame = self._make_view("overview")
        self.overview_scroll = self._scroll(frame)
        self.overview_scroll.grid(row=0, column=0, sticky="nsew")

    def _build_action_view(self):
        frame = self._make_view("action")
        self.action_scroll = self._scroll(frame)
        self.action_scroll.grid(row=0, column=0, sticky="nsew")

    def _build_history_view(self):
        frame = self._make_view("history")
        frame.grid_columnconfigure(0, weight=0, minsize=330)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        list_card = self._card(frame)
        list_card.grid(row=0, column=0, padx=(0, 12), sticky="nsew")
        list_card.grid_rowconfigure(1, weight=1)
        list_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            list_card, text="Auditorías guardadas", font=(FONT, 12, "bold"),
            text_color=COLORS["text"], anchor="w",
        ).grid(row=0, column=0, padx=14, pady=(12, 6), sticky="w")
        self.history_list = self._scroll(list_card)
        self.history_list.grid(row=1, column=0, padx=6, pady=(0, 8), sticky="nsew")
        self.history_detail = self._scroll(frame)
        self.history_detail.grid(row=0, column=1, sticky="nsew")

    def _build_fleet_view(self):
        frame = self._make_view("fleet")
        self.fleet_scroll = self._scroll(frame)
        self.fleet_scroll.grid(row=0, column=0, sticky="nsew")

    def _build_audit_view(self):
        frame = self._make_view("audit")
        frame.grid_rowconfigure(2, weight=1)

        top = self._card(frame)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top.grid_columnconfigure(0, weight=1)
        left = ctk.CTkFrame(top, fg_color="transparent")
        left.grid(row=0, column=0, padx=16, pady=14, sticky="w")
        ctk.CTkLabel(
            left, text="Auditoría del sistema", font=(FONT, 15, "bold"),
            text_color=COLORS["text"], anchor="w",
        ).pack(anchor="w")
        self.audit_path_label = ctk.CTkLabel(
            left, text=f"Alcance de nombres: {self.selected_path}",
            font=(FONT, 9), text_color=COLORS["muted"], anchor="w",
        )
        self.audit_path_label.pack(anchor="w", pady=(3, 0))
        actions = ctk.CTkFrame(top, fg_color="transparent")
        actions.grid(row=0, column=1, padx=16, pady=14, sticky="e")
        self.btn_select_folder_view = ctk.CTkButton(
            actions, text="Seleccionar carpeta", height=32, corner_radius=8,
            font=(FONT, 10), fg_color=COLORS["panel_alt"],
            hover_color=COLORS["border"], text_color=COLORS["text"],
            command=self.elegir_carpeta,
        )
        self.btn_select_folder_view.pack(side="left", padx=(0, 6))
        self.btn_audit_view = ctk.CTkButton(
            actions, text="Iniciar auditoría", height=32, corner_radius=8,
            font=(FONT, 10, "bold"), fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"], text_color="#06201C",
            command=self._start_audit_from_ui,
        )
        self.btn_audit_view.pack(side="left")

        summary = ctk.CTkFrame(frame, fg_color="transparent")
        summary.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        self.summary_labels = {}
        for i, (key, label_text, color) in enumerate([
            ("ok", "Correctas", COLORS["success"]),
            ("finding", "Hallazgos", COLORS["error"]),
            ("unverifiable", "No verificables", COLORS["warning"]),
            ("error", "Errores", COLORS["error"]),
        ]):
            card = self._card(summary)
            card.grid(row=0, column=i, padx=(0 if i == 0 else 6, 0), sticky="ew")
            summary.grid_columnconfigure(i, weight=1)
            value = ctk.CTkLabel(
                card, text="0", font=(FONT, 24, "bold"), text_color=color,
            )
            value.pack(pady=(9, 0))
            ctk.CTkLabel(
                card, text=label_text, font=(FONT, 9), text_color=COLORS["muted"],
            ).pack(pady=(0, 9))
            self.summary_labels[key] = value

        results = self._card(frame)
        results.grid(row=2, column=0, sticky="nsew")
        results.grid_rowconfigure(1, weight=1)
        results.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            results, text="Resultados y guía de corrección", font=(FONT, 12, "bold"),
            text_color=COLORS["text"], anchor="w",
        ).grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")
        self.txt_results = ctk.CTkTextbox(
            results, fg_color=COLORS["bg"], text_color=COLORS["text"],
            border_width=0, font=("Consolas", 10), corner_radius=8,
            wrap="none",
        )
        self.txt_results.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.txt_results.configure(state="disabled")
        self.txt_results.tag_config("ok", foreground=COLORS["success"])
        self.txt_results.tag_config("finding", foreground=COLORS["error"])
        self.txt_results.tag_config("unverifiable", foreground=COLORS["warning"])
        self.txt_results.tag_config("error", foreground=COLORS["error"])
        self.txt_results.tag_config("header", foreground=COLORS["blue"])
        self.txt_results.tag_config("dim", foreground=COLORS["muted"])

    # ==================== NAVEGACIÓN Y ESTADO ====================

    VIEW_TITLES = {
        "overview": ("Resumen ejecutivo", "Estado consolidado y prioridades de la última evaluación."),
        "action": ("Plan de acción", "Qué se detectó, por qué importa y cómo verificar la corrección."),
        "history": ("Historial de auditorías", "Solo un OK posterior confirma una mejora."),
        "fleet": ("Vista de equipos", "Equipos locales e importados, por atención."),
        "audit": ("Auditoría del sistema", "Comprobaciones reales de Windows; el resumen se guarda al finalizar."),
    }

    def show_view(self, name):
        if name not in self.views:
            return
        for frame in self.views.values():
            frame.grid_remove()
        self.views[name].grid(row=0, column=0, sticky="nsew")
        self.current_view = name
        title, subtitle = self.VIEW_TITLES.get(name, ("Guardian Pro", ""))
        if self.demo_mode:
            subtitle = "DEMO — DATOS FICTICIOS · " + subtitle
        self.header_title.configure(text=title)
        self.header_subtitle.configure(text=subtitle)
        for key, button in self.nav_buttons.items():
            if key == name:
                button.configure(fg_color=COLORS["panel_alt"], text_color=COLORS["text"])
            else:
                button.configure(fg_color="transparent", text_color=COLORS["muted"])

    def _select_folder_and_show_audit(self):
        if self.demo_mode:
            messagebox.showinfo(
                "Guardian Pro",
                "Salga del modo demo para seleccionar una carpeta real y ejecutar una auditoría.",
            )
            return
        self.show_view("audit")
        self.elegir_carpeta()

    def _start_audit_from_ui(self):
        if self.demo_mode:
            messagebox.showinfo(
                "Guardian Pro",
                "El modo demo es solo de lectura. Salga del modo demo para auditar este equipo.",
            )
            return
        self.show_view("audit")
        self.iniciar_auditoria()

    def _new_audit_from_ui(self):
        if self.demo_mode:
            messagebox.showinfo(
                "Guardian Pro",
                "El modo demo no modifica el historial real. Salga del modo demo para iniciar una auditoría nueva.",
            )
            return
        self.show_view("audit")
        self.nueva_auditoria()

    def _on_repair_button(self):
        if self.demo_mode:
            messagebox.showinfo(
                "Guardian Pro",
                "Las reparaciones están deshabilitadas en el modo demo.",
            )
            return
        if self.focus_record is not None:
            messagebox.showinfo(
                "Guardian Pro",
                "Está consultando una auditoría guardada o importada. "
                "Vuelva al plan de la auditoría actual para habilitar reparaciones.",
            )
            return
        self.mostrar_dialogo_reparacion()

    def _on_report_button(self):
        if self.demo_mode:
            messagebox.showinfo(
                "Guardian Pro",
                "Salga del modo demo para generar un informe PDF con resultados reales.",
            )
            return
        self.crear_pdf()

    def _focus_on_record(self, record, source):
        if not record:
            return
        self.focus_record = record
        self.focus_source = source
        self.show_view("action")
        self._refresh_action_view()
        self._refresh_sidebar_state()

    def _clear_focus(self):
        self.focus_record = None
        self.focus_source = ""
        self._refresh_action_view()
        self._refresh_sidebar_state()

    def _refresh_all_views(self):
        for callback in (
            self._refresh_header,
            self._refresh_sidebar_state,
            self._refresh_overview_view,
            self._refresh_action_view,
            self._refresh_history_view,
            self._refresh_fleet_view,
        ):
            try:
                callback()
            except Exception as exc:
                print(f"[Guardian] Error actualizando {callback.__name__}: {exc}", file=sys.stderr)

    def _refresh_header(self):
        records = self._display_records()
        latest = self._latest_record(records)
        if self.demo_mode:
            status = "DEMO — DATOS FICTICIOS"
            color = COLORS["warning"]
        elif latest:
            status = f"Última evaluación: {self._short_date(latest['collected_at'])}"
            color = COLORS["muted"]
        else:
            status = "Sin auditorías"
            color = COLORS["muted"]
        self.lbl_header_status.configure(text=status, text_color=color)
        if self.demo_mode:
            self.demo_banner.grid()
        else:
            self.demo_banner.grid_remove()
        self.btn_demo_toggle.configure(
            text="Salir de demo" if self.demo_mode else "Modo demo",
            fg_color=COLORS["warning"] if self.demo_mode else "#6B4B1E",
            hover_color="#FFD08A" if self.demo_mode else "#876026",
            text_color="#241A08" if self.demo_mode else COLORS["text"],
        )

    def _refresh_sidebar_state(self):
        self.sidebar_device_label.configure(
            text=self.device_identity.get("name", "Equipo local")
        )
        self.sidebar_os_label.configure(text=self.device_identity.get("os", ""))
        self.sidebar_demo_label.configure(
            text="DEMO — DATOS FICTICIOS" if self.demo_mode else ""
        )
        busy = (
            self.audit_in_progress or self.repair_in_progress
            or self.import_in_progress
        )
        select_ok = not busy and not self.demo_mode
        self.btn_select_folder.configure(
            state="normal" if select_ok else "disabled",
            fg_color=COLORS["panel_alt"],
            text_color=COLORS["text"] if select_ok else COLORS["muted"],
        )
        audit_ok = not busy and not self.demo_mode
        self.btn_audit.configure(
            state="normal" if audit_ok else "disabled",
            text="Iniciar auditoría",
            fg_color=COLORS["accent"] if audit_ok else COLORS["panel_alt"],
            text_color="#06201C" if audit_ok else COLORS["muted"],
        )
        self.btn_new_audit.configure(
            state="normal" if audit_ok else "disabled",
            fg_color=COLORS["panel_alt"],
            text_color=COLORS["text"] if audit_ok else COLORS["muted"],
        )
        fixable = any(r.can_fix for r in self.check_results)
        repair_ok = (
            fixable and not self.demo_mode and self.focus_record is None and not busy
        )
        self.btn_repair.configure(
            state="normal" if repair_ok else "disabled",
            text="Reparar hallazgos",
            fg_color="#8A5A22" if repair_ok else COLORS["panel_alt"],
            text_color=COLORS["text"] if repair_ok else COLORS["muted"],
        )
        report_ok = (
            bool(self.check_results or self.pre_repair_context_captured)
            and not self.demo_mode and not busy
        )
        self.btn_report.configure(
            state="normal" if report_ok else "disabled",
            fg_color="#214B78" if report_ok else COLORS["panel_alt"],
            text_color=COLORS["text"] if report_ok else COLORS["muted"],
        )
        export_ok = (
            not self.demo_mode and not busy
            and bool(self.current_audit_record or self.history)
        )
        self.btn_export_json.configure(
            state="normal" if export_ok else "disabled",
            text_color=COLORS["text"] if export_ok else COLORS["muted"],
        )
        import_ok = not self.demo_mode and not busy and not self.import_in_progress
        self.btn_import_json.configure(
            state="normal" if import_ok else "disabled",
            text="Importando..." if self.import_in_progress else "Importar informes",
            text_color=COLORS["text"] if import_ok else COLORS["muted"],
        )
        self.btn_demo_toggle.configure(state="disabled" if busy else "normal")
        if hasattr(self, "btn_select_folder_view"):
            self.btn_select_folder_view.configure(
                state="normal" if select_ok else "disabled",
                fg_color=COLORS["panel_alt"],
                text_color=COLORS["text"] if select_ok else COLORS["muted"],
            )
        if hasattr(self, "btn_audit_view"):
            self.btn_audit_view.configure(
                state="normal" if audit_ok else "disabled",
                fg_color=COLORS["accent"] if audit_ok else COLORS["panel_alt"],
                text_color="#06201C" if audit_ok else COLORS["muted"],
            )

    # ==================== DATOS PARA LAS VISTAS ====================

    @staticmethod
    def _short_date(value):
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed.astimezone().strftime("%d/%m/%Y %H:%M")
        except (ValueError, TypeError):
            return str(value or "No disponible")

    @staticmethod
    def _record_key(record):
        return workspace._datetime_key(record.get("collected_at", ""))

    def _display_records(self):
        return list(self.demo_audits if self.demo_mode else self.history)

    def _latest_record(self, records):
        if not records:
            return None
        return max(records, key=lambda record: (self._record_key(record), record.get("audit_id", "")))

    def _real_fleet_reports(self):
        reports = {report["audit_id"]: report for report in self.fleet_reports}
        latest = self._latest_record(self.history)
        if latest:
            try:
                reports[latest["audit_id"]] = workspace.report_from_audit(latest)
            except workspace.WorkspaceError:
                pass
        return list(reports.values())

    def _display_fleet(self):
        reports = self.demo_audits if self.demo_mode else self._real_fleet_reports()
        try:
            return workspace.fleet_overview(reports)
        except Exception as exc:
            print(f"[Guardian] No se pudo consolidar la flota: {exc}", file=sys.stderr)
            return []

    def _current_action_context(self):
        """Devuelve (checks, source, allow_repair, record, title)."""
        if self.demo_mode:
            record = self.focus_record if self.focus_source == "demo" else None
            if record is None:
                record = self._latest_record(self.demo_audits)
            if record is None:
                return None
            return record["checks"], "demo", False, record, record["device"]["name"]
        if self.focus_record is not None:
            return (
                self.focus_record["checks"],
                self.focus_source or "history",
                False,
                self.focus_record,
                self.focus_record["device"]["name"],
            )
        if self.check_results and not self.audit_in_progress:
            return (
                self.check_results,
                "live",
                True,
                self.current_audit_record,
                self.device_identity.get("name", "Equipo local"),
            )
        latest = self._latest_record(self.history)
        if latest is not None:
            return latest["checks"], "history", False, latest, latest["device"]["name"]
        return None

    def _record_finished_audit(self):
        """Guarda la auditoría real sin bloquear ni romper el resultado principal."""
        if not self.check_results:
            return
        try:
            saved = self.workspace.save_audit(self.check_results, self.device_identity)
            self.current_audit_record = saved
            self.history = self.workspace.load_history()
            self.storage_warning = ""
            self._append_log("[HISTORIAL] Auditoría guardada en el almacenamiento local.", "dim")
        except Exception as exc:
            # La auditoría y el PDF deben seguir funcionando aunque el almacén falle.
            self.storage_warning = f"No se pudo guardar el historial local: {exc}"
            try:
                record = workspace.build_audit_record(
                    self.check_results, self.device_identity
                )
                previous = self.workspace.latest_for_device(
                    self.device_identity.get("id", "")
                )
                if previous is not None:
                    record["comparison"] = workspace.compare_audits(previous, record)
                self.current_audit_record = record
            except Exception:
                self.current_audit_record = None
            self._append_log(
                f"[AVISO] {self.storage_warning}. La auditoría actual sigue disponible en memoria.",
                "unverifiable",
            )

    # ==================== VISTA: RESUMEN ====================

    def _refresh_overview_view(self):
        self._clear_children(self.overview_scroll)
        records = self._display_records()
        latest = self._latest_record(records)
        fleet = self._display_fleet()
        if latest is None and not fleet:
            self._empty_state(
                self.overview_scroll,
                "Todavía no hay auditorías guardadas",
                "Ejecute una auditoría de este equipo para obtener un diagnóstico priorizado. "
                "También puede cargar la demostración para recorrer la interfaz con datos ficticios, "
                "que nunca se mezclan con el historial real.",
                "Iniciar primera auditoría",
                self._start_audit_from_ui,
            )
            ctk.CTkButton(
                self.overview_scroll, text="Cargar demostración", height=34,
                corner_radius=8, font=(FONT, 11), fg_color=COLORS["panel_alt"],
                hover_color=COLORS["border"], command=self._toggle_demo,
            ).pack(anchor="w", padx=8, pady=(0, 8))
            if self.storage_warning:
                self._muted_label(
                    self.overview_scroll,
                    f"Almacenamiento local: {self.storage_warning}",
                    wraplength=760,
                ).pack(anchor="w", padx=8, pady=(8, 0))
            return

        if latest is None:
            latest = fleet[0]["latest"] if fleet else None
        plan = workspace.build_action_plan(
            latest["checks"] if latest else [],
            allow_repair=False,
            source="demo" if self.demo_mode else "history",
        )
        high = sum(1 for item in plan if item["status"] == "finding" and item["severity"] == "high")
        review = sum(1 for item in plan if item["status"] in {"error", "unverifiable"})

        metrics = ctk.CTkFrame(self.overview_scroll, fg_color="transparent")
        metrics.pack(fill="x", pady=(0, 10))
        values = [
            ("Prioridades", len(plan), COLORS["warning"]),
            ("Hallazgos altos", high, COLORS["error"]),
            ("Requieren revisión", review, COLORS["blue"]),
            ("Equipos", len(fleet), COLORS["text"]),
            ("Auditorías", len(records), COLORS["text"]),
        ]
        for index, (label, value, color) in enumerate(values):
            metrics.grid_columnconfigure(index, weight=1)
            card = self._card(metrics)
            card.grid(row=0, column=index, padx=(0 if index == 0 else 6, 0), sticky="ew")
            ctk.CTkLabel(
                card, text=str(value), font=(FONT, 25, "bold"), text_color=color,
            ).pack(anchor="w", padx=14, pady=(11, 0))
            ctk.CTkLabel(
                card, text=label, font=(FONT, 9), text_color=COLORS["muted"],
            ).pack(anchor="w", padx=14, pady=(0, 10))

        last_card = self._card(self.overview_scroll)
        last_card.pack(fill="x", pady=(0, 10))
        last_card.grid_columnconfigure(0, weight=1)
        left = ctk.CTkFrame(last_card, fg_color="transparent")
        left.grid(row=0, column=0, padx=16, pady=13, sticky="w")
        ctk.CTkLabel(
            left, text="Última evaluación", font=(FONT, 10, "bold"),
            text_color=COLORS["muted"], anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            left, text=f"{self._short_date(latest['collected_at'])} · {latest['device']['name']}",
            font=(FONT, 14, "bold"), text_color=COLORS["text"], anchor="w",
        ).pack(anchor="w", pady=(2, 0))
        self._muted_label(
            left,
            f"{latest['device'].get('os', '')} · "
            f"{latest['summary']['finding']} hallazgo(s), "
            f"{latest['summary']['unverifiable'] + latest['summary']['error']} por revisar",
            wraplength=520,
        ).pack(anchor="w", pady=(2, 0))
        ctk.CTkButton(
            last_card, text="Abrir plan de acción", height=30, corner_radius=8,
            font=(FONT, 10, "bold"), fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"], text_color="#06201C",
            command=lambda: self._focus_on_record(
                latest, "demo" if self.demo_mode else "history"
            ),
        ).grid(row=0, column=1, padx=16, sticky="e")

        if self.storage_warning:
            warn = self._card(self.overview_scroll, fg_color="#2A2114", border_color=COLORS["demo_border"])
            warn.pack(fill="x", pady=(0, 10))
            self._muted_label(warn, f"Almacenamiento local: {self.storage_warning}", wraplength=760).pack(
                anchor="w", padx=14, pady=10
            )

        self._build_trend_chart(self.overview_scroll, records)

        priorities = self._card(self.overview_scroll)
        priorities.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(
            priorities, text="Prioridades de la última auditoría", font=(FONT, 12, "bold"),
            text_color=COLORS["text"], anchor="w",
        ).pack(anchor="w", padx=16, pady=(13, 6))
        if not plan:
            self._muted_label(
                priorities, "No hay acciones pendientes en la última auditoría.", wraplength=760
            ).pack(anchor="w", padx=16, pady=(0, 14))
        else:
            for item in plan[:3]:
                row = ctk.CTkFrame(priorities, fg_color="transparent")
                row.pack(fill="x", padx=16, pady=4)
                self._badge(
                    row, self._status_text(item["status"]),
                    self._status_color(item["status"]),
                ).pack(side="left", padx=(0, 8))
                ctk.CTkLabel(
                    row, text=item["name"], font=(FONT, 10, "bold"),
                    text_color=COLORS["text"], anchor="w",
                ).pack(side="left")
                ctk.CTkLabel(
                    row, text=item["what"], font=(FONT, 9),
                    text_color=COLORS["muted"], anchor="w",
                ).pack(side="left", padx=(10, 0))
            ctk.CTkButton(
                priorities, text="Ver todas las prioridades", height=30,
                corner_radius=8, font=(FONT, 10), fg_color=COLORS["panel_alt"],
                hover_color=COLORS["border"], command=lambda: self.show_view("action"),
            ).pack(anchor="w", padx=16, pady=(8, 14))

        comparison = latest.get("comparison") if latest else None
        changes = self._card(self.overview_scroll)
        changes.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(
            changes, text="Cambios desde la evaluación anterior", font=(FONT, 12, "bold"),
            text_color=COLORS["text"], anchor="w",
        ).pack(anchor="w", padx=16, pady=(13, 6))
        if not comparison:
            self._muted_label(
                changes,
                "No hay una auditoría anterior válida para este equipo. "
                "No se presenta una tendencia ni una resolución sin evidencia.",
                wraplength=760,
            ).pack(anchor="w", padx=16, pady=(0, 14))
        else:
            summary = comparison.get("summary", {})
            self._muted_label(
                changes,
                f"Nuevos: {summary.get('new', 0)} · Persistentes: {summary.get('persistent', 0)} · "
                f"Resueltos confirmados: {summary.get('resolved', 0)} · "
                f"No verificables: {summary.get('unverifiable', 0)}",
                wraplength=760,
            ).pack(anchor="w", padx=16, pady=(0, 14))

    def _build_trend_chart(self, parent, records):
        card = self._card(parent)
        card.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(
            card, text="Tendencia de atención", font=(FONT, 12, "bold"),
            text_color=COLORS["text"], anchor="w",
        ).pack(anchor="w", padx=16, pady=(13, 0))
        self._muted_label(
            card,
            "Elementos que requieren atención (hallazgos, errores y comprobaciones no verificables) "
            "en las últimas auditorías. No es una puntuación de seguridad.",
            wraplength=760,
        ).pack(anchor="w", padx=16, pady=(2, 8))
        recent = sorted(records, key=self._record_key)[-8:]
        if not recent:
            return
        chart = ctk.CTkFrame(card, fg_color="transparent", height=116)
        chart.pack(fill="x", padx=16, pady=(0, 14))
        chart.pack_propagate(False)
        values = [
            record["summary"]["finding"]
            + record["summary"]["error"]
            + record["summary"]["unverifiable"]
            for record in recent
        ]
        maximum = max(values) if values else 0
        for index, (record, value) in enumerate(zip(recent, values)):
            column = ctk.CTkFrame(chart, fg_color="transparent")
            column.place(relx=index / max(len(recent), 1), rely=0, relwidth=1 / max(len(recent), 1), relheight=1)
            holder = ctk.CTkFrame(column, fg_color="transparent", height=76)
            holder.pack(fill="x", pady=(4, 0))
            holder.pack_propagate(False)
            height = 8 if maximum == 0 else max(8, int(68 * value / maximum))
            bar = ctk.CTkFrame(
                holder, fg_color=COLORS["warning"] if value else COLORS["border"],
                corner_radius=4, height=height,
            )
            bar.place(relx=0.5, rely=1.0, anchor="s", relwidth=0.48)
            ctk.CTkLabel(
                column, text=str(value), font=(FONT, 9, "bold"),
                text_color=COLORS["text"],
            ).pack()
            ctk.CTkLabel(
                column, text=self._short_date(record["collected_at"])[:5],
                font=(FONT, 8), text_color=COLORS["muted"],
            ).pack()
        if len(recent) < 2:
            self._muted_label(
                card, "Se necesitan al menos dos auditorías para observar una tendencia.",
                wraplength=760,
            ).pack(anchor="w", padx=16, pady=(0, 12))

    @staticmethod
    def _status_text(status):
        return {
            "ok": "OK", "finding": "HALLAZGO", "error": "ERROR",
            "unverifiable": "NO VERIFICABLE",
        }.get(status, str(status).upper())

    @staticmethod
    def _status_color(status):
        return {
            "ok": COLORS["success"], "finding": COLORS["error"],
            "error": COLORS["error"], "unverifiable": COLORS["warning"],
        }.get(status, COLORS["muted"])

    @staticmethod
    def _severity_text(severity):
        return {"high": "Alta", "medium": "Media", "low": "Baja", "info": "Informativa"}.get(
            severity, str(severity)
        )

    # ==================== VISTA: PLAN DE ACCIÓN ====================

    def _refresh_action_view(self):
        self._clear_children(self.action_scroll)
        context = self._current_action_context()
        if context is None:
            self._empty_state(
                self.action_scroll,
                "No hay un plan de acción todavía",
                "El plan se genera a partir de una auditoría real. Ejecute una auditoría o cargue "
                "la demostración para ver cómo se priorizan los hallazgos y las verificaciones.",
                "Iniciar auditoría",
                self._start_audit_from_ui,
            )
            return

        checks, source, allow_repair, record, title = context
        plan = workspace.build_action_plan(
            checks, allow_repair=allow_repair, source=source
        )
        source_label = {
            "live": "Auditoría actual de este equipo",
            "history": "Auditoría guardada — solo lectura",
            "imported": "Informe importado — solo lectura",
            "demo": "DEMO — DATOS FICTICIOS",
        }.get(source, source)

        header = self._card(self.action_scroll)
        header.pack(fill="x", pady=(0, 10))
        header.grid_columnconfigure(0, weight=1)
        left = ctk.CTkFrame(header, fg_color="transparent")
        left.grid(row=0, column=0, padx=16, pady=12, sticky="w")
        ctk.CTkLabel(
            left, text=title or "Plan de acción", font=(FONT, 14, "bold"),
            text_color=COLORS["text"], anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            left, text=f"{source_label} · {len(plan)} prioridad(es)",
            font=(FONT, 9), text_color=COLORS["muted"], anchor="w",
        ).pack(anchor="w", pady=(2, 0))
        if self.focus_record is not None:
            ctk.CTkButton(
                header, text="Volver al plan actual", height=30, corner_radius=8,
                font=(FONT, 10), fg_color=COLORS["panel_alt"],
                hover_color=COLORS["border"], command=self._clear_focus,
            ).grid(row=0, column=1, padx=16, sticky="e")

        if source in {"history", "imported", "demo"}:
            note = self._card(
                self.action_scroll, fg_color="#1B2434", border_color=COLORS["border"]
            )
            note.pack(fill="x", pady=(0, 10))
            self._muted_label(
                note,
                "Las reparaciones están deshabilitadas para este contexto. "
                "Solo la auditoría actual de este equipo puede preparar una reparación con confirmación.",
                wraplength=760,
            ).pack(anchor="w", padx=14, pady=10)

        if not plan:
            self._empty_state(
                self.action_scroll,
                "Sin acciones pendientes",
                "La última evaluación no contiene hallazgos, errores ni comprobaciones no verificables.",
            )
            return

        for index, item in enumerate(plan, start=1):
            self._build_plan_card(self.action_scroll, index, item)

    def _build_plan_card(self, parent, index, item):
        card = self._card(parent)
        card.pack(fill="x", pady=(0, 9))
        card.grid_columnconfigure(1, weight=1)
        accent = self._status_color(item["status"])
        ctk.CTkFrame(card, fg_color=accent, width=4, corner_radius=2).grid(
            row=0, column=0, rowspan=2, sticky="ns", padx=(0, 0), pady=8
        )
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=1, padx=14, pady=(12, 2), sticky="ew")
        top.grid_columnconfigure(1, weight=1)
        self._badge(
            top, self._status_text(item["status"]), self._status_color(item["status"]),
        ).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkLabel(
            top, text=f"{index}. {item['name']}", font=(FONT, 12, "bold"),
            text_color=COLORS["text"], anchor="w",
        ).grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(
            top, text=f"Severidad {self._severity_text(item['severity'])} · {item['action_label']}",
            font=(FONT, 9), text_color=COLORS["muted"], anchor="e",
        ).grid(row=0, column=2, sticky="e")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.grid(row=1, column=1, padx=14, pady=(0, 12), sticky="ew")
        body.grid_columnconfigure(0, weight=1)
        for row, (label, text) in enumerate([
            ("Qué se detectó", item["what"]),
            ("Por qué importa", item["why"]),
            ("Siguiente paso", item["next_step"]),
            ("Cómo verificar", item["verification"]),
        ]):
            ctk.CTkLabel(
                body, text=label, font=(FONT, 9, "bold"),
                text_color=COLORS["muted"], anchor="w",
            ).grid(row=row * 2, column=0, sticky="w", pady=(4, 0))
            ctk.CTkLabel(
                body, text=text, font=(FONT, 10), text_color=COLORS["text"],
                anchor="w", justify="left", wraplength=760,
            ).grid(row=row * 2 + 1, column=0, sticky="w")

        actions = ctk.CTkFrame(body, fg_color="transparent")
        actions.grid(row=8, column=0, sticky="w", pady=(8, 0))
        if item["can_repair"]:
            ctk.CTkButton(
                actions, text="Preparar reparación", height=28, corner_radius=7,
                font=(FONT, 9, "bold"), fg_color="#8A5A22", hover_color="#A56A28",
                command=self.mostrar_dialogo_reparacion,
            ).pack(side="left", padx=(0, 8))
        if item["check_id"] == "defender":
            ctk.CTkButton(
                actions, text="Ver guía manual", height=28, corner_radius=7,
                font=(FONT, 9), fg_color=COLORS["panel_alt"],
                hover_color=COLORS["border"], command=self._show_defender_guide,
            ).pack(side="left", padx=(0, 8))
        if not item["can_repair"]:
            ctk.CTkLabel(
                actions, text="No hay reparación automática para esta acción.",
                font=(FONT, 9), text_color=COLORS["muted"],
            ).pack(side="left")

    def _show_defender_guide(self):
        messagebox.showinfo(
            self.DEFENDER_MANUAL_TITLE,
            self.DEFENDER_MANUAL_DETAILS,
        )

    # ==================== VISTA: HISTORIAL ====================

    def _refresh_history_view(self):
        self._clear_children(self.history_list)
        self._clear_children(self.history_detail)
        records = sorted(self._display_records(), key=self._record_key, reverse=True)
        if not records:
            self._empty_state(
                self.history_detail,
                "Historial vacío",
                "Cada auditoría finalizada se guarda localmente como un resumen sanitizado. "
                "Ejecute una auditoría para crear el primer registro.",
                "Iniciar auditoría",
                self._start_audit_from_ui,
            )
            return
        valid_ids = {record["audit_id"] for record in records}
        if self.history_selection not in valid_ids:
            self.history_selection = records[0]["audit_id"]

        for record in records[:50]:
            selected = record["audit_id"] == self.history_selection
            card = self._card(
                self.history_list,
                fg_color=COLORS["panel_alt"] if selected else COLORS["panel"],
                border_color=COLORS["accent"] if selected else COLORS["border"],
            )
            card.pack(fill="x", padx=2, pady=3)
            button = ctk.CTkButton(
                card,
                text=(
                    f"{self._short_date(record['collected_at'])}\n"
                    f"{record['device']['name']} · "
                    f"{record['summary']['finding']} hallazgo(s) · "
                    f"{record['summary']['unverifiable'] + record['summary']['error']} por revisar"
                ),
                anchor="w", height=54, corner_radius=7,
                font=(FONT, 9), fg_color="transparent",
                hover_color=COLORS["border"], text_color=COLORS["text"],
                command=lambda audit_id=record["audit_id"]: self._select_history(audit_id),
            )
            button.pack(fill="x", padx=4, pady=4)

        selected_record = next(
            (record for record in records if record["audit_id"] == self.history_selection),
            records[0],
        )
        self._render_history_detail(selected_record, records)

    def _select_history(self, audit_id):
        self.history_selection = audit_id
        self._refresh_history_view()

    def _render_history_detail(self, record, records):
        card = self._card(self.history_detail)
        card.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(
            card, text=f"Auditoría del {self._short_date(record['collected_at'])}",
            font=(FONT, 15, "bold"), text_color=COLORS["text"], anchor="w",
        ).pack(anchor="w", padx=16, pady=(14, 2))
        self._muted_label(
            card,
            f"{record['device']['name']} · {record['device'].get('os', '')} · "
            f"ID de auditoría: {record['audit_id']}",
            wraplength=460,
        ).pack(anchor="w", padx=16, pady=(0, 8))

        chips = ctk.CTkFrame(card, fg_color="transparent")
        chips.pack(anchor="w", padx=16, pady=(0, 8))
        for key, text in (
            ("ok", "Correctas"), ("finding", "Hallazgos"),
            ("unverifiable", "No verificables"), ("error", "Errores"),
        ):
            self._badge(
                chips, f"{text}: {record['summary'][key]}",
                self._status_color(key),
            ).pack(side="left", padx=(0, 6))

        comparison = record.get("comparison")
        if comparison is None:
            comparison = self._comparison_with_previous(record, records)
        ctk.CTkLabel(
            card, text="Comparación con la evaluación anterior", font=(FONT, 11, "bold"),
            text_color=COLORS["text"], anchor="w",
        ).pack(anchor="w", padx=16, pady=(8, 4))
        if not comparison:
            self._muted_label(
                card,
                "No hay una auditoría anterior válida para este equipo. "
                "No se declara ninguna mejora ni resolución.",
                wraplength=460,
            ).pack(anchor="w", padx=16, pady=(0, 8))
        else:
            summary = comparison.get("summary", {})
            self._muted_label(
                card,
                f"Nuevos: {summary.get('new', 0)} · Persistentes: {summary.get('persistent', 0)} · "
                f"Resueltos confirmados: {summary.get('resolved', 0)} · "
                f"No verificables: {summary.get('unverifiable', 0)} · "
                f"No evaluados: {summary.get('not_evaluated', 0)}",
                wraplength=460,
            ).pack(anchor="w", padx=16, pady=(0, 6))
            for key, label in (
                ("new", "Hallazgos nuevos"),
                ("persistent", "Problemas persistentes"),
                ("resolved", "Resueltos con evidencia (estado OK)"),
                ("unverifiable", "No verificables"),
                ("not_evaluated", "No evaluados en esta auditoría"),
            ):
                items = comparison.get(key, [])
                if not items:
                    continue
                ctk.CTkLabel(
                    card, text=label, font=(FONT, 9, "bold"),
                    text_color=COLORS["muted"], anchor="w",
                ).pack(anchor="w", padx=16, pady=(4, 1))
                for item in items:
                    ctk.CTkLabel(
                        card,
                        text=f"· {item['name']} ({self._status_text(item['status'])})",
                        font=(FONT, 9), text_color=COLORS["text"], anchor="w",
                    ).pack(anchor="w", padx=26)
        ctk.CTkLabel(
            card,
            text="Una recomendación o un comando ejecutado no equivalen a una resolución. "
                 "Solo un estado OK en una auditoría posterior cuenta como resuelto.",
            font=(FONT, 9), text_color=COLORS["muted"], anchor="w",
            justify="left", wraplength=460,
        ).pack(anchor="w", padx=16, pady=(10, 6))
        ctk.CTkButton(
            card, text="Ver plan de esta auditoría", height=30, corner_radius=8,
            font=(FONT, 10, "bold"), fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"], text_color="#06201C",
            command=lambda: self._focus_on_record(
                record, "demo" if self.demo_mode else "history"
            ),
        ).pack(anchor="w", padx=16, pady=(0, 14))

    def _comparison_with_previous(self, record, records):
        device_id = record["device"]["id"]
        current_time = self._record_key(record)
        previous = [
            candidate for candidate in records
            if candidate["device"]["id"] == device_id
            and candidate["audit_id"] != record["audit_id"]
            and self._record_key(candidate) <= current_time
        ]
        if not previous:
            return None
        previous_record = max(previous, key=self._record_key)
        try:
            return workspace.compare_audits(previous_record, record)
        except workspace.WorkspaceError:
            return None

    # ==================== VISTA: EQUIPOS ====================

    def _refresh_fleet_view(self):
        self._clear_children(self.fleet_scroll)
        overview = self._display_fleet()
        header = self._card(self.fleet_scroll)
        header.pack(fill="x", pady=(0, 10))
        header.grid_columnconfigure(0, weight=1)
        left = ctk.CTkFrame(header, fg_color="transparent")
        left.grid(row=0, column=0, padx=16, pady=12, sticky="w")
        ctk.CTkLabel(
            left, text="Equipos representados", font=(FONT, 14, "bold"),
            text_color=COLORS["text"], anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            left,
            text=(
                f"DEMO — DATOS FICTICIOS · {len(overview)} equipo(s)" if self.demo_mode
                else f"{len(overview)} equipo(s) · {len(self.fleet_reports)} informe(s) importado(s)"
            ),
            font=(FONT, 9), text_color=COLORS["muted"], anchor="w",
        ).pack(anchor="w", pady=(2, 0))
        if not self.demo_mode:
            ctk.CTkButton(
                header, text="Importar informes", height=30, corner_radius=8,
                font=(FONT, 10, "bold"), fg_color=COLORS["accent"],
                hover_color=COLORS["accent_hover"], text_color="#06201C",
                command=self._start_import,
            ).grid(row=0, column=1, padx=16, sticky="e")

        if self.import_messages:
            log = self._card(self.fleet_scroll, fg_color="#1B2434")
            log.pack(fill="x", pady=(0, 10))
            ctk.CTkLabel(
                log, text="Resultado de la última importación", font=(FONT, 10, "bold"),
                text_color=COLORS["text"], anchor="w",
            ).pack(anchor="w", padx=14, pady=(10, 3))
            for message in self.import_messages[-6:]:
                ctk.CTkLabel(
                    log, text=message, font=(FONT, 9), text_color=COLORS["muted"],
                    anchor="w", justify="left", wraplength=760,
                ).pack(anchor="w", padx=14)
            ctk.CTkLabel(log, text="", font=(FONT, 1)).pack(pady=2)

        if not overview:
            self._empty_state(
                self.fleet_scroll,
                "Todavía no hay equipos en el panel",
                "Exporte un informe JSON desde otro equipo y use «Importar informes» para consolidarlo. "
                "Los informes son datos pasivos: no ejecutan comprobaciones ni reparaciones. "
                "También puede activar el modo demo para ver tres equipos ficticios.",
                "Importar informes",
                self._start_import,
            )
            return

        for item in overview:
            card = self._card(self.fleet_scroll)
            card.pack(fill="x", pady=(0, 9))
            card.grid_columnconfigure(0, weight=1)
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.grid(row=0, column=0, padx=16, pady=(12, 3), sticky="ew")
            top.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(
                top, text=item["device"]["name"], font=(FONT, 13, "bold"),
                text_color=COLORS["text"], anchor="w",
            ).grid(row=0, column=0, sticky="w")
            if not self.demo_mode and item["device"]["id"] == self.device_identity.get("id"):
                self._badge(top, "Este equipo", COLORS["accent"]).grid(
                    row=0, column=1, padx=(8, 0), sticky="w"
                )
            ctk.CTkLabel(
                top,
                text=f"{item['device'].get('os', '')} · Última: {self._short_date(item['latest']['collected_at'])}",
                font=(FONT, 9), text_color=COLORS["muted"], anchor="w",
            ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))
            counts = item["summary"]
            self._muted_label(
                card,
                f"Hallazgos: {counts['finding']} · No verificables: {counts['unverifiable']} · "
                f"Errores: {counts['error']} · Auditorías del equipo: {item['history_count']}",
                wraplength=760,
            ).grid(row=1, column=0, padx=16, sticky="w")
            plan = item["plan"]
            if plan:
                first = plan[0]
                self._muted_label(
                    card,
                    f"Prioridad principal: {first['name']} — {first['what']}",
                    wraplength=760,
                ).grid(row=2, column=0, padx=16, pady=(3, 0), sticky="w")
            comparison = item.get("comparison")
            if comparison:
                summary = comparison.get("summary", {})
                text = (
                    f"Cambios: {summary.get('new', 0)} nuevo(s), "
                    f"{summary.get('persistent', 0)} persistente(s), "
                    f"{summary.get('resolved', 0)} resuelto(s) confirmado(s)."
                )
            else:
                text = "Sin una evaluación anterior válida para comparar."
            self._muted_label(card, text, wraplength=760).grid(
                row=3, column=0, padx=16, pady=(3, 0), sticky="w"
            )
            ctk.CTkButton(
                card, text="Ver plan de este equipo", height=28, corner_radius=7,
                font=(FONT, 9, "bold"), fg_color=COLORS["panel_alt"],
                hover_color=COLORS["border"],
                command=lambda r=item["latest"], s=("demo" if self.demo_mode else "imported"): self._focus_on_record(r, s),
            ).grid(row=4, column=0, padx=16, pady=(8, 12), sticky="w")

    # ==================== IMPORTACIÓN Y EXPORTACIÓN ====================

    def _start_import(self):
        if self.demo_mode:
            messagebox.showinfo(
                "Guardian Pro",
                "Salga del modo demo antes de importar informes reales.",
            )
            return
        if self.import_in_progress or self.audit_in_progress or self.repair_in_progress:
            return
        paths = filedialog.askopenfilenames(
            title="Importar informes de Guardian Pro",
            filetypes=[("Informes Guardian JSON", "*.json"), ("Todos los archivos", "*.*")],
        )
        if not paths:
            return
        self.import_messages = []
        self.import_in_progress = True
        self.import_queue = queue.Queue()
        self._refresh_sidebar_state()
        self.lbl_progress.configure(text="Validando informes importados...")
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        thread = threading.Thread(
            target=self._worker_import, args=(list(paths),), daemon=True
        )
        try:
            self.after(80, lambda: self._poll_import(thread))
            thread.start()
        except Exception as exc:
            self._finish_import(f" No se pudo iniciar la importación: {exc}")

    def _worker_import(self, paths):
        valid = []
        for path in paths:
            try:
                report = self.workspace.read_report_file(path)
                valid.append((path, report))
            except Exception as exc:
                self.import_queue.put(("error", path, str(exc)))
        if valid:
            try:
                results = self.workspace.add_imported_reports([report for _, report in valid])
            except Exception as exc:
                self.import_queue.put(("fatal", "", str(exc)))
            else:
                for (path, _), result in zip(valid, results):
                    self.import_queue.put(("result", path, result))
        self.import_queue.put(("done", "", None))

    def _poll_import(self, thread):
        done = False
        try:
            while True:
                kind, path, data = self.import_queue.get_nowait()
                if kind == "error":
                    name = os.path.basename(str(path)) or "archivo"
                    self.import_messages.append(f"✗ {name}: {data}")
                elif kind == "result":
                    name = os.path.basename(str(path)) or "archivo"
                    outcome = data.get("outcome", "invalid")
                    label = {
                        "new": "nuevo",
                        "older": "anterior al último del equipo",
                        "duplicate": "duplicado",
                        "invalid": "inválido",
                    }.get(outcome, outcome)
                    self.import_messages.append(f"• {name}: {label}. {data.get('detail', '')}")
                elif kind == "fatal":
                    self.import_messages.append(f"✗ Error de almacenamiento: {data}")
                elif kind == "done":
                    done = True
        except queue.Empty:
            pass
        except Exception as exc:
            self.import_messages.append(f"✗ Error procesando la importación: {exc}")
            done = True
        if done or not thread.is_alive():
            self._finish_import()
            return
        self.after(80, lambda: self._poll_import(thread))

    def _finish_import(self, extra_message=""):
        if not self.import_in_progress and not extra_message:
            return
        self.import_in_progress = False
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1)
        self.lbl_progress.configure(text="Importación finalizada")
        if extra_message:
            self.import_messages.append(extra_message)
        try:
            self.fleet_reports = self.workspace.load_fleet()
        except Exception as exc:
            self.import_messages.append(f"✗ No se pudo recargar la flota: {exc}")
        self._refresh_all_views()
        self.show_view("fleet")
        summary = "\n".join(self.import_messages[-10:]) or "No se importó ningún archivo."
        messagebox.showinfo("Guardian Pro — Importación", summary)

    def _export_current_report(self):
        if self.demo_mode:
            messagebox.showinfo(
                "Guardian Pro",
                "Los datos de demostración no se exportan. Salga del modo demo para compartir un informe real.",
            )
            return
        record = self.current_audit_record
        if record is None:
            record = self._latest_record(self.history)
        if record is None:
            messagebox.showwarning("Guardian Pro", "No hay una auditoría real para exportar.")
            return
        notice = (
            "Va a compartir un resumen sanitizado de la auditoría.\n\n"
            f"Dispositivo: {record['device']['name']} ({record['device']['id']})\n"
            f"Sistema: {record['device'].get('os', '')}\n"
            f"Fecha: {self._short_date(record['collected_at'])}\n\n"
            "El informe incluye nombre, estado, severidad y recomendación de cada comprobación. "
            "No incluye nombres de archivo detectados, rutas locales, evidencias ni secretos. "
            "Aun así, revise el archivo antes de compartirlo."
        )
        if not messagebox.askokcancel("Compartir informe de auditoría", notice):
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=f"Guardian_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            title="Guardar informe sanitizado",
            filetypes=[("Informe Guardian JSON", "*.json")],
        )
        if not path:
            return
        try:
            self.workspace.write_report(record, path)
            messagebox.showinfo("Guardian Pro", f"Informe exportado en:\n{path}")
        except Exception as exc:
            messagebox.showerror("Guardian Pro", f"No se pudo exportar el informe:\n{exc}")

    def _toggle_demo(self):
        if self.audit_in_progress or self.repair_in_progress or self.import_in_progress:
            messagebox.showinfo(
                "Guardian Pro",
                "Espere a que termine la operación activa antes de cambiar el modo de visualización.",
            )
            return
        if self.demo_mode:
            self.demo_mode = False
            self.demo_audits = []
            self.focus_record = None
            self.focus_source = ""
            self._append_log("[DEMO] Modo demostración desactivado. Se muestra el historial real.", "dim")
            self._refresh_all_views()
            self.show_view("overview")
            return
        self.demo_audits = workspace.generate_demo_audits()
        self.demo_mode = True
        self.focus_record = None
        self.focus_source = ""
        self._append_log("[DEMO] Modo demostración activado: datos ficticios solo en memoria.", "dim")
        self._refresh_all_views()
        self.show_view("overview")

    def elegir_carpeta(self):
        ruta = filedialog.askdirectory(initialdir=self.selected_path, title="Seleccionar carpeta para análisis de nombres de archivo")
        if not ruta:
            return
        protected_reason = self._protected_scan_reason(ruta)
        if protected_reason:
            self._append_log(
                f"[RECHAZADA] No se permite analizar directamente {ruta}: {protected_reason}.",
                "error"
            )
            messagebox.showwarning(
                "Carpeta protegida",
                f"Guardian Pro no analiza directamente {ruta} porque es {protected_reason}.\n\n"
                "Seleccione una carpeta de usuario o una carpeta de pruebas."
            )
            return

        resolved = self._resolve_real_path(ruta, strict=True)
        if not resolved:
            self._append_log(
                f"[RECHAZADA] No se pudo resolver la carpeta seleccionada de forma segura: {ruta}.",
                "error"
            )
            messagebox.showwarning(
                "Carpeta no verificable",
                f"Guardian Pro no pudo resolver la ruta seleccionada de forma segura:\n{ruta}\n\n"
                "La carpeta no existe, no es accesible o contiene un enlace no verificable. "
                "Seleccione una carpeta de usuario o una carpeta de pruebas."
            )
            return

        protected_reason = self._protected_scan_reason(resolved)
        if protected_reason:
            self._append_log(
                f"[RECHAZADA] La ruta real de {ruta} es {resolved}, que es {protected_reason}.",
                "error"
            )
            messagebox.showwarning(
                "Carpeta protegida",
                f"Guardian Pro no analiza {ruta} porque su ruta real es {resolved} "
                f"y corresponde a {protected_reason}.\n\n"
                "Seleccione una carpeta de usuario o una carpeta de pruebas."
            )
            return

        self.selected_path = resolved
        self.audit_path_label.configure(text=f"Alcance de nombres: {resolved}")
        self._append_log(f"[SISTEMA] Carpeta seleccionada: {resolved}")

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

    def _reset_audit_state(self, preserve_repair_context: bool = False):
        """Inicializa de forma única el estado de una auditoría nueva.

        No toca `audit_in_progress` ni `repair_in_progress`: el ciclo de vida
        de una operación activa lo controlan el worker y sus finalizadores.

        Con `preserve_repair_context=True` se conserva el estado inicial y el
        historial de acciones para la reauditoría automática posterior a una
        reparación. Una auditoría nueva independiente limpia todo el contexto.
        """
        self.check_results = []
        self.repair_actions_to_run = []
        self.sensitive_files = []
        self.audit_timestamp = ""
        self.current_audit_record = None
        self.focus_record = None
        self.focus_source = ""
        if not preserve_repair_context:
            self.repair_actions = []
            self.pre_repair_results = []
            self.pre_repair_sensitive_files = []
            self.pre_repair_timestamp = ""
            self.pre_repair_path = ""
            self.pre_repair_context_captured = False
            self.post_repair_audit_attempted = False
        # Evitar que eventos de una operación anterior se interpreten como
        # resultados de la auditoría nueva. Solo se llama sin operaciones activas.
        while True:
            try:
                self.result_queue.get_nowait()
            except queue.Empty:
                break
        self._update_summary_counts()

    def _capture_repair_context(self):
        """Guarda una copia independiente del estado previo a la reparación."""
        if not self.pre_repair_context_captured:
            self.pre_repair_results = copy.deepcopy(self.check_results)
            self.pre_repair_sensitive_files = list(self.sensitive_files)
            self.pre_repair_timestamp = self.audit_timestamp
            self.pre_repair_path = self.selected_path
            self.pre_repair_context_captured = True
        # Un nuevo lote invalida la reauditoría anterior hasta que se ejecute
        # otra reauditoría posterior.
        self.post_repair_audit_attempted = False

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
    def _resolve_real_path(path: str, *, strict: bool = True) -> str:
        """Devuelve la ruta real canónica conservando mayúsculas/minúsculas.

        `os.path.realpath()` resuelve enlaces simbólicos y junctions de
        Windows. Con `strict=True` la ruta debe existir y poder resolverse;
        si no, se devuelve "" para que el llamador aplique un fallo seguro.
        """
        if not path:
            return ""
        try:
            expanded = os.path.expandvars(os.path.expanduser(str(path)))
            resolved = os.path.realpath(expanded, strict=strict)
            # GetFinalPathName puede devolver prefijos extendidos de Windows.
            # Solo se aceptan formas que puedan compararse de forma segura:
            # unidad con letra o UNC. Las rutas de volumen/GLOBALROOT/dispositivo
            # no se consideran verificables y se rechazan.
            if resolved.startswith("\\\\?\\UNC\\"):
                resolved = "\\\\" + resolved[8:]
            elif resolved.startswith("\\\\?\\"):
                remainder = resolved[4:]
                if len(remainder) >= 2 and remainder[1] == ":":
                    resolved = remainder
                else:
                    return ""
            elif resolved.startswith("\\\\.\\"):
                remainder = resolved[4:]
                if len(remainder) >= 2 and remainder[1] == ":":
                    resolved = remainder
                else:
                    return ""
            return os.path.normpath(os.path.abspath(resolved))
        except (OSError, ValueError, RuntimeError):
            return ""

    @classmethod
    def _normalize_path_for_compare(cls, path: str, *, strict: bool = False) -> str:
        """Resuelve una ruta y devuelve su clave de comparación.

        La resolución usa `os.path.realpath()`, que resuelve enlaces
        simbólicos y junctions. La clave final es insensible a mayúsculas y
        usa separadores normalizados. Esta forma es solo para comparar; el
        recorrido debe usar `_resolve_real_path()` para conservar la ruta real.
        """
        resolved = cls._resolve_real_path(path, strict=strict)
        return os.path.normcase(resolved) if resolved else ""

    @staticmethod
    def _path_is_within(candidate: str, root: str) -> bool:
        """Comprueba pertenencia usando límites de directorio, no prefijos."""
        if not candidate or not root:
            return False
        boundary = root.rstrip("\\/") or root
        return candidate == boundary or candidate.startswith(boundary + os.sep)

    @staticmethod
    def _is_reparse_or_link(path: str) -> bool:
        """Detecta enlaces simbólicos, junctions y puntos de reanálisis.

        Se usa `lstat` para no seguir el enlace. En Windows se consulta
        `st_file_attributes`; en otros sistemas se comprueba `S_ISLNK`.
        """
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            return True
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        return bool(getattr(info, "st_file_attributes", 0) & reparse_flag)

    @classmethod
    def _protected_scan_reason(cls, path: str, *, strict: bool = False) -> str:
        """Devuelve el motivo por el que una raíz no debe escanearse, o ''."""
        candidate = cls._normalize_path_for_compare(path, strict=strict)
        if not candidate:
            return "una ruta que no se pudo resolver de forma segura" if strict else ""

        drive, tail = os.path.splitdrive(candidate)
        # Una raíz completa de unidad o de recurso UNC es demasiado amplia;
        # sus subcarpetas de usuario sí pueden analizarse.
        if drive and tail in ("", os.sep):
            if drive.startswith("\\\\"):
                return f"la raíz completa del recurso de red {drive}"
            return f"la raíz completa de la unidad {drive}\\"

        env_roots = (
            ("SystemRoot", "carpeta del sistema"),
            ("WINDIR", "carpeta del sistema"),
            ("ProgramFiles", "directorio de instalación de aplicaciones"),
            ("ProgramFiles(x86)", "directorio de instalación de aplicaciones"),
            ("ProgramW6432", "directorio de instalación de aplicaciones"),
            ("ProgramData", "directorio de datos de sistema"),
        )
        for env_name, label in env_roots:
            value = os.environ.get(env_name)
            if not value:
                continue
            # Las raíces protegidas también se resuelven para cubrir el caso
            # de una variable de entorno que apunte a un enlace o junction.
            root = cls._normalize_path_for_compare(value, strict=True)
            if not root:
                # Si la raíz configurada no existe, no puede alcanzarse; se
                # conserva una comparación léxica como defensa adicional.
                root = cls._normalize_path_for_compare(value)
            if not root:
                continue
            # El límite de directorio evita confundir C:\Windows con
            # C:\WindowsBackup.
            if cls._path_is_within(candidate, root):
                return f"{label} {value}"

        return ""

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

    def iniciar_auditoria(self, preserve_repair_context: bool = False):
        if self.audit_in_progress or self.repair_in_progress or self.import_in_progress:
            return

        # Inicializar el estado antes de marcar la operación como activa. Si el
        # reset falla, no dejamos la auditoría bloqueada.
        self._reset_audit_state(preserve_repair_context=preserve_repair_context)
        self.audit_in_progress = True

        try:
            self.audit_timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            self.btn_audit.configure(
                state="disabled", text="Auditando...",
                fg_color=COLORS["panel_alt"], text_color=COLORS["muted"],
            )
            self.btn_repair.configure(state="disabled", fg_color=COLORS["panel_alt"])
            self.btn_report.configure(state="disabled", fg_color=COLORS["panel_alt"])
            self.btn_new_audit.configure(state="disabled")
            self.btn_select_folder.configure(state="disabled")
            self.btn_export_json.configure(state="disabled")
            self.btn_import_json.configure(state="disabled")
            self.btn_demo_toggle.configure(state="disabled")
            if hasattr(self, "btn_audit_view"):
                self.btn_audit_view.configure(state="disabled", fg_color=COLORS["panel_alt"])
            if hasattr(self, "btn_select_folder_view"):
                self.btn_select_folder_view.configure(state="disabled")
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
            self._refresh_sidebar_state()
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
        self.btn_report.configure(
            state="normal" if (self.check_results or self.pre_repair_context_captured) else "disabled"
        )
        self.btn_new_audit.configure(state="normal")

        # Habilitar reparación solo si hay hallazgos reparables
        fixable = any(r.can_fix for r in self.check_results)
        self.btn_repair.configure(state="normal" if fixable else "disabled")

        self._append_log("")
        self._append_log("=== Auditoría finalizada ===")
        self._record_finished_audit()
        self._refresh_all_views()

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
        if result.manual_guidance:
            for line in result.manual_guidance.splitlines():
                prefix = "        " if line.strip() else ""
                self.txt_results.insert("end", f"{prefix}{line}\n", "dim")
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

    @staticmethod
    def _defender_bool(value):
        """Convierte un valor booleano de PowerShell sin usar verdad simple."""
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            if value == 1:
                return True
            if value == 0:
                return False
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1"}:
                return True
            if normalized in {"false", "0"}:
                return False
        return None

    @classmethod
    def _defender_status_evidence(cls, status: dict) -> str:
        """Resume el estado real y los diagnósticos disponibles de Defender."""
        def label(value, true_text, false_text):
            parsed = cls._defender_bool(value)
            if parsed is True:
                return true_text
            if parsed is False:
                return false_text
            return "No disponible"

        mode = status.get("AMRunningMode")
        mode_text = str(mode).strip() if mode not in (None, "") else "No disponible"
        return " | ".join((
            f"Protección en tiempo real: {label(status.get('RealTimeProtectionEnabled'), 'Habilitada', 'Deshabilitada')}",
            f"Tamper Protection: {label(status.get('IsTamperProtected'), 'Activada', 'Desactivada')}",
            f"Antivirus: {label(status.get('AntivirusEnabled'), 'Habilitado', 'Deshabilitado')}",
            f"AMRunningMode: {mode_text}",
            f"Preferencia DisableRealtimeMonitoring: {label(status.get('DisableRealtimeMonitoring'), 'Sí', 'No')}",
        ))

    def _query_defender_status(self) -> dict:
        """Consulta estado y diagnósticos de Defender con errores controlados."""
        script = (
            "$status = Get-MpComputerStatus -ErrorAction Stop; "
            "$pref = $null; "
            "try { $pref = Get-MpPreference -ErrorAction Stop } catch { }; "
            "[pscustomobject]@{"
            "RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled; "
            "IsTamperProtected = $status.IsTamperProtected; "
            "AntivirusEnabled = $status.AntivirusEnabled; "
            "AMRunningMode = [string]$status.AMRunningMode; "
            "DisableRealtimeMonitoring = $(if ($null -ne $pref) { $pref.DisableRealtimeMonitoring } else { $null })"
            "} | ConvertTo-Json -Compress"
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
            raise ValueError("salida vacía")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON inválido: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("formato de estado de Defender inesperado")
        return data

    def _check_defender(self):
        """Comprueba la protección en tiempo real de Microsoft Defender."""
        try:
            status = self._query_defender_status()
            evidence = self._defender_status_evidence(status)
            realtime = self._defender_bool(status.get("RealTimeProtectionEnabled"))

            if realtime is True:
                self.result_queue.put(("result", CheckResult(
                    name="Microsoft Defender",
                    status="ok",
                    evidence=evidence,
                    severity="info",
                    recommendation="La protección en tiempo real está activa."
                )))
            elif realtime is False:
                self.result_queue.put(("result", CheckResult(
                    name="Microsoft Defender",
                    status="finding",
                    evidence=evidence,
                    severity="high",
                    recommendation=self.DEFENDER_MANUAL_INTRO,
                    manual_guidance=self.DEFENDER_MANUAL_DETAILS
                )))
            else:
                self.result_queue.put(("result", CheckResult(
                    name="Microsoft Defender",
                    status="unverifiable",
                    evidence=evidence,
                    severity="info",
                    recommendation=(
                        "No se pudo confirmar el estado de la protección en tiempo real. "
                        "Verifique manualmente con 'Get-MpComputerStatus'."
                    )
                )))

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
        scope_errors = []
        link_skips = []
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

        if not root_path:
            publish_result(
                "error",
                "No se seleccionó una carpeta para el análisis de nombres.",
                "Seleccione una carpeta válida."
            )
            return

        # Rechazar ubicaciones protegidas antes del recorrido. Esto evita
        # recorrer C:\Windows o una raíz de unidad.
        protected_reason = self._protected_scan_reason(root_path)
        if protected_reason:
            publish_result(
                "error",
                f"Ruta bloqueada antes del recorrido: {root_path} es {protected_reason}.",
                "Seleccione una carpeta de usuario o una carpeta de pruebas. "
                "No se recorrió la ubicación protegida ni se generaron hallazgos de archivos."
            )
            return

        # Validar la raíz antes de recorrer: distingue ruta inexistente,
        # archivo en lugar de carpeta y falta de permisos.
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

        # Resolver la ruta real antes de autorizar el recorrido. Si no se puede
        # verificar, se falla de forma segura y no se presenta un OK vacío.
        resolved_root = self._resolve_real_path(root_path, strict=True)
        if not resolved_root:
            publish_result(
                "error",
                f"No se pudo resolver la ruta seleccionada de forma segura: {root_path}. "
                "La carpeta no existe, no es accesible o contiene un enlace no verificable.",
                "Seleccione una carpeta de usuario o una carpeta de pruebas y vuelva a iniciar "
                "la auditoría. No se recorrió la ubicación."
            )
            return

        protected_reason = self._protected_scan_reason(resolved_root)
        if protected_reason:
            publish_result(
                "error",
                f"Ruta bloqueada tras resolver la ruta real: {root_path} -> {resolved_root} "
                f"es {protected_reason}.",
                "Seleccione una carpeta de usuario o una carpeta de pruebas. "
                "No se recorrió la ubicación protegida ni se generaron hallazgos de archivos."
            )
            return

        # El ámbito del recorrido es la ruta canónica ya validada. La clave
        # normalizada se usa solo para comparaciones de pertenencia.
        root_path = resolved_root
        root_key = self._normalize_path_for_compare(root_path)

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
                # Confirmar que el directorio entregado sigue dentro del ámbito
                # canónico. Esto protege incluso si os.walk recibiera una ruta
                # inesperada o si cambió un enlace durante el recorrido.
                current_key = self._normalize_path_for_compare(current_root, strict=True)
                if not current_key or not self._path_is_within(current_key, root_key):
                    scope_errors.append(current_root)
                    dirs[:] = []
                    continue

                # Excluir directorios modificando la lista in-place. Con
                # topdown=True esto impide que os.walk descienda a ellos.
                # Los enlaces simbólicos, junctions y puntos de reanálisis se
                # excluyen siempre para no salir del árbol autorizado.
                kept_dirs = []
                for dirname in dirs:
                    if dirname.lower() in exclude_dirs or dirname.startswith('.'):
                        continue
                    candidate = os.path.join(current_root, dirname)
                    try:
                        if self._is_reparse_or_link(candidate):
                            link_skips.append(candidate)
                            continue
                    except OSError as exc:
                        walk_errors.append((candidate, exc))
                        continue

                    resolved_dir_key = self._normalize_path_for_compare(candidate, strict=True)
                    if not resolved_dir_key:
                        walk_errors.append((candidate, OSError("no se pudo resolver el directorio")))
                        continue
                    if not self._path_is_within(resolved_dir_key, root_key):
                        link_skips.append(candidate)
                        continue
                    if self._protected_scan_reason(candidate):
                        link_skips.append(candidate)
                        continue
                    kept_dirs.append(dirname)
                dirs[:] = kept_dirs

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
            if scope_errors:
                accumulated.append(f"{len(scope_errors)} directorio(s) fuera del ámbito autorizado")
            if link_skips:
                accumulated.append(f"{len(link_skips)} enlace(s)/punto(s) de reanálisis excluido(s)")
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
        if scope_errors:
            error_parts.append(f"{len(scope_errors)} directorio(s) fuera del ámbito autorizado")
        if link_skips:
            error_parts.append(f"{len(link_skips)} enlace(s)/punto(s) de reanálisis excluido(s)")
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
            if link_skips:
                recommendation += (
                    " Los enlaces simbólicos, junctions y puntos de reanálisis se excluyeron "
                    "para no salir del ámbito autorizado."
                )
            publish_result(
                "finding",
                evidence,
                recommendation,
                severity="low"
            )
        elif partial:
            recommendation = (
                "No se puede confirmar la ausencia de nombres sensibles: hubo directorios o archivos "
                "que no se pudieron revisar. Solo se examinaron nombres, no el contenido. "
                "Ejecute Guardian Pro como administrador o seleccione una carpeta accesible."
            )
            if link_skips:
                recommendation += (
                    " Los enlaces simbólicos, junctions y puntos de reanálisis se excluyeron "
                    "para no salir del ámbito autorizado."
                )
            publish_result(
                "unverifiable",
                f"Revisados: {scanned} archivos | Sin coincidencias en lo revisado | Análisis parcial: {error_summary}",
                recommendation
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
            # Microsoft Defender se comprueba, pero no se repara automáticamente:
            # Windows puede bloquear el cambio por Tamper Protection o una
            # directiva. La corrección es una guía manual y una nueva auditoría.
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
        if self.audit_in_progress or self.repair_in_progress or self.import_in_progress:
            return

        actions = self._build_repair_actions()
        if not actions:
            messagebox.showinfo(
                "Guardian Pro",
                "No hay hallazgos que puedan repararse automáticamente. "
                "Si Microsoft Defender requiere activación manual, siga las "
                "instrucciones mostradas en los resultados."
            )
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

        # Conservar el estado que originó este lote antes de ejecutar nada.
        self._capture_repair_context()
        self.repair_actions_to_run = selected

        # Ejecutar solo las acciones aceptadas, en hilo secundario.
        self.repair_in_progress = True
        self.btn_repair.configure(
            state="disabled", text="Reparando...",
            fg_color=COLORS["panel_alt"], text_color=COLORS["muted"],
        )
        self.btn_audit.configure(state="disabled", fg_color=COLORS["panel_alt"])
        self.btn_new_audit.configure(state="disabled")
        self.btn_report.configure(state="disabled", fg_color=COLORS["panel_alt"])
        self.btn_select_folder.configure(state="disabled")
        self.btn_export_json.configure(state="disabled")
        self.btn_import_json.configure(state="disabled")
        self.btn_demo_toggle.configure(state="disabled")
        if hasattr(self, "btn_audit_view"):
            self.btn_audit_view.configure(state="disabled", fg_color=COLORS["panel_alt"])
        if hasattr(self, "btn_select_folder_view"):
            self.btn_select_folder_view.configure(state="disabled")
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
                    if (action.manual_guidance and not action.verified
                            and action.manual_guidance not in action.verification_evidence):
                        action.verification_evidence = (
                            f"{action.verification_evidence} {action.manual_guidance}"
                        ).strip()
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

        rdp_disable: consulta con código 0 de fDenyTSConnections=1 y consulta
        con código 0 de reglas RDP por Group sin ninguna Enabled=True/1. 2
        cuenta como deshabilitada. Cualquier error de consulta es error.

        Microsoft Defender no forma parte del mecanismo de reparación: su
        corrección es manual y se verifica con una nueva auditoría.
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
        self.btn_report.configure(
            state="normal" if (self.check_results or self.pre_repair_context_captured) else "disabled"
        )
        self.btn_select_folder.configure(state="normal")
        self._refresh_all_views()

        # Re-escanear solo si al menos una acción del lote actual llegó a ejecutarse.
        if any(a.attempted for a in current_actions):
            if messagebox.askyesno("Guardian Pro", "Reparaciones completadas. ¿Desea realizar una nueva auditoría para verificar los cambios?"):
                self.nueva_auditoria(auto_start=True, preserve_repair_context=True)

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

    @staticmethod
    def _pdf_section_title(pdf, title: str):
        pdf.ln(2)
        pdf.set_font("Helvetica", 'B', 13)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, GuardianProMaster._pdf_safe(title), ln=True)
        pdf.ln(1)

    def _pdf_add_scope(self, pdf, path: str):
        pdf.set_font("Helvetica", '', 10)
        self._pdf_multicell(pdf, self._pdf_safe(
            f"  Alcance del análisis de archivos: {path or 'No seleccionado'}"
        ), 5)
        self._pdf_multicell(pdf, self._pdf_safe(
            "  El alcance indica la carpeta seleccionada. Si la comprobación de archivos reporta "
            "errores de acceso o de recorrido, el análisis no cubrió la carpeta completa."
        ), 5)
        pdf.ln(2)

    def _pdf_add_summary(self, pdf, results: list):
        counts = {"ok": 0, "finding": 0, "unverifiable": 0, "error": 0}
        for r in results:
            if r.status in counts:
                counts[r.status] += 1

        pdf.set_font("Helvetica", '', 10)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 6, self._pdf_safe(f"  Correctas: {counts['ok']}"), ln=True)
        pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 6, self._pdf_safe(f"  Hallazgos: {counts['finding']}"), ln=True)
        pdf.set_text_color(200, 150, 0)
        pdf.cell(0, 6, self._pdf_safe(f"  No verificables: {counts['unverifiable']}"), ln=True)
        pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 6, self._pdf_safe(f"  Errores: {counts['error']}"), ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

    def _pdf_add_check_details(self, pdf, results: list):
        for r in results:
            pdf.set_font("Helvetica", 'B', 10)
            status_text = {
                "ok": "OK", "finding": "HALLAZGO", "unverifiable": "NO VERIFICABLE", "error": "ERROR"
            }.get(r.status, r.status.upper())
            pdf.cell(0, 6, self._pdf_safe(f"{r.name} — {status_text}"), ln=True)

            pdf.set_font("Helvetica", '', 9)
            pdf.set_text_color(80, 80, 80)
            self._pdf_multicell(pdf, self._pdf_safe(f"  Evidencia: {r.evidence}"), 5)
            if r.recommendation:
                self._pdf_multicell(pdf, self._pdf_safe(f"  Recomendación: {r.recommendation}"), 5)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(3)

    @staticmethod
    def _has_defender_finding(results: list) -> bool:
        return any(
            r.name == "Microsoft Defender" and r.status == "finding"
            for r in results
        )

    def _pdf_add_defender_manual_guidance(self, pdf, results: list, state_label="estado inicial"):
        """Añade la guía manual solo cuando Defender aparece como hallazgo."""
        defender = next((
            r for r in results
            if r.name == "Microsoft Defender" and r.status == "finding"
        ), None)
        if defender is None:
            return

        self._pdf_section_title(pdf, self.DEFENDER_MANUAL_TITLE)
        pdf.set_font("Helvetica", '', 9)
        pdf.set_text_color(80, 80, 80)
        self._pdf_multicell(pdf, self._pdf_safe(
            f"  Qué se detectó en el {state_label}: la protección en tiempo real de "
            "Microsoft Defender está desactivada."
        ), 5)
        if defender.evidence:
            self._pdf_multicell(pdf, self._pdf_safe(f"  Evidencia: {defender.evidence}"), 5)
        self._pdf_multicell(pdf, self._pdf_safe(f"  {self.DEFENDER_MANUAL_INTRO}"), 5)
        self._pdf_multicell(pdf, self._pdf_safe(
            "  Pasos para activarla manualmente:"
        ), 5)
        self._pdf_multicell(pdf, self._pdf_safe(self.DEFENDER_MANUAL_STEPS), 5)
        self._pdf_multicell(pdf, self._pdf_safe(
            "  Después de activarla, vuelve a ejecutar una auditoría en Guardian "
            "para verificar el estado."
        ), 5)
        self._pdf_multicell(pdf, self._pdf_safe(f"  {self.DEFENDER_MANUAL_NOTE}"), 5)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

    def _pdf_add_sensitive_files(self, pdf, files: list, title: str):
        if not files:
            return
        self._pdf_section_title(pdf, title)
        pdf.set_font("Helvetica", '', 8)
        pdf.set_text_color(80, 80, 80)
        for file_path in files[:50]:
            self._pdf_multicell(pdf, self._pdf_safe(f"  > {file_path}"), 4.5)
        if len(files) > 50:
            self._pdf_multicell(
                pdf, self._pdf_safe(f"  ... y {len(files) - 50} archivos más."), 4.5
            )
        pdf.set_text_color(0, 0, 0)

    def _pdf_add_repair_history(self, pdf, title: str):
        repair_history = [
            a for a in self.repair_actions
            if a.attempted or a.skipped or a.selected or a.verification_status == "permission_denied"
        ]
        if not repair_history:
            return
        self._pdf_section_title(pdf, title)
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
            if a.manual_guidance and a.manual_guidance not in a.verification_evidence:
                self._pdf_multicell(pdf, self._pdf_safe(f"  Guía: {a.manual_guidance}"), 5)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(3)

    def _pdf_comparison_for_results(self):
        """Obtiene una comparación válida para el resumen ejecutivo."""
        if self.pre_repair_context_captured and self.post_repair_audit_attempted and self.check_results:
            return workspace.compare_check_lists(
                self.pre_repair_results, self.check_results
            ), "auditoría inicial"
        if self.current_audit_record:
            comparison = self.current_audit_record.get("comparison")
            if comparison:
                return comparison, "auditoría anterior"
            try:
                previous = self.workspace.previous_for(self.current_audit_record)
                if previous is not None:
                    return workspace.compare_audits(previous, self.current_audit_record), "auditoría anterior"
            except Exception:
                pass
        return None, ""

    def _pdf_add_executive_summary(self, pdf, results, comparison, comparison_label, state_label):
        """Primera sección empresarial, sin ocultar el detalle técnico posterior."""
        self._pdf_section_title(pdf, "Resumen ejecutivo")
        counts = {"ok": 0, "finding": 0, "unverifiable": 0, "error": 0}
        for result in results:
            if result.status in counts:
                counts[result.status] += 1
        plan = workspace.build_action_plan(results, allow_repair=False, source="history")

        pdf.set_font("Helvetica", '', 10)
        pdf.set_text_color(0, 0, 0)
        self._pdf_multicell(pdf, self._pdf_safe(
            f"  Dispositivo evaluado: {self.device_identity.get('name', 'Equipo local')} "
            f"({self.device_identity.get('os', 'Sistema no disponible')})"
        ), 5)
        self._pdf_multicell(pdf, self._pdf_safe(
            f"  Fecha de la evaluación: {self.audit_timestamp or 'No disponible'} · {state_label}"
        ), 5)
        self._pdf_multicell(pdf, self._pdf_safe(
            f"  Resultados: {counts['ok']} correctas, {counts['finding']} hallazgos, "
            f"{counts['unverifiable']} no verificables y {counts['error']} errores."
        ), 5)
        pdf.ln(3)

        pdf.set_font("Helvetica", 'B', 10)
        self._pdf_multicell(pdf, "  Hallazgos que requieren atención prioritaria:", 5)
        pdf.set_font("Helvetica", '', 9)
        if not plan:
            self._pdf_multicell(pdf, self._pdf_safe(
                "  No se identificaron hallazgos ni comprobaciones pendientes de revisión "
                "en los resultados disponibles."
            ), 5)
        else:
            for item in plan[:3]:
                self._pdf_multicell(pdf, self._pdf_safe(
                    f"  - {item['name']} ({item['status'].upper()}): {item['what']}"
                ), 5)
                if item.get("recommendation"):
                    self._pdf_multicell(pdf, self._pdf_safe(
                        f"    Recomendación: {item['recommendation']}"
                    ), 5)
        pdf.ln(2)

        pdf.set_font("Helvetica", 'B', 10)
        self._pdf_multicell(pdf, "  Acciones recomendadas:", 5)
        pdf.set_font("Helvetica", '', 9)
        if not plan:
            self._pdf_multicell(pdf, self._pdf_safe(
                "  Mantener las comprobaciones periódicas y revisar cualquier cambio posterior."
            ), 5)
        else:
            for item in plan[:3]:
                self._pdf_multicell(pdf, self._pdf_safe(
                    f"  - {item['next_step']} Verificación: {item['verification']}"
                ), 5)
        pdf.ln(2)

        pdf.set_font("Helvetica", 'B', 10)
        self._pdf_multicell(pdf, "  Cambios respecto a una evaluación anterior:", 5)
        pdf.set_font("Helvetica", '', 9)
        if comparison is None:
            self._pdf_multicell(pdf, self._pdf_safe(
                "  No hay una auditoría anterior válida para este dispositivo. "
                "No se presenta una tendencia ni se declara una resolución."
            ), 5)
        else:
            summary = comparison.get("summary", {})
            self._pdf_multicell(pdf, self._pdf_safe(
                f"  Comparación con {comparison_label}: nuevos {summary.get('new', 0)}, "
                f"persistentes {summary.get('persistent', 0)}, "
                f"resueltos confirmados por estado OK {summary.get('resolved', 0)}, "
                f"no verificables {summary.get('unverifiable', 0)}, "
                f"no evaluados {summary.get('not_evaluated', 0)}."
            ), 5)
            for key, label in (
                ("new", "Hallazgos nuevos"),
                ("persistent", "Problemas persistentes"),
                ("resolved", "Resueltos confirmados"),
                ("unverifiable", "No verificables"),
            ):
                names = [item["name"] for item in comparison.get(key, [])]
                if names:
                    self._pdf_multicell(pdf, self._pdf_safe(
                        f"    {label}: {', '.join(names[:6])}"
                        + (" ..." if len(names) > 6 else "")
                    ), 5)
        pdf.ln(2)

        pdf.set_font("Helvetica", 'B', 10)
        self._pdf_multicell(pdf, "  Aspectos pendientes de verificación:", 5)
        pdf.set_font("Helvetica", '', 9)
        pending = [
            result for result in results
            if result.status in {"error", "unverifiable"}
        ]
        if pending:
            for result in pending[:6]:
                self._pdf_multicell(pdf, self._pdf_safe(
                    f"  - {result.name}: {result.recommendation or 'Repita la comprobación.'}"
                ), 5)
        else:
            self._pdf_multicell(pdf, self._pdf_safe(
                "  No hay comprobaciones pendientes en los resultados disponibles. "
                "Esto no demuestra por sí solo que el equipo sea seguro."
            ), 5)
        if self.pre_repair_context_captured and not self.post_repair_audit_attempted:
            self._pdf_multicell(pdf, self._pdf_safe(
                "  No se realizó una reauditoría posterior. El estado actual de las "
                "reparaciones no está verificado en este informe."
            ), 5)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(3)

    def crear_pdf(self):
        if not self.check_results and not self.pre_repair_context_captured:
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
            if self.pre_repair_context_captured:
                pdf.cell(0, 6, self._pdf_safe(
                    f"Auditoría inicial: {self.pre_repair_timestamp or 'No disponible'}"
                ), ln=True, align='C')
                post_label = self.audit_timestamp if self.post_repair_audit_attempted else "no realizada"
                pdf.cell(0, 6, self._pdf_safe(f"Reauditoría posterior: {post_label or 'sin resultados'}"), ln=True, align='C')
            else:
                pdf.cell(0, 6, self._pdf_safe(f"Auditoría: {self.audit_timestamp}"), ln=True, align='C')
            pdf.ln(10)

            if self.pre_repair_context_captured:
                if self.post_repair_audit_attempted and self.check_results:
                    executive_results = self.check_results
                    executive_state = "estado posterior a las reparaciones"
                else:
                    executive_results = self.pre_repair_results
                    executive_state = "estado inicial; no hay reauditoría posterior verificada"
            else:
                executive_results = self.check_results
                executive_state = "auditoría actual"
            comparison, comparison_label = self._pdf_comparison_for_results()
            self._pdf_add_executive_summary(
                pdf, executive_results, comparison, comparison_label, executive_state
            )

            if not self.pre_repair_context_captured:
                # Formato ordinario: auditoría sin ciclo de reparación.
                self._pdf_section_title(pdf, "1. Resumen de comprobaciones")
                self._pdf_add_scope(pdf, self.selected_path)
                self._pdf_add_summary(pdf, self.check_results)

                self._pdf_section_title(pdf, "2. Detalle de comprobaciones")
                self._pdf_add_check_details(pdf, self.check_results)
                self._pdf_add_defender_manual_guidance(pdf, self.check_results)
                self._pdf_add_repair_history(pdf, "3. Reparaciones y acciones omitidas")
                self._pdf_add_sensitive_files(
                    pdf, self.sensitive_files,
                    "4. Archivos con nombres sensibles (solo nombres, no contenido)"
                )
            else:
                # Ciclo de corrección: estado inicial, acciones y estado posterior.
                self._pdf_section_title(pdf, "1. Estado inicial (antes de la reparación)")
                self._pdf_add_scope(pdf, self.pre_repair_path)
                self._pdf_add_summary(pdf, self.pre_repair_results)
                self._pdf_add_check_details(pdf, self.pre_repair_results)
                self._pdf_add_defender_manual_guidance(
                    pdf, self.pre_repair_results, "estado inicial"
                )
                self._pdf_add_sensitive_files(
                    pdf, self.pre_repair_sensitive_files,
                    "Archivos sensibles en el estado inicial (solo nombres, no contenido)"
                )

                self._pdf_add_repair_history(pdf, "2. Acciones de corrección")

                self._pdf_section_title(pdf, "3. Estado posterior (reauditoría)")
                if self.post_repair_audit_attempted and self.check_results:
                    self._pdf_add_scope(pdf, self.selected_path)
                    self._pdf_add_summary(pdf, self.check_results)
                    self._pdf_add_check_details(pdf, self.check_results)
                    if not self._has_defender_finding(self.pre_repair_results):
                        self._pdf_add_defender_manual_guidance(
                            pdf, self.check_results, "estado posterior"
                        )
                    self._pdf_add_sensitive_files(
                        pdf, self.sensitive_files,
                        "Archivos sensibles en el estado posterior (solo nombres, no contenido)"
                    )
                elif self.post_repair_audit_attempted:
                    self._pdf_multicell(pdf, self._pdf_safe(
                        "  La reauditoría se intentó pero no produjo resultados. "
                        "El estado posterior no está verificado."
                    ), 5)
                else:
                    self._pdf_multicell(pdf, self._pdf_safe(
                        "  No se realizó una reauditoría posterior. "
                        "El estado actual no está verificado en este informe."
                    ), 5)

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

    def nueva_auditoria(self, auto_start=False, preserve_repair_context=False):
        """Resetea el estado para una nueva auditoría o reauditoría posterior."""
        if self.audit_in_progress or self.repair_in_progress:
            return
        self._reset_audit_state(preserve_repair_context=preserve_repair_context)
        if preserve_repair_context:
            self.post_repair_audit_attempted = True
        self._clear_results()
        self.progress_bar.set(0)
        self.progress_bar.configure(mode="determinate")
        self.lbl_progress.configure(text="Listo para iniciar")
        self.btn_audit.configure(state="normal", text="🔍  Iniciar auditoría")
        self.btn_repair.configure(state="disabled")
        self.btn_report.configure(state="disabled")
        self.btn_new_audit.configure(state="normal")
        self.btn_select_folder.configure(state="normal")
        if preserve_repair_context:
            self._append_log("=== Guardian Pro — Reauditoría posterior a reparaciones ===")
        else:
            self._append_log("=== Guardian Pro — Nueva auditoría ===")
        self._append_log(f"Carpeta seleccionada: {self.selected_path}")
        self._append_log("")
        self._refresh_all_views()

        if auto_start:
            self.iniciar_auditoria(preserve_repair_context=preserve_repair_context)


if __name__ == "__main__":
    app = GuardianProMaster()
    app.mainloop()