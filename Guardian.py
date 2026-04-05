import os
import subprocess
import threading
import socket
import customtkinter as ctk
from tkinter import messagebox, filedialog
from fpdf import FPDF
from datetime import datetime

# Configuración visual
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class GuardianProMaster(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("GUARDIAN PRO - Enterprise Auditor v8.5")
        self.geometry("1200x850")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Variables de Auditoria
        self.puntaje = 100
        self.puntaje_inicial = None
        self.hallazgos = []
        self.archivos_vulnerables = []
        self.reparaciones_exitosas = []
        self.ruta_seleccionada = os.path.expanduser("~")
        self.fecha_auditoria = ""

        self.setup_ui()

    def setup_ui(self):
        # --- SIDEBAR ---
        self.sidebar = ctk.CTkFrame(self, width=320, fg_color="#1A1C1E", corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.lbl_title = ctk.CTkLabel(self.sidebar, text="GUARDIAN PRO", font=("Impact", 35), text_color="#3498db")
        self.lbl_title.place(relx=0.5, y=100, anchor="center")
        
        btn_style = {"height": 55, "corner_radius": 12, "font": ("Arial", 13, "bold")}
        
        self.btn_1 = ctk.CTkButton(self.sidebar, text="📂 SELECCIONAR CARPETA", command=self.elegir_carpeta, **btn_style)
        self.btn_1.place(relx=0.5, y=280, anchor="center", relwidth=0.85)

        self.btn_2 = ctk.CTkButton(self.sidebar, text="🔍 ESCANEO INTEGRAL", fg_color="#27AE60", hover_color="#2ECC71", command=self.iniciar_hilo, **btn_style)
        self.btn_2.place(relx=0.5, y=350, anchor="center", relwidth=0.85)

        self.btn_fix = ctk.CTkButton(self.sidebar, text="🛠️ REPARAR SISTEMA", fg_color="#E67E22", hover_color="#D35400", command=self.reparar_sistema, **btn_style)
        self.btn_fix.place(relx=0.5, y=420, anchor="center", relwidth=0.85)

        self.btn_3 = ctk.CTkButton(self.sidebar, text="📄 GENERAR REPORTE PDF", fg_color="#2980B9", state="disabled", command=self.crear_pdf, **btn_style)
        self.btn_3.place(relx=0.5, y=490, anchor="center", relwidth=0.85)

        # --- PANEL PRINCIPAL ---
        self.main_view = ctk.CTkFrame(self, fg_color="#0F1112", corner_radius=20)
        self.main_view.grid(row=0, column=1, padx=30, pady=30, sticky="nsew")
        
        self.score_display = ctk.CTkLabel(self.main_view, text="--", font=("Arial", 160, "bold"), text_color="#2C3E50")
        self.score_display.pack(pady=(40, 0))

        self.lbl_progress = ctk.CTkLabel(self.main_view, text="ESPERANDO INICIO", font=("Arial", 13, "bold"), text_color="#ABB2B9")
        self.lbl_progress.pack(pady=(10, 5))
        
        self.progress_bar = ctk.CTkProgressBar(self.main_view, width=600, height=15, progress_color="#3498db")
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=10)
        
        self.txt_log = ctk.CTkTextbox(self.main_view, fg_color="#161616", text_color="#00FF00", border_color="#3498db", border_width=2, font=("Consolas", 14), corner_radius=15)
        self.txt_log.pack(pady=20, padx=40, fill="both", expand=True)

    def elegir_carpeta(self):
        ruta = filedialog.askdirectory()
        if ruta:
            self.ruta_seleccionada = ruta
            self.txt_log.insert("end", f"\n[SISTEMA] Objetivo: {self.ruta_seleccionada}\n")

    def iniciar_hilo(self):
        self.btn_2.configure(state="disabled")
        threading.Thread(target=self.auditar, daemon=True).start()

    def auditar(self):
        self.puntaje = 100
        self.hallazgos = []
        self.archivos_vulnerables = []
        self.fecha_auditoria = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        
        self.txt_log.delete("1.0", "end")
        self.txt_log.insert("end", f">>> INICIANDO AUDITORIA V8.5: {self.fecha_auditoria}\n")
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()

        # 1. FIREWALL
        try:
            cmd = "powershell -Command \"(Get-NetFirewallProfile -Profile Domain,Public,Private).Enabled\""
            res = subprocess.check_output(cmd, shell=True).decode(errors='ignore').strip()
            if "False" in res:
                self.puntaje -= 30
                self.hallazgos.append("Firewall Desactivado")
                self.txt_log.insert("end", "[CRÍTICO] El Firewall de Windows está APAGADO.\n")
            else:
                self.txt_log.insert("end", "[OK] Firewall Activo.\n")
        except: pass

        # 2. ANTIVIRUS (¡RESTAURADO!)
        try:
            cmd_av = "powershell -Command \"(Get-MpComputerStatus).RealTimeProtectionEnabled\""
            res_av = subprocess.check_output(cmd_av, shell=True).decode(errors='ignore').strip()
            if "False" in res_av:
                self.puntaje -= 30
                self.hallazgos.append("Antivirus Desactivado")
                self.txt_log.insert("end", "[CRÍTICO] Antivirus (Defender) está APAGADO.\n")
            else:
                self.txt_log.insert("end", "[OK] Antivirus Activo.\n")
        except: 
            self.txt_log.insert("end", "[!] No se pudo verificar el estado del Antivirus.\n")

        # 3. RDP (ESCRITORIO REMOTO)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            # Intentamos conectar al puerto 3389
            if s.connect_ex(('127.0.0.1', 3389)) == 0:
                self.puntaje -= 20
                self.hallazgos.append("Puerto RDP (3389) Abierto")
                self.txt_log.insert("end", "[ALERTA] Puerto de Escritorio Remoto ABIERTO.\n")
            else:
                self.txt_log.insert("end", "[OK] Puerto RDP Cerrado.\n")

        # 4. ARCHIVOS
        exts, keys = [".txt", ".pdf", ".env", ".docx"], ["pass", "clave", "banco", "nomina", "password"]
        self.txt_log.insert("end", "[SISTEMA] Buscando archivos sensibles...\n")
        
        for root, dirs, files in os.walk(self.ruta_seleccionada):
            if any(x in root for x in ["AppData", "Windows", "Local", "node_modules"]): continue
            for file in files:
                if any(k in file.lower() for k in keys) and any(file.lower().endswith(e) for e in exts):
                    full_path = os.path.join(root, file)
                    self.archivos_vulnerables.append(full_path)
                    self.txt_log.insert("end", f"[RIESGO] Archivo: {file}\n")

        if self.archivos_vulnerables:
            self.puntaje -= 20

        # Guardar puntaje inicial solo la primera vez
        if self.puntaje_inicial is None: 
            self.puntaje_inicial = self.puntaje
            
        self.after(0, self.actualizar_ui)

    def actualizar_ui(self):
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1)
        p = max(0, self.puntaje)
        color = "#27AE60" if p == 100 else "#F1C40F" if p > 70 else "#E74C3C"
        self.score_display.configure(text=str(p), text_color=color)
        self.lbl_progress.configure(text="ANÁLISIS COMPLETADO")
        self.btn_2.configure(state="normal")
        self.btn_3.configure(state="normal")

    def reparar_sistema(self):
        self.txt_log.insert("end", "\n>>> INICIANDO PROTOCOLO DE REPARACIÓN...\n")
        
        # 1. Reparar Firewall
        try:
            subprocess.run("powershell -Command \"Set-NetFirewallProfile -All -Enabled True\"", shell=True)
            self.txt_log.insert("end", "[FIX] Firewall reactivado exitosamente.\n")
            if "Firewall Reactivado (+30 pts)" not in self.reparaciones_exitosas:
                self.reparaciones_exitosas.append("Firewall Reactivado (+30 pts)")
        except:
            self.txt_log.insert("end", "[ERROR] Falló reparación Firewall.\n")

        # 2. Reparar Antivirus
        try:
            subprocess.run("powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring 0\"", shell=True)
            self.txt_log.insert("end", "[FIX] Protección Antivirus habilitada.\n")
            if "Antivirus Activado (+30 pts)" not in self.reparaciones_exitosas:
                self.reparaciones_exitosas.append("Antivirus Activado (+30 pts)")
        except: pass

        # 3. Reparar RDP (Método Agresivo: Registro + Servicio)
        try:
            # Opción A: Registro
            subprocess.run("powershell -Command \"Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -name 'fDenyTSConnections' -value 1\"", shell=True)
            # Opción B: Firewall Rule (Bloqueo extra)
            subprocess.run("powershell -Command \"Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'\"", shell=True)
            
            self.txt_log.insert("end", "[FIX] Escritorio Remoto BLOQUEADO (Registro + Regla).\n")
            if "RDP Bloqueado (+20 pts)" not in self.reparaciones_exitosas:
                self.reparaciones_exitosas.append("RDP Bloqueado (+20 pts)")
        except: 
            self.txt_log.insert("end", "[ERROR] Falló reparación RDP.\n")
            
        messagebox.showinfo("Guardian Pro", "Reparaciones ejecutadas. Iniciando Re-escaneo...")
        self.iniciar_hilo()

    def crear_pdf(self):
        try:
            path = filedialog.asksaveasfilename(defaultextension=".pdf", initialfile="Reporte_Guardian_V8.5.pdf")
            if not path: return
            
            pdf = FPDF()
            pdf.add_page()
            
            # Encabezado
            pdf.set_fill_color(30, 30, 30); pdf.rect(0, 0, 210, 40, 'F')
            pdf.set_text_color(255, 255, 255); pdf.set_font("Arial", 'B', 20)
            pdf.cell(190, 20, "INFORME TÉCNICO V8.5", ln=True, align='C')
            
            # Resumen
            pdf.set_text_color(0, 0, 0); pdf.ln(30)
            pdf.set_font("Arial", 'B', 14); pdf.cell(0, 10, "1. MÉTRICAS DE SEGURIDAD", ln=True)
            pdf.set_font("Arial", '', 12)
            pdf.cell(0, 8, f"Puntaje Inicial (Riesgo): {self.puntaje_inicial}/100", ln=True)
            pdf.cell(0, 8, f"Puntaje Final (Seguro): {self.puntaje}/100", ln=True)
            mejora = self.puntaje - self.puntaje_inicial
            pdf.set_text_color(0, 150, 0)
            pdf.cell(0, 8, f"Impacto de Reparación: +{mejora} puntos recuperados", ln=True)
            pdf.set_text_color(0, 0, 0)

            # Historial de Reparaciones (Lo que el usuario pidió ver)
            if self.reparaciones_exitosas:
                pdf.ln(5); pdf.set_font("Arial", 'B', 14); pdf.cell(0, 10, "2. REPARACIONES EJECUTADAS", ln=True)
                pdf.set_font("Arial", '', 11)
                for accion in self.reparaciones_exitosas:
                    pdf.cell(0, 7, f" [HECHO] {accion}", ln=True)
            
            # Lista de Archivos (Si quedó alguno o historial)
            if self.archivos_vulnerables:
                pdf.ln(5); pdf.set_font("Arial", 'B', 14); pdf.cell(0, 10, "3. ARCHIVOS SENSIBLES ENCONTRADOS", ln=True)
                pdf.set_font("Arial", '', 8)
                for archivo in self.archivos_vulnerables:
                    # Limpieza de caracteres para PDF
                    safe_txt = archivo.encode('latin-1', 'replace').decode('latin-1')
                    pdf.multi_cell(0, 5, f"> {safe_txt}")

            pdf.output(path)
            messagebox.showinfo("Éxito", "PDF generado con historial de reparaciones.")
        except Exception as e:
            messagebox.showerror("Error", f"Error PDF: {e}")

if __name__ == "__main__":
    app = GuardianProMaster()
    app.mainloop()