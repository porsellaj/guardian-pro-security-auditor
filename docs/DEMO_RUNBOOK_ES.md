# Guardian Pro — Guion de demostración (5 minutos)

## Objetivo

Presentar el flujo completo del Operations Center sin tocar configuraciones
reales de Windows y sin mezclar datos ficticios con el historial del equipo.

La demo usa **tres equipos ficticios y cuatro auditorías en memoria**. No
escribe en `history.json` ni en `fleet.json`.

## Antes de empezar

### Requisitos

- Windows 10/11.
- Python 3.10 o superior.
- Dependencias instaladas:

```powershell
pip install -r requirements.txt
```

### Arranque aislado recomendado

Para evitar cualquier duda sobre datos locales durante una presentación, use un
directorio temporal para el historial:

```powershell
$env:GUARDIAN_PRO_DATA_DIR = "$env:TEMP\GuardianProDemo"
python Guardian.py
```

El modo demo no escribe en ese directorio de todos modos; el aislamiento es una
medida adicional de transparencia.

### Comprobaciones previas

1. Cierre otras instancias de Guardian Pro.
2. Confirme que la ventana abre a 1100×750 o más.
3. No ejecute reparaciones reales durante la demo.
4. Tenga claro que **Modo demo** deshabilita auditoría, reparaciones, PDF,
   exportación e importación. Es intencional.

## Guion cronometrado

### 0:00–0:25 — Apertura

**Decir:**

> “Guardian Pro es un centro de operaciones local para Windows. Convierte una
> revisión defensiva en historial comparable y un plan de acción explicable.
> No calcula una puntuación de seguridad ni certifica cumplimiento.”

Señalar la barra lateral: Resumen ejecutivo, Plan de acción, Historial, Vista de
equipos y Auditoría del sistema.

### 0:25–0:45 — Activar la demo

1. Pulsar **Modo demo** en la esquina superior derecha.
2. Señalar el banner persistente **DEMO — DATOS FICTICIOS**.
3. Señalar la etiqueta de demo en la barra lateral.

**Decir:**

> “Los tres equipos y las cuatro auditorías son ficticios. Están solo en
> memoria. Las acciones reales están deshabilitadas para que una demo nunca
> pueda reparar ni exportar datos inventados.”

### 0:45–1:30 — Resumen ejecutivo

1. Abrir **Resumen ejecutivo**.
2. Señalar las métricas: prioridades, hallazgos altos, revisiones, equipos y
   auditorías.
3. Señalar la tarjeta **Última evaluación**.
4. Señalar el gráfico **Tendencia de atención**.
5. Leer la nota: “No es una puntuación de seguridad”.

**Decir:**

> “El gráfico cuenta elementos que requieren atención: hallazgos, errores y
> comprobaciones no verificables. No convierte eso en un número arbitrario de
> seguridad.”

### 1:30–2:15 — Vista de equipos

1. Abrir **Vista de equipos**.
2. Mostrar los tres equipos ficticios.
3. Señalar el orden: primero el que tiene más hallazgos altos.
4. Abrir **Ver plan de este equipo** en uno de ellos.

**Decir:**

> “La flota se consolida sin servidor. En producción, los informes se importan
> como JSON validado y pasivo. En demo, todo es ficticio y de solo lectura.”

### 2:15–3:00 — Plan de acción

1. Mostrar una tarjeta del plan.
2. Leer las cuatro secciones: qué se detectó, por qué importa, siguiente paso y
   cómo verificar.
3. Señalar que Defender dice **Intervención manual necesaria**.
4. Señalar que no aparece un botón de reparación en contexto de demo o informe
   importado.
5. Pulsar **Volver al plan actual** si se abrió desde la flota.

**Decir:**

> “El orden es determinista: primero hallazgos altos, después revisiones
> pendientes, luego hallazgos medios y bajos. Un error nunca se presenta como
> OK.”

### 3:00–3:45 — Historial y comparación

1. Abrir **Historial**.
2. Seleccionar la auditoría más reciente de `ADMIN-PC-03`.
3. Mostrar la comparación: un firewall resuelto y Defender persistente.
4. Leer la nota inferior sobre resolución.

**Decir:**

> “Solo cuenta como resuelto cuando una auditoría posterior devuelve OK. Un
> comando ejecutado no es una resolución. Un error o una comprobación ausente
> tampoco.”

### 3:45–4:20 — Auditoría real y límites de la demo

1. Abrir **Auditoría del sistema**.
2. Señalar que **Seleccionar carpeta** e **Iniciar auditoría** están
   deshabilitados en demo.
3. Pulsar **Salir de demo**.
4. Mostrar que la vista real vuelve sin haber guardado los datos ficticios.

**Decir:**

> “Al salir, el historial real no cambió. La demo no contamina el equipo.”

Si ya existe una auditoría real preparada:

5. Abrir **Resumen ejecutivo** y mostrar la última evaluación real.
6. Abrir **Auditoría del sistema** y señalar el alcance de nombres.

Si no existe una auditoría real, no ejecute un escaneo largo durante los cinco
minutos. Explique que la auditoría real se ejecuta aparte y que los resultados
se guardan al finalizar.

### 4:20–4:50 — Exportación y privacidad

Si hay una auditoría real:

1. Pulsar **Exportar JSON**.
2. Leer el aviso de privacidad.
3. Cancelar o guardar en una carpeta temporal.
4. Explicar qué incluye: dispositivo, sistema, fecha, comprobaciones, estados,
   severidades y recomendaciones.
5. Explicar qué no incluye: rutas, nombres de archivo, evidencia, secretos.

Si no hay una auditoría real:

> “La exportación está deshabilitada en demo a propósito. Los datos ficticios no
> se exportan. El JSON real es sanitizado, pero sigue identificando el equipo por
> nombre e ID hasheado; hay que revisarlo antes de compartirlo.”

### 4:50–5:00 — Cierre

**Decir:**

> “Guardian Pro prioriza claridad y evidencia: historial local, comparación
> conservadora, plan explicable y flota sin servidor. Todavía requiere validación
> manual en la VM Windows de destino, y no certifica ni garantiza seguridad.”

## Plan B si algo falla

| Problema | Acción |
|----------|--------|
| No abre la ventana | Verificar `python -c "import customtkinter"` y reinstalar `requirements.txt`. |
| **Modo demo** deshabilitado | Esperar a que termine una auditoría o reparación activa. |
| Una vista se ve cortada | Usar la barra de desplazamiento; la ventana mínima es 1020×680. |
| No hay historial real | No es necesario para la demo; usar solo las vistas demo. |
| Se pide una reparación | No aceptar durante la presentación; la demo no la ofrece y el flujo real exige confirmación y administrador. |
| Se abre un mensaje inesperado | Leerlo y cerrarlo; no confirmar acciones de reparación. |

## Mensajes que deben evitarse

- “Guardian Pro certifica que el equipo es seguro.”
- “El score de seguridad es X.”
- “La reparación quedó resuelta” sin una auditoría posterior con `OK`.
- “La demo son datos reales.”
- “El informe JSON no contiene información del equipo.” Sí contiene nombre e ID
  hasheado; no contiene rutas ni nombres de archivo.

## Después de la demo

1. Confirmar que **Modo demo** está desactivado.
2. Cerrar la aplicación.
3. Si se usó `GUARDIAN_PRO_DATA_DIR` temporal, se puede eliminar ese directorio
   de forma manual.
4. No borrar el historial real del usuario.

## Estado de validación

La revisión visual de las vistas nuevas se realizó en el entorno de desarrollo
Windows 11 a 1100×750 y 1240×800. La validación manual en la VM Windows de
destino sigue pendiente, junto con la activación manual de Defender, las
reparaciones reales y la revisión del PDF en un visor real.
