# Guardian Pro — Brief de producto

## Resumen

Guardian Pro es una aplicación de escritorio para Windows que convierte una
revisión defensiva básica en un **centro de operaciones local**: auditoría,
historial comparable, plan de acción explicable y vista consolidada de equipos.

Está pensada para personas y equipos pequeños de IT que necesitan una lectura
clara de pocos controles, sin desplegar un SIEM, un EDR ni una plataforma web.

> Guardian Pro no certifica cumplimiento, no garantiza seguridad y no sustituye
> una evaluación profesional, un antivirus/EDR ni un escaneo de vulnerabilidades.

## Problema

En muchos equipos pequeños, la revisión de Windows termina en una lista de
resultados aislados:

- no queda un historial claro de qué cambió;
- no se distingue entre un hallazgo, un error de consulta y una comprobación no
  verificable;
- no hay un criterio repetible para decidir qué atender primero;
- compartir resultados suele exponer rutas, nombres de archivo o evidencia
  innecesaria;
- los informes de varios equipos no se consolidan.

## Propuesta de valor

1. **Evidencia antes que puntuación.** Guardian no inventa un “score de
   seguridad”. Muestra estados, hechos y recomendaciones.
2. **Historial comparable.** Cada auditoría se guarda localmente y se compara
   con la anterior. Una mejora solo se marca resuelta cuando una auditoría
   posterior devuelve `OK`.
3. **Plan de acción determinista.** El orden se explica: hallazgos altos,
   revisiones pendientes, hallazgos medios y bajos. Cada tarjeta responde:
   qué se detectó, por qué importa, siguiente paso y cómo verificar.
4. **Privacidad por diseño.** El historial local no guarda la ruta seleccionada,
   nombres de archivo, contenido, evidencias, secretos ni contraseñas. La
   exportación JSON usa un esquema sanitizado y estricto.
5. **Flota sin servidor.** Los informes se importan como datos pasivos. No se
   ejecuta nada del archivo importado y no se habilitan reparaciones.
6. **Demo segura.** Tres equipos ficticios permiten presentar el producto sin
   mezclar datos reales con el historial.

## Capacidades implementadas

| Área | Estado |
|------|--------|
| Firewall, Defender, RDP y nombres de archivo | Implementado |
| Reparación de firewall y RDP con confirmación y permisos | Implementado |
| Defender solo detección + guía manual | Implementado |
| Resumen ejecutivo | Implementado |
| Plan de acción explicable | Implementado |
| Historial local con comparación | Implementado |
| Vista de equipos con importación JSON | Implementado |
| Exportación JSON sanitizada | Implementado |
| PDF con resumen ejecutivo y detalle técnico | Implementado |
| Modo demo de tres equipos | Implementado |
| Pruebas automatizadas | 134 pruebas en verde en el entorno de desarrollo |

## Público objetivo

- Profesionales de IT generalistas que administran entre 3 y 50 equipos.
- Consultores que necesitan un diagnóstico inicial y un informe legible.
- Pequeñas empresas sin equipo de seguridad dedicado.
- Formadores o demostraciones que necesitan un flujo reproducible sin tocar
  configuraciones reales.

## Flujo de valor en cinco minutos

1. Abrir **Modo demo**.
2. Mostrar el **Resumen ejecutivo**: prioridades, equipos y tendencia.
3. Abrir **Vista de equipos**: tres equipos ficticios, con un cambio confirmado.
4. Abrir **Plan de acción**: explicación y verificación de cada prioridad.
5. Abrir **Historial**: comparación y regla de resolución.
6. Salir de demo, ejecutar una auditoría real y mostrar que el historial se
   guarda sin rutas ni nombres de archivo.
7. Exportar JSON después del aviso de privacidad y explicar qué contiene y qué no.

## Diferenciación

- **Local-first:** no requiere servidor, nube ni cuenta.
- **Explicable:** cada prioridad tiene una razón y una verificación.
- **Conservador:** un error no es un OK; una reparación ejecutada no es una
  resolución.
- **Sanitizado:** el JSON de flota no incluye evidencia ni nombres de archivo.
- **Seguro por defecto:** demo e importaciones son de solo lectura y no pueden
  disparar reparaciones.

## Evidencia técnica

- `Guardian.py`: interfaz CustomTkinter, comprobaciones Windows, ciclo de
  reparación y PDF.
- `guardian_workspace.py`: persistencia atómica, comparación, plan determinista,
  validación JSON, flota y demo.
- `test_guardian.py` y `test_guardian_workspace.py`: 134 pruebas automatizadas.
- Documentación: `README.md`, `docs/ARCHITECTURE.md`,
  `docs/DEMO_RUNBOOK_ES.md`.

## Limitaciones que deben decirse en una presentación

- El historial y la flota son JSON local, sin cifrado.
- El informe JSON sanitizado sigue identificando el equipo por nombre e ID
  hasheado; hay que revisarlo antes de compartirlo.
- El PDF puede contener rutas, nombres de archivo y evidencia técnica.
- La activación manual de Defender y las reparaciones reales deben validarse en
  una VM Windows de destino.
- La validación visual de las vistas nuevas se realizó en el entorno de
  desarrollo Windows 11; la revisión en la VM objetivo sigue pendiente.
- No hay certificación, garantía de seguridad ni puntuación numérica.

## Próximos pasos posibles

- Validación manual completa en VM Windows 11 elevada y no elevada.
- Revisión del PDF en visores reales y ajuste de maquetación.
- Firma de código y empaquetado para distribución.
- Política de retención configurable desde la interfaz.
- Exportación consolidada de flota y plantillas de informe por organización.
- Integración opcional con inventario corporativo, sin convertir el producto en
  una plataforma web.
