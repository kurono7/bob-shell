---
name: espacios-skill
description: revisa saltos de linea , identacion, espacios finales
---

# Skill: Revisión de Espacios y Formato

## Objetivo
Revisar y corregir problemas relacionados con espacios, saltos de línea, indentación y espacios finales en el código.

## Reglas de Revisión

### 1. Espacios Finales (Trailing Whitespace)
- **Detectar** líneas que terminan con espacios o tabulaciones innecesarias
- **Reportar** cada ocurrencia con el número de línea exacto
- **Sugerir** eliminar todos los espacios finales

### 2. Saltos de Línea
- **Verificar** que los archivos terminen con un salto de línea final
- **Detectar** múltiples líneas vacías consecutivas (más de 2)
- **Revisar** saltos de línea inconsistentes (mezcla de CRLF y LF)
- **Sugerir** usar un solo tipo de salto de línea según el estándar del proyecto

### 3. Indentación
- **Identificar** el estilo de indentación predominante (espacios vs tabs)
- **Detectar** mezcla de espacios y tabs en el mismo archivo
- **Verificar** consistencia en el número de espacios (2, 4, etc.)
- **Reportar** líneas con indentación incorrecta o inconsistente
- **Sugerir** estandarizar según el estilo del proyecto

### 4. Espacios en Blanco Innecesarios
- **Detectar** múltiples espacios consecutivos donde solo se necesita uno
- **Revisar** espacios antes de comas, punto y coma, o paréntesis de cierre
- **Verificar** espacios después de paréntesis de apertura o antes de cierre

## Proceso de Análisis

1. **Escanear** el archivo línea por línea
2. **Identificar** el patrón de indentación dominante
3. **Detectar** todas las violaciones de formato
4. **Priorizar** problemas por severidad:
   - Alta: Mezcla de tabs y espacios
   - Media: Espacios finales, indentación inconsistente
   - Baja: Múltiples líneas vacías

## Formato de Reporte

Para cada problema encontrado, reportar:
- **Tipo**: Categoría del problema (espacios finales, indentación, etc.)
- **Línea**: Número de línea exacto
- **Descripción**: Explicación clara del problema
- **Sugerencia**: Cómo corregirlo

## Excepciones

- Archivos binarios o generados automáticamente
- Archivos de configuración con formato específico requerido
- Strings multilínea donde los espacios son intencionales
- Comentarios con formato ASCII art