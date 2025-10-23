from app import create_app
from collections import defaultdict

# 1. Crear una instancia de la aplicación
app = create_app()

# 2. Definir las categorías y los prefijos de las rutas para agruparlas
ROUTE_CATEGORIES = {
    "AUTENTICACIÓN Y PERFIL": ["/login", "/logout", "/registro", "/recuperar", "/reset_password", "/verificar", "/editar_perfil"],
    "PANEL DE ADMINISTRADOR": ["/admin_dashboard", "/admin_registro"],
    "GESTIÓN DE USUARIOS": ["/usuarios"],
    "GESTIÓN DE PROFESORES": ["/profesor"],
    "GESTIÓN DE CURSOS": ["/curso"],
    "GESTIÓN DE ESTUDIANTES": ["/estudiante"],
    "GESTIÓN DE ASIGNATURAS": ["/asignatura"],
    "GESTIÓN DE HORARIOS": ["/horario"],
    "GESTIÓN DE ASISTENCIAS": ["/asistencia"],
    "VISTAS DE ESTUDIANTE": ["/mi_asistencia", "/mi_reporte"],
    "REPORTES (Admin)": ["/reporte"],
    "API Y BÚSQUEDAS (Helpers)": ["/buscar", "/get_horarios_cursos"],
    "RUTAS PRINCIPALES Y ESTÁTICAS": ["/", "/static"],
}

# Función para asignar una categoría a una ruta
def get_category(rule_path):
    for category, prefixes in ROUTE_CATEGORIES.items():
        for prefix in prefixes:
            if rule_path.startswith(prefix):
                return category
    return "OTRAS RUTAS"

# 2. Usar el contexto de la aplicación para acceder a todas sus configuraciones
with app.app_context():
    # 3. Agrupar las rutas por categoría
    grouped_rules = defaultdict(list)
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        category = get_category(rule.rule)
        grouped_rules[category].append(rule)

    # 4. Abrir (o crear) un archivo para escribir las rutas
    with open('rutas.txt', 'w', encoding='utf-8') as f:
        f.write("📍 Rutas Flask registradas en AsisPro:\n")
        f.write("="*40 + "\n\n")
        
        # 5. Escribir las rutas agrupadas en el archivo
        # Ordenar las categorías para una salida consistente
        sorted_categories = sorted(grouped_rules.keys(), key=lambda c: list(ROUTE_CATEGORIES.keys()).index(c) if c in ROUTE_CATEGORIES else 99)

        for category in sorted_categories:
            f.write("#######################################\n")
            f.write(f"#-------------- {category} -------------#\n")
            f.write("#######################################\n\n")

            for rule in grouped_rules[category]:
                # Limpiar y formatear los métodos HTTP
                methods = ', '.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))
                
                # Escribir la información de cada ruta
                f.write(f"Ruta: {rule.rule}\n")
                f.write(f"  -> Endpoint: {rule.endpoint}\n")
                f.write(f"  -> Métodos: {methods}\n\n")

print("✅ ¡Listo! El archivo 'rutas.txt' ha sido generado con todas las rutas de la aplicación.")
