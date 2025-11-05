from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, g, current_app, jsonify
)
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
import psycopg2.extras
import random
import hashlib

from app.db import get_db_connection
from app import mail

main = Blueprint('main', __name__)

#######################################
#-------------- DECORADORES Y HELPERS -------------#
#######################################

def login_required(f):
    """Decorador que verifica si un usuario ha iniciado sesión."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Debes iniciar sesión para acceder a esta sección.", "warning")
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

def rol_required(*roles):
    """
    Decorador para restringir el acceso a rutas basado en roles de usuario.
    Roles: 1=Admin, 2=Profesor, 3=Estudiante.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not g.user:
                flash("Debes iniciar sesión para acceder a esta sección.", "warning")
                return redirect(url_for('main.login'))

            if g.user.get('role') not in roles:
                flash("No tienes permisos para acceder a esta sección.", "danger")
                user_role = g.user.get('role')
                if user_role == 1:
                    return redirect(url_for('main.admin_dashboard'))
                elif user_role == 2:
                    return redirect(url_for('main.asistencias'))
                elif user_role == 3:
                    return redirect(url_for('main.mi_asistencia'))
                return redirect(url_for('main.index'))
            return f(*args, **kwargs)
        return wrapper
    return decorator

def generate_confirmation_token(email):
    """Genera un token de confirmación para un correo electrónico."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    """Confirma un token, devolviendo el email si es válido y no ha expirado."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except Exception:
        return False
    return email

def send_email(to_email, reset_url):
    """Envía un correo de recuperación de contraseña."""
    try:
        html_body = render_template(
            'email/recuperacion.html',
            reset_url=reset_url,
            year=datetime.now().year
        )
        msg = Message(
            "Restablecer Contraseña - AsisPro",
            sender="ACGC Estudio <acgc.estudio@gmail.com>",
            recipients=[to_email]
        )
        msg.html = html_body
        mail.send(msg)
        current_app.logger.info(f"Correo de recuperación enviado a {to_email}")
        return True
    except Exception as e:
        current_app.logger.error(f"Error al enviar correo de recuperación a {to_email}: {e}")
        return False

def send_verification_email(to_email, codigo):
    """Envía un correo de verificación de cuenta con un código."""
    try:
        html_body = render_template(
            'email/verificacion.html', 
            codigo=codigo, 
            year=datetime.now().year
        )
        msg = Message("Tu código de verificación - IED Simón Bolívar",
                      sender="ACGC Estudio <acgc.estudio@gmail.com>",
                      recipients=[to_email])
        msg.html = html_body
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Error al enviar correo de verificación a {to_email}: {e}")
        return False

def has_accents(text):
    """Verifica si un string contiene tildes."""
    accents = 'áéíóúÁÉÍÓÚ'
    return any(char in accents for char in text)

#######################################
#-------------- GESTIÓN DE CONTEXTO DE APP -------------#
#######################################

def get_db():
    """Abre una nueva conexión a la base de datos si no existe una para la petición actual."""
    if 'db' not in g:
        print("🔗 Abriendo nueva conexión a la base de datos para esta petición...")
        g.db = get_db_connection()
    return g.db

@main.teardown_app_request
def close_db(exception=None):
    """Cierra la conexión a la base de datos al final de la petición."""
    db = g.pop('db', None)
    if db is not None:
        db.close()
        print("✅ Conexión a la base de datos cerrada.")
# --- FIN: Gestión centralizada de la conexión a la BD ---

@main.before_app_request
def load_logged_in_user():
    # Evitar ejecutar esto para las rutas de archivos estáticos
    if request.endpoint == 'static':
        return

    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        cursor = get_db().cursor()
        cursor.execute("SELECT id_usuario, username, id_rol, correo FROM usuarios WHERE id_usuario = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            # Generamos el hash del correo para la URL de Gravatar
            email_hash = hashlib.md5(user[3].lower().encode('utf-8')).hexdigest()
            gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=identicon&s=32"
            g.user = {'id': user[0], 'username': user[1], 'role': user[2], 'email': user[3], 'avatar': gravatar_url} # Añadimos el avatar al objeto de usuario
        else:
            g.user = None

@main.app_context_processor
def inject_user():
    """Inyecta la variable 'user' en el contexto de todas las plantillas."""
    return dict(user=g.user)
@main.app_context_processor
def inject_config():
    """Inyecta las configuraciones globales en todas las plantillas."""
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    config = {}
    try:
        cursor.execute("SELECT clave, valor FROM configuracion")
        for row in cursor.fetchall():
            config[row['clave']] = row['valor']
    except Exception as e:
        print(f"⚠️ Error al cargar la configuración global: {e}")
    finally:
        cursor.close()
    
    # Obtenemos las redes sociales dinámicamente de la configuración
    cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cursor.execute("SELECT clave, valor, icono FROM configuracion WHERE grupo = 'social' AND valor IS NOT NULL AND valor != '' ORDER BY id")
        rutas_sociales = cursor.fetchall()
    except Exception as e:
        print(f"⚠️ Error al cargar las rutas sociales: {e}")
        rutas_sociales = []
    finally:
        cursor.close()
    return dict(config=config, rutas_sociales=rutas_sociales)

@main.app_context_processor
def inject_now():
    """Inyecta el objeto datetime en el contexto de todas las plantillas."""
    return {'now': datetime.now}


#######################################
#-------------- RUTA / (INDEX) -------------#
#######################################

@main.route('/')
def index():
    
    # Si el usuario es admin, redirigir al dashboard de admin
    if session.get('user_role') == 1:
        return redirect(url_for('main.admin_dashboard'))

    return render_template('index.html')

#######################################
#-------------- RUTA /registro -------------#
#######################################

@main.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        correo = request.form['correo'].lower()
        nombre_completo = request.form['nombre_completo'].upper()
        identificacion = request.form['identificacion'].upper()
        id_rol = request.form['id_rol']

        if has_accents(username):
            flash('El nombre de usuario no puede contener tildes.', 'warning')
            cursor.close()
            return redirect(url_for('main.registro'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM usuarios WHERE correo = %s OR identificacion = %s", (correo, identificacion))
        exists = cursor.fetchone()
        if exists:
            flash('El correo o la identificación ya están registrados.', 'warning')
            cursor.close()
            return redirect(url_for('main.registro'))

        # Generar código de verificación
        codigo = random.randint(100000, 999999)

        # Guardar datos temporales en sesión
        session['registro_temporal'] = {
            'username': username,
            'password': generate_password_hash(password),
            'correo': correo,
            'nombre_completo': nombre_completo,
            'identificacion': identificacion,
            'id_rol': id_rol,
            'codigo': str(codigo)
        }

        # Enviar el correo
        try:
            if send_verification_email(correo, codigo):
                flash('Se envió un código de verificación al correo proporcionado.', 'info')
            else:
                return redirect(url_for('main.registro')) # Si el correo falla, redirige
            return redirect(url_for('main.verificar')) # Si el correo se envía, va a verificar
        except Exception as e:
            flash(f'Ocurrió un error inesperado: {e}', 'danger')
            return redirect(url_for('main.registro'))
    else: # GET: Cargar roles para el formulario
        cursor = get_db().cursor(cursor_factory=psycopg2.extras.DictCursor)
        try:
            cursor.execute("SELECT id_rol, nombre AS nombre_rol FROM roles WHERE id_rol != 1") # Excluir rol de admin
            roles = cursor.fetchall()
        finally:
            cursor.close()
        return render_template('auth/registro.html', roles=roles)


#######################################
#-------------- RUTA /login -------------#
#######################################

@main.route('/login', methods=['GET', 'POST'])
def login():
    # Verificación proactiva: si no hay usuarios, redirigir a la configuración inicial.
    # Esto se ejecuta tanto para GET como para POST.
    conn_check = get_db()
    cursor_check = conn_check.cursor()
    try:
        cursor_check.execute("SELECT 1 FROM usuarios LIMIT 1")
        if cursor_check.fetchone() is None:
            flash('No hay usuarios en el sistema. Por favor, registra el primer administrador.', 'info')
            return redirect(url_for('main.setup'))
    finally:
        cursor_check.close()

    if request.method == 'POST':
        identifier = request.form['username']
        password = request.form['password']
        MAX_LOGIN_ATTEMPTS = 5
        LOCKOUT_PERIOD_MINUTES = 15

        try:
            conn = get_db()
            cursor = conn.cursor()

            # Obtener datos del usuario, incluyendo intentos de login y bloqueo
            cursor.execute("""
                SELECT id_usuario, password, id_rol, failed_login_attempts, lockout_until
                FROM usuarios 
                WHERE (username = %s OR correo = %s) AND estado = TRUE
            """, (identifier, identifier))

            user = cursor.fetchone()
            if user:
                user_id, db_password, user_role, attempts, lockout_until = user
                # 1. Verificar si la cuenta está bloqueada
                if lockout_until and lockout_until > datetime.now():
                    remaining_time = (lockout_until - datetime.now()).seconds // 60
                    flash(f'Cuenta bloqueada por demasiados intentos fallidos. Inténtalo de nuevo en {remaining_time + 1} minutos.', 'danger')
                    cursor.close()
                    return render_template('auth/login.html')
                # 2. Verificar la contraseña
                if check_password_hash(db_password, password):
                    # Si es correcta, resetear intentos y establecer sesión
                    cursor.execute("""
                        UPDATE usuarios
                        SET failed_login_attempts = 0, lockout_until = NULL
                        WHERE id_usuario = %s
                    """, (user_id,))
                    conn.commit()
                    session['user_id'] = user_id
                    session['user_role'] = user_role
                    flash('Has iniciado sesión correctamente.', 'success')
                    # Redirigir según el rol
                    if user_role == 1:
                        return redirect(url_for('main.admin_dashboard'))
                    elif user_role == 3:
                        return redirect(url_for('main.mi_asistencia'))
                    elif user_role == 2:
                        return redirect(url_for('main.asistencias'))
                    else:
                        return redirect(url_for('main.index'))
                else:
                    # 3. Si la contraseña es incorrecta, incrementar intentos
                    attempts += 1
                    if attempts >= MAX_LOGIN_ATTEMPTS:
                        # Bloquear la cuenta
                        lockout_time = datetime.now() + timedelta(minutes=LOCKOUT_PERIOD_MINUTES)
                        cursor.execute("""
                            UPDATE usuarios SET failed_login_attempts = %s, lockout_until = %s
                            WHERE id_usuario = %s
                        """, (attempts, lockout_time, user_id))
                        flash(f'Has superado el número de intentos. Tu cuenta ha sido bloqueada por {LOCKOUT_PERIOD_MINUTES} minutos.', 'danger')
                    else:
                        # Solo actualizar el contador
                        cursor.execute("UPDATE usuarios SET failed_login_attempts = %s WHERE id_usuario = %s", (attempts, user_id))
                        flash(f'Contraseña incorrecta. Te quedan {MAX_LOGIN_ATTEMPTS - attempts} intentos.', 'warning')
                    conn.commit()
                    flash('Contraseña incorrecta.', 'danger')
            else:
                flash('Usuario no encontrado o inactivo.', 'danger')
        except Exception as e:
            flash(f'Ocurrió un error al iniciar sesión: {e}', 'danger')
        finally:
            if 'cursor' in locals() and not cursor.closed:
                cursor.close()
    return render_template('auth/login.html')

#######################################
#-------------- RUTA /setup -------------#
#######################################

@main.route('/setup', methods=['GET', 'POST'])
def setup():
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT 1 FROM usuarios LIMIT 1")
        if cursor.fetchone():
            flash('El sistema ya tiene un administrador registrado.', 'warning')
            return redirect(url_for('main.login'))

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            correo = request.form['correo'].lower()
            nombre_completo = request.form['nombre_completo'].upper()
            identificacion = request.form['identificacion'].upper()
            
            # --- INICIO: Verificación y creación de roles ---
            # Asegura que los roles básicos existan antes de crear el primer usuario.
            roles_a_verificar = {
                1: 'Administrador',
                2: 'Profesor',
                3: 'Estudiante'
            }
            for id_rol, nombre_rol in roles_a_verificar.items():
                cursor.execute("SELECT 1 FROM roles WHERE id_rol = %s", (id_rol,))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO roles (id_rol, nombre) VALUES (%s, %s)", (id_rol, nombre_rol))
            conn.commit() # Guardar los nuevos roles
            # --- FIN: Verificación y creación de roles ---

            hashed_password = generate_password_hash(password)
            
            cursor.execute("""
                INSERT INTO usuarios (username, password, correo, nombre_completo, identificacion, id_rol, fecha_registro, estado)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                username,
                hashed_password,
                correo,
                nombre_completo,
                identificacion,
                1, # id_rol para Administrador
                datetime.now(),
                True
            ))
            conn.commit()
            flash('Administrador registrado exitosamente. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('main.login'))

    except Exception as e:
        flash(f'Ocurrió un error durante la configuración: {e}', 'danger')
    finally:
        cursor.close()

    return render_template('auth/setup.html')

#######################################
#-------------- RUTA /logout -------------#
#######################################

@main.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('main.login'))

#######################################
#-------------- RUTA /admin_dashboard -------------#
#######################################

@main.route('/admin_dashboard')
@rol_required(1)
def admin_dashboard():
    return render_template('admin_dashboard.html')

#######################################
#-------------- RUTA /profesores -------------#
#######################################

@main.route('/profesores')
@rol_required(1)
def profesores():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Número de profesores por página
    offset = (page - 1) * per_page

    conn = get_db()
    cursor = conn.cursor()

    # Obtener el total de profesores para la paginación
    cursor.execute("SELECT COUNT(*) FROM profesores")
    total_items = cursor.fetchone()[0]
    total_pages = (total_items + per_page - 1) // per_page

    # Obtener los profesores para la página actual
    cursor.execute("""
        SELECT id_profesor, nombre_completo, documento, especialidad
        FROM profesores
        ORDER BY nombre_completo
        LIMIT %s OFFSET %s
    """, (per_page, offset))
    lista_profesores = cursor.fetchall()

    cursor.close()

    return render_template('profesores/profesores.html', profesores=lista_profesores, 
                           page=page, total_pages=total_pages)


#######################################
#-------------- RUTA /registrar_profesor -------------#
#######################################

@main.route('/registrar_profesor', methods=['GET', 'POST'])
@rol_required(1)
@login_required
def registrar_profesor():
    if request.method == 'POST':
        id_usuario = request.form.get('id_usuario')
        nombre_completo = request.form['nombre_completo'].upper()
        documento = request.form['documento'].upper()
        especialidad = request.form['especialidad'].upper()

        if not id_usuario:
            flash('Debe seleccionar un usuario válido.', 'danger')
            return redirect(url_for('main.registrar_profesor'))

        conn = get_db()
        cursor = conn.cursor()
        try:
            # Verificar si el usuario ya es un profesor
            cursor.execute("SELECT 1 FROM profesores WHERE id_usuario = %s", (id_usuario,))
            if cursor.fetchone():
                flash('Este usuario ya está registrado como profesor.', 'warning')
                return redirect(url_for('main.profesores'))

            # Si no existe, insertarlo
            cursor.execute("""
                INSERT INTO profesores (id_usuario, nombre_completo, documento, especialidad)
                VALUES (%s, %s, %s, %s)
            """, (id_usuario, nombre_completo, documento, especialidad))
            conn.commit()
            flash('Profesor registrado exitosamente.', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Error al registrar profesor: {e}', 'danger')
        finally:
            cursor.close()

        return redirect(url_for('main.profesores'))

    return render_template('profesores/registrar_profesor.html')


#######################################
#-------------- RUTA /editar_profesor -------------#
#######################################
@main.route('/editar_profesor/<int:id>', methods=['GET', 'POST'])
@rol_required(1)
@login_required
def editar_profesor(id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        nombre_completo = request.form['nombre_completo'].upper()
        documento = request.form['documento'].upper()
        especialidad = request.form['especialidad'].upper()

        try:
            cursor.execute("""
                UPDATE profesores
                SET nombre_completo = %s, documento = %s, especialidad = %s
                WHERE id_profesor = %s
            """, (nombre_completo, documento, especialidad, id))
            conn.commit()
            flash('Profesor actualizado exitosamente.', 'success')
        except Exception as e:
            flash(f'Error al actualizar profesor: {e}', 'danger')
        finally:
            cursor.close()

        return redirect(url_for('main.profesores'))
    else:
        cursor.execute("SELECT * FROM profesores WHERE id_profesor = %s", (id,))
        profesor = cursor.fetchone()
        cursor.close()
        return render_template('profesores/editar_profesor.html', profesor=profesor)


#######################################
#-------------- RUTA /eliminar_profesor -------------#
#######################################
@main.route('/eliminar_profesor/<int:id>', methods=['POST', 'GET'])
@rol_required(1)
@login_required
def eliminar_profesor(id):
    conn = get_db()
    cursor = conn.cursor()

    try:
        # El orden de eliminación es crucial para no violar las restricciones de clave foránea.

        # 1. Eliminar las entradas de horarios donde el profesor imparte clase.
        cursor.execute("DELETE FROM horarios WHERE id_profesor = %s", (id,))

        # 2. Desvincular al profesor de la tabla intermedia asignatura_profesores.
        cursor.execute("DELETE FROM asignatura_profesores WHERE id_profesor = %s", (id,))

        # 3. Eliminar los cursos que son dirigidos por este profesor.
        # Si la base de datos tuviera ON DELETE CASCADE en las tablas que dependen de 'cursos',
        # este paso eliminaría automáticamente asistencias, horarios de esos cursos, etc.
        # Si no, se necesitarían más DELETEs aquí.
        cursor.execute("DELETE FROM cursos WHERE id_profesor = %s", (id,))

        # 4. Finalmente, eliminar al profesor de la tabla principal.
        cursor.execute("DELETE FROM profesores WHERE id_profesor = %s", (id,))

        conn.commit()
        flash('Profesor y todos sus datos asociados (incluyendo cursos dirigidos) han sido eliminados.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al eliminar profesor: {e}', 'danger')
    finally:
        cursor.close()

    return redirect(url_for('main.profesores'))


#######################################
#-------------- RUTA /cursos -------------#
#######################################

@main.route('/cursos')
@rol_required(1)
def cursos():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    conn = get_db()
    cursor = conn.cursor()

    # Contar total de cursos
    cursor.execute("SELECT COUNT(*) FROM cursos")
    total_items = cursor.fetchone()[0]
    total_pages = (total_items + per_page - 1) // per_page

    # Obtener cursos paginados
    cursor.execute("""
        SELECT c.id_curso, c.grado, 
               p.nombre_completo AS profesor
        FROM cursos c
        JOIN profesores p ON c.id_profesor = p.id_profesor
        ORDER BY c.grado
        LIMIT %s OFFSET %s
    """, (per_page, offset))
    lista_cursos = cursor.fetchall()
    cursor.close()

    return render_template('cursos/cursos.html', cursos=lista_cursos, page=page, total_pages=total_pages)


#######################################
#-------------- RUTA /registrar_curso -------------#
#######################################

@main.route('/registrar_curso', methods=['GET', 'POST'])
@rol_required(1)
@login_required
def registrar_curso():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        grado = request.form['grado'].upper()
        id_profesor = request.form['id_profesor']
        cursor.execute("""
            INSERT INTO cursos (grado, id_profesor)
            VALUES (%s, %s)
        """, (grado, id_profesor))
        conn.commit()
        cursor.close()
        flash('Curso registrado exitosamente', 'success')
        return redirect(url_for('main.cursos'))
    cursor.execute("SELECT id_profesor, nombre_completo FROM profesores")
    profesores = cursor.fetchall()
    cursor.close()
    print(profesores)
    return render_template('cursos/registrar_curso.html', profesores=profesores)


#######################################
#-------------- RUTA /editar_curso -------------#
#######################################

@main.route('/editar_curso/<int:id>', methods=['GET', 'POST'])
@rol_required(1)
@login_required
def editar_curso(id):
    conn = get_db()
    cursor = conn.cursor()
    if request.method == 'POST':
        grado = request.form['grado'].upper()
        id_profesor = request.form['id_profesor']
        cursor.execute("""
            UPDATE cursos
            SET grado = %s, id_profesor = %s
            WHERE id_curso = %s
        """, (grado, id_profesor, id))
        conn.commit()
        cursor.close()
        flash('Curso actualizado exitosamente', 'success')
        return redirect(url_for('main.cursos'))
    cursor.execute("SELECT * FROM cursos WHERE id_curso = %s", (id,))
    curso = cursor.fetchone()
    cursor.execute("SELECT id_profesor, nombre_completo FROM profesores")
    profesores = cursor.fetchall()
    cursor.close()
    return render_template('cursos/editar_curso.html', curso=curso, profesores=profesores)

#######################################
#-------------- RUTA /eliminar_curso -------------#
#######################################

@main.route('/eliminar_curso/<int:id>', methods=['POST', 'GET'])
@rol_required(1)
@login_required
def eliminar_curso(id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Para manejar las llaves foráneas, debemos eliminar los registros relacionados primero.
        # El orden es importante para no violar otras restricciones.

        # 1. Eliminar registros de asistencia asociados al curso.
        cursor.execute("DELETE FROM asistencias WHERE id_curso = %s", (id,))

        # 2. Eliminar horarios asociados al curso.
        cursor.execute("DELETE FROM horarios WHERE id_curso = %s", (id,))

        # 3. Eliminar asignaturas asociadas al curso.
        cursor.execute("DELETE FROM asignatura WHERE id_curso = %s", (id,))

        # 4. Eliminar las asociaciones de estudiantes con este curso.
        cursor.execute("DELETE FROM estudiantes_cursos WHERE id_curso = %s", (id,))

        # 5. Finalmente, eliminar el curso.
        cursor.execute("DELETE FROM cursos WHERE id_curso = %s", (id,))
        conn.commit()
        flash('Curso y todos sus datos asociados han sido eliminados.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al eliminar curso: {e}', 'danger')
    finally:
        cursor.close()
    return redirect(url_for('main.cursos'))


#######################################
#-------------- RUTA /estudiantes -------------#
#######################################
@main.route('/estudiantes')
@rol_required(1)
def estudiantes():
    conn = get_db()
    cursor = conn.cursor()

    # Obtener estudiantes con curso y grado
    cursor.execute("""
        SELECT e.id_estudiante, e.nombre, c.grado AS curso
        FROM estudiantes e
        JOIN estudiantes_cursos ec ON e.id_estudiante = ec.id_estudiante
        JOIN cursos c ON ec.id_curso = c.id_curso
        ORDER BY c.grado, e.nombre
    """)

    lista_estudiantes = cursor.fetchall()

    cursor.close()

    # Agrupar estudiantes por curso (grado)
    estudiantes_por_curso = {}
    for estudiante in lista_estudiantes:
        curso = estudiante[2]
        if curso not in estudiantes_por_curso:
            estudiantes_por_curso[curso] = []
        estudiantes_por_curso[curso].append(estudiante)

    return render_template('estudiantes/estudiantes.html', estudiantes_por_grado=estudiantes_por_curso)

#######################################
#-------------- RUTA /buscar_usuarios -------------#
#######################################

@main.route('/buscar_usuarios', methods=['GET'])
def buscar_usuarios():
    q = request.args.get('q', '')
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id_usuario, nombre_completo, identificacion, username
            FROM usuarios
            WHERE nombre_completo ILIKE %s OR identificacion ILIKE %s
            LIMIT 10
        """, (f'%{q}%', f'%{q}%'))
        usuarios = cursor.fetchall()
    except Exception as e:
        print(f"Error en buscar_usuarios: {e}")
        return jsonify([]), 500
    finally:
        cursor.close()

    results = []
    for u in usuarios:
        results.append({
            'id': u[0],
            'label': f"{u[1]} - {u[2]}",
            'nombre': u[1],
            'identificacion': u[2],
            'username': u[3]
        })
        print(u)

    return jsonify(results)

#######################################
#-------------- RUTA /check_availability -------------#
#######################################

@main.route('/check_availability')
def check_availability():
    """Verifica si un valor para un campo específico ya existe en la base de datos."""
    field = request.args.get('field')
    value = request.args.get('value', '').strip()

    if not field or not value:
        return jsonify({'available': False, 'message': 'Campo o valor no proporcionado.'}), 400

    # Normalizar el valor como se hace en el registro
    if field == 'correo':
        value = value.lower()
    elif field == 'identificacion':
        value = value.upper()

    allowed_fields = ['username', 'correo', 'identificacion']
    if field not in allowed_fields:
        return jsonify({'available': False, 'message': 'Campo no válido.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    # La construcción de la consulta es segura porque 'field' está validado contra una lista permitida.
    cursor.execute(f"SELECT 1 FROM usuarios WHERE {field} = %s", (value,))
    exists = cursor.fetchone()
    cursor.close()

    return jsonify({'available': not exists})


#######################################
#-------------- RUTA /registrar_estudiante -------------#
#######################################
@main.route('/registrar_estudiante', methods=['GET', 'POST'])
@rol_required(1)
def registrar_estudiante():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        nombre_completo = request.form['nombre_completo'].upper()
        documento = request.form['documento'].upper()
        id_usuario = request.form['id_usuario']
        id_curso = request.form['curso']

        # Obtener grado del curso seleccionado
        cursor.execute("SELECT grado FROM cursos WHERE id_curso = %s", (id_curso,))
        grado_result = cursor.fetchone()
        if grado_result: # Check if grado_result is not None
            grado = grado_result[0]
        else:
            flash('Curso no válido', 'error')
            cursor.close()
            return redirect(url_for('main.registrar_estudiante'))

        # Verificar si el usuario es un profesor
        cursor.execute("SELECT id_rol FROM usuarios WHERE id_usuario = %s", (id_usuario,))
        user_role_result = cursor.fetchone()
        if user_role_result and user_role_result[0] == 2: # Asumiendo que el rol de profesor es 2
            flash('Un usuario con rol de profesor no puede ser registrado como estudiante.', 'danger')
            cursor.close()
            return redirect(url_for('main.registrar_estudiante'))

        # Verificar si el documento ya está registrado en la tabla de estudiantes
        cursor.execute("SELECT 1 FROM estudiantes WHERE documento = %s", (documento,))
        documento_existente = cursor.fetchone()
        if documento_existente:
            flash('El documento de identificación ya está registrado para otro estudiante.', 'danger')
            cursor.close()
            return redirect(url_for('main.registrar_estudiante'))

        id_estudiante = None
        # Verificar si el usuario ya está registrado como estudiante
        cursor.execute("SELECT id_estudiante FROM estudiantes WHERE id_usuario = %s", (id_usuario,))
        estudiante_existente = cursor.fetchone()

        if estudiante_existente:
            id_estudiante = estudiante_existente[0]
            # Check if this existing student is already in this course
            cursor.execute("""
                SELECT 1 FROM estudiantes_cursos
                WHERE id_estudiante = %s AND id_curso = %s
            """, (id_estudiante, id_curso))
            if cursor.fetchone():
                flash('Este estudiante ya está asignado a este curso.', 'warning')
                conn.rollback() # Ensure no partial changes if any
                cursor.close()
                return redirect(url_for('main.registrar_estudiante'))
            else:
                flash('El usuario ya está registrado como estudiante. Asignando a un nuevo curso.', 'info')
        else:
            # Registrar nuevo estudiante y obtener ID con RETURNING
            cursor.execute("""
                INSERT INTO estudiantes (nombre, documento, grado, id_usuario) 
                VALUES (%s, %s, %s, %s)
                RETURNING id_estudiante
            """, (nombre_completo, documento, grado, id_usuario)) # 'grado' is part of the 'estudiantes' table schema
            id_estudiante = cursor.fetchone()[0]
            conn.commit() # Commit the student insertion
            flash('Nuevo estudiante registrado correctamente y asignado al curso.', 'success')

        # Relacionar estudiante con curso
        if id_estudiante: # Should always be true here
            cursor.execute("""
                INSERT INTO estudiantes_cursos (id_estudiante, id_curso)
                VALUES (%s, %s)
            """, (id_estudiante, id_curso))
            conn.commit() # Commit the course assignment
        else:
            flash('Error interno: No se pudo obtener el ID del estudiante.', 'danger')
            conn.rollback()

        cursor.close()
        return redirect(url_for('main.registrar_estudiante'))

    # Método GET: Obtener cursos con nombre del profesor
    cursor.execute("""
        SELECT c.id_curso, c.grado, p.nombre_completo
        FROM cursos c
        LEFT JOIN profesores p ON c.id_profesor = p.id_profesor
        ORDER BY c.grado
    """)
    cursos = cursor.fetchall()

    cursor.close()

    return render_template('estudiantes/registrar_estudiante.html', cursos=cursos)


#######################################
#-------------- RUTA /editar_estudiante -------------#
#######################################
@main.route('/editar_estudiante/<int:id>', methods=['GET', 'POST'])
@rol_required(1)
def editar_estudiante(id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    try:
        if request.method == 'POST':
            nombre = request.form['nombre'].upper()
            id_curso = request.form['id_curso']

            # Actualiza estudiante
            cursor.execute("""
                UPDATE estudiantes
                SET nombre = %s
                WHERE id_estudiante = %s
            """, (nombre, id))

            # Actualiza curso en la tabla intermedia (asumiendo un estudiante por curso)
            # Si un estudiante puede estar en varios cursos, la lógica debe cambiar.
            cursor.execute("""
                UPDATE estudiantes_cursos
                SET id_curso = %s
                WHERE id_estudiante = %s
            """, (id_curso, id))

            conn.commit()
            flash('Estudiante actualizado correctamente.', 'success')
            return redirect(url_for('main.estudiantes'))

        # GET: Traer datos actuales del estudiante y la lista de cursos
        cursor.execute("""
            SELECT e.id_estudiante, e.nombre, ec.id_curso
            FROM estudiantes e
            LEFT JOIN estudiantes_cursos ec ON e.id_estudiante = ec.id_estudiante
            WHERE e.id_estudiante = %s
        """, (id,))
        estudiante = cursor.fetchone()

        if not estudiante:
            flash('Estudiante no encontrado.', 'danger')
            return redirect(url_for('main.estudiantes'))

        cursor.execute("SELECT id_curso, grado FROM cursos ORDER BY grado")
        cursos = cursor.fetchall()

        return render_template('estudiantes/editar_estudiante.html', estudiante=estudiante, cursos=cursos)

    except Exception as e:
        conn.rollback()
        flash(f"Ocurrió un error: {e}", "danger")
        return redirect(url_for('main.estudiantes'))
    finally:
        cursor.close()


#######################################
#-------------- RUTA /eliminar_estudiante -------------#
#######################################
@main.route('/eliminar_estudiante/<int:id>', methods=['GET', 'POST'])
@rol_required(1)
def eliminar_estudiante(id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # 1. Eliminar registros de asistencia asociados al estudiante
        cursor.execute("DELETE FROM asistencias WHERE id_estudiante = %s", (id,))

        # 2. Eliminar las asociaciones del estudiante con cursos
        cursor.execute("DELETE FROM estudiantes_cursos WHERE id_estudiante = %s", (id,))

        # 3. Finalmente, eliminar el estudiante de la tabla principal
        cursor.execute("DELETE FROM estudiantes WHERE id_estudiante = %s", (id,))
        conn.commit()
        flash('Estudiante eliminado exitosamente.', 'success')
    except Exception as e:
        flash(f'Error al eliminar estudiante: {e}', 'danger')
    finally:
        cursor.close()
    return redirect(url_for('main.estudiantes'))

#######################################
#-------------- RUTA /reporte -------------#
#######################################

@main.route('/reporte')
@rol_required(1)
def reporte():
    # 1. Obtener y validar filtros desde la URL
    fecha_inicio = request.args.get('inicio')
    fecha_fin = request.args.get('fin')
    id_curso_filtro = request.args.get('id_curso', type=int)
    id_profesor_filtro = request.args.get('id_profesor', type=int)
    id_asignatura_filtro = request.args.get('id_asignatura', type=int)
    id_estudiante_filtro = request.args.get('id_estudiante', type=int) # NUEVO

    page = request.args.get('page', 1, type=int)
    per_page = 15
    offset = (page - 1) * per_page

    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    try:
        # 2. Obtener datos para los menús desplegables de filtros
        cursor.execute("SELECT id_curso, grado FROM cursos ORDER BY grado")
        cursos = cursor.fetchall()
        cursor.execute("SELECT id_profesor, nombre_completo FROM profesores ORDER BY nombre_completo")
        profesores = cursor.fetchall()
        cursor.execute("SELECT id_asignatura, tema FROM asignatura ORDER BY tema")
        asignaturas = cursor.fetchall()
        cursor.execute("SELECT id_estudiante, nombre FROM estudiantes ORDER BY nombre") # NUEVO
        todos_estudiantes = cursor.fetchall() # NUEVO

        filtros_activos = {
            'inicio': fecha_inicio, 'fin': fecha_fin,
            'id_curso': id_curso_filtro, 'id_profesor': id_profesor_filtro,
            'id_asignatura': id_asignatura_filtro, 'id_estudiante': id_estudiante_filtro # NUEVO
        }

        if id_estudiante_filtro:
            # VISTA DE DETALLE PARA UN ESTUDIANTE
            cursor.execute("SELECT nombre FROM estudiantes WHERE id_estudiante = %s", (id_estudiante_filtro,))
            estudiante_seleccionado = cursor.fetchone()

            count_query = "SELECT COUNT(a.id_asistencia) FROM asistencias a JOIN horarios h ON a.id_horario = h.id_horario JOIN asignatura s ON CAST(h.asignatura AS integer) = s.id_asignatura JOIN profesores p ON h.id_profesor = p.id_profesor"
            query = """
                SELECT a.fecha, a.estado, a.observaciones, s.tema AS asignatura, p.nombre_completo AS profesor, h.hora_inicio, h.hora_fin 
                FROM asistencias a
                JOIN horarios h ON a.id_horario = h.id_horario
                JOIN asignatura s ON CAST(h.asignatura AS integer) = s.id_asignatura
                JOIN profesores p ON h.id_profesor = p.id_profesor
            """
            
            conditions = ["a.id_estudiante = %s"]
            params = [id_estudiante_filtro]

            if fecha_inicio: conditions.append("a.fecha >= %s"); params.append(fecha_inicio)
            if fecha_fin: conditions.append("a.fecha <= %s"); params.append(fecha_fin)
            if id_asignatura_filtro: conditions.append("s.id_asignatura = %s"); params.append(id_asignatura_filtro)
            if id_curso_filtro: conditions.append("a.id_curso = %s"); params.append(id_curso_filtro)
            if id_profesor_filtro: conditions.append("p.id_profesor = %s"); params.append(id_profesor_filtro)

            where_clause = " WHERE " + " AND ".join(conditions)
            cursor.execute(count_query + where_clause, tuple(params)) 
            total_items = cursor.fetchone()[0] # Acceder al primer elemento de la tupla
            total_pages = (total_items + per_page - 1) // per_page

            query += where_clause + f" ORDER BY a.fecha DESC, h.hora_inicio DESC LIMIT {per_page} OFFSET {offset}"
            cursor.execute(query, tuple(params))
            asistencias_detalle = cursor.fetchall()

            return render_template('reportes/reporte.html', 
                                   vista_detalle=True,
                                   asistencias_detalle=asistencias_detalle,
                                   estudiante_seleccionado=estudiante_seleccionado,
                                   cursos=cursos, profesores=profesores, asignaturas=asignaturas, todos_estudiantes=todos_estudiantes,
                                   page=page, total_pages=total_pages, filtros_activos=filtros_activos)
        else:
            # VISTA DE RESUMEN GENERAL
            base_query = """
                FROM estudiantes e
                JOIN estudiantes_cursos ec ON e.id_estudiante = ec.id_estudiante
                JOIN cursos c ON ec.id_curso = c.id_curso
                LEFT JOIN asistencias a ON e.id_estudiante = a.id_estudiante AND a.id_curso = c.id_curso
            """
            join_clause = ""
            conditions = []
            params = []

            if id_profesor_filtro:
                # Se une horarios solo si es necesario filtrar por profesor o asignatura
                join_clause += " LEFT JOIN horarios h ON a.id_horario = h.id_horario "
                conditions.append("h.id_profesor = %s")
                params.append(id_profesor_filtro)
            
            if id_curso_filtro:
                conditions.append("c.id_curso = %s")
                params.append(id_curso_filtro)
            if fecha_inicio:
                conditions.append("a.fecha >= %s")
                params.append(fecha_inicio)
            if fecha_fin:
                conditions.append("a.fecha <= %s")
                params.append(fecha_fin)

            where_clause = ""
            if conditions:
                where_clause = " WHERE " + " AND ".join(conditions)

            count_query = "SELECT COUNT(DISTINCT e.id_estudiante) " + base_query + join_clause + where_clause 
            cursor.execute(count_query, tuple(params)) 
            total_items = cursor.fetchone()[0] # Acceder al primer elemento de la tupla
            total_pages = (total_items + per_page - 1) // per_page

            select_clause = """
                SELECT
                    e.id_estudiante, e.nombre, c.grado,
                    COUNT(a.id_asistencia) FILTER (WHERE a.estado = 'Presente') AS presentes,
                    COUNT(a.id_asistencia) FILTER (WHERE a.estado = 'Ausente') AS ausentes,
                    COUNT(a.id_asistencia) FILTER (WHERE a.estado = 'Tarde') AS tardes,
                    COUNT(a.id_asistencia) FILTER (WHERE a.estado = 'Justificado') AS justificados,
                    COUNT(a.id_asistencia) AS clases_registradas
            """
            group_by_clause = " GROUP BY e.id_estudiante, e.nombre, c.grado ORDER BY c.grado, e.nombre"
            limit_offset_clause = f" LIMIT {per_page} OFFSET {offset}"

            full_query = select_clause + base_query + join_clause + where_clause + group_by_clause + limit_offset_clause
            cursor.execute(full_query, tuple(params))
            reporte_resumen = cursor.fetchall()

            return render_template('reportes/reporte.html', 
                                   vista_detalle=False,
                                   reporte_resumen=reporte_resumen,
                                   cursos=cursos, profesores=profesores, asignaturas=asignaturas, todos_estudiantes=todos_estudiantes,
                                   page=page, total_pages=total_pages, filtros_activos=filtros_activos)
    finally:
        cursor.close()



#######################################
#-------------- RUTA /recuperar -------------#
#######################################
@main.route('/recuperar', methods=['GET', 'POST'])
def recuperar():
    if request.method == 'POST':
        email = request.form.get('correo', '').strip()
        username = request.form.get('username', '').strip()

        if not email and not username:
            flash('Debes ingresar el correo o el nombre de usuario.', 'warning')
            return redirect(url_for('main.recuperar'))

        conn = get_db()
        cursor = conn.cursor()
        try:
            if email and username:
                cursor.execute("""
                    SELECT id_usuario, correo, username FROM usuarios
                    WHERE correo = %s OR username = %s
                """, (email, username))
            else:
                cursor.execute("SELECT id_usuario, correo, username FROM usuarios WHERE correo = %s", (email,))

            user = cursor.fetchone()

            if user:
                user_id, user_email, user_username = user
                serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
                token = serializer.dumps({'email': user_email, 'username': user_username}, salt=current_app.config['SECURITY_PASSWORD_SALT'])

                cursor.execute("INSERT INTO password_reset_tokens (user_id, token) VALUES (%s, %s)", (user_id, token))
                conn.commit()

                reset_url = url_for('main.reset_password', token=token, _external=True)
                send_email(user_email, reset_url)

                flash('Se ha enviado un correo con instrucciones para restablecer tu contraseña.', 'info')
            else:
                flash('No se encontró ningún usuario con ese correo o nombre de usuario.', 'warning')
        finally:
            cursor.close()

        return redirect(url_for('main.login'))

    return render_template('recuperar/recuperar.html')



#######################################
#-------------- RUTA /reset_password -------------#
#######################################
@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Verificar si el token existe y no fue usado
    cursor.execute("SELECT id, used FROM password_reset_tokens WHERE token = %s", (token,))
    token_data = cursor.fetchone()
    if not token_data:
        flash('El enlace es inválido o ha expirado.', 'danger')
        cursor.close()
        return redirect(url_for('main.recuperar'))
    
    token_id, used = token_data
    
    if used:
        flash('Este enlace ya fue utilizado.', 'warning')
        cursor.close()
        return redirect(url_for('main.login'))

    try:
        data = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
        email = data['email']
        username = data['username']
    except Exception:
        flash('El enlace es inválido o ha expirado.', 'danger')
        cursor.close()
        return redirect(url_for('main.recuperar'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Las contraseñas no coinciden.', 'warning')
            return redirect(request.url)

        hashed_password = generate_password_hash(password)
        cursor.execute("UPDATE usuarios SET password = %s WHERE correo = %s AND username = %s", (hashed_password, email, username))
        # Marcar token como usado
        cursor.execute("UPDATE password_reset_tokens SET used = TRUE WHERE id = %s", (token_id,))
        conn.commit()
        cursor.close()

        flash('Tu contraseña ha sido actualizada correctamente.', 'success')
        return redirect(url_for('main.login'))

    cursor.close()
    return render_template('recuperar/reset_password.html')

#######################################
#-------------- RUTA /buscar_usuario -------------#
#######################################
@main.route('/buscar_usuario')
def buscar_usuario():
    termino = request.args.get('q', '')
    cursor = get_db().cursor()
    cursor.execute("SELECT id_usuario, username FROM usuarios WHERE username ILIKE %s LIMIT 10", (f'%{termino}%',))
    resultados = cursor.fetchall()
    cursor.close()

    sugerencias = [{'id': r[0], 'text': r[1]} for r in resultados]
    return jsonify(sugerencias)

#######################################
#-------------- RUTA /verificar -------------#
#######################################

@main.route('/verificar', methods=['GET', 'POST'])
def verificar():
    if request.method == 'POST':
        codigo_ingresado = request.form['codigo']
        datos = session.get('registro_temporal')

        if not datos:
            flash('No hay datos de registro en proceso.', 'danger')
            return redirect(url_for('main.registro'))

        if datos['codigo'] != codigo_ingresado:
            flash('Código incorrecto. Intenta de nuevo.', 'warning')
            return redirect(url_for('main.verificar'))

        # Guardar el usuario en la base de datos
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO usuarios (username, password, correo, nombre_completo, identificacion, id_rol, fecha_registro, estado)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                datos['username'],
                datos['password'],
                datos['correo'],
                datos['nombre_completo'],
                datos['identificacion'],
                datos['id_rol'],
                datetime.now(),
                True
            ))
            conn.commit()
            flash('Usuario registrado exitosamente.', 'success')
            session.pop('registro_temporal', None)
        except Exception as e:
            flash(f'Error al registrar usuario: {e}', 'danger')
        finally:
            cursor.close()

        return redirect(url_for('main.login'))

    return render_template('auth/verificar.html')


#######################################
#-------------- RUTA /admin_registro -------------#
#######################################
@main.route('/admin_registro', methods=['GET', 'POST'])  # <-- Agrega methods aquí
@rol_required(1)
def admin_registro():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        correo = request.form['correo'].lower()
        nombre_completo = request.form['nombre_completo'].upper()
        identificacion = request.form['identificacion'].upper()
        id_rol = request.form['id_rol']

        if has_accents(username):
            flash('El nombre de usuario no puede contener tildes.', 'warning')
            cursor.close()
            return redirect(url_for('main.admin_registro'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM usuarios WHERE correo = %s OR identificacion = %s", (correo, identificacion))
        exists = cursor.fetchone()
        if exists:
            flash('El correo o la identificación ya están registrados.', 'warning')
            cursor.close()
            return redirect(url_for('main.admin_registro'))

        # Generar código de verificación
        codigo = random.randint(100000, 999999)

        # Guardar datos temporales en sesión
        session['registro_temporal'] = {
            'username': username,
            'password': generate_password_hash(password),
            'correo': correo,
            'nombre_completo': nombre_completo,
            'identificacion': identificacion,
            'id_rol': id_rol,
            'codigo': str(codigo)
        }

        # Enviar el correo
        try:
            if not send_verification_email(correo, codigo):
                return redirect(url_for('main.admin_registro'))
        except Exception as e:
            flash(f'Error al enviar el correo: {e}', 'danger')
            return redirect(url_for('main.admin_registro'))

        return redirect(url_for('main.verificar'))

    return render_template('auth/admin_registro.html')

#######################################
#-------------- RUTA /usuarios -------------#
#######################################

@main.route('/usuarios')
@rol_required(1)
def listar_usuarios():
    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Obtener parámetros de filtro de la URL
    username_filter = request.args.get('username_filter', '').strip()
    nombre_completo_filter = request.args.get('nombre_completo_filter', '').strip()
    id_rol_filter = request.args.get('id_rol_filter', type=int)

    try:
        # Obtener todos los roles para el filtro
        cursor.execute("SELECT id_rol, nombre FROM roles ORDER BY nombre")
        roles = cursor.fetchall()

        query = """
            SELECT u.id_usuario, u.username, u.nombre_completo, u.correo, r.nombre AS nombre_rol, u.fecha_registro, u.estado
            FROM usuarios u
            JOIN roles r ON u.id_rol = r.id_rol
        """
        conditions = []
        params = []

        if username_filter:
            conditions.append("u.username ILIKE %s")
            params.append(f'%{username_filter}%')
        if nombre_completo_filter:
            conditions.append("u.nombre_completo ILIKE %s")
            params.append(f'%{nombre_completo_filter}%')
        if id_rol_filter:
            conditions.append("u.id_rol = %s")
            params.append(id_rol_filter)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY u.fecha_registro DESC"

        cursor.execute(query, tuple(params))
        usuarios = cursor.fetchall()
    except Exception as e:
        flash(f"Error al cargar los usuarios: {e}", "danger")
        usuarios = []
        roles = [] # Ensure roles is defined even on error
    finally:
        cursor.close()
    
    return render_template('usuarios/usuarios.html', usuarios=usuarios, roles=roles,
                           username_filter=username_filter, nombre_completo_filter=nombre_completo_filter,
                           id_rol_filter=id_rol_filter)

#######################################
#-------------- RUTA /usuarios/editar -------------#
#######################################

@main.route('/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@rol_required(1)
def editar_usuario(id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == 'POST':
        username = request.form['username']
        nombre_completo = request.form['nombre_completo'].upper()
        correo = request.form['correo'].lower()
        id_rol = request.form['id_rol']
        estado = 'estado' in request.form

        if has_accents(username):
            flash('El nombre de usuario no puede contener tildes.', 'warning')
            # No cerramos el cursor aquí para que el GET funcione
            return redirect(url_for('main.editar_usuario', id=id))

        try:
            cursor.execute("""
                UPDATE usuarios
                SET username = %s, nombre_completo = %s, correo = %s, id_rol = %s, estado = %s
                WHERE id_usuario = %s
            """, (username, nombre_completo, correo, id_rol, estado, id))
            conn.commit()
            flash('Usuario actualizado correctamente.', 'success')
            return redirect(url_for('main.listar_usuarios'))
        except Exception as e:
            conn.rollback()
            flash(f'Error al actualizar el usuario: {e}', 'danger')
        finally:
            cursor.close()

    # GET
    try:
        cursor.execute("SELECT * FROM usuarios WHERE id_usuario = %s", (id,))
        usuario = cursor.fetchone()
        cursor.execute("SELECT id_rol, nombre AS nombre_rol FROM roles ORDER BY id_rol")
        roles = cursor.fetchall()
        if not usuario:
            flash('Usuario no encontrado.', 'danger')
            return redirect(url_for('main.listar_usuarios'))
        return render_template('usuarios/editar_usuario.html', usuario=usuario, roles=roles)
    finally:
        cursor.close()

#######################################
#-------------- RUTA /usuarios/cambiar_estado -------------#
#######################################

@main.route('/usuarios/cambiar_estado/<int:id>', methods=['POST'])
@rol_required(1)
def cambiar_estado_usuario(id):
    if id == session.get('user_id'):
        flash('No puedes cambiar tu propio estado.', 'danger')
        return redirect(url_for('main.listar_usuarios'))

    conn = get_db()
    cursor = conn.cursor()
    try:
        # Primero, obtenemos el estado actual
        cursor.execute("SELECT estado FROM usuarios WHERE id_usuario = %s", (id,))
        usuario = cursor.fetchone()

        if usuario:
            nuevo_estado = not usuario[0] # Invertimos el estado actual
            cursor.execute("UPDATE usuarios SET estado = %s WHERE id_usuario = %s", (nuevo_estado, id))
            conn.commit()
            flash(f'El estado del usuario ha sido cambiado a {"Activo" if nuevo_estado else "Inactivo (Baneado)"}.', 'success')
        else:
            flash('Usuario no encontrado.', 'danger')
    except Exception as e:
        conn.rollback()
        flash(f'Error al cambiar el estado del usuario: {e}', 'danger')
    finally:
        cursor.close()
    
    return redirect(url_for('main.listar_usuarios'))

#######################################
#-------------- RUTA /usuarios/eliminar -------------#
#######################################

@main.route('/usuarios/eliminar/<int:id>', methods=['POST'])
@rol_required(1)
def eliminar_usuario(id):
    # ¡CUIDADO! Eliminar un usuario puede causar problemas de integridad de datos.
    # Una mejor práctica es desactivarlo. Esta función es para casos extremos.
    if id == session.get('user_id'):
        flash('No puedes eliminar tu propia cuenta.', 'danger')
        return redirect(url_for('main.listar_usuarios'))

    conn = get_db()
    cursor = conn.cursor()
    try:
        # Primero, eliminar referencias en otras tablas (profesores, estudiantes, etc.)
        cursor.execute("DELETE FROM profesores WHERE id_usuario = %s", (id,))
        cursor.execute("DELETE FROM estudiantes WHERE id_usuario = %s", (id,))
        cursor.execute("DELETE FROM password_reset_tokens WHERE user_id = %s", (id,))
        
        # Finalmente, eliminar el usuario
        cursor.execute("DELETE FROM usuarios WHERE id_usuario = %s", (id,))
        conn.commit()
        flash('Usuario eliminado permanentemente.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al eliminar el usuario: {e}. Es posible que tenga datos asociados.', 'danger')
    finally:
        cursor.close()
    return redirect(url_for('main.listar_usuarios'))


#######################################
#-------------- RUTA /asignatura -------------#
#######################################
@main.route('/asignatura')
@rol_required(1)
def asignatura():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            a.id_asignatura,
            a.tema,
            c.grado, 
            STRING_AGG(p.nombre_completo, ', ') AS profesores
        FROM asignatura a
        JOIN cursos c ON a.id_curso = c.id_curso
        LEFT JOIN asignatura_profesores ap ON a.id_asignatura = ap.id_asignatura
        LEFT JOIN profesores p ON ap.id_profesor = p.id_profesor
        GROUP BY a.id_asignatura, a.tema, c.grado
        ORDER BY c.grado, a.tema;
    """)
    asignaturas = cursor.fetchall()

    cursor.close()

    return render_template("asignatura/asignatura.html", asignaturas=asignaturas)


#######################################
#-------------- RUTA /asignatura/registrar -------------#
#######################################
@main.route('/asignatura/registrar', methods=['GET', 'POST'])
@rol_required(1)
def registrar_asignatura():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id_profesor, nombre_completo FROM profesores")
    profesores = cursor.fetchall()

    cursor.execute("SELECT id_curso, grado FROM cursos")
    cursos = cursor.fetchall()

    if request.method == 'POST':
        id_profesores = request.form.getlist('id_profesores')
        id_curso = request.form['id_curso']
        tema = request.form['tema'].upper()

        if not id_profesores or not id_curso or not tema:
            flash('Debes agregar al menos un profesor.', 'danger')
            return render_template('asignatura/registrar_asignatura.html',
                                   profesores=profesores, 
                                   cursos=cursos,
                                   tema_previo=tema,
                                   id_curso_previo=int(id_curso) if id_curso else None
                                   )
        else:
            try:
                # Insertar la asignatura y obtener su ID
                cursor.execute("""
                    INSERT INTO asignatura (id_curso, tema)
                    VALUES (%s, %s) RETURNING id_asignatura
                """, (id_curso, tema))
                id_asignatura = cursor.fetchone()[0]

                # Insertar las relaciones en la tabla asignatura_profesores
                for id_profesor in id_profesores:
                    cursor.execute("INSERT INTO asignatura_profesores (id_asignatura, id_profesor) VALUES (%s, %s)", (id_asignatura, id_profesor))
                
                conn.commit()
                flash('Asignatura registrada exitosamente con sus profesores.', 'success')
                return redirect(url_for('main.asignatura'))
            except Exception as e:
                conn.rollback()
                flash(f'Error al registrar la asignatura: {e}', 'danger')

    cursor.close()

    return render_template(
        'asignatura/registrar_asignatura.html',
        profesores=profesores,
        cursos=cursos,
        tema_previo=None,
        id_curso_previo=None
    )



#######################################
#-------------- RUTA /asignatura/editar -------------#
#######################################
@main.route('/asignatura/editar/<int:id>', methods=['GET', 'POST'])
@rol_required(1)
def editar_asignatura(id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == 'POST':
        tema = request.form['tema'].upper()
        id_curso = request.form['id_curso']
        id_profesores_nuevos = request.form.getlist('id_profesores')

        if not id_profesores_nuevos:
            flash('Una asignatura debe tener al menos un profesor.', 'danger')
            return redirect(request.url)

        try:
            # 1. Actualizar datos básicos de la asignatura
            cursor.execute("""
                UPDATE asignatura SET tema = %s, id_curso = %s WHERE id_asignatura = %s
            """, (tema, id_curso, id))

            # 2. Obtener profesores actuales
            cursor.execute("SELECT id_profesor FROM asignatura_profesores WHERE id_asignatura = %s", (id,))
            id_profesores_actuales = {row['id_profesor'] for row in cursor.fetchall()}

            # Convertir a set para facilitar la comparación
            id_profesores_nuevos_set = {int(p_id) for p_id in id_profesores_nuevos}

            # 3. Determinar qué profesores añadir y cuáles quitar
            profesores_a_anadir = id_profesores_nuevos_set - id_profesores_actuales
            profesores_a_quitar = id_profesores_actuales - id_profesores_nuevos_set

            # 4. Añadir nuevas relaciones
            if profesores_a_anadir:
                args_str = ','.join(cursor.mogrify("(%s,%s)", (id, p_id)).decode('utf-8') for p_id in profesores_a_anadir)
                cursor.execute("INSERT INTO asignatura_profesores (id_asignatura, id_profesor) VALUES " + args_str)

            # 5. Quitar relaciones antiguas
            if profesores_a_quitar:
                cursor.execute("DELETE FROM asignatura_profesores WHERE id_asignatura = %s AND id_profesor = ANY(%s)", (id, list(profesores_a_quitar)))

            conn.commit()
            flash('Asignatura actualizada correctamente.', 'success')
            return redirect(url_for('main.asignatura'))
        except Exception as e:
            conn.rollback()
            flash(f'Error al actualizar la asignatura: {e}', 'danger')

    # GET
    cursor.execute("SELECT * FROM asignatura WHERE id_asignatura = %s", (id,))
    asignatura = cursor.fetchone()

    if not asignatura:
        flash('Asignatura no encontrada.', 'danger')
        return redirect(url_for('main.asignatura'))

    # Obtener profesores ya asociados a esta asignatura
    cursor.execute("""
        SELECT p.id_profesor, p.nombre_completo
        FROM profesores p
        JOIN asignatura_profesores ap ON p.id_profesor = ap.id_profesor
        WHERE ap.id_asignatura = %s
    """, (id,))
    profesores_asignados = cursor.fetchall()

    cursor.execute("SELECT id_curso, grado FROM cursos ORDER BY grado")
    cursos = cursor.fetchall()

    cursor.close()

    return render_template('asignatura/editar_asignatura.html',
                           asignatura=asignatura,
                           cursos=cursos,
                           profesores_asignados=profesores_asignados)


#######################################
#-------------- RUTA /asignatura/eliminar -------------#
#######################################
@main.route('/asignatura/eliminar/<int:id>', methods=['POST'])
@rol_required(1)
def eliminar_asignatura(id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # La eliminación en cascada (ON DELETE CASCADE) se encargará de asignatura_profesores
        cursor.execute("DELETE FROM asignatura WHERE id_asignatura = %s", (id,))
        conn.commit()
        flash('Asignatura eliminada correctamente.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al eliminar la asignatura: {e}', 'danger')
    finally:
        cursor.close()

    return redirect(url_for('main.asignatura'))


#######################################
#-------------- RUTA /horario -------------#
#######################################
@main.route('/horario')
@rol_required(1)
def horario():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    id_profesor_filtro = request.args.get('id_profesor', type=int)

    try:
        # Obtener profesores para el filtro
        cur.execute("SELECT id_profesor, nombre_completo FROM profesores ORDER BY nombre_completo")
        profesores = cur.fetchall()

        # Construir la consulta base
        query = """
            SELECT 
                h.id_horario, 
                c.grado AS curso,
                p.nombre_completo AS profesor,
                h.dia_semana, 
                h.hora_inicio, 
                h.hora_fin, 
                a.tema AS asignatura
            FROM horarios h
            JOIN cursos c ON h.id_curso = c.id_curso
            JOIN profesores p ON h.id_profesor = p.id_profesor
            JOIN asignatura a ON CAST(h.asignatura AS integer) = a.id_asignatura
        """
        params = []
        if id_profesor_filtro:
            query += " WHERE h.id_profesor = %s"
            params.append(id_profesor_filtro)
        
        query += " ORDER BY h.hora_inicio, h.dia_semana;"

        cur.execute(query, tuple(params))
        horarios_db = cur.fetchall()

        # Procesar en una estructura de tabla: {hora: {dia: clase}}
        horario_tabla = {}
        dias_semana = ["Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado"]

        for item in horarios_db:
            # Usar el rango horario como clave para la fila
            rango_horario_str = f"{item['hora_inicio'].strftime('%I:%M %p')} - {item['hora_fin'].strftime('%I:%M %p')}"
            if rango_horario_str not in horario_tabla:
                horario_tabla[rango_horario_str] = {dia: None for dia in dias_semana}
            
            # Capitalizar día para que coincida con la lista
            dia_item = item['dia_semana'].capitalize()
            if dia_item in dias_semana:
                horario_tabla[rango_horario_str][dia_item] = item

        # --- INICIO: Ordenar el horario por hora de inicio ---
        # Convertir el diccionario a una lista de tuplas (hora_inicio_obj, rango_str, datos_dia)
        horario_ordenado_temp = []
        for rango_str, datos_dia in horario_tabla.items():
            # Extraer la hora de inicio del string para poder ordenar
            hora_inicio_obj = datetime.strptime(rango_str.split(' - ')[0], '%I:%M %p').time()
            horario_ordenado_temp.append((hora_inicio_obj, rango_str, datos_dia))
        
        # Ordenar la lista basándose en el objeto de tiempo de la hora de inicio
        horario_ordenado_temp.sort(key=lambda x: x[0])
        # --- FIN: Ordenar el horario ---

    except Exception as e:
        flash(f"Error al cargar los horarios: {e}", "danger")
        horario_ordenado_temp, profesores = [], []
    finally:
        cur.close()

    return render_template('horario/horario.html', horario_ordenado=horario_ordenado_temp, dias_semana=dias_semana,
                           profesores=profesores, id_profesor_filtro=id_profesor_filtro)



#######################################
#-------------- RUTA /editar_horario -------------#
#######################################
@main.route('/editar_horario/<int:id>', methods=['GET', 'POST'])
@rol_required(1)
def editar_horario(id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    try:
        if request.method == 'POST':
            dia = request.form['dia']
            hora_inicio = request.form['hora_inicio']
            hora_fin = request.form['hora_fin']
            id_profesor = request.form['id_profesor']
            id_curso = request.form['id_curso']
            id_asignatura = request.form['id_asignatura']

            cur.execute("""
                UPDATE horarios 
                SET id_curso = %s, id_profesor = %s, dia_semana = %s, hora_inicio = %s, hora_fin = %s, asignatura = %s
                WHERE id_horario = %s
            """, (id_curso, id_profesor, dia, hora_inicio, hora_fin, id_asignatura, id))

            conn.commit()
            flash("Horario actualizado con éxito", "success")
            return redirect(url_for('main.horario'))

        # GET: Obtener datos para el formulario
        cur.execute("SELECT id_curso, grado FROM cursos ORDER BY grado")
        cursos = cur.fetchall()
        cur.execute("SELECT id_profesor, nombre_completo FROM profesores ORDER BY nombre_completo")
        profesores = cur.fetchall()
        cur.execute("SELECT id_asignatura, tema FROM asignatura ORDER BY tema")
        asignaturas = cur.fetchall()

        # Obtener datos del horario actual
        cur.execute("SELECT * FROM horarios WHERE id_horario = %s", (id,))
        horario = cur.fetchone()

        if not horario:
            flash("Horario no encontrado.", "danger")
            return redirect(url_for('main.horario'))
        
        return render_template('horario/editar_horario.html', horario=horario, cursos=cursos, profesores=profesores, asignaturas=asignaturas)

    except Exception as e:
        conn.rollback()
        flash(f"Ocurrió un error: {str(e)}", "danger")
        return redirect(url_for('main.asignatura'))
    finally:
        cur.close()


#######################################
#-------------- RUTA /eliminar_horario -------------#
#######################################
@main.route('/eliminar_horario/<int:id>', methods=['POST', 'GET'])
@rol_required(1)
def eliminar_horario(id):
    try:
        conn = get_db()
        cur = conn.cursor()

        # Eliminar el horario
        cur.execute("DELETE FROM horarios WHERE id_horario = %s", (id,))
        conn.commit()

        flash("Horario eliminado con éxito", "success")
    except Exception as e:
        flash(f"No se pudo eliminar el horario: {str(e)}", "danger")
    finally:
        cur.close()

    return redirect(url_for('main.horario'))



#######################################
#-------------- RUTA /registrar_horario -------------#
#######################################
@main.route('/registrar_horario', methods=['GET', 'POST'])
@rol_required(1)
def registrar_horario():
    conn = get_db()
    cur = conn.cursor()

    if request.method == 'POST':
        dia = request.form['dia']
        hora_inicio = request.form['hora_inicio']
        hora_fin = request.form['hora_fin']
        id_profesor = request.form['id_profesor']
        id_curso = request.form['id_curso']
        asignatura = request.form['id_asignatura'].upper()

        try:
            cur.execute("""
                INSERT INTO horarios (id_curso, id_profesor, dia_semana, hora_inicio, hora_fin, asignatura)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (id_curso, id_profesor, dia, hora_inicio, hora_fin, asignatura))

            conn.commit()
            flash("Horario registrado con éxito", "success")
            return redirect(url_for('main.horario'))
        except Exception as e:
            conn.rollback()  # 👈 Esto limpia la transacción fallida
            flash(f"Error al registrar horario: {str(e)}", "danger")

    # Consultas separadas después del rollback
    try:
        cur.execute("SELECT id_curso, grado FROM cursos")
        cursos = cur.fetchall()

        cur.execute("SELECT id_profesor, nombre_completo FROM profesores ORDER BY nombre_completo")
        profesores = cur.fetchall()

        cur.execute("SELECT id_asignatura, tema FROM asignatura")
        asignaturas = cur.fetchall()
    except Exception as e:
        flash(f"Error al obtener datos: {str(e)}", "danger")
        cursos, profesores, asignaturas = [], [], []

    cur.close()

    return render_template('horario/registrar_horario.html',
                           cursos=cursos, profesores=profesores, asignaturas=asignaturas)



#######################################
#-------------- RUTA /editar_perfil -------------#
#######################################
@main.route('/editar_perfil', methods=['GET', 'POST'])
@login_required
def editar_perfil():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a esta página.', 'warning')
        return redirect(url_for('main.login'))

    user_id = session['user_id']

    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        nuevo_username = request.form['username']
        nueva_password = request.form['password']
        confirmar_password = request.form['confirm_password']

        if has_accents(nuevo_username):
            flash('El nombre de usuario no puede contener tildes.', 'warning')
            cursor.close()
            return redirect(url_for('main.editar_perfil'))

        if nueva_password != confirmar_password:
            flash('Las contraseñas no coinciden.', 'warning')
            return redirect(url_for('main.editar_perfil'))

        hashed_password = generate_password_hash(nueva_password)

        # Actualizar datos
        cursor.execute("""
            UPDATE usuarios
            SET username = %s, password = %s
            WHERE id_usuario = %s
        """, (nuevo_username, hashed_password, user_id))
        conn.commit()

        flash('Tu perfil ha sido actualizado correctamente.', 'success')
        cursor.close()
        return redirect(url_for('main.admin_dashboard'))  # Ajusta según tu app

    # Método GET: cargar datos actuales del usuario
    cursor.execute("SELECT username FROM usuarios WHERE id_usuario = %s", (user_id,))
    user_data = cursor.fetchone()
    cursor.close()

    if user_data:
        username_actual = user_data[0]
    else:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('main.login'))

    return render_template('recuperar/editar_perfil.html', username=username_actual)



#######################################
#-------------- RUTA /asistencias -------------#
#######################################
@main.route("/asistencias")
@rol_required(1, 2) # Admin y Profesor
def asistencias():
    # 1. Obtener filtros de la URL
    fecha_str = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    id_curso_filtro = request.args.get('id_curso', type=int)
    page = request.args.get('page', 1, type=int)
    per_page = 5 # Número de clases por página
    offset = (page - 1) * per_page

    try:
        fecha_obj = datetime.strptime(fecha_str, '%Y-%m-%d')
    except (ValueError, TypeError):
        fecha_obj = datetime.now()
        fecha_str = fecha_obj.strftime('%Y-%m-%d')

    dias_semana = ["Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado", "Domingo"]
    dia_semana_str = dias_semana[fecha_obj.weekday()]

    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # 2. Obtener todos los cursos para el menú de filtro
        cur.execute("SELECT id_curso, grado FROM cursos ORDER BY grado")
        cursos_para_filtro = cur.fetchall()

        total_pages = 1
        vista_horarios = []
        # Solo proceder si se ha seleccionado un curso
        if id_curso_filtro:
            # 3. Contar el total de horarios para la paginación
            count_query = """
                SELECT COUNT(DISTINCT h.id_horario)
                FROM horarios h
                LEFT JOIN asistencias a ON h.id_horario = a.id_horario
                WHERE h.id_curso = %s AND (LOWER(h.dia_semana) = LOWER(%s) OR a.fecha = %s)
            """
            cur.execute(count_query, (id_curso_filtro, dia_semana_str, fecha_obj.date()))
            total_items = cur.fetchone()[0]
            total_pages = (total_items + per_page - 1) // per_page

            # 4. Obtener los horarios para la página actual
            cur.execute("""
                SELECT DISTINCT h.id_horario, h.hora_inicio, h.hora_fin, 
                                p.nombre_completo AS profesor, s.tema AS asignatura
                FROM horarios h
                JOIN profesores p ON h.id_profesor = p.id_profesor
                LEFT JOIN asignatura s ON CAST(h.asignatura AS integer) = s.id_asignatura
                LEFT JOIN asistencias a ON h.id_horario = a.id_horario
                WHERE
                    h.id_curso = %s AND
                    (LOWER(h.dia_semana) = LOWER(%s) OR a.fecha = %s)
                ORDER BY h.hora_inicio
                LIMIT %s OFFSET %s;
            """, (id_curso_filtro, dia_semana_str, fecha_obj.date(), per_page, offset))
            horarios_del_dia = cur.fetchall()

            # 5. Para cada horario de la página actual, obtener los estudiantes
            for horario in horarios_del_dia:
                cur.execute("""
                    SELECT 
                        e.id_estudiante,
                        e.nombre,
                        a.estado, a.id_asistencia
                    FROM estudiantes e
                    JOIN estudiantes_cursos ec ON e.id_estudiante = ec.id_estudiante
                    LEFT JOIN asistencias a ON e.id_estudiante = a.id_estudiante
                        AND a.id_horario = %s AND a.fecha = %s
                    WHERE ec.id_curso = %s
                    ORDER BY e.nombre;
                """, (horario['id_horario'], fecha_obj.date(), id_curso_filtro))
                
                estudiantes_con_asistencia = cur.fetchall()
                
                vista_horarios.append({
                    'horario': horario,
                    'estudiantes': estudiantes_con_asistencia
                })
    except Exception as e:
        flash(f"Error al cargar las asistencias: {e}", "danger")
        vista_horarios, cursos_para_filtro = [], []
    finally:
        pass # La conexión se cierra automáticamente con teardown_app_request

    return render_template("asistencias/asistencia.html",
                           vista_horarios=vista_horarios,
                           cursos_filtro=cursos_para_filtro,
                           fecha_seleccionada=fecha_str,
                           id_curso_seleccionado=id_curso_filtro,
                           page=page,
                           total_pages=total_pages)


#######################################
#-------------- RUTA /asistencias/registrar -------------#
#######################################
@main.route("/asistencias/registrar", methods=["GET", "POST"])
@rol_required(1, 2) # Admin y Profesor
def registrar_asistencia():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == "POST":
        id_horario = request.form.get("id_horario")
        id_curso = request.form.get("id_curso")
        id_profesor = request.form.get("id_profesor_real")
        fecha = request.form.get("fecha")
        estudiantes = request.form.getlist("estudiantes[]")

        if not id_profesor:
            flash("Debe seleccionar un profesor válido.", "danger")
            return redirect(url_for("main.registrar_asistencia"))

        cur.execute("""
            SELECT hora_inicio, hora_fin, dia_semana
            FROM horarios
            WHERE id_horario = %s AND id_curso = %s
        """, (id_horario, id_curso))
        horario = cur.fetchone()

        if not horario:
            flash("El horario seleccionado no es válido.", "danger")
            return redirect(url_for("main.registrar_asistencia"))

        hora_inicio, hora_fin, dia_semana = horario

        # --- INICIO: Validación de horario y día para profesores ---
        # Si el usuario es un profesor (rol 2), se aplican validaciones de tiempo y día.
        if session.get('user_role') == 2:
            fecha_obj = datetime.strptime(fecha, '%Y-%m-%d').date()
            dias_es = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]
            dia_semana_num_fecha = fecha_obj.weekday()

            # 1. Validar que el día de la semana coincida
            if dia_semana.lower() != dias_es[dia_semana_num_fecha]:
                flash(f"No puedes registrar asistencia para una clase de '{dia_semana}' en un {dias_es[dia_semana_num_fecha].capitalize()}.", "danger")
                return redirect(request.referrer or url_for("main.registrar_asistencia"))

            # 2. Validar que la hora actual esté dentro del rango del horario, SOLO si la fecha es hoy.
            if fecha_obj == datetime.now().date():
                hora_actual = datetime.now().time()
                if not (hora_inicio <= hora_actual <= hora_fin):
                    flash("Como profesor, solo puedes registrar asistencia para la fecha de hoy durante el horario de la clase.", "danger")
                    return redirect(url_for("main.registrar_asistencia"))

        try:
            for id_estudiante in estudiantes:
                estado = request.form.get(f"estado_{id_estudiante}")
                observaciones = request.form.get(f"observaciones_{id_estudiante}", "").upper()
                archivo = request.files.get(f"excusa_{id_estudiante}")
                excusa_data = archivo.read() if archivo and archivo.filename else None

                # Verificar duplicado
                cur.execute("""
                    SELECT 1 FROM asistencias
                    WHERE id_horario = %s AND id_curso = %s AND id_estudiante = %s AND fecha = %s
                """, (id_horario, id_curso, id_estudiante, fecha))

                if cur.fetchone():
                    flash(f"El estudiante {id_estudiante} ya tiene asistencia registrada en este horario y fecha.", "warning")
                    continue

                # Insertar asistencia
                cur.execute("""
                    INSERT INTO asistencias (id_horario, fecha, id_estudiante, estado, observaciones, id_profesor, excusa_archivo, id_curso)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (id_horario, fecha, id_estudiante, estado, observaciones, id_profesor, excusa_data, id_curso))

            conn.commit()
            flash("Asistencias registradas correctamente", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error al registrar asistencias: {str(e)}", "danger")
        finally:
            cur.close()

        return redirect(url_for("main.asistencias"))

    # GET
    profesor_autocompletado = None
    # Si el usuario es un profesor, obtenemos sus datos para autocompletar
    if session.get('user_role') == 2:
        user_id = session.get('user_id')
        try:
            cur.execute(""" 
                SELECT id_profesor, nombre_completo
                FROM profesores WHERE id_usuario = %s
            """, (user_id,))
            profesor_autocompletado = cur.fetchone()
        except Exception as e:
            flash(f"Error al obtener datos del profesor: {e}", "danger")

    cur.close()
    return render_template("asistencias/registrar_asistencias.html", profesor_autocompletado=profesor_autocompletado)



#######################################
#-------------- RUTA /get_horarios_cursos -------------#
#######################################
@main.route("/get_horarios_cursos/<int:id_profesor>")
@rol_required(1, 2) # Admin y Profesor
def get_horarios_cursos(id_profesor):
    cur = get_db().cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("""
            SELECT 
                h.id_horario, h.dia_semana, h.hora_inicio, h.hora_fin,
                c.id_curso, c.grado,
                COALESCE(a.tema, 'Asignatura no especificada') AS asignatura
            FROM horarios h
            JOIN cursos c ON h.id_curso = c.id_curso
            LEFT JOIN asignatura a ON CAST(h.asignatura AS integer) = a.id_asignatura
            WHERE h.id_profesor = %s
            ORDER BY h.hora_inicio, h.dia_semana
        """, (id_profesor,))
        
        # Convertir time objects a string para que sean serializables en JSON
        data = []
        for row in cur.fetchall():
            row_dict = dict(row)
            row_dict['hora_inicio'] = row_dict['hora_inicio'].strftime('%I:%M %p')
            row_dict['hora_fin'] = row_dict['hora_fin'].strftime('%I:%M %p')
            data.append(row_dict)

        return jsonify(data)
    finally:
        cur.close()


#######################################
#-------------- RUTA /asistencias/estudiantes -------------#
#######################################
@main.route("/asistencias/estudiantes/<int:id_curso>")
@rol_required(1, 2) # Admin y Profesor
def obtener_estudiantes(id_curso):
    cur = get_db().cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("""
            SELECT e.id_estudiante, e.nombre
            FROM estudiantes e
            JOIN estudiantes_cursos ec ON e.id_estudiante = ec.id_estudiante
            WHERE ec.id_curso = %s
            ORDER BY e.nombre
        """, (id_curso,))
        estudiantes = cur.fetchall()
        if not estudiantes:
            return jsonify({"error": "No hay estudiantes en este curso"}), 404
        
        # Convertir las filas del cursor (que son como diccionarios) a una lista de diccionarios reales
        estudiantes_list = [dict(row) for row in estudiantes]
        return jsonify(estudiantes_list)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()



#######################################
#-------------- RUTA /editar_asistencia -------------#
#######################################
@main.route('/editar_asistencia/<int:id>', methods=['GET', 'POST'])
@rol_required(1, 2) # Admin y Profesor
def editar_asistencia(id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Guardar los parámetros de la URL para la redirección
    fecha_filtro = request.args.get('fecha')
    id_curso_filtro = request.args.get('id_curso')

    cursor.execute("SELECT * FROM asistencias WHERE id_asistencia = %s", (id,))
    asistencia = cursor.fetchone()

    if not asistencia:
        flash('Asistencia no encontrada.', 'danger')
        return redirect(url_for('main.asistencias'))

    if request.method == 'POST':
        try:
            # --- INICIO: Validación de horario para profesores ---
            # Si el usuario es un profesor (rol 2), se verifica que esté dentro del horario de la clase.
            if session.get('user_role') == 2:
                cursor.execute("""
                    SELECT h.hora_inicio, h.hora_fin
                    FROM asistencias a
                    JOIN horarios h ON a.id_horario = h.id_horario
                    WHERE a.id_asistencia = %s
                """, (id,))
                horario = cursor.fetchone()
                if horario:
                    hora_actual = datetime.now().time()
                    if not (horario['hora_inicio'] <= hora_actual <= horario['hora_fin']):
                        flash("Como profesor, solo puedes editar la asistencia durante el horario de la clase.", "danger")
                        return redirect(url_for('main.asistencias', fecha=fecha_filtro, id_curso=id_curso_filtro))
            # --- FIN: Validación de horario para profesores ---
            estado = request.form['estado']
            observaciones = request.form['observaciones'].upper()
            cursor.execute("""
                UPDATE asistencias
                SET estado = %s, observaciones = %s
                WHERE id_asistencia = %s
            """, (estado, observaciones, id))
            conn.commit()
            flash('Asistencia actualizada correctamente.', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Error al actualizar la asistencia: {e}', 'danger')
        finally:
            cursor.close()

        return redirect(url_for('main.asistencias', fecha=fecha_filtro, id_curso=id_curso_filtro))

    cursor.close()
    return render_template('asistencias/editar_asistencia.html', asistencia=asistencia, fecha_filtro=fecha_filtro, id_curso_filtro=id_curso_filtro)

#######################################
#-------------- RUTA /buscar_profesores -------------#
#######################################
@main.route('/buscar_profesores', methods=['GET'])
@rol_required(1, 2) # Admin y Profesor
def buscar_profesores():
    q = request.args.get('q', '').strip()
    print(f"Buscar profesores con query: {q}")
    if len(q) < 2:
        print("Query muy corta")
        return jsonify([])

    try:
        cursor = get_db().cursor()
        sql = """ 
            SELECT id_profesor, nombre_completo, documento, especialidad, id_usuario
            FROM profesores
            WHERE nombre_completo ILIKE %s OR documento ILIKE %s
            LIMIT 10;
        """
        like_q = f'%{q}%'
        cursor.execute(sql, (like_q, like_q))
        profesores = cursor.fetchall()
        print(f"Profesores encontrados: {len(profesores)}")
    except Exception as e:
        print(f"Error en buscar_profesores: {e}")
        return jsonify([]), 500
    finally:
        cursor.close()

    results = []
    for p in profesores:
        results.append({
            'id': p[0],
            'label': f"{p[1]} - {p[2]}",
            'nombre_completo': p[1],
            'identificacion': p[2],
            'especialidad': p[3],
        })

    return jsonify(results)


#######################################
#-------------- RUTA /eliminar_asistencia_individual -------------#
#######################################
@main.route('/eliminar_asistencia_individual/<int:id>', methods=['POST'])
@rol_required(1, 2) # Admin y Profesor
def eliminar_asistencia_individual(id):
    fecha_filtro = request.form.get('fecha')
    id_curso_filtro = request.form.get('id_curso')
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM asistencias WHERE id_asistencia = %s", (id,))
        conn.commit()
        flash('Registro de asistencia eliminado correctamente.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al eliminar el registro: {e}', 'danger')
    finally:
        if 'conn' in locals() and conn is not None:
            cursor.close()
    
    return redirect(url_for('main.asistencias', fecha=fecha_filtro, id_curso=id_curso_filtro))


#######################################
#-------------- RUTA /eliminar_asistencia_horario -------------#
#######################################
@main.route('/eliminar_asistencia_horario', methods=['POST', 'GET'])
@rol_required(1, 2) # Admin y Profesor
def eliminar_asistencia_horario():
    id_horario = request.form.get('id_horario', type=int)
    id_curso = request.form.get('id_curso', type=int)
    fecha = request.form.get('fecha', type=str)

    if not all([id_horario, id_curso, fecha]):
        flash('Faltan datos para eliminar las asistencias.', 'danger')
        return redirect(request.referrer or url_for('main.asistencias'))

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM asistencias 
            WHERE id_horario = %s AND id_curso = %s AND fecha = %s
        """, (id_horario, id_curso, fecha))
        
        deleted_count = cursor.rowcount
        conn.commit()
        flash(f'Se eliminaron {deleted_count} registros de asistencia para esta clase.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al eliminar las asistencias: {e}', 'danger')
    finally:
        if 'conn' in locals() and conn is not None:
            cursor.close()

    return redirect(url_for('main.asistencias', fecha=fecha, id_curso=id_curso))


#######################################
#-------------- RUTA /mi_asistencia -------------#
#######################################
@main.route('/mi_asistencia')
@rol_required(3)  # Estudiante
def mi_asistencia():
    # 1. Obtener filtros desde la URL
    fecha_inicio = request.args.get('inicio')
    fecha_fin = request.args.get('fin')
    id_asignatura_filtro = request.args.get('id_asignatura', type=int)
    id_profesor_filtro = request.args.get('id_profesor', type=int)
    estado_filtro = request.args.get('estado')

    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    asistencias, asignaturas, profesores = [], [], []

    try:
        # Obtener el id_estudiante a partir del id_usuario
        cursor.execute("SELECT id_estudiante FROM estudiantes WHERE id_usuario = %s", (user_id,))
        estudiante = cursor.fetchone() 
        if not estudiante:
            flash('No se encontró el perfil de estudiante asociado a tu cuenta.', 'warning')
            return redirect(url_for('main.index'))
        
        id_estudiante = estudiante['id_estudiante']

        # Construir consulta principal para asistencias
        query = """
            SELECT 
                a.fecha,
                a.estado,
                a.observaciones,
                s.tema AS asignatura,
                p.nombre_completo AS profesor,
                h.hora_inicio, 
                h.hora_fin 
            FROM asistencias a
            JOIN horarios h ON a.id_curso = h.id_curso AND a.id_profesor = h.id_profesor
            JOIN asignatura s ON CAST(h.asignatura AS integer) = s.id_asignatura
            JOIN profesores p ON h.id_profesor = p.id_profesor
        """

        conditions = ["a.id_estudiante = %s"]
        params = [id_estudiante]

        if fecha_inicio:
            conditions.append("a.fecha >= %s")
            params.append(fecha_inicio)
        if fecha_fin:
            conditions.append("a.fecha <= %s")
            params.append(fecha_fin)
        if id_asignatura_filtro:
            conditions.append("s.id_asignatura = %s")
            params.append(id_asignatura_filtro)
        if id_profesor_filtro:
            conditions.append("p.id_profesor = %s")
            params.append(id_profesor_filtro)
        if estado_filtro:
            conditions.append("a.estado = %s")
            params.append(estado_filtro)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY a.fecha DESC, h.hora_inicio DESC"

        cursor.execute(query, tuple(params))
        asistencias = cursor.fetchall()

        # Consultas para filtros desplegables
        cursor.execute("""
            SELECT DISTINCT s.id_asignatura, s.tema 
            FROM asignatura s 
            JOIN horarios h ON s.id_asignatura = CAST(h.asignatura AS integer) 
            JOIN asistencias a ON a.id_curso = h.id_curso AND a.id_profesor = h.id_profesor
            WHERE a.id_estudiante = %s 
            ORDER BY s.tema
        """, (id_estudiante,))
        asignaturas = cursor.fetchall()

        cursor.execute("""
            SELECT DISTINCT p.id_profesor, p.nombre_completo 
            FROM profesores p 
            JOIN horarios h ON p.id_profesor = h.id_profesor 
            JOIN asistencias a ON a.id_curso = h.id_curso AND a.id_profesor = h.id_profesor 
            WHERE a.id_estudiante = %s 
            ORDER BY p.nombre_completo
        """, (id_estudiante,))
        profesores = cursor.fetchall()

    except Exception as e:
        flash(f'Error al cargar tus asistencias: {e}', 'danger')
        asistencias = []
        asignaturas = []
        profesores = []
    finally:
        cursor.close()
    
    filtros_activos = {
        'inicio': fecha_inicio,
        'fin': fecha_fin,
        'id_asignatura': id_asignatura_filtro,
        'id_profesor': id_profesor_filtro,
        'estado': estado_filtro
    }

    return render_template(
        'estudiantes/mi_asistencia.html', 
        asistencias=asistencias, 
        asignaturas=asignaturas, 
        profesores=profesores, 
        filtros_activos=filtros_activos
    )

#######################################
#-------------- RUTA /asistencia_estudiante -------------#
#######################################
@main.route('/asistencia_estudiante', methods=['GET'])
@rol_required(1) # Solo para administradores
def asistencia_estudiante():
    # 1. Obtener filtros desde la URL
    id_estudiante_filtro = request.args.get('id_estudiante', type=int)
    fecha_inicio = request.args.get('inicio')
    fecha_fin = request.args.get('fin')
    id_asignatura_filtro = request.args.get('id_asignatura', type=int)
    estado_filtro = request.args.get('estado')

    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    asistencias, estudiante_seleccionado = [], None
    
    try:
        # Obtener todos los estudiantes para el filtro
        cursor.execute("SELECT id_estudiante, nombre FROM estudiantes ORDER BY nombre")
        todos_estudiantes = cursor.fetchall()

        if id_estudiante_filtro:
            # Obtener datos del estudiante seleccionado
            cursor.execute("SELECT id_estudiante, nombre FROM estudiantes WHERE id_estudiante = %s", (id_estudiante_filtro,))
            estudiante_seleccionado = cursor.fetchone()

            # Construir la consulta de asistencias
            query = """
                SELECT a.fecha, a.estado, a.observaciones, s.tema AS asignatura, p.nombre_completo AS profesor, h.hora_inicio, h.hora_fin 
                FROM asistencias a
                JOIN horarios h ON a.id_horario = h.id_horario
                JOIN asignatura s ON CAST(h.asignatura AS integer) = s.id_asignatura
                JOIN profesores p ON h.id_profesor = p.id_profesor
            """
            conditions = ["a.id_estudiante = %s"]
            params = [id_estudiante_filtro]

            if fecha_inicio: conditions.append("a.fecha >= %s"); params.append(fecha_inicio)
            if fecha_fin: conditions.append("a.fecha <= %s"); params.append(fecha_fin)
            if id_asignatura_filtro: conditions.append("s.id_asignatura = %s"); params.append(id_asignatura_filtro)
            if estado_filtro: conditions.append("a.estado = %s"); params.append(estado_filtro)

            query += " WHERE " + " AND ".join(conditions) + " ORDER BY a.fecha DESC, h.hora_inicio DESC"
            cursor.execute(query, tuple(params))
            asistencias = cursor.fetchall()

    except Exception as e:
        flash(f'Error al cargar las asistencias del estudiante: {e}', 'danger')
    finally:
        cursor.close()

    filtros_activos = {
        'id_estudiante': id_estudiante_filtro, 'inicio': fecha_inicio, 'fin': fecha_fin, 
        'id_asignatura': id_asignatura_filtro, 'estado': estado_filtro
    }

    return render_template('estudiantes/asistencia_estudiante.html', 
                           asistencias=asistencias,
                           estudiante_seleccionado=estudiante_seleccionado,
                           todos_estudiantes=todos_estudiantes,
                           filtros_activos=filtros_activos)



#######################################
#-------------- ruta configuracion  -------------#
#######################################

@main.route("/configuracion", methods=['GET'])
@rol_required(1)
def configuracion():
    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        # Obtener ajustes generales
        cursor.execute("SELECT * FROM configuracion WHERE grupo = 'general' ORDER BY id")
        general_settings = cursor.fetchall()

        # Obtener redes sociales
        cursor.execute("SELECT * FROM configuracion WHERE grupo = 'social' ORDER BY id")
        social_settings = cursor.fetchall()

    except Exception as e:
        flash(f'Error al cargar la configuración: {e}', 'danger')
        general_settings, social_settings = [], []
    finally:
        cursor.close()
    
    return render_template("config/config.html", general_settings=general_settings, social_settings=social_settings)

@main.route("/configuracion/actualizar", methods=['POST'])
@rol_required(1)
def configuracion_actualizar():
    conn = get_db()
    cursor = conn.cursor()
    try:
        for key, value in request.form.items():
            if key.startswith('valor_'):
                setting_id = key.split('_')[1]
                cursor.execute("UPDATE configuracion SET valor = %s WHERE id = %s", (value, setting_id))
        conn.commit()
        flash('Configuración actualizada correctamente.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al actualizar: {e}', 'danger')
    finally:
        cursor.close()
    return redirect(url_for('main.configuracion'))

@main.route("/configuracion/social/agregar", methods=['POST'])
@rol_required(1)
def configuracion_social_agregar():
    conn = get_db()
    cursor = conn.cursor()
    try:
        nombre = request.form['nombre_red'].lower().replace(' ', '_')
        clave = f"url_{nombre}"
        url = request.form['url_red']
        icono = request.form['icono_red']
        descripcion = f"URL para {nombre.replace('_', ' ').title()}"
        
        cursor.execute(
            "INSERT INTO configuracion (clave, valor, descripcion, tipo, grupo, icono) VALUES (%s, %s, %s, 'url', 'social', %s)",
            (clave, url, descripcion, icono)
        )
        conn.commit()
        flash('Nueva red social agregada.', 'success')
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        flash(f'La red social "{nombre}" ya existe.', 'warning')
    except Exception as e:
        conn.rollback()
        flash(f'Error al agregar la red: {e}', 'danger')
    finally:
        cursor.close()
    return redirect(url_for('main.configuracion'))
 
@main.route("/configuracion/eliminar/<int:id>", methods=['POST'])
@rol_required(1)
def configuracion_eliminar(id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM configuracion WHERE id = %s AND grupo = 'social'", (id,))
        conn.commit()
        flash('El enlace ha sido eliminado.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al eliminar: {e}', 'danger')
    finally:
        cursor.close()
    return redirect(url_for('main.configuracion'))



#######################################
#-------------- RUTA /mi_reporte -------------#
#######################################
@main.route('/mi_reporte')
@rol_required(3) # Estudiante
def mi_reporte():
    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    try:
        cursor.execute("SELECT id_estudiante, nombre FROM estudiantes WHERE id_usuario = %s", (user_id,))
        estudiante = cursor.fetchone()
        if not estudiante:
            flash('No se encontró el perfil de estudiante asociado a tu cuenta.', 'warning')
            return redirect(url_for('main.index'))

        cursor.execute("""
            SELECT
                estado,
                COUNT(id_asistencia) as total
            FROM asistencias
            WHERE id_estudiante = %s
            GROUP BY estado
        """, (estudiante['id_estudiante'],))
        reporte_data = cursor.fetchall()
        reporte = {row['estado']: row['total'] for row in reporte_data}

        # Calcular porcentajes
        total_registros = sum(reporte.values())
        porcentajes = {
            'presente': 0,
            'ausente': 0,
            'tarde': 0,
            'justificado': 0
        }
        if total_registros > 0:
            porcentajes['presente'] = (reporte.get('Presente', 0) / total_registros) * 100
            porcentajes['ausente'] = (reporte.get('Ausente', 0) / total_registros) * 100
            porcentajes['tarde'] = (reporte.get('Tarde', 0) / total_registros) * 100
            porcentajes['justificado'] = (reporte.get('Justificado', 0) / total_registros) * 100

    finally:
        cursor.close()

    return render_template('estudiantes/mi_reporte.html', reporte=reporte, estudiante=estudiante, porcentajes=porcentajes)
