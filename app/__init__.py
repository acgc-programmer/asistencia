from flask import Flask
from flask_mail import Mail
from dotenv import load_dotenv
import os

mail = Mail()

def simple_string_hash(s):
    """
    Una función de hash simple y determinista para cadenas.
    Devuelve un entero que puede ser usado para seleccionar colores, etc.
    """
    hash_val = 0
    for char in s:
        hash_val = (hash_val << 5) - hash_val + ord(char)
        hash_val |= 0  # Asegura que se mantenga como un entero de 32 bits
    return hash_val

def create_app():
    app = Flask(__name__)
    
    # Cargar variables del archivo .env
    load_dotenv()

    # Configuraciones desde el .env
    app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY'),
        SECURITY_PASSWORD_SALT=os.getenv('SECURITY_PASSWORD_SALT'),

        # Configuración para Gmail
        MAIL_SERVER='smtp.gmail.com',
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USERNAME=os.getenv('MAIL_USERNAME'),  # Tu correo de Gmail
        MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),  # Tu contraseña de aplicación de Gmail
        MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER')  # Ej: 'tucorreo@dominio.com'
    )

    mail.init_app(app)  # Inicializa la instancia global de mail con la app
    
    # Registrar el filtro personalizado de hash para Jinja2
    app.jinja_env.filters['hash'] = simple_string_hash

    # Registrar blueprints
    from app.route import main
    app.register_blueprint(main)
    
    return app
