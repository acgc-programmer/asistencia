from flask import Flask
from dotenv import load_dotenv
import os
import resend

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
        SECURITY_PASSWORD_SALT=os.getenv('SECURITY_PASSWORD_SALT')
    )

    # Configurar la clave de API de Resend
    resend.api_key = os.getenv("RESEND_API_KEY")

    # Registrar el filtro personalizado de hash para Jinja2
    app.jinja_env.filters['hash'] = simple_string_hash

    # Registrar blueprints
    from app.route import main
    app.register_blueprint(main)
    
    return app
