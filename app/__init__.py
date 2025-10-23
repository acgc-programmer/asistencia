from flask import Flask
from flask_mail import Mail
from dotenv import load_dotenv
import os

mail = Mail()

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
    
    # Registrar blueprints
    from app.route import main
    app.register_blueprint(main)
    
    return app
