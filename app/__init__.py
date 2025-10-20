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
        MAIL_SERVER=os.getenv('MAIL_SERVER'),
        MAIL_PORT=int(os.getenv('MAIL_PORT')),
        MAIL_USE_TLS=os.getenv('MAIL_USE_TLS') == 'True',
        MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
        MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    )
    
    mail.init_app(app)  # Inicializas mail aquí
    
    # Registrar blueprints
    from app.route import main
    app.register_blueprint(main)
    
    return app
