import os
import psycopg2

def get_db_connection():
    database_url = os.getenv("DATABASE_URL")
    conn = None
    if database_url:
        # Conexión para producción (Render, etc.)
        # print("🔗 Conectando a la base de datos en la nube (Render)...")
        # El bloque try/except está en las rutas, así que aquí dejamos que el error se propague
        conn = psycopg2.connect(database_url, sslmode='require')
    else:
        # Conexión para desarrollo local
        # print("💻 Conectando a la base de datos local...")
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME", "asistencia"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "acgc.2008"),
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432")
        )
    
    # print("✅ Conexión a la base de datos establecida.")
    return conn
