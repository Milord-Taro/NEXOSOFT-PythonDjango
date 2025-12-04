# CRUD/services.py
from pymongo import MongoClient

# 1. URL de conexión a MongoDB local
MONGO_URI = "mongodb://localhost:27017/"

# 2. Cliente que se conecta al servidor de Mongo
client = MongoClient(MONGO_URI)

# 3. Base de datos que usaremos para el proyecto
db = client["nexosoft_db"]

# 4. Colección (tabla) donde guardaremos los usuarios
usuarios_collection = db["usuarios"]
