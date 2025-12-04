# CRUD/views.py
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from bson.objectid import ObjectId
import re
from .decorators import usuario_requerido, admin_requerido, no_logueado
from bson.objectid import ObjectId

from .services import usuarios_collection

ROLES_PERMITIDOS = ["cliente", "vendedor", "admin"]

def landing(request):
    return render(request, "CRUD/landing.html")

@no_logueado
def registro(request):
    if request.method == "POST":
        nombre = request.POST.get("nombre", "").strip()
        correo = request.POST.get("correo", "").strip().lower()
        password1 = request.POST.get("password1", "")
        password2 = request.POST.get("password2", "")
        rol = request.POST.get("rol", "").strip().lower()

        # --- 🔒 SEGURIDAD: impedir que alguien se registre como admin ---
        if rol == "admin":
            rol = "cliente"  # Bloqueamos creación manual de cuentas admin

        # Validaciones básicas
        if not nombre or not correo or not password1 or not password2 or not rol:
            messages.error(request, "Todos los campos son obligatorios.")
            return render(request, "CRUD/registro.html")

        if rol not in ROLES_PERMITIDOS:
            messages.error(request, "Rol inválido.")
            return render(request, "CRUD/registro.html")

        if password1 != password2:
            messages.error(request, "Las contraseñas no coinciden.")
            return render(request, "CRUD/registro.html")

        if len(password1) < 8:
            messages.error(request, "La contraseña debe tener mínimo 8 caracteres.")
            return render(request, "CRUD/registro.html")
        
        if not re.search(r"[A-Za-z]", password1) or not re.search(r"[0-9]", password1):
            messages.error(request, "La contraseña debe incluir letras y números.")
            return render(request, "CRUD/registro.html")

        # Verificar si ya existe un usuario con ese correo
        existente = usuarios_collection.find_one({"correo": correo})
        if existente:
            messages.error(request, "Ya existe un usuario registrado con ese correo.")
            return render(request, "CRUD/registro.html")

        # Hashear contraseña con las utilidades de Django
        password_hash = make_password(password1)

        usuario_doc = {
            "nombre": nombre,
            "correo": correo,
            "password_hash": password_hash,
            "rol": rol,
            "estado_cuenta": "activo",
            "estado_vendedor": "ninguno",
            "tienda": None,
        }

        usuarios_collection.insert_one(usuario_doc)
        messages.success(request, "Registro exitoso. Ahora puedes iniciar sesión.")
        return redirect("login")

    return render(request, "CRUD/registro.html")

@no_logueado
def login_usuario(request):
    if request.method == "POST":
        correo = request.POST.get("correo", "").strip().lower()
        password = request.POST.get("password", "")

        if not correo or not password:
            messages.error(request, "Debes ingresar correo y contraseña.")
            return render(request, "CRUD/login.html")

        usuario = usuarios_collection.find_one({"correo": correo})
        if not usuario:
            messages.error(request, "Correo o contraseña incorrectos.")
            return render(request, "CRUD/login.html")

        if not check_password(password, usuario.get("password_hash", "")):
            messages.error(request, "Correo o contraseña incorrectos.")
            return render(request, "CRUD/login.html")

        # Guardamos datos básicos en la sesión
        request.session["usuario_id"] = str(usuario["_id"])
        request.session["usuario_nombre"] = usuario["nombre"]
        request.session["usuario_rol"] = usuario["rol"]

        messages.success(request, f"Bienvenido, {usuario.get('nombre', 'Usuario')}")
        return redirect("perfil")

    return render(request, "CRUD/login.html")


def logout_usuario(request):
    request.session.flush()
    messages.info(request, "Sesión cerrada correctamente.")
    return redirect("login")


def _obtener_usuario_sesion(request):
    """Función de apoyo: trae el usuario logueado desde Mongo por el id en sesión."""
    usuario_id = request.session.get("usuario_id")
    if not usuario_id:
        return None
    usuario = usuarios_collection.find_one({"_id": ObjectId(usuario_id)})
    return usuario

@usuario_requerido
def perfil(request):
    usuario = _obtener_usuario_sesion(request)
    if not usuario:
        messages.error(request, "Debes iniciar sesión para ver tu perfil.")
        return redirect("login")
    
    if usuario.get("estado_cuenta") == "pendiente_eliminacion":
        messages.warning(request, "Tu cuenta está en proceso de eliminación.")

    usuario["_id"] = str(usuario["_id"])
    return render(request, "CRUD/perfil.html", {"usuario": usuario})

@usuario_requerido
def editar_perfil(request):
    usuario = _obtener_usuario_sesion(request)
    if not usuario:
        messages.error(request, "Debes iniciar sesión para editar tu perfil.")
        return redirect("login")

    if request.method == "POST":
        nombre = request.POST.get("nombre", "").strip()
        rol_form = request.POST.get("rol", "").strip().lower()

        if not nombre:
            messages.error(request, "El nombre no puede estar vacío.")
            return redirect("editar_perfil")

        # --- BLOQUEO COMPLETO PARA ADMIN ---
        if usuario["rol"] == "admin":
            # Admin NO puede cambiar su propio rol
            rol = "admin"
        else:
            # Si NO es admin, NUNCA puede cambiar rol
            rol = usuario["rol"]

        # Actualizar en MongoDB
        usuarios_collection.update_one(
            {"_id": usuario["_id"]},
            {"$set": {"nombre": nombre, "rol": rol}}
        )

        # Actualizar sesión
        request.session["usuario_nombre"] = nombre
        request.session["usuario_rol"] = rol

        messages.success(request, "Perfil actualizado correctamente.")
        return redirect("perfil")

    usuario["_id"] = str(usuario["_id"])
    return render(request, "CRUD/editar_perfil.html", {"usuario": usuario, "roles": ROLES_PERMITIDOS})

@usuario_requerido
def solicitar_vendedor(request):
    usuario = _obtener_usuario_sesion(request)
    if not usuario:
        messages.error(request, "Debes iniciar sesión.")
        return redirect("login")

    # Si ya es vendedor o está en proceso
    if usuario.get("estado_vendedor") in ["pendiente", "aprobado"]:
        messages.info(request, "Ya has enviado una solicitud o ya eres vendedor.")
        return redirect("perfil")

    if request.method == "POST":
        nombre_tienda = request.POST.get("nombre_tienda", "").strip()
        descripcion = request.POST.get("descripcion", "").strip()

        if not nombre_tienda or not descripcion:
            messages.error(request, "Todos los campos son obligatorios.")
            return redirect("solicitar_vendedor")

        usuarios_collection.update_one(
            {"_id": usuario["_id"]},
            {
                "$set": {
                    "estado_vendedor": "pendiente",
                    "tienda": {
                        "nombre": nombre_tienda,
                        "descripcion": descripcion,
                    }
                }
            }
        )

        messages.success(request, "Solicitud enviada. Un administrador la revisará.")
        return redirect("perfil")

    return render(request, "CRUD/solicitar_vendedor.html")

@usuario_requerido
def eliminar_cuenta(request):
    usuario = _obtener_usuario_sesion(request)
    if not usuario:
        messages.error(request, "Debes iniciar sesión.")
        return redirect("login")

    if request.method == "POST":
        # Confirmación desde el formulario
        usuarios_collection.update_one(
        {"_id": usuario["_id"]},
        {"$set": {"estado_cuenta": "pendiente_eliminacion"}}
        )

        messages.info(request, "Tu solicitud de eliminación ha sido enviada.")
        return redirect("perfil")

@usuario_requerido
@admin_requerido
def lista_solicitudes(request):
    if request.session.get("usuario_rol") != "admin":
        messages.error(request, "Acceso no autorizado.")
        return redirect("login")
    solicitudes_cursor = usuarios_collection.find({"estado_vendedor": "pendiente"})

    solicitudes = []
    for s in solicitudes_cursor:
        s["id"] = str(s["_id"])   # <- convertimos el ObjectId a string SIN "_"
        solicitudes.append(s)

    return render(request, "CRUD/solicitudes_vendedores.html", {"solicitudes": solicitudes})

@usuario_requerido
def dashboard_home(request):
    usuario = _obtener_usuario_sesion(request)
    return render(request, "CRUD/dashboard_home.html", {"usuario": usuario})

@admin_requerido
def aprobar_solicitud(request, id):
    if request.session.get("usuario_rol") != "admin":
        return redirect("login")

    usuarios_collection.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"estado_vendedor": "aprobado", "rol": "vendedor"}}
    )
    messages.success(request, "Solicitud aprobada.")
    return redirect("lista_solicitudes")

@admin_requerido
def rechazar_solicitud(request, id):
    if request.session.get("usuario_rol") != "admin":
        return redirect("login")

    usuarios_collection.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"estado_vendedor": "rechazado"}}
    )
    messages.info(request, "Solicitud rechazada.")
    return redirect("lista_solicitudes")

