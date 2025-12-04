from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps

def usuario_requerido(view_func):
    def wrapper(request, *args, **kwargs):
        if not request.session.get("usuario_id"):
            messages.error(request, "Debes iniciar sesión para acceder.")
            return redirect("login")
        return view_func(request, *args, **kwargs)
    return wrapper

def admin_requerido(view_func):
    """Permite acceso solo a usuarios con rol admin."""
    def wrapper(request, *args, **kwargs):
        if request.session.get("usuario_rol") != "admin":
            messages.error(request, "No tienes permiso para acceder a esta sección.")
            return redirect("perfil")
        return view_func(request, *args, **kwargs)
    return wrapper

def no_logueado(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.session.get("usuario_id"):
            messages.info(request, "Ya estás logueado.")
            return redirect("perfil")
        return view_func(request, *args, **kwargs)
    return wrapper