# CRUD/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("", views.landing, name="landing"),
    path("registro/", views.registro, name="registro"),
    path("login/", views.login_usuario, name="login"),
    path("logout/", views.logout_usuario, name="logout"),
    path("perfil/", views.perfil, name="perfil"),
    path("perfil/editar/", views.editar_perfil, name="editar_perfil"),
    path("perfil/eliminar/", views.eliminar_cuenta, name="eliminar_cuenta"),
    path("solicitar-vendedor/", views.solicitar_vendedor, name="solicitar_vendedor"),
    path("dashboard/", views.dashboard_home, name="dashboard_home"),
    path("dashboard/solicitudes-vendedores/", views.lista_solicitudes, name="lista_solicitudes"),
    path("dashboard/solicitudes-vendedores/<id>/aprobar/", views.aprobar_solicitud, name="aprobar_solicitud"),
    path("dashboard/solicitudes-vendedores/<id>/rechazar/", views.rechazar_solicitud, name="rechazar_solicitud"),
        
]