# NEXOSOFT/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("CRUD.urls")),  # aquí enchufamos las URLs de la app CRUD
]
