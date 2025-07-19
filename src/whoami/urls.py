from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("labs/", views.labs, name="labs"),
    path("guides/", views.guide, name="guide"),
]
