# Default imports
from django.urls import path

# Custom imports
from .views import ListCreateArticles

urlpatterns = [
    path("", ListCreateArticles.as_view(), name="list_create_articles"),
]