from django.contrib import admin
from django.urls import path, include
from .views import LoginView, UserRegisterView, RefreshTokenView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("articles/", include("article.urls")),
    path('login', LoginView.as_view()),
    path('register', UserRegisterView.as_view()),
    path('token/refresh', RefreshTokenView.as_view())
]