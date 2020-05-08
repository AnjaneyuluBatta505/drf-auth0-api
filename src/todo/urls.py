from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r'todo', views.TodoViewset)

urlpatterns = [
    path('', include(router.urls)),
]
