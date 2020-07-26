from django.urls import path
from django.urls import include

from ta_zbooni.api.v1.urls import router

from .views import UserViewSet


router.register(r'users', UserViewSet, basename='user')


urlpatterns = [
    path('', include(router.urls))
]
