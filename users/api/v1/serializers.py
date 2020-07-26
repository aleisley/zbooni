from rest_framework import serializers

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password


class UserSerializer(serializers.HyperlinkedModelSerializer):
    """ HyperlinkedModelSerializer for `User` objects. """

    url = serializers.HyperlinkedIdentityField(view_name='user-detail')
    password = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = get_user_model()
        fields = (
            'url',
            'email',
            'first_name',
            'last_name',
            'password',
        )

    validate_password = make_password
