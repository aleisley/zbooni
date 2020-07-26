from rest_framework import serializers

import django.contrib.auth.password_validation as validators
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core import exceptions


class BaseUserSerializer(serializers.BaseSerializer):
    """ Base Serializer for `User` objects. """

    class Meta:
        model = get_user_model()
        fields = (
            'email',
            'first_name',
            'last_name',
            'is_active',
        )


class UserSerializer(serializers.HyperlinkedModelSerializer):
    """ HyperlinkedModelSerializer for `User` objects. """

    url = serializers.HyperlinkedIdentityField(view_name='user-detail')

    class Meta(BaseUserSerializer.Meta):
        fields = ('url',) + BaseUserSerializer.Meta.fields


class RegisterUserSerializer(serializers.ModelSerializer):
    """ ModelSerializer for registering new `Users` """

    password = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)
    confirm_password = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    class Meta(BaseUserSerializer.Meta):
        fields = BaseUserSerializer.Meta.fields + (
            'password', 'confirm_password')

    def validate(self, attrs):
        """
        Overrides the serializer validate method to check the password.

        Raises:
            serializers.ValidationError: Raised if the password doesn't
                match the one entered on confirm password, too similar
                to the email, too short, etc.

        Returns:
            attrs: Cleaned data values.
        """
        User = self.Meta.model
        confirm_password = attrs.pop('confirm_password', '')
        password = attrs.get('password')
        user = User(**attrs)

        if password != confirm_password:
            raise serializers.ValidationError(
                {'confirm_password': 'Passwords do not match.'})

        try:
            validators.validate_password(password=password, user=user)
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({'password': list(e.messages)})
        else:
            attrs['password'] = make_password(password)

        return attrs


class UserAuthTokenSerializer(serializers.Serializer):
    """ Serializer for `User` access token generation. """

    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = get_user_model()
        fields = (
            'email',
            'password',
        )

    def validate(self, attrs):
        """
        Overrides the serializer validate method to check if user with
        given credentials are found.

        Raises:
            serializers.ValidationError: Will raise a non field error
                if either the email or password is wrong.

        Returns:
            attrs: Cleaned data values.
        """
        User = get_user_model()
        email = attrs.get('email')
        password = attrs.get('password')
        error_msg = {'detail': 'User with given credentials not found.'}

        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            raise serializers.ValidationError(error_msg)

        if not user.check_password(password):
            raise serializers.ValidationError(error_msg)

        return attrs
