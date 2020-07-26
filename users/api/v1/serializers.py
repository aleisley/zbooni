from rest_framework import serializers

import django.contrib.auth.password_validation as validators
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core import exceptions


class BaseUserSerializer(serializers.HyperlinkedModelSerializer):
    """ Base Serializer for `User` objects. """

    url = serializers.HyperlinkedIdentityField(view_name='user-detail')
    is_active = serializers.BooleanField(read_only=True)

    class Meta:
        model = get_user_model()
        fields = (
            'url',
            'email',
            'first_name',
            'last_name',
            'is_active',
        )


class UnauthorizedUserSerializer(BaseUserSerializer):
    """
    HyperlinkedModelSerializer for `User` objects.
    This is used by users who aren't authenticated
    """

    class Meta:
        model = get_user_model()
        fields = ('url', 'first_name', 'is_active')


class UserSerializer(BaseUserSerializer):
    """ HyperlinkedModelSerializer for `User` objects. """

    pass


class RegisterUserSerializer(BaseUserSerializer):
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


class ChangePasswordSerializer(BaseUserSerializer):
    """ Serializer for changing password. """

    password = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)
    new_password = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    class Meta(BaseUserSerializer.Meta):
        fields = ('url', 'password', 'new_password')

    def validate(self, attrs):
        """
        Override the validate method to check if the passwords are
        all without errors.

        Raises:
            serializers.ValidationError 1: Raised if the password
                entered is not the same as the one currently saved.
            serializers.ValidationError 2: Raised if the password
                and new_password fields are the same.
            serializers.ValidationError 3: Raised if the new_password
                didn't pass the validate_password method.

        Returns:
            attrs: Cleaned data values.
        """
        password = attrs.get('password')
        new_password = attrs.get('new_password')

        user = self.context['request'].user
        if not user.check_password(password):
            raise serializers.ValidationError(
                {'password': 'The password entered is incorrect.'}
            )

        if password == new_password:
            raise serializers.ValidationError(
                {'password': 'New password should be different.'}
            )

        try:
            validators.validate_password(password=new_password, user=user)
        except exceptions.ValidationError as e:
            raise serializers.ValidationError(
                {'new_password': list(e.messages)}
            )

        return attrs

    def save(self, **kwargs):
        user = kwargs.get('user')
        user.set_password(self.validated_data['new_password'])
        user.save(update_fields=['password'])


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
