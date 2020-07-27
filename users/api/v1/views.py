import datetime
import logging

from oauth2_provider.models import AccessToken
from oauth2_provider.settings import oauth2_settings
from oauthlib import common
from rest_framework import exceptions
from rest_framework import permissions
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework.viewsets import ViewSet

from django.contrib.auth import get_user_model
from django.core.mail import EmailMessage
from django.template.loader import render_to_string

from .permissions import IsOwnUserOrRaiseError
from .serializers import ChangePasswordSerializer
from .serializers import RegisterUserSerializer
from .serializers import TokenSerializer
from .serializers import UnauthorizedUserSerializer
from .serializers import UserAuthTokenSerializer
from .serializers import UserSerializer


logger = logging.getLogger(__name__)


class UserViewSet(ModelViewSet):
    """ ViewSet for `User` objects. """

    queryset = get_user_model().objects.all()

    def get_serializer_class(self):
        """
        Override the get_serializer_class to change the serializer of
        the different viewset actions.
        """
        if self.action in ('status',):
            return TokenSerializer
        elif self.action in ('password'):
            return ChangePasswordSerializer
        elif self.action in ('create'):
            return RegisterUserSerializer
        else:
            if self.request.user and self.request.user.is_authenticated:
                return UserSerializer
            else:
                return UnauthorizedUserSerializer

    def perform_create(self, serializer):
        """
        Override the perform_create method to do the ff:
            - Deactivate user upon saving
            - Send activation token to the user's email
        """
        user = serializer.save(is_active=False)
        user_email = user.email
        logger.info(f'Created user with email {user_email}')

        # Send the mail
        token, created = Token.objects.get_or_create(user=user)
        mail_subject = 'Activate your user account.'
        message = render_to_string('users/activate_email.html', {
            'token': token
        })
        email = EmailMessage(mail_subject, message, to=[user_email])
        email.send()
        logger.info(f'Successfully sent email to {user_email}')

    @action(detail=True, methods=['put'])
    def status(self, request, pk=None):
        """
        Endpoint for setting the `is_active` field of the users to True
        if the correct token is given. Non-idempotent.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = self.get_object()

        try:
            Token.objects.get(user=user, key=serializer.data['token'])
        except Token.DoesNotExist:
            return Response(
                {'token': 'Wrong token for user.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Set the user as active.
        user.is_active = True
        user.save(update_fields=['is_active'])
        user_serializer = UserSerializer(
            user, context={'request': request})
        return Response(user_serializer.data)

    @action(
        detail=True,
        methods=['post'],
        permission_classes=[permissions.IsAuthenticated, IsOwnUserOrRaiseError]
    )
    def password(self, request, pk=None):
        """ Endpoint for changing passwords. Non-idempotent. """
        user = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=user)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserAuthTokenViewSet(ViewSet):
    """ ViewSet for fetch the oauth2 access token. """
    serializer_class = UserAuthTokenSerializer
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        """ Override the create method to fetch token for the response. """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Generate token
        access_token = self._generate_access_token(serializer)
        return Response(
            {'token': access_token.token},
            status=status.HTTP_201_CREATED,
        )

    def _generate_access_token(self, serializer):
        """
        Generates the access token for the given user.

        Returns:
            AccessToken: OAuth Toolkit's AccessToken instance.
        """
        User = get_user_model()
        user = User.objects.get(email=serializer.data['email'])

        expiration_dt = (
            datetime.datetime.now() +
            datetime.timedelta(
                seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        )
        # No need to create an Application.
        access_token = AccessToken(
            user=user,
            expires=expiration_dt,
            token=common.generate_token()
        )
        access_token.save()

        return access_token
