import logging

from rest_framework.viewsets import ModelViewSet

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMessage
from django.template.loader import render_to_string

from .serializers import UserSerializer


logger = logging.getLogger(__name__)


class UserViewSet(ModelViewSet):
    """ ViewSet for `User` objects. """

    serializer_class = UserSerializer
    queryset = get_user_model().objects.filter(is_active=True)

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
        mail_subject = 'Activate your user account.'
        message = render_to_string('users/activate_email.html', {
            'user': user,
            'token': PasswordResetTokenGenerator().make_token(user)
        })
        email = EmailMessage(mail_subject, message, to=[user_email])
        email.send()
        logger.info(f'Successfully sent email to {user_email}')
