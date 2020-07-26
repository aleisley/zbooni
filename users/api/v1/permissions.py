from rest_framework import permissions


class IsOwnUserOrRaiseError(permissions.BasePermission):
    """ Custom permission to check object level permissions. """

    def has_object_permission(self, request, view, obj):
        """
        Checks if either the request method is safe or if the
        user object being changed is not their own.

        Returns:
            Bool: True if safe or if the object's email is the
                same with the user's email. Else, False
        """
        if request.method in permissions.SAFE_METHODS:
            return True

        return obj.email == request.user.email
