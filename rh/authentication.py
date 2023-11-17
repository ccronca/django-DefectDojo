import logging
from crum import impersonate
from djangosaml2.backends import Saml2Backend
from dojo.models import Dojo_Group, Dojo_Group_Member, Role, Dojo_User
from dojo.authorization.roles_permissions import Roles
from django.contrib.auth.models import Permission
from dojo.authorization.authorization import user_has_configuration_permission
from dojo.authorization.roles_permissions import Permissions

logger = logging.getLogger("saml2")

class ModifiedSaml2Backend(Saml2Backend):
    def _update_user(self, user, attributes: dict, attribute_mapping: dict, force_save: bool = False):
        if 'groups' in attributes:
            group_names = attributes['groups']

            # Users have to be authorized to view groups in general to view their own groups
            # https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/group/views.py#L95-L97
            # TESTING PURPOSES: Don't use in production the group can contain user information that might
            # be considered confidential
            if not user_has_configuration_permission(user, 'view_group'):
                user.user_permissions.add(Permission.objects.get(codename='view_group'))
                logger.debug("User %s has been granted group view permission", user)

            for group_name in group_names:
                created_group = False

                # By default, when a group is created, the owner is automatically assigned as the currently logged-in user.
                # However, in this particular scenario, assigning the admin as the owner seems sensible
                with impersonate(Dojo_User.objects.get(username='admin')):
                    group, created_group = Dojo_Group.objects.get_or_create(name=group_name)

                if created_group:
                    logger.debug("Group %s was created", str(group))

                # We must save the user; otherwise, Django will not create the membership
                # see: https://docs.djangoproject.com/en/1.10/releases/1.8/#assigning-unsaved-objects-to-relations-raises-an-error
                user = self.save_user(user)

                group_member, is_member_created = Dojo_Group_Member.objects.get_or_create(group=group, user=user,
                    defaults={'role': Role.objects.get(id=Roles.Maintainer)})

                if is_member_created:
                    logger.debug("User %s become member of group %s", user, str(group))

            # CleanUp Groups
            for group_member in Dojo_Group_Member.objects.select_related('group').filter(user=user):
                group = group_member.group
                if str(group) not in group_names:
                    logger.info("Deleting membership of user %s from group %s", user, str(group))
                    group_member.delete()

        return super()._update_user(user, attributes, attribute_mapping, force_save)