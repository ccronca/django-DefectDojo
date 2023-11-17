import logging
from crum import impersonate
from djangosaml2.backends import Saml2Backend
from dojo.models import Dojo_Group, Dojo_Group_Member, Role, Dojo_User
from dojo.authorization.roles_permissions import Roles

logger = logging.getLogger("saml2")

class ModifiedSaml2Backend(Saml2Backend):
    def _update_user(self, user, attributes: dict, attribute_mapping: dict, force_save: bool = False):
        if 'groups' in attributes:
            group_names = attributes['groups']
            for group_name in group_names:
                created_group = False

                # By default, when a group is created, the owner is automatically assigned as the currently logged-in user.
                # However, in this particular scenario, our requirement is to designate the admin as the owner.
                with impersonate(Dojo_User.objects.get(username='admin')):
                    group, created_group = Dojo_Group.objects.get_or_create(name=group_name)

                if created_group:
                    logger.debug("Group %s was created", str(group))

                # We must save the user; otherwise, Django will not create the membership
                # see: https://docs.djangoproject.com/en/1.10/releases/1.8/#assigning-unsaved-objects-to-relations-raises-an-error
                user.save()

                # A potential bug has been identified in DefectDojo:
                # when a user lacks the "Group Viewer" permission in Configuration Permissions, they are unable to view the details of
                # their assigned groups, regardless of their role within those groups.
                # https://defectdojo.github.io/django-DefectDojo/usage/permissions/#groups
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