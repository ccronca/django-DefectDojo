import logging
logger = logging.getLogger('dojo')

from djangosaml2.backends import Saml2Backend
from dojo.models import Dojo_Group, Dojo_Group_Member, Role

class ModifiedSaml2Backend(Saml2Backend):
    def _update_user(self, user, attributes: dict, attribute_mapping: dict, force_save: bool = False):
        if 'groups' in attributes:
            for group in attributes['groups']:
                dojo_group_member = Dojo_Group_Member(
                    group=Dojo_Group.objects.get(name=group),
                    user=user,
                    role=Role.objects.get(name='Writer'))
                user.save()
                dojo_group_member.save()

        return super()._update_user(user, attributes, attribute_mapping, force_save)