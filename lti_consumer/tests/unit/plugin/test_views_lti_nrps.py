"""
Tests for LTI Names and Role Provisioning Service views.
"""
from mock import patch, PropertyMock, Mock
from Cryptodome.PublicKey import RSA
from jwkest.jwk import RSAKey
from django.urls import reverse
from rest_framework.test import APITransactionTestCase

from lti_consumer.lti_xblock import LtiConsumerXBlock
from lti_consumer.models import LtiConfiguration
from lti_consumer.tests.unit.test_utils import make_xblock


class LtiNrpsViewSetTestCase(APITransactionTestCase):
    """
    Test LtiNrpsViewSet actions
    """

    def setUp(self):
        super(LtiNrpsViewSetTestCase, self).setUp()

        # Create custom LTI Block
        self.rsa_key_id = "1"
        rsa_key = RSA.generate(2048)
        self.key = RSAKey(
            key=rsa_key,
            kid=self.rsa_key_id
        )
        self.public_key = rsa_key.publickey().export_key()

        self.xblock_attributes = {
            'lti_version': 'lti_1p3',
            'lti_1p3_launch_url': 'http://tool.example/launch',
            'lti_1p3_oidc_url': 'http://tool.example/oidc',
            # Intentionally using the same key for tool key to
            # allow using signing methods and make testing easier.
            'lti_1p3_tool_public_key': self.public_key,

            # LTI NRPS related attributes
            'lti_1p3_enable_nrps': True
        }

        self.xblock = make_xblock('lti_consumer', LtiConsumerXBlock, self.xblock_attributes)

        # Set dummy location so that UsageKey lookup is valid
        self.xblock.location = 'block-v1:course+test+2020+type@problem+block@test'

        # Create configuration
        self.lti_config = LtiConfiguration.objects.create(
            location=str(self.xblock.location),
            version=LtiConfiguration.LTI_1P3,
        )
        # Preload XBlock to avoid calls to modulestore
        self.lti_config.block = self.xblock

        # Patch internal method to avoid calls to modulestore
        patcher = patch(
            'lti_consumer.models.LtiConfiguration.block',
            new_callable=PropertyMock,
            return_value=self.xblock
        )
        self.addCleanup(patcher.stop)
        self._lti_block_patch = patcher.start()

        self._mock_user = Mock()

    def _set_lti_token(self, scopes=None):
        """
        Generates and sets a LTI Auth token in the request client.
        """
        if not scopes:
            scopes = ''

        consumer = self.lti_config.get_lti_consumer()
        token = consumer.key_handler.encode_and_sign({
            "iss": "https://example.com",
            "scopes": scopes,
        })
        # pylint: disable=no-member
        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer {}".format(token)
        )

    @patch("lti_consumer.plugin.views.compat")
    def test_get_context_memberships(self, compat_patcher):

        compat_patcher.get_user_enrollments.return_value = []
        compat_patcher.get_user_profiles.return_value = []
        compat_patcher.get_external_ids.return_value = []

        context_membership_endpoint = reverse(
            'lti_consumer:lti-nrps-view-memberships',
            kwargs={
                "lti_config_id": self.lti_config.id
            }
        )

        self._set_lti_token('https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly')
        response = self.client.get(context_membership_endpoint)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['content-type'], 'application/vnd.ims.lti-nrps.v2.membershipcontainer+json')
        self.assertEqual(
            response.data['id'],
            'http://testserver/lti_consumer/v1/lti/{}/lti-nrps/memberships'.format(
                self.lti_config.id,
            ),
        )
        self.assertEqual(response.data['context']['id'], 'course-v1:course+test+2020')
        self.assertEqual(response.data['members'], [])
