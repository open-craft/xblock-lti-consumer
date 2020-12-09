"""
Tests for LTI Names and Role Provisioning Service views.
"""
from mock import patch, PropertyMock, Mock
from Cryptodome.PublicKey import RSA
from jwkest.jwk import RSAKey
from django.urls import reverse
from django.utils.http import urlencode
from rest_framework import serializers
from rest_framework.test import APITransactionTestCase

from lti_consumer.lti_xblock import LtiConsumerXBlock
from lti_consumer.models import LtiConfiguration
from lti_consumer.tests.unit.test_utils import make_xblock


# pylint: disable=abstract-method
class MockUserReadOnlySerializer(serializers.Serializer):
    """
    Dummy class to mock UserReadOnlySerializer
    """


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

        # patch compat module and it's concerning methods
        serializer_compat_patcher = patch(
            'lti_consumer.lti_1p3.extensions.rest_framework.serializers.compat'
        )
        self.addCleanup(serializer_compat_patcher.stop)
        self._serializer_compat_patcher = serializer_compat_patcher.start()
        self._serializer_compat_patcher.get_user_readonly_serializer.return_value = MockUserReadOnlySerializer

        # create a fixed external uuid
        self._fixed_external_id = 'aad2e332-85df-4a08-ab64-a312e6dc4b72'
        mock_external_id_instance = Mock()
        mock_external_id_instance.external_user_id = self._fixed_external_id
        self._serializer_compat_patcher.get_or_create_externalid.return_value = (mock_external_id_instance, False,)

        self.context_membership_endpoint = reverse(
            'lti_consumer:lti-nrps-view-memberships',
            kwargs={
                "lti_config_id": self.lti_config.id
            }
        )

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

    def test_context_membership_unauthenticated_request(self):
        """
        Test if context membership throws 403 if request is unauthenticated
        """
        response = self.client.get(self.context_membership_endpoint)
        self.assertEqual(response.status_code, 403)

    def test_context_membership_token_with_incorrect_scope(self):
        """
        Test if context membership throws 403 if token don't have correct scope
        """
        self._set_lti_token()
        response = self.client.get(self.context_membership_endpoint)
        self.assertEqual(response.status_code, 403)

    def _generate_mock_member(self, num, role='student'):
        """
        Helper method to generate mock users.
        """
        members = []

        mock_instructor_role = Mock()
        mock_instructor_role.role = 'instructor'

        mock_staff_role = Mock()
        mock_staff_role.role = 'staff'

        for _ in range(num):
            member = Mock()
            if role == 'student':
                member.courseenrollment_set.count.return_value = 1
                member.courseaccessrole_set.all.return_value = []
            elif role == 'instructor':
                member.courseenrollment_set.count.return_value = 0
                member.courseaccessrole_set.all.return_value = [mock_instructor_role, mock_staff_role]
            elif role == 'staff':
                member.courseenrollment_set.count.return_value = 0
                member.courseaccessrole_set.all.return_value = [mock_staff_role]
            members.append(member)
        return members

    def _parse_link_headers(self, links):
        """
        Helper method to parse Link headers.
        For example given string -
            '<http://example.com/next>; rel="next", <http://example.com/prev>; rel="prev"'
        This method will return a dictionary containing-
            {
                'next': 'http://example.com/next',
                'pref': 'http://example.com/prev',
            }
        """
        result = {}
        for link in links.split(','):
            link_part, rel_part = link.split(';')
            link_part = link_part[1:][:-1].strip()
            rel_part = rel_part.replace('rel="', '').replace('"', '').strip()
            result[rel_part] = link_part
        return result

    @patch('lti_consumer.plugin.views.LtiNrpsViewSet.build_queryset')
    @patch('lti_consumer.plugin.views.LtiNrpsViewSet.get_page_size')
    def test_context_membership_token_with_correct_scope(self, get_page_size_patcher, build_queryset_patcher):
        """
        Test if context membership returns correct response when token has correct scope
        """
        get_page_size_patcher.return_value = 10
        build_queryset_patcher.return_value = self._generate_mock_member(0)
        self._set_lti_token('https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly')
        response = self.client.get(self.context_membership_endpoint)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['content-type'], 'application/vnd.ims.lti-nrps.v2.membershipcontainer+json')

    @patch('lti_consumer.plugin.views.LtiNrpsViewSet.build_queryset')
    @patch('lti_consumer.plugin.views.LtiNrpsViewSet.get_page_size')
    def test_get_context_membership(self, get_page_size_patcher, build_queryset_patcher):
        """
        Test context membership endpoint response structure.
        """
        get_page_size_patcher.return_value = 10
        mock_members = self._generate_mock_member(4)
        build_queryset_patcher.return_value = mock_members
        self._set_lti_token('https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly')
        response = self.client.get(self.context_membership_endpoint)
        self.assertEqual(
            response.data['id'],
            'http://testserver/lti_consumer/v1/lti/{}/lti-nrps/memberships?page=1'.format(
                self.lti_config.id,
            ),
        )
        self.assertEqual(len(response.data['members']), 4)
        self.assertEqual(response.has_header('Link'), False)

    @patch('lti_consumer.plugin.views.LtiNrpsViewSet.build_queryset')
    @patch('lti_consumer.plugin.views.LtiNrpsViewSet.get_page_size')
    def test_get_context_membership_pagination(self, get_page_size_patcher, build_queryset_patcher):
        """
        Test that context membership endpoint supports pagination with Link headers.
        """
        get_page_size_patcher.return_value = 10
        mock_members = self._generate_mock_member(15)
        build_queryset_patcher.return_value = mock_members
        self._set_lti_token('https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly')
        response = self.client.get(self.context_membership_endpoint)
        self.assertEqual(
            response.data['id'],
            'http://testserver/lti_consumer/v1/lti/{}/lti-nrps/memberships?page=1'.format(
                self.lti_config.id,
            ),
        )
        self.assertEqual(len(response.data['members']), 10)
        self.assertEqual(response.has_header('Link'), True)

        header_links = self._parse_link_headers(response['Link'])

        response = self.client.get(header_links['next'])
        self.assertEqual(len(response.data['members']), 5)
        self.assertEqual(response.has_header('Link'), False)

    @patch('lti_consumer.plugin.views.LtiNrpsViewSet.build_queryset')
    @patch('lti_consumer.plugin.views.LtiNrpsViewSet.get_page_size')
    def test_get_context_membership_filter(self, get_page_size_patcher, build_queryset_patcher):
        """
        Test if context membership properly builds query with given filter role.
        """
        get_page_size_patcher.return_value = 10
        mock_members = self._generate_mock_member(5)
        build_queryset_patcher.return_value = mock_members
        self._set_lti_token('https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly')

        response = self.client.get('{}?role=Administrator'.format(self.context_membership_endpoint))
        self.assertEqual(
            response.data['id'],
            'http://testserver/lti_consumer/v1/lti/{}/lti-nrps/memberships?{}'.format(
                self.lti_config.id,
                urlencode({
                    'page': 1,
                    'role': 'Administrator'
                })
            ),
        )

        # actual filtering will happen in Django ORM, here we test if correct role has passed for filtering.
        self.assertEqual(
            build_queryset_patcher.call_args[0][0],
            'staff'
        )
