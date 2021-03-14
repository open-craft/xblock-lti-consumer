"""
Tests for LTI Names and Role Provisioning Service views.
"""
from mock import patch, PropertyMock, Mock
from Cryptodome.PublicKey import RSA
from jwkest.jwk import RSAKey
from rest_framework.test import APITransactionTestCase
from rest_framework.reverse import reverse

from lti_consumer.lti_xblock import LtiConsumerXBlock
from lti_consumer.models import LtiConfiguration
from lti_consumer.tests.unit.test_utils import make_xblock


class MockUserQueryset(list):
    """
    Utility class to mock user queryset and count call.
    """
    def count(self):
        """
        Mock call to count method.
        """
        return len(self)


class LtiNrpsTestCase(APITransactionTestCase):
    """
    Test LtiNrpsViewSet actions
    """

    def setUp(self):
        super().setUp()

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

        # patch profile image call
        self._serializer_compat_patcher.get_user_profile_image.return_value = {
            'medium': 'test-image-url'
        }

        # create a fixed external uuid
        self._fixed_external_id = 'aad2e332-85df-4a08-ab64-a312e6dc4b72'
        mock_external_id_instance = Mock()
        mock_external_id_instance.external_user_id = self._fixed_external_id
        self._serializer_compat_patcher.get_or_create_externalid.return_value = (mock_external_id_instance, False,)
        self.context_membership_endpoint = reverse(
            'lti_consumer:lti-nrps-memberships-view-list',
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

    def _generate_mock_member(self, num, role='student'):
        """
        Helper method to generate mock users.
        """
        members = MockUserQueryset()

        mock_instructor_role = Mock()
        mock_instructor_role.role = 'instructor'

        mock_staff_role = Mock()
        mock_staff_role.role = 'staff'

        for i in range(num):
            member = Mock()
            member.name = 'Member {}'.format(i)
            member.email = 'member{}@example.com'.format(i)
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


class LtiNrpsContextMembershipViewsetTestCase(LtiNrpsTestCase):
    """
    Test LTI-NRPS Context Membership Endpoint
    """

    def test_unauthenticated_request(self):
        """
        Test if context membership throws 403 if request is unauthenticated
        """
        response = self.client.get(self.context_membership_endpoint)
        self.assertEqual(response.status_code, 403)

    def test_token_with_incorrect_scope(self):
        """
        Test if context membership throws 403 if token don't have correct scope
        """
        self._set_lti_token()
        response = self.client.get(self.context_membership_endpoint)
        self.assertEqual(response.status_code, 403)

    @patch('lti_consumer.plugin.views.expose_pii_fields', return_value=False)
    @patch('lti_consumer.plugin.views.compat.get_course_members')
    def test_token_with_correct_scope(self, get_course_members_patcher, expose_pii_fields_patcher):  # pylint: disable=unused-argument
        """
        Test if context membership returns correct response when token has correct scope
        """
        get_course_members_patcher.return_value = self._generate_mock_member(0)
        self._set_lti_token('https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly')
        response = self.client.get(self.context_membership_endpoint)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['content-type'], 'application/vnd.ims.lti-nrps.v2.membershipcontainer+json')

    @patch('lti_consumer.plugin.views.expose_pii_fields', return_value=False)
    @patch('lti_consumer.plugin.views.compat.get_course_members')
    def test_get_without_pii(self, get_course_members_patcher, expose_pii_fields_patcher):
        """
        Test context membership endpoint response structure with PII not exposed.
        """
        mock_members = self._generate_mock_member(4)
        get_course_members_patcher.return_value = mock_members
        self._set_lti_token('https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly')
        response = self.client.get(self.context_membership_endpoint)
        self.assertEqual(response.data['id'], 'http://testserver{}'.format(self.context_membership_endpoint))
        self.assertEqual(len(response.data['members']), 4)
        self.assertEqual(response.has_header('Link'), False)

        expose_pii_fields_patcher.assert_called()

        # name & email should not be exposed.
        member_fields = response.data['members'][0].keys()
        self.assertEqual(all([
            'user_id' in member_fields,
            'roles' in member_fields,
            'status' in member_fields,
            'email' not in member_fields,
            'name' not in member_fields,
        ]), True)

    @patch('lti_consumer.plugin.views.expose_pii_fields', return_value=True)
    @patch('lti_consumer.plugin.views.compat.get_course_members')
    def test_get_with_pii(self, get_course_members_patcher, expose_pii_fields_patcher):
        """
        Test context membership endpoint response structure with PII exposed.
        """
        mock_members = self._generate_mock_member(4)
        get_course_members_patcher.return_value = mock_members
        self._set_lti_token('https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly')
        response = self.client.get(self.context_membership_endpoint)

        self.assertEqual(response.data['id'], 'http://testserver{}'.format(self.context_membership_endpoint))
        self.assertEqual(len(response.data['members']), 4)
        self.assertEqual(response.has_header('Link'), False)

        expose_pii_fields_patcher.assert_called()

        # name & email should be present along with user_id, roles etc.
        member_fields = response.data['members'][0].keys()
        self.assertEqual(all([
            'user_id' in member_fields,
            'roles' in member_fields,
            'status' in member_fields,
            'email' in member_fields,
            'name' in member_fields,
        ]), True)

    @patch('lti_consumer.plugin.views.expose_pii_fields', return_value=False)
    @patch('lti_consumer.plugin.views.compat.get_course_members')
    def test_pagination(self, get_course_members_patcher, expose_pii_fields_patcher):  # pylint: disable=unused-argument
        """
        Test that context membership endpoint supports pagination with Link headers.
        """
        mock_members = self._generate_mock_member(15)
        get_course_members_patcher.return_value = mock_members
        self._set_lti_token('https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly')
        response = self.client.get(self.context_membership_endpoint)

        self.assertEqual(response.data['id'], 'http://testserver{}'.format(self.context_membership_endpoint))
        self.assertEqual(len(response.data['members']), 10)
        self.assertEqual(response.has_header('Link'), True)

        header_links = self._parse_link_headers(response['Link'])

        response = self.client.get(header_links['next'])
        self.assertEqual(len(response.data['members']), 5)

        header_links = self._parse_link_headers(response['Link'])
        self.assertEqual(header_links.get('next'), None)

    @patch('lti_consumer.plugin.views.expose_pii_fields', return_value=False)
    @patch('lti_consumer.plugin.views.compat.get_course_members')
    def test_filter(self, get_course_members_patcher, expose_pii_fields_patcher):  # pylint: disable=unused-argument
        """
        Test if context membership properly builds query with given filter role.
        """
        mock_members = self._generate_mock_member(5)
        get_course_members_patcher.return_value = mock_members
        self._set_lti_token('https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly')

        self.client.get('{}?role={}'.format(
            self.context_membership_endpoint,
            'http://purl.imsglobal.org/vocab/lis/v2/membership#Administrator'
        ))

        call_kwargs = get_course_members_patcher.call_args[1]
        self.assertEqual(call_kwargs['include_students'], False)
        self.assertEqual(call_kwargs['access_roles'], ['staff'])

    @patch('lti_consumer.plugin.views.expose_pii_fields', return_value=False)
    @patch('lti_consumer.plugin.views.compat.get_course_members')
    @patch('lti_consumer.plugin.views.lti_nrps_enrollment_limit', return_value=10)
    def test_enrollment_limit_gate(self, limit_patcher, get_course_members_patcher, expose_pii_fields_patcher):  # pylint: disable=unused-argument
        """
        Test if number of enrolled user is larger than the limit, api returns 404 response.
        """
        mock_members = self._generate_mock_member(15)
        get_course_members_patcher.return_value = mock_members
        self._set_lti_token('https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly')

        response = self.client.get(self.context_membership_endpoint)
        self.assertEqual(response.status_code, 404)
