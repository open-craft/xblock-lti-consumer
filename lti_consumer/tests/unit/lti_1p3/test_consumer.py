"""
Unit tests for LTI 1.3 consumer implementation
"""
from __future__ import absolute_import, unicode_literals

import ddt
from mock import Mock, patch
from django.test.testcases import TestCase
from six.moves.urllib.parse import urlparse, parse_qs
from Crypto.PublicKey import RSA

from lti_consumer.lti_1p3.consumer import LtiConsumer1p3


# Variables required for testing and verification
ISS = "http://test-platform.example/"
OIDC_URL = "http://test-platform/oidc"
LAUNCH_URL = "http://test-platform/launch"
CLIENT_ID = "1"
DEPLOYMENT_ID = "1"
# Consider storing a fixed key
RSA_KEY_ID = "1"
RSA_KEY = RSA.generate(2048).export_key('PEM')


# Test classes
@ddt.ddt
class TestLti1p3Consumer(TestCase):
    """
    Unit tests for LtiConsumer1p3
    """
    def setUp(self):
        super(TestLti1p3Consumer, self).setUp()

        # Set up consumer
        self.lti_consumer = LtiConsumer1p3(
            iss=ISS,
            lti_oidc_url=OIDC_URL,
            lti_launch_url=LAUNCH_URL,
            client_id=CLIENT_ID,
            deployment_id=DEPLOYMENT_ID,
            rsa_key=RSA_KEY,
            rsa_key_id=RSA_KEY_ID
        )

    @ddt.data(
        (
            ['student'],
            ['http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student']
        ),
        (
            ['student', 'staff'],
            [
                'http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student',
                'http://purl.imsglobal.org/vocab/lis/v2/system/person#Administrator'
            ]
        )
    )
    @ddt.unpack
    def test_get_user_roles(self, roles, expected_output):
        """
        Check that user roles are correctly translated to LTI 1.3 compliant rolenames.
        """
        roles = self.lti_consumer._get_user_roles(roles)  # pylint: disable=protected-access
        self.assertEqual(roles, expected_output)

    def test_get_user_roles_invalid(self):
        """
        Check that invalid user roles are throw a ValueError.
        """
        with self.assertRaises(ValueError):
            self.lti_consumer._get_user_roles(['invalid'])  # pylint: disable=protected-access

    def test_prepare_preflight_request(self):
        """
        Check if preflight request is properly formed and has all required keys.
        """
        preflight_request_data = self.lti_consumer.prepare_preflight_request(
            callback_url=LAUNCH_URL,
            hint="test-hint",
            lti_hint="test-lti-hint"
        )

        # Extract and check parameters from OIDC launch request url
        parameters = parse_qs(urlparse(preflight_request_data['oidc_url']).query)
        self.assertItemsEqual(
            parameters.keys(),
            [
                'iss',
                'login_hint',
                'lti_message_hint',
                'client_id',
                'target_link_uri',
                'lti_deployment_id'
            ]
        )
        self.assertEqual(parameters['iss'][0], ISS)
        self.assertEqual(parameters['client_id'][0], CLIENT_ID)
        self.assertEqual(parameters['login_hint'][0], "test-hint")
        self.assertEqual(parameters['lti_message_hint'][0], "test-lti-hint")
        self.assertEqual(parameters['lti_deployment_id'][0], DEPLOYMENT_ID)
        self.assertEqual(parameters['target_link_uri'][0], LAUNCH_URL)

    @ddt.data(
        # User with no roles
        (
            {"user_id": "1", "roles": []},
            {
                "sub": "1",
                "https://purl.imsglobal.org/spec/lti/claim/roles": []
            }
        ),
        # Student user, no optional data
        (
            {"user_id": "1", "roles": ['student']},
            {
                "sub": "1",
                "https://purl.imsglobal.org/spec/lti/claim/roles": [
                    "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student"
                ]
            }
        ),
        # User with extra data
        (
            {"user_id": "1", "roles": [], "full_name": "Jonh", "email_address": "jonh@example.com"},
            {
                "sub": "1",
                "https://purl.imsglobal.org/spec/lti/claim/roles": [],
                "name": "Jonh",
                "email": "jonh@example.com"
            }
        ),

    )
    @ddt.unpack
    def test_set_user_data(self, data, expected_output):
        """
        Check if setting user data works
        """
        self.lti_consumer.set_user_data(**data)
        self.assertEqual(
            self.lti_consumer.lti_claim_user_data,
            expected_output
        )

    def test_check_no_user_data_error(self):
        """
        Check if the launch request fails if no user data is set.
        """
        with self.assertRaises(ValueError):
            self.lti_consumer.generate_launch_request(
                preflight_response=Mock(),
                resource_link=Mock()
            )

    @patch('time.time', return_value=1000)
    def check_launch_request(self, mock_time):
        """
        Check if the launch request works if user data is set.
        """
        self.lti_consumer.set_user_data(
            user_id="1",
            roles=[]
        )
        launch_request = self.lti_consumer.generate_launch_request(
            preflight_response={
                "nonce": "test",
                "state": "state"
            },
            resource_link="link"
        )

        self.assertEqual(mock_time.call_count, 2)

        # Check launch request contents
        self.assertItemsEqual(launch_request.keys(), ['state', 'id_token'])
        self.assertEqual(launch_request['nonce'], 'test')

        # TODO: Decode and check token
