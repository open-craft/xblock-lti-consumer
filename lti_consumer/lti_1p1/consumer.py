"""
This module encapsulates code which implements the LTI specification.

For more details see:
https://www.imsglobal.org/activity/learning-tools-interoperability
"""

from __future__ import absolute_import, unicode_literals

import logging

import six.moves.urllib.error
import six.moves.urllib.parse
from six import text_type

from ..exceptions import LtiError
from ..oauth import get_oauth_request_signature, verify_oauth_body_signature

log = logging.getLogger(__name__)

LTI_PARAMETERS = [
    'lti_message_type',
    'lti_version',
    'resource_link_title',
    'resource_link_description',
    'user_image',
    'lis_person_name_given',
    'lis_person_name_family',
    'lis_person_name_full',
    'lis_person_contact_email_primary',
    'lis_person_sourcedid',
    'role_scope_mentor',
    'context_type',
    'context_title',
    'context_label',
    'launch_presentation_locale',
    'launch_presentation_document_target',
    'launch_presentation_css_url',
    'launch_presentation_width',
    'launch_presentation_height',
    'launch_presentation_return_url',
    'tool_consumer_info_product_family_code',
    'tool_consumer_info_version',
    'tool_consumer_instance_guid',
    'tool_consumer_instance_name',
    'tool_consumer_instance_description',
    'tool_consumer_instance_url',
    'tool_consumer_instance_contact_email',
]


class LtiConsumer1p1(object):  # pylint: disable=bad-option-value, useless-object-inheritance
    """
    Limited implementation of the LTI 1.1/2.0 specification.

    For the LTI 1.1 specification see:
    https://www.imsglobal.org/specs/ltiv1p1

    For the LTI 2.0 specification see:
    https://www.imsglobal.org/specs/ltiv2p0
    """
    CONTENT_TYPE_RESULT_JSON = 'application/vnd.ims.lis.v2.result+json'

    @property
    def custom_lti_parameters(self):
        """
        Returns all custom LTI launch parameters

        This property is expected to be overridden by individual implementations
        of this class. It should return a dictionary with the names and values
        of all custom LTI launch parameters. Each parameter should be prefixed
        with `custom_` per the LTI specifications.
        See http://www.imsglobal.org/LTI/v1p1p1/ltiIMGv1p1p1.html#_Toc316828520

        Arguments:
            None

        Returns:
            dict: Custom LTI launch parameters
        """
        return {}

    def get_signed_lti_parameters(
            self,
            lti_launch_url,
            oauth_key,
            oauth_secret,
            user_id,
            roles,
            resource_link_id,
            lis_result_sourcedid,
            context_id,
            context_title,
            context_label,
            launch_presentation_return_url='',
            lis_outcome_service_url=None,
            lis_person_sourcedid=None,
            lis_person_contact_email_primary=None,
            launch_presentation_locale=None
    ):
        """
        Signs LTI launch request and returns signature and OAuth parameters.

        Arguments:
            None

        Returns:
            dict: LTI launch parameters
        """

        # Must have parameters for correct signing from LTI:
        lti_parameters = {
            text_type('user_id'): user_id,
            text_type('oauth_callback'): text_type('about:blank'),
            text_type('launch_presentation_return_url'): launch_presentation_return_url,
            text_type('lti_message_type'): text_type('basic-lti-launch-request'),
            text_type('lti_version'): text_type('LTI-1p0'),
            text_type('roles'): roles,

            # Parameters required for grading:
            text_type('resource_link_id'): resource_link_id,
            text_type('lis_result_sourcedid'): lis_result_sourcedid,

            text_type('context_id'): context_id,

            text_type('context_title'): context_title,
            text_type('context_label'): context_label,
        }

        if lis_outcome_service_url is not None:
            lti_parameters.update({
                text_type('lis_outcome_service_url'): lis_outcome_service_url
            })

        if lis_person_sourcedid is not None:
            lti_parameters["lis_person_sourcedid"] = lis_person_sourcedid
        if lis_person_contact_email_primary is not None:
            lti_parameters["lis_person_contact_email_primary"] = lis_person_contact_email_primary
        if launch_presentation_locale is not None:
            lti_parameters["launch_presentation_locale"] = launch_presentation_locale

        # Appending custom parameter for signing.
        lti_parameters.update(self.custom_lti_parameters)

        headers = {
            # This is needed for body encoding:
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        oauth_signature = get_oauth_request_signature(
            oauth_key,
            oauth_secret,
            lti_launch_url,
            headers,
            lti_parameters
        )

        # Parse headers to pass to template as part of context:
        oauth_signature = dict([param.strip().replace('"', '').split('=') for param in oauth_signature.split(',')])

        oauth_signature[u'oauth_nonce'] = oauth_signature.pop(u'OAuth oauth_nonce')

        # oauthlib encodes signature with
        # 'Content-Type': 'application/x-www-form-urlencoded'
        # so '='' becomes '%3D'.
        # We send form via browser, so browser will encode it again,
        # So we need to decode signature back:
        oauth_signature[u'oauth_signature'] = six.moves.urllib.parse.unquote(
            oauth_signature[u'oauth_signature']
        )

        # Add LTI parameters to OAuth parameters for sending in form.
        lti_parameters.update(oauth_signature)
        return lti_parameters

    def verify_result_headers(self, request, oauth_secret, lis_outcome_service_url, verify_content_type=True):
        """
        Helper method to validate LTI 2.0 REST result service HTTP headers.  returns if correct, else raises LtiError

        Arguments:
            request (webob.Request):  Request object
            lis_outcome_service_url (string):  URL for storing grades
            verify_content_type (bool):  If true, verifies the content type of the request is that spec'ed by LTI 2.0

        Returns:
            nothing, but will only return if verification succeeds

        Raises:
            LtiError if verification fails
        """
        content_type = request.headers.get('Content-Type')
        if verify_content_type and content_type != LtiConsumerBase.CONTENT_TYPE_RESULT_JSON:
            log.error("[LTI]: v2.0 result service -- bad Content-Type: %s", content_type)
            error_msg = "For LTI 2.0 result service, Content-Type must be {}.  Got {}".format(
                LtiConsumerBase.CONTENT_TYPE_RESULT_JSON,
                content_type
            )
            raise LtiError(error_msg)

        try:
            return verify_oauth_body_signature(request, oauth_secret, lis_outcome_service_url)
        except (ValueError, LtiError) as err:
            log.error("[LTI]: v2.0 result service -- OAuth body verification failed: %s", str(err))
            raise LtiError(str(err))
