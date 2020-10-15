"""
LTI consumer plugin passthrough views
"""
from django.utils.decorators import method_decorator
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_filters.rest_framework import DjangoFilterBackend
from opaque_keys.edx.keys import UsageKey
from rest_framework import viewsets
from rest_framework.decorators import action
import urllib.parse
from webob import Response

from lti_consumer.models import LtiConfiguration, LtiAgsLineItem
from lti_consumer.lti_1p3.exceptions import (
    Lti1p3Exception,
    UnsupportedGrantType,
    MalformedJwtToken,
    MissingRequiredClaim,
    NoSuitableKeys,
    TokenSignatureExpired,
    UnknownClientId,
)
from lti_consumer.lti_1p3.extensions.rest_framework.serializers import LtiAgsLineItemSerializer
from lti_consumer.lti_1p3.extensions.rest_framework.permissions import LtiAgsPermissions
from lti_consumer.lti_1p3.extensions.rest_framework.authentication import Lti1p3ApiAuthentication
from lti_consumer.lti_1p3.extensions.rest_framework.renderers import LineItemsRenderer, LineItemRenderer
from lti_consumer.lti_1p3.extensions.rest_framework.parsers import LineItemParser
from lti_consumer.plugin.compat import (
    run_xblock_handler,
    run_xblock_handler_noauth,
)


@require_http_methods(["GET"])
def public_keyset_endpoint(request, usage_id=None):
    """
    Gate endpoint to fetch public keysets from a problem

    This is basically a passthrough function that uses the
    OIDC response parameter `login_hint` to locate the block
    and run the proper handler.
    """
    try:
        usage_key = UsageKey.from_string(usage_id)

        return run_xblock_handler_noauth(
            request=request,
            course_id=str(usage_key.course_key),
            usage_id=str(usage_key),
            handler='public_keyset_endpoint'
        )
    except Exception:  # pylint: disable=broad-except
        return Response(status=404)


@require_http_methods(["GET", "POST"])
def launch_gate_endpoint(request, suffix):
    """
    Gate endpoint that triggers LTI launch endpoint XBlock handler

    This is basically a passthrough function that uses the
    OIDC response parameter `login_hint` to locate the block
    and run the proper handler.
    """
    try:
        usage_key = UsageKey.from_string(
            request.GET.get('login_hint')
        )

        return run_xblock_handler(
            request=request,
            course_id=str(usage_key.course_key),
            usage_id=str(usage_key),
            handler='lti_1p3_launch_callback',
            suffix=suffix
        )
    except Exception:  # pylint: disable=broad-except
        return Response(status=404)


@csrf_exempt
@require_http_methods(["POST"])
def access_token_endpoint(request, usage_id=None):
    """
    Gate endpoint to enable tools to retrieve access tokens
    """
    try:
        usage_key = UsageKey.from_string(usage_id)

        return run_xblock_handler_noauth(
            request=request,
            course_id=str(usage_key.course_key),
            usage_id=str(usage_key),
            handler='lti_1p3_access_token'
        )
    except Exception:  # pylint: disable=broad-except
        return Response(status=404)


class LtiAgsLineItemViewset(viewsets.ModelViewSet):
    """
    LineItem endpoint implementation from LTI Advantage.

    See full documentation at:
    https://www.imsglobal.org/spec/lti-ags/v2p0#line-item-service
    """
    serializer_class = LtiAgsLineItemSerializer
    pagination_class = None

    # Custom permission classes for LTI APIs
    authentication_classes = [Lti1p3ApiAuthentication]
    permission_classes = [LtiAgsPermissions]

    # Renderer/parser classes to accept LTI AGS content types
    renderer_classes = [
        LineItemsRenderer,
        LineItemRenderer,
    ]
    parser_classes = [LineItemParser]

    # Filters
    filter_backends = [DjangoFilterBackend]
    filterset_fields = [
        'resource_link_id',
        'resource_id',
        'tag'
    ]

    def get_queryset(self):
        lti_configuration = self.request.lti_configuration

        # Return all LineItems related to the LTI configuration.
        # TODO:
        # Note that each configuration currently maps 1:1
        # to each resource link (block), and this filter needs
        # improved once we start reusing LTI configurations.
        return LtiAgsLineItem.objects.filter(
            lti_configuration=lti_configuration
        )

    def perform_create(self, serializer):
        lti_configuration = self.request.lti_configuration
        serializer.save(lti_configuration=lti_configuration)


@method_decorator(xframe_options_exempt, name='list')
class LaunchGateViewSet(viewsets.ViewSet):
    """
    API endpoint for launching the LTI 1.3 tool.

    This endpoint is only valid when a LTI 1.3 tool is being used.

    Returns:
        webob.response: HTML LTI launch form or error page if misconfigured
    """

    # Handles GET requests with no suffix
    def list(self, request, *args, **kwargs):
        return self._handle_request(request, *args, **kwargs)

    def _handle_request(self, request, *args, **kwargs):
        lti_config = request.lti_configuration
        if lti_config.version != LtiConfiguration.LTI_1P3:
            return Response(status=404)

        xblock = lti_config.block
        usage_key = lti_config.location

        loader = ResourceLoader(__name__)
        context = {}

        lti_consumer = lti_config.get_lti_consumer()

        try:
            # Pass user data
            lti_consumer.set_user_data(
                user_id=xblock.external_user_id,
                # Pass django user role to library
                role=xblock.runtime.get_user_role()
            )

            # Set launch context
            # Hardcoded for now, but we need to translate from
            # self.launch_target to one of the LTI compliant names,
            # either `iframe`, `frame` or `window`
            # This is optional though
            lti_consumer.set_launch_presentation_claim('iframe')

            # Set context claim
            # This is optional
            context_title = " - ".join([
                xblock.course.display_name_with_default,
                xblock.course.display_org_with_default
            ])
            lti_consumer.set_context_claim(
                xblock.context_id,
                context_types=[LTI_1P3_CONTEXT_TYPE.course_offering],
                context_title=context_title,
                context_label=xblock.context_id
            )

            context.update({
                "preflight_response": dict(request.GET),
                "launch_request": lti_consumer.generate_launch_request(
                    resource_link=str(usage_key),  # pylint: disable=no-member
                    preflight_response=dict(request.GET)
                )
            })

            context.update({'launch_url': xblock.lti_1p3_launch_url})
            template = loader.render_mako_template('/templates/html/lti_1p3_launch.html', context)
            return Response(template, content_type='text/html')
        except Lti1p3Exception:
            template = loader.render_mako_template('/templates/html/lti_1p3_launch_error.html', context)
            return Response(template, status=400, content_type='text/html')
        except Exception:  # pylint: disable=broad-except
            return Response(status=404)


@method_decorator(xframe_options_exempt, name='list')
class OIDCViewSet(viewsets.ViewSet):
    """
    API endpoint to initiate an OIDC Preflight Request for an LTI1.3 Launch

    This endpoint is only valid when a LTI 1.3 tool is being used.
    """
    def list(self, request, *args, **kwargs):
        lti_config = request.lti_configuration
        if lti_config.version != LtiConfiguration.LTI_1P3:
            return Response(status=404)

        lti_consumer = lti_config.get_lti_consumer()
        context = lti_consumer.prepare_preflight_url(
            callback_url=get_lms_lti_launch_link(lti_config.id),
            hint=str(lti_config.location),
            lti_hint=str(lti_config.location)
        )

        loader = ResourceLoader(__name__)
        template = loader.render_mako_template('/templates/html/lti_1p3_oidc.html', context)
        return Response(template, content_type='text/html')


class PublicKeySetViewSet(viewsets.ViewSet):
    """
    API endpoint to retrieve public keys sets for an LtiConfiguration

    This endpoint is only valid when a LTI 1.3 tool is being used.
    """

    def list(self, request, *args, **kwargs):
        lti_config = request.lti_configuration
        if lti_config.version != LtiConfiguration.LTI_1P3:
            return Response(status=404)

        return Response(
            json_body=lti_config.get_lti_consumer().get_public_keyset(),
            content_type='application/json',
            content_disposition='attachment; filename=keyset.json'
        )


@method_decorator(csrf_exempt, name='create')
class TokenViewSet(viewsets.ViewSet):
    """
    API endpoint to create access tokens for the LTI 1.3 tool.

    This endpoint is only valid when a LTI 1.3 tool is being used.

    Returns:
        webob.response:
            Either an access token or error message detailing the failure.
            All responses are RFC 6749 compliant.

    References:
        Sucess: https://tools.ietf.org/html/rfc6749#section-4.4.3
        Failure: https://tools.ietf.org/html/rfc6749#section-5.2
    """

    def create(self, request, *args, **kwargs):
        lti_config = request.lti_configuration
        if lti_config.version != LtiConfiguration.LTI_1P3:
            return Response(status=404)

        lti_consumer = lti_config.get_lti_consumer()
        try:
            token = lti_consumer.access_token(
                dict(urllib.parse.parse_qsl(
                    request.body.decode('utf-8'),
                    keep_blank_values=True
                ))
            )
            # The returned `token` is compliant with RFC 6749 so we just
            # need to return a 200 OK response with the token as Json body
            return Response(json_body=token, content_type="application/json")

        # Handle errors and return a proper response
        except MissingRequiredClaim:
            # Missing request attibutes
            return Response(
                json_body={"error": "invalid_request"},
                status=400
            )
        except (MalformedJwtToken, TokenSignatureExpired):
            # Triggered when a invalid grant token is used
            return Response(
                json_body={"error": "invalid_grant"},
                status=400,
            )
        except (NoSuitableKeys, UnknownClientId):
            # Client ID is not registered in the block or
            # isn't possible to validate token using available keys.
            return Response(
                json_body={"error": "invalid_client"},
                status=400,
            )
        except UnsupportedGrantType:
            return Response(
                json_body={"error": "unsupported_grant_type"},
                status=400,
            )
