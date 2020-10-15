"""
URL mappings for LTI Consumer plugin.
"""

from __future__ import absolute_import

from django.conf import settings
from django.conf.urls import url, include

from rest_framework import routers

from lti_consumer.plugin.views import (
    public_keyset_endpoint,
    launch_gate_endpoint,
    access_token_endpoint,
    # LTI Configuration Launch URLs
    LaunchGateViewSet,
    OIDCViewSet,
    PublicKeySetViewSet,
    TokenViewSet,
    # LTI Advantage URLs
    LtiAgsLineItemViewSet,
)


# LTI 1.3 APIs router
lti_1p3_router = routers.SimpleRouter(trailing_slash=False)

# LTI Configuration Launch URLs
lti_1p3_router.register(r'launch', LaunchGateViewSet, basename='lti-launch-view')
lti_1p3_router.register(r'oidc', OIDCViewSet, basename='lti-oidc-view')
lti_1p3_router.register(r'public_keysets', PublicKeySetViewSet, basename='lti-public-keysets-view')
lti_1p3_router.register(r'token', TokenViewSet, basename='lti-token-view')

# LTI Advantage URLs
lti_1p3_router.register(r'lti-ags', LtiAgsLineItemViewSet, basename='lti-ags-view')

app_name = 'lti_consumer'
urlpatterns = [
    url(
        'lti_consumer/v1/public_keysets/{}$'.format(settings.USAGE_ID_PATTERN),
        public_keyset_endpoint,
        name='lti_consumer.public_keyset_endpoint'
    ),
    url(
        'lti_consumer/v1/launch/(?:/(?P<suffix>.*))?$',
        launch_gate_endpoint,
        name='lti_consumer.launch_gate'
    ),
    url(
        'lti_consumer/v1/token/{}$'.format(settings.USAGE_ID_PATTERN),
        access_token_endpoint,
        name='lti_consumer.access_token'
    ),
    url(
        r'lti_consumer/v1/lti/(?P<lti_config_id>[-\w]+)/',
        include(lti_1p3_router.urls)
    )
]
