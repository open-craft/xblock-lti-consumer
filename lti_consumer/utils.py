# -*- coding: utf-8 -*-
"""
Utility functions for LTI Consumer block
"""
from django.conf import settings


def _(text):
    """
    Make '_' a no-op so we can scrape strings
    """
    return text


def lti_1p3_enabled():
    """
    Returns `true` if LTI 1.3 integration is enabled for instance.
    """
    return settings.FEATURES.get('LTI_1P3_ENABLED', False) is True  # pragma: no cover


def get_lms_base():
    """
    Returns LMS base url to be used as issuer on OAuth2 flows

    TODO: This needs to be improved and account for Open edX sites and
    organizations.
    One possible improvement is to use `contentstore.get_lms_link_for_item`
    and strip the base domain name.
    """
    return settings.LMS_ROOT_URL


def get_lms_lti_link(lti_config_id, extra_path=None):
    link = "{lms_base}/api/lti_consumer/v1/lti/{lti_config_id}".format(
        lms_base=get_lms_base(),
        lti_config_id=str(lti_config_id),
    )

    if extra_path:
        link = '/'.join([link, extra_path])

    return link


def get_lms_lti_keyset_link(lti_config_id):
    """
    Returns an LMS link to LTI public keyset endpoint

    :param lti_config_id: LTI configuration id
    """
    return get_lms_lti_link(lti_config_id, extra_path='public_keysets')


def get_lms_lti_oidc_callback_link(lti_config_id):
    """
    Returns an LMS link to LTI Launch endpoint

    :param lti_config_id: LTI configuration id
    """
    return get_lms_lti_link(lti_config_id, extra_path='launch')


def get_lms_lti_launch_link(lti_config_id):
    """
    Returns an LMS link to LTI OIDC Preflight endpoint

    :param lti_config_id: LTI configuration id
    """
    return get_lms_lti_link(lti_config_id, extra_path='oidc')


def get_lms_lti_access_token_link(lti_config_id):
    """
    Returns an LMS link to LTI Launch endpoint

    :param lti_config_id: LTI configuration id
    """
    return get_lms_lti_link(lti_config_id, extra_path='token')


def get_lti_ags_lineitems_url(lti_config_id):
    """
    Return the LTI AGS endpoint

    :param lti_config_id: LTI configuration id
    """
    return get_lms_lti_link(lti_config_id, extra_path='lti-ags')
