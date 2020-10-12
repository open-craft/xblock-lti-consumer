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


def get_lms_lti_keyset_link(lti_configuration):
    """
    Returns an LMS link to LTI public keyset endpoint

    :param location: the location of the block
    """
    return "{lms_base}/api/lti_consumer/v1/lti/{lti_config_id}/public_keysets/".format(
        lms_base=get_lms_base(),
        lti_config_id=str(lti_configuration.id),
    )


def get_lms_lti_launch_link(lti_configuration):
    """
    Returns an LMS link to LTI Launch endpoint

    :param location: the location of the block
    """
    return "{lms_base}/api/lti_consumer/v1/lti/{lti_config_id}/launch/".format(
        lms_base=get_lms_base(),
        lti_config_id=str(lti_configuration.id),
    )


def get_lms_lti_access_token_link(lti_configuration):
    """
    Returns an LMS link to LTI Launch endpoint

    :param location: the location of the block
    """
    return "{lms_base}/api/lti_consumer/v1/lti/{lti_config_id}/token/".format(
        lms_base=get_lms_base(),
        lti_config_id=str(lti_configuration.id),
    )


def get_lti_ags_lineitems_url(lti_config_id):
    """
    Return the LTI AGS endpoint

    :param lti_config_id: LTI configuration id
    """
    return "{lms_base}/api/lti_consumer/v1/lti/{lti_config_id}/lti-ags".format(
        lms_base=get_lms_base(),
        lti_config_id=str(lti_config_id),
    )
