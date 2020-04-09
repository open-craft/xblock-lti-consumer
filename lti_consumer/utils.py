# -*- coding: utf-8 -*-
"""
Utility functions for LTI Consumer block
"""
from six import text_type
# These imports are WIP until a better way of constructing LMS URLs from Studio is found
from django.conf import settings


def _(text):
    """
    Make '_' a no-op so we can scrape strings
    """
    return text


def get_lms_base():
    """
    Returns LMS base url to be used as issuer on OAuth2 flows
    """
    return settings.LMS_BASE


def get_lms_lti_keyset_link(location):
    """
    Returns an LMS link to LTI public keyset endpoint

    :param location: the location of the block
    """
    return u"http://{lms_base}/api/lti_consumer/v1/public_keysets/{location}".format(
        lms_base=get_lms_base(),
        location=text_type(location),
    )


def get_lms_lti_launch_link():
    """
    Returns an LMS link to LTI Launch endpoint

    :param location: the location of the block
    """
    return u"http://{lms_base}/api/lti_consumer/v1/launch/".format(
        lms_base=get_lms_base(),
    )
