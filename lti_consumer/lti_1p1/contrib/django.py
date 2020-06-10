"""
This module provides functionality for rendering an LTI embed without an XBlock.
"""
from ..consumer import LtiConsumer1p1


def lti_embed(
    *
    html_element_id,
    lti_launch_url,
    oauth_key,
    oauth_secret,
    resource_link_id,
    user_id,
    roles,
    context_id,
    context_title,
    context_label,
    result_sourcedid=None,
    person_sourcedid=None,
    person_contact_email_primary=None,
    outcome_service_url=None,
    launch_presentation_locale=None,
    **custom_parameters
):
    lti_consumer = LtiConsumer1p1(lti_launch_url, oauth_key, oauth_secret)

    # Set LTI parameters from kwargs
    lti_consumer.set_user_data(
        user_id,
        roles,
        result_sourcedid=result_sourcedid,
        person_sourcedid=person_sourcedid,
        person_contact_email_primary=person_contact_email_primary
    )
    lti_consumer.set_context_data(
        context_id,
        context_title,
        context_label
    )

    if outcome_service_url:
        lti_consumer.set_outcome_service_url(outcome_service_url)

    if launch_presentation_locale:
        lti_consumer.set_launch_presentation_locale(launch_presentation_locale)

    lti_consumer.set_custom_parameters(
        **{
            key: value
            for key, value in custom_parameters.items()
            if key.startswith('custom_')
        }
    )

    # Prepare form data
    lti_parameters = lti_consumer.generate_launch_request(resource_link_id)
    context = {
        'launch_url': lti_launch_url,
        'element_id': html_element_id
    }
    context.update({'lti_parameters': lti_parameters})
    template = loader.render_mako_template('/templates/html/lti_launch.html', context)
    return Response(template, content_type='text/html')
