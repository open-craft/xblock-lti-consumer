
"""
Effective LTI settings of one placement, resolved over its bound configuration.

The resolver is read-only: it never loads a block, writes a row, creates a configuration,
generates keys or caches the result. Every runtime reader (launch, presentation, grading,
validation) resolves through it, so they cannot disagree about which value wins.
"""

import uuid
from dataclasses import dataclass, field

# Placement columns that override the bound configuration. NULL inherits; blank, False,
# 0 and [] are values, so source presence is never inferred by comparing to the shared row.
OVERRIDE_FIELDS = (
    'version',
    'lti_1p1_launch_url',
    'lti_1p1_client_key',
    'lti_1p1_client_secret',
    'lti_1p3_launch_url',
    'lti_1p3_oidc_url',
    'lti_1p3_redirect_uris',
    'lti_advantage_deep_linking_enabled',
    'lti_advantage_deep_linking_launch_url',
    'lti_advantage_ags_mode',
    'lti_advantage_enable_nrps',
    'display_name',
    'enable_grading',
    'grade_weight',
    'accept_grades_after_due_date',
    'hide_external_tool',
    'open_tool_in',
    'inline_height',
    'modal_height',
    'modal_width',
    'launch_button_text',
    'send_extra_parameters',
    'custom_parameters',
)

# Historical tool-verification pair. Both NULL means the shared pair applies; either value
# present means the whole historical pair applies, with no member borrowed from the shared row.
FROZEN_TOOL_PUBLIC_KEY = 'frozen_lti_1p3_tool_public_key'
FROZEN_TOOL_KEYSET_URL = 'frozen_lti_1p3_tool_keyset_url'

# Every placement column that belongs to the effective-value boundary; CCX sync copies none of them.
PLACEMENT_CONFIGURATION_FIELDS = OVERRIDE_FIELDS + (FROZEN_TOOL_PUBLIC_KEY, FROZEN_TOOL_KEYSET_URL)


class LtiConfigurationError(Exception):
    """This placement has no resolvable configuration and needs to be configured."""


@dataclass(frozen=True, repr=False)
class EffectiveLtiConfiguration:
    """
    Resolved settings of one placement.

    Credentials and signing material are kept out of repr() so a log line or a traceback
    cannot leak them. The result is internal only: it is never an HTTP payload.
    """

    config_store: str
    config_id: uuid.UUID
    passport_id: uuid.UUID | None
    external_id: str | None
    external_config: dict | None = field(default=None, repr=False)
    version: str | None = None
    lti_1p1_launch_url: str | None = None
    lti_1p1_client_key: str | None = None
    lti_1p1_client_secret: str | None = field(default=None, repr=False)
    lti_1p3_launch_url: str | None = None
    lti_1p3_oidc_url: str | None = None
    lti_1p3_redirect_uris: list | None = None
    lti_1p3_client_id: str | None = None
    lti_1p3_deployment_id: str | None = None
    lti_1p3_private_key: str | None = field(default=None, repr=False)
    lti_1p3_private_key_id: str | None = None
    lti_1p3_public_jwk: str | None = None
    lti_1p3_tool_key_mode: str | None = None
    lti_1p3_tool_public_key: str | None = None
    lti_1p3_tool_keyset_url: str | None = None
    lti_advantage_deep_linking_enabled: bool | None = None
    lti_advantage_deep_linking_launch_url: str | None = None
    lti_advantage_ags_mode: str | None = None
    lti_advantage_enable_nrps: bool | None = None
    lti_1p3_proctoring_enabled: bool = False
    display_name: str | None = None
    enable_grading: bool | None = None
    grade_weight: float | None = None
    accept_grades_after_due_date: bool | None = None
    hide_external_tool: bool | None = None
    open_tool_in: str | None = None
    inline_height: int | None = None
    modal_height: int | None = None
    modal_width: int | None = None
    launch_button_text: str | None = None
    send_extra_parameters: bool | None = None
    custom_parameters: list | None = None

    @property
    def is_external(self):
        """Whether this placement references an external configuration dynamically."""
        return self.config_store == 'CONFIG_EXTERNAL'

    def value(self, name):
        """Return one setting: dynamic for an external reference, resolved otherwise."""
        if self.is_external:
            return (self.external_config or {}).get(name)
        return getattr(self, name)

    def __repr__(self):
        return f'EffectiveLtiConfiguration(config_store={self.config_store!r}, passport_id={self.passport_id!r})'


def resolve_lti_configuration(placement):
    """
    Merge a placement's explicit overrides over its bound configuration.

    An external placement is a dynamic reference: its values come from the external
    configuration on every call and no local row is materialized. An internal placement
    with no binding raises, so a caller can never silently fall back to block fields.
    """
    if placement.config_store == placement.CONFIG_EXTERNAL:
        external = placement.external_config
        return EffectiveLtiConfiguration(
            config_store=placement.config_store,
            config_id=placement.config_id,
            passport_id=None,
            external_id=placement.external_id,
            external_config=external,
            # An external reference may omit its version; the stored value stays the fallback.
            version=external.get('version') if external.get('version') is not None else placement.version,
        )

    if placement.config_store != placement.CONFIG_ON_DB or placement.reusable_configuration is None:
        raise LtiConfigurationError(
            'This LTI placement needs a bound configuration before its settings can be resolved.',
        )

    configuration = placement.reusable_configuration
    values = {
        name: getattr(placement, name) if getattr(placement, name) is not None else getattr(configuration, name)
        for name in OVERRIDE_FIELDS
    }

    public_key = getattr(placement, FROZEN_TOOL_PUBLIC_KEY)
    keyset_url = getattr(placement, FROZEN_TOOL_KEYSET_URL)
    if public_key is None and keyset_url is None:
        public_key = configuration.lti_1p3_tool_public_key
        keyset_url = configuration.lti_1p3_tool_keyset_url

    return EffectiveLtiConfiguration(
        config_store=placement.config_store,
        config_id=placement.config_id,
        passport_id=configuration.passport_id,
        external_id=placement.external_id,
        version=values['version'],
        # Registration-owned identity and material come from stored fields, never from
        # property getters that would generate or create them.
        lti_1p3_client_id=configuration.lti_1p3_client_id,
        lti_1p3_deployment_id=configuration.lti_1p3_deployment_id,
        lti_1p3_private_key=configuration.lti_1p3_internal_private_key,
        lti_1p3_private_key_id=configuration.lti_1p3_internal_private_key_id,
        lti_1p3_public_jwk=configuration.lti_1p3_internal_public_jwk,
        lti_1p3_tool_key_mode=configuration.lti_1p3_tool_key_mode,
        lti_1p3_tool_public_key=public_key,
        lti_1p3_tool_keyset_url=keyset_url,
        lti_1p3_proctoring_enabled=placement.lti_1p3_proctoring_enabled,
        **{name: values[name] for name in OVERRIDE_FIELDS if name != 'version'},
    )
