"""
XBlock fields whose runtime read comes from the placement's effective configuration.

The platform asks a block for `has_score` and `weight` before it calls `max_score()`. These
descriptors answer that read from the bound configuration without persisting a mirror: storage,
authoring, export and `is_set_on` keep using the stored field.
"""

from xblock.fields import Boolean, Field, Float

from lti_consumer.effective import LtiConfigurationError


class _EffectiveFieldMixin:
    """
    Read the runtime value from the host's `get_grading_configuration()`.

    Grading reads go through that one entry point. It answers `None` when the persisted
    placement is an external reference, which owns grading on the block, so the stored value
    wins. A placement without a resolvable binding reports the class's safe default instead,
    because the platform asks for grading metadata before any launch code can raise.
    """

    safe_default = None

    def __init__(self, *args, effective_member, **kwargs):
        self.effective_member = effective_member
        super().__init__(*args, **kwargs)

    def __get__(self, xblock, xblock_class=None):
        if xblock is None:
            return self
        try:
            effective = xblock.get_grading_configuration()
        except LtiConfigurationError:
            # Why: the platform reads grading metadata before max_score(), so an unbound
            # placement must look not-scorable instead of revealing a stale author value.
            return self.safe_default
        if effective is None:
            return Field.__get__(self, xblock, xblock_class)
        return getattr(effective, self.effective_member)

    def read_from(self, xblock):
        """Storage, authoring and export read the stored field, never the effective value."""
        return Field.__get__(self, xblock, type(xblock))


class EffectiveBoolean(_EffectiveFieldMixin, Boolean):
    """A Boolean field whose runtime value is the placement's effective setting."""

    safe_default = False


class EffectiveFloat(_EffectiveFieldMixin, Float):
    """A Float field whose runtime value is the placement's effective setting."""

    safe_default = 0.0
