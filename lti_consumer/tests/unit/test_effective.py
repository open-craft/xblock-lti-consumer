
"""
Tests for the read-only effective-configuration resolver.
"""

from dataclasses import FrozenInstanceError
from unittest import mock

from django.test import TestCase

from lti_consumer.effective import (
    OVERRIDE_FIELDS,
    LtiConfigurationError,
    resolve_lti_configuration,
)
from lti_consumer.models import LtiConfiguration, ReusableLtiConfiguration

COURSE_KEY = 'course-v1:Org+Course+Run'
LOCATION = 'block-v1:Org+Course+Run+type@lti_consumer+block@effective'

SHARED_VALUES = {
    'version': ReusableLtiConfiguration.LTI_1P3,
    'lti_1p1_launch_url': 'https://tool.example/1p1-launch',
    'lti_1p1_client_key': 'shared-key',
    'lti_1p1_client_secret': 'shared-secret',
    'lti_1p3_launch_url': 'https://tool.example/launch',
    'lti_1p3_oidc_url': 'https://tool.example/oidc',
    'lti_1p3_redirect_uris': ['https://tool.example/redirect'],
    'lti_advantage_deep_linking_enabled': True,
    'lti_advantage_deep_linking_launch_url': 'https://tool.example/deep-link',
    'lti_advantage_ags_mode': 'programmatic',
    'lti_advantage_enable_nrps': True,
    'display_name': 'Shared name',
    'enable_grading': True,
    'grade_weight': 5.0,
    'accept_grades_after_due_date': True,
    'hide_external_tool': True,
    'open_tool_in': 'modal',
    'inline_height': 600,
    'modal_height': 70,
    'modal_width': 60,
    'launch_button_text': 'Launch',
    'send_extra_parameters': True,
    'custom_parameters': ['shared=1'],
}

# One override per ordinary column. Each is distinct from the shared value, and blank, 0, []
# and False are used wherever the type allows them, so inheriting could not produce a pass.
# Choice columns keep another valid choice: blank is not a version, AGS mode or open-in value.
OVERRIDE_VALUES = {
    'version': ReusableLtiConfiguration.LTI_1P1,
    'lti_1p1_launch_url': '',
    'lti_1p1_client_key': '',
    'lti_1p1_client_secret': '',
    'lti_1p3_launch_url': '',
    'lti_1p3_oidc_url': '',
    'lti_1p3_redirect_uris': [],
    'lti_advantage_deep_linking_enabled': False,
    'lti_advantage_deep_linking_launch_url': '',
    'lti_advantage_ags_mode': 'disabled',
    'lti_advantage_enable_nrps': False,
    'display_name': '',
    'enable_grading': False,
    'grade_weight': 0,
    'accept_grades_after_due_date': False,
    'hide_external_tool': False,
    'open_tool_in': 'new_window',
    'inline_height': 0,
    'modal_height': 0,
    'modal_width': 0,
    'launch_button_text': '',
    'send_extra_parameters': False,
    'custom_parameters': [],
}

# The falsey override each ordinary column type must be exercised with. Choice columns are
# excluded: blank is not a valid version, AGS mode or open-in value for a consumer.
FALSEY_BY_TYPE = (
    ('', (
        'lti_1p1_launch_url',
        'lti_1p1_client_key',
        'lti_1p1_client_secret',
        'lti_1p3_launch_url',
        'lti_1p3_oidc_url',
        'lti_advantage_deep_linking_launch_url',
        'display_name',
        'launch_button_text',
    )),
    (0, ('grade_weight', 'inline_height', 'modal_height', 'modal_width')),
    ([], ('lti_1p3_redirect_uris', 'custom_parameters')),
    (False, (
        'lti_advantage_deep_linking_enabled',
        'lti_advantage_enable_nrps',
        'enable_grading',
        'accept_grades_after_due_date',
        'hide_external_tool',
        'send_extra_parameters',
    )),
)
CHOICE_OVERRIDE_FIELDS = ('version', 'lti_advantage_ags_mode', 'open_tool_in')


class EffectiveConfigurationTests(TestCase):
    """The resolver merges overrides over the bound configuration, and nothing else."""

    def setUp(self):
        super().setUp()
        self.configuration = ReusableLtiConfiguration.objects.create(
            name='Shared configuration',
            context_type='course',
            context_key=COURSE_KEY,
            **SHARED_VALUES,
        )
        self.placement = LtiConfiguration.objects.create(
            location=LOCATION,
            config_store=LtiConfiguration.CONFIG_ON_DB,
            reusable_configuration=self.configuration,
        )

    def test_every_override_column_starts_unset_and_inherits(self):
        """NULL means "not set" for every ordinary and frozen column."""
        effective = resolve_lti_configuration(self.placement)
        for name in OVERRIDE_FIELDS:
            with self.subTest(field=name):
                self.assertIsNone(getattr(self.placement, name))
                self.assertEqual(getattr(effective, name), SHARED_VALUES[name])

    def test_every_override_column_wins_when_set(self):
        """A concrete override wins after save and reload, including blank, False, 0 and []."""
        for name in OVERRIDE_FIELDS:
            with self.subTest(field=name):
                self.assertNotEqual(SHARED_VALUES[name], OVERRIDE_VALUES[name])
                setattr(self.placement, name, OVERRIDE_VALUES[name])
                self.placement.save()
                try:
                    stored = LtiConfiguration.objects.get(pk=self.placement.pk)
                    effective = resolve_lti_configuration(stored)
                    self.assertEqual(getattr(effective, name), OVERRIDE_VALUES[name])
                finally:
                    setattr(self.placement, name, None)
                    self.placement.save()

    def test_falsey_value_matrix_covers_each_override_type(self):
        """Blank, 0, [] and False are exercised wherever the type allows; choices are not blanked."""
        falsey_fields = set()
        for falsey, names in FALSEY_BY_TYPE:
            falsey_fields.update(names)
            for name in names:
                with self.subTest(field=name):
                    self.assertEqual(OVERRIDE_VALUES[name], falsey)
                    self.assertNotEqual(SHARED_VALUES[name], falsey)
        self.assertEqual(falsey_fields | set(CHOICE_OVERRIDE_FIELDS), set(OVERRIDE_FIELDS))

    def test_result_is_immutable(self):
        """Callers cannot write resolved settings back through the result."""
        effective = resolve_lti_configuration(self.placement)
        with self.assertRaises(FrozenInstanceError):
            effective.display_name = 'changed'

    def test_shared_identity_and_material_are_never_overridden(self):
        """Client ID, deployment ID, signing material and key mode stay configuration-owned."""
        self.configuration.lti_1p3_client_id = 'shared-client-id'
        self.configuration.lti_1p3_deployment_id = 'deployment-7'
        self.configuration.lti_1p3_internal_private_key = 'private-key'
        self.configuration.lti_1p3_internal_private_key_id = 'kid'
        self.configuration.lti_1p3_internal_public_jwk = '{"kty": "RSA"}'
        self.configuration.lti_1p3_tool_key_mode = 'public_key'
        self.configuration.save()

        effective = resolve_lti_configuration(self.placement)

        self.assertEqual(effective.lti_1p3_client_id, 'shared-client-id')
        self.assertEqual(effective.lti_1p3_deployment_id, 'deployment-7')
        self.assertEqual(effective.lti_1p3_private_key, 'private-key')
        self.assertEqual(effective.lti_1p3_private_key_id, 'kid')
        self.assertEqual(effective.lti_1p3_public_jwk, '{"kty": "RSA"}')
        self.assertEqual(effective.lti_1p3_tool_key_mode, 'public_key')
        self.assertEqual(effective.passport_id, self.configuration.passport_id)

    def test_tool_verification_is_one_whole_pair(self):
        """Both NULL inherits the shared pair; any present member uses the whole historical pair."""
        self.configuration.lti_1p3_tool_public_key = 'shared-public-key'
        self.configuration.lti_1p3_tool_keyset_url = 'https://shared.example/jwks'
        self.configuration.save()

        effective = resolve_lti_configuration(self.placement)
        self.assertEqual(effective.lti_1p3_tool_public_key, 'shared-public-key')
        self.assertEqual(effective.lti_1p3_tool_keyset_url, 'https://shared.example/jwks')

        self.placement.frozen_lti_1p3_tool_public_key = 'historical-public-key'
        self.placement.save()
        effective = resolve_lti_configuration(self.placement)
        self.assertEqual(effective.lti_1p3_tool_public_key, 'historical-public-key')
        # No member is borrowed from the shared row, even when the historical one is NULL.
        self.assertIsNone(effective.lti_1p3_tool_keyset_url)

        self.placement.frozen_lti_1p3_tool_public_key = None
        self.placement.frozen_lti_1p3_tool_keyset_url = 'https://historical.example/jwks'
        self.placement.save()
        effective = resolve_lti_configuration(self.placement)
        self.assertIsNone(effective.lti_1p3_tool_public_key)
        self.assertEqual(effective.lti_1p3_tool_keyset_url, 'https://historical.example/jwks')

        # Both members present keep their historical values: no shared member is borrowed and
        # the resolver imposes no source validation on a pair a consumer might reject.
        self.placement.frozen_lti_1p3_tool_public_key = 'historical-public-key'
        self.placement.frozen_lti_1p3_tool_keyset_url = 'https://historical.example/jwks'
        self.placement.save()
        effective = resolve_lti_configuration(
            LtiConfiguration.objects.get(pk=self.placement.pk),
        )
        self.assertEqual(effective.lti_1p3_tool_public_key, 'historical-public-key')
        self.assertEqual(effective.lti_1p3_tool_keyset_url, 'https://historical.example/jwks')
        self.assertNotEqual(effective.lti_1p3_tool_public_key, 'shared-public-key')
        self.assertNotEqual(effective.lti_1p3_tool_keyset_url, 'https://shared.example/jwks')

        self.placement.frozen_lti_1p3_tool_public_key = ''
        self.placement.frozen_lti_1p3_tool_keyset_url = ''
        self.placement.save()
        effective = resolve_lti_configuration(self.placement)
        self.assertEqual(effective.lti_1p3_tool_public_key, '')
        self.assertEqual(effective.lti_1p3_tool_keyset_url, '')

    def test_resolving_is_read_only(self):
        """No write, no row creation, no key generation and no block read."""
        placement_before = LtiConfiguration.objects.values().get(pk=self.placement.pk)
        configuration_before = ReusableLtiConfiguration.objects.values().get(pk=self.configuration.pk)

        with mock.patch(
            'lti_consumer.plugin.compat.load_enough_xblock', side_effect=AssertionError('block read'),
        ), mock.patch.object(
            ReusableLtiConfiguration,
            'generate_lti_1p3_keys_if_missing',
            side_effect=AssertionError('key generation'),
        ):
            effective = resolve_lti_configuration(self.placement)
            for name in OVERRIDE_FIELDS:
                getattr(effective, name)
            self.assertEqual(effective.lti_1p3_private_key, '')
            self.assertEqual(effective.lti_1p3_public_jwk, '')

        self.assertEqual(LtiConfiguration.objects.count(), 1)
        self.assertEqual(ReusableLtiConfiguration.objects.count(), 1)
        self.assertEqual(LtiConfiguration.objects.values().get(pk=self.placement.pk), placement_before)
        self.assertEqual(
            ReusableLtiConfiguration.objects.values().get(pk=self.configuration.pk), configuration_before,
        )

    def test_missing_internal_binding_raises(self):
        """An internal placement without a bound configuration never falls back."""
        for config_store, reusable_configuration in (
            (LtiConfiguration.CONFIG_ON_XBLOCK, None),
            (LtiConfiguration.CONFIG_ON_DB, None),
            ('edX', self.configuration),
        ):
            with self.subTest(config_store=config_store):
                placement = LtiConfiguration(
                    config_store=config_store,
                    reusable_configuration=reusable_configuration,
                )
                with self.assertRaises(LtiConfigurationError):
                    resolve_lti_configuration(placement)

    def test_version_drives_dispatch_and_validation(self):
        """Both consumer dispatch and validation read the resolved version, not the nullable column."""
        self.placement.version = ReusableLtiConfiguration.LTI_1P1
        self.assertEqual(self.placement.get_effective_version(), ReusableLtiConfiguration.LTI_1P1)

        with mock.patch.object(
            LtiConfiguration, '_get_lti_1p1_consumer', return_value='lti_1p1',
        ) as lti_1p1, mock.patch.object(LtiConfiguration, '_get_lti_1p3_consumer') as lti_1p3:
            self.assertEqual(self.placement.get_lti_consumer(), 'lti_1p1')
        lti_1p1.assert_called_once_with()
        lti_1p3.assert_not_called()

    def test_repr_never_exposes_credentials(self):
        """A log line or traceback cannot leak a secret or signing material."""
        self.configuration.lti_1p1_client_secret = 'shared-secret'
        self.configuration.lti_1p3_internal_private_key = 'private-key'
        self.configuration.save()

        rendered = repr(resolve_lti_configuration(self.placement))

        self.assertNotIn('shared-secret', rendered)
        self.assertNotIn('private-key', rendered)
        self.assertIn(str(self.configuration.passport_id), rendered)


class ExternalEffectiveConfigurationTests(TestCase):
    """An external placement stays a dynamic reference with no local row."""

    def setUp(self):
        super().setUp()
        self.placement = LtiConfiguration.objects.create(
            location=LOCATION,
            config_store=LtiConfiguration.CONFIG_EXTERNAL,
            external_id='app:slug',
            version=ReusableLtiConfiguration.LTI_1P1,
        )

    def _reload(self):
        return LtiConfiguration.objects.get(pk=self.placement.pk)

    @mock.patch('lti_consumer.models.get_external_config_from_filter')
    def test_external_values_are_dynamic_and_version_keeps_priority(self, filter_mock):
        filter_mock.return_value = {
            'version': ReusableLtiConfiguration.LTI_1P3,
            'lti_1p3_launch_url': 'https://external.example/launch',
        }

        effective = resolve_lti_configuration(self._reload())
        self.assertTrue(effective.is_external)
        self.assertIsNone(effective.passport_id)
        self.assertEqual(effective.config_store, LtiConfiguration.CONFIG_EXTERNAL)
        self.assertEqual(effective.version, ReusableLtiConfiguration.LTI_1P3)
        self.assertEqual(effective.value('lti_1p3_launch_url'), 'https://external.example/launch')
        # No local configuration and no ordinary defaults are materialized.
        self.assertEqual(ReusableLtiConfiguration.objects.count(), 0)
        self.assertIsNone(effective.display_name)

        filter_mock.return_value = {'lti_1p3_launch_url': 'https://external.example/second'}
        refreshed = resolve_lti_configuration(self._reload())
        self.assertEqual(refreshed.value('lti_1p3_launch_url'), 'https://external.example/second')
        # Without a provider version, the stored value stays the fallback.
        self.assertEqual(refreshed.version, ReusableLtiConfiguration.LTI_1P1)

    def test_external_resolution_never_reads_a_block_or_writes(self):
        with mock.patch('lti_consumer.models.get_external_config_from_filter', return_value={}):
            with mock.patch(
                'lti_consumer.plugin.compat.load_enough_xblock',
                side_effect=AssertionError('block read'),
            ):
                effective = resolve_lti_configuration(self._reload())

        self.assertEqual(effective.external_config, {})
        self.assertEqual(LtiConfiguration.objects.count(), 1)
        self.assertEqual(
            LtiConfiguration.objects.values().get(pk=self.placement.pk).get('reusable_configuration_id'), None,
        )
