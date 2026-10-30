"""
Tests for grading fields that resolve their runtime value from the effective configuration.
"""

from unittest.mock import Mock

from django.db import DatabaseError
from django.test import SimpleTestCase
from lxml import etree
from xblock.core import XBlock
from xblock.fields import Boolean, Float, Scope, String
from xblock.utils.studio_editable import StudioEditableXBlockMixin

from lti_consumer.effective import LtiConfigurationError
from lti_consumer.fields import EffectiveBoolean, EffectiveFloat
from lti_consumer.tests.test_utils import make_xblock


class GradedBlock(StudioEditableXBlockMixin, XBlock):
    """Minimal block with the two grading fields and an injectable effective result."""

    entry_point = 'lti_consumer'
    editable_fields = ('has_score', 'weight')
    config_type = String(default='new', scope=Scope.settings)
    has_score = EffectiveBoolean(
        effective_member='enable_grading',
        display_name='This activity is graded',
        default=False,
        scope=Scope.settings,
    )
    weight = EffectiveFloat(
        effective_member='grade_weight',
        display_name='Grade Weight',
        default=1.0,
        scope=Scope.settings,
        values={'min': 0},
    )


class EffectiveGradingFieldTests(SimpleTestCase):
    """The runtime read resolves, while storage, authoring and export stay stored."""

    def setUp(self):
        super().setUp()
        self.block = make_xblock('lti_consumer', GradedBlock, {})
        self.effective = Mock(enable_grading=False, grade_weight=1.0, is_external=False)
        self.block.get_effective_configuration = Mock(return_value=self.effective)

    def test_descriptor_is_the_field_and_keeps_its_field_contract(self):
        for name, descriptor_class in (('has_score', EffectiveBoolean), ('weight', EffectiveFloat)):
            with self.subTest(field=name):
                field = GradedBlock.__dict__[name]
                self.assertIs(getattr(GradedBlock, name), field)
                self.assertIs(self.block.fields.get(name), field)
                self.assertIsInstance(field, descriptor_class)
                self.assertEqual(field.scope, Scope.settings)

        self.assertIsInstance(GradedBlock.has_score, Boolean)
        self.assertIsInstance(GradedBlock.weight, Float)
        self.assertEqual(GradedBlock.has_score.effective_member, 'enable_grading')
        self.assertEqual(GradedBlock.weight.effective_member, 'grade_weight')
        self.assertIs(GradedBlock.has_score.default, False)
        self.assertEqual(GradedBlock.weight.default, 1.0)

    def test_internal_placement_reads_effective_values_over_stored_ones(self):
        self.block.has_score = True
        self.block.weight = 4.0
        # A stale author value must not choose the branch: the resolver's source does.
        self.block.config_type = 'external'
        self.effective.enable_grading = False
        self.effective.grade_weight = 0.0

        self.assertIs(self.block.has_score, False)
        self.assertIsInstance(self.block.has_score, bool)
        self.assertEqual(self.block.weight, 0.0)
        self.assertIsInstance(self.block.weight, float)

    def test_internal_placement_uses_inherited_effective_values(self):
        self.block.has_score = False
        self.block.weight = 1.0
        self.effective.enable_grading = True
        self.effective.grade_weight = 5.0

        self.assertIs(self.block.has_score, True)
        self.assertEqual(self.block.weight, 5.0)

    def test_effective_reads_are_not_cached(self):
        self.effective.enable_grading = False
        self.effective.grade_weight = 0.0
        self.assertIs(self.block.has_score, False)
        self.effective.enable_grading = True
        self.effective.grade_weight = 2.5

        self.assertIs(self.block.has_score, True)
        self.assertEqual(self.block.weight, 2.5)
        self.assertEqual(self.block.get_effective_configuration.call_count, 3)

    def test_external_placement_keeps_the_stored_values(self):
        self.block.has_score = True
        self.block.weight = 2.5
        # A stale author value must not choose the branch: the resolver's source does.
        self.block.config_type = 'new'
        self.effective.is_external = True
        self.effective.enable_grading = False
        self.effective.grade_weight = 0.0

        self.assertIs(self.block.has_score, True)
        self.assertEqual(self.block.weight, 2.5)

    def test_missing_binding_reports_not_scorable_instead_of_stored_values(self):
        self.block.has_score = True
        self.block.weight = 4.0
        self.block.get_effective_configuration.side_effect = LtiConfigurationError('no placement')

        self.assertIs(self.block.has_score, False)
        self.assertEqual(self.block.weight, 0.0)

    def test_other_errors_are_not_swallowed(self):
        for error in (ValueError('bad configuration'), DatabaseError('database down')):
            with self.subTest(error=type(error).__name__):
                self.block.get_effective_configuration.side_effect = error
                with self.assertRaises(type(error)):
                    _ = self.block.has_score
                with self.assertRaises(type(error)):
                    _ = self.block.weight

    def test_reads_do_not_change_dirty_or_set_state(self):
        field = GradedBlock.has_score
        self.effective.enable_grading = True
        self.assertFalse(field.is_set_on(self.block))

        self.assertIs(self.block.has_score, True)

        self.assertFalse(field.is_set_on(self.block))
        self.assertEqual(self.block._dirty_fields, {})  # pylint: disable=protected-access
        self.assertEqual(self.block._field_data_cache, {})  # pylint: disable=protected-access

    def test_stored_value_drives_storage_authoring_export_and_editor(self):
        field = GradedBlock.has_score
        self.effective.enable_grading = False
        self.effective.grade_weight = 0.0

        self.assertFalse(field.is_set_on(self.block))
        self.block.has_score = True
        self.block.weight = 2.5
        self.assertTrue(field.is_set_on(self.block))

        self.assertIs(field.read_from(self.block), True)
        self.assertEqual(GradedBlock.weight.read_from(self.block), 2.5)
        self.assertIs(field.read_json(self.block), True)

        node = etree.Element('lti_consumer')
        self.block.add_xml_to_node(node)
        self.assertEqual(node.get('has_score'), 'true')
        self.assertEqual(node.get('weight'), '2.5')

        editor_info = self.block._make_field_info  # pylint: disable=protected-access
        self.assertIs(editor_info('has_score', field)['value'], True)
        self.assertEqual(editor_info('weight', GradedBlock.weight)['value'], 2.5)
