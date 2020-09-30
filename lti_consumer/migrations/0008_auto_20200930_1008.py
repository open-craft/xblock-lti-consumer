# Generated by Django 2.2.16 on 2020-09-30 10:08

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('lti_consumer', '0007_auto_20200717_2011'),
    ]

    operations = [
        migrations.AlterField(
            model_name='lticonfiguration',
            name='config_store',
            field=models.CharField(choices=[('CONFIG_ON_XBLOCK', 'Configuration Stored on XBlock fields')], default='CONFIG_ON_XBLOCK', max_length=255),
        ),
        migrations.AlterField(
            model_name='lticonfiguration',
            name='version',
            field=models.CharField(choices=[('lti_1p1', 'LTI 1.1'), ('lti_1p3', 'LTI 1.3 (with LTI Advantage Support)')], default='lti_1p1', max_length=10),
        ),
        migrations.CreateModel(
            name='LtiAgsScore',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField()),
                ('score_given', models.IntegerField()),
                ('score_maximum', models.IntegerField()),
                ('comment', models.TextField()),
                ('activity_progress', models.CharField(choices=[('initialized', 'Initialized'), ('started', 'Started'), ('in_progress', 'InProgress'), ('submitted', 'Submitted'), ('completed', 'Completed')], max_length=20)),
                ('grading_progress', models.CharField(choices=[('fully_graded', 'FullyGraded'), ('pending', 'Pending'), ('pending_manual', 'PendingManual'), ('failed', 'Failed'), ('not_ready', 'NotReady')], max_length=20)),
                ('user_id', models.CharField(max_length=255)),
                ('line_item', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scores', to='lti_consumer.LtiAgsLineItem')),
            ],
        ),
    ]
