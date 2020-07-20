# Generated by Django 2.2.14 on 2020-07-17 17:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lti_consumer', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='lticonfiguration',
            name='version',
            field=models.CharField(choices=[('LTI_1P1', 'LTI 1.1'), ('LTI_1P3', 'LTI 1.3 (with LTI Advantage Support)')], default='LTI_1P1', max_length=10),
        ),
    ]
