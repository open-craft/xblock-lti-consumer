# Generated by Django 2.2.14 on 2020-07-17 18:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lti_consumer', '0005_auto_20200717_1827'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ltiagslineitem',
            name='end_date_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='ltiagslineitem',
            name='start_date_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]