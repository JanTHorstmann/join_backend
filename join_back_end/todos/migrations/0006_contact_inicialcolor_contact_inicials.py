# Generated by Django 5.1 on 2024-09-08 07:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('todos', '0005_todoitem_inwichsection'),
    ]

    operations = [
        migrations.AddField(
            model_name='contact',
            name='inicialcolor',
            field=models.CharField(default=1, max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='contact',
            name='inicials',
            field=models.CharField(default=1, max_length=100),
            preserve_default=False,
        ),
    ]
