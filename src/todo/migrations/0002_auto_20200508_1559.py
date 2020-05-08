# Generated by Django 3.0.6 on 2020-05-08 15:59

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('todo', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='todo',
            name='date',
            field=models.DateField(default=datetime.datetime(2020, 5, 8, 15, 59, 0, 655417, tzinfo=utc)),
        ),
        migrations.CreateModel(
            name='Auth0User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=255)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
