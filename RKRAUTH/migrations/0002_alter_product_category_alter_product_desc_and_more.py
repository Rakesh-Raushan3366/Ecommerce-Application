# Generated by Django 4.1.4 on 2022-12-25 10:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("RKRAUTH", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="product",
            name="category",
            field=models.CharField(default="", max_length=80),
        ),
        migrations.AlterField(
            model_name="product",
            name="desc",
            field=models.CharField(max_length=500),
        ),
        migrations.AlterField(
            model_name="product",
            name="product_name",
            field=models.CharField(max_length=80),
        ),
        migrations.AlterField(
            model_name="product",
            name="subcategory",
            field=models.CharField(default="", max_length=80),
        ),
    ]
