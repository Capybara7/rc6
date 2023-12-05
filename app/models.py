"""
Definition of models.
"""

from django.db import models

class MyImage(models.Model):
    image = models.ImageField(upload_to='images/')

# Create your models here.
