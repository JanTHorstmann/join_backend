from django.db import models
from django.conf import settings
from django.db.models import JSONField
import datetime

class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    inicials = models.CharField(max_length=100)
    inicialcolor = models.CharField(max_length=100)
    phone = models.CharField(max_length=100)
    token = models.CharField(max_length=100)

class TodoItem(models.Model):
    title = models.CharField(max_length=100)
    description = models.CharField(max_length=300)
    assigned_to = models.ManyToManyField(Contact, blank=True)
    due_date = models.DateField(default=datetime.date.today)
    priority = models.CharField(max_length=300)
    category = models.CharField(max_length=300)
    subtasks = JSONField(default=list)
    created_at = models.DateField(default=datetime.date.today)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True 
    ) 
    token = models.CharField(max_length=100)
    inWichSection = models.CharField(max_length=10)

class UserToken(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='token')
    token = models.CharField(max_length=100)

    def __str__(self):
        return f"Token for {self.user.username}: {self.token}"