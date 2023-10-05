from django.db import models
from django.utils import timezone
from apps.room.models import Room

# Create your models here.
class User(models.Model):

    user_room = models.ForeignKey(Room , related_name='related_user_room', on_delete=models.DO_NOTHING)

    first_name = models.CharField('first_name', max_length=15, blank=False, null=False, db_index=True)

    last_name = models.CharField('last_name', max_length=15, blank=True, null = False, db_index=True)

    age = models.PositiveIntegerField('age', default=0, blank=False, null=False)

    email = models.EmailField('email', max_length=50, blank=False, null=False, db_index=True)

    phone = models.CharField('phone', max_length=15, blank=False, null=False)

    created_at = models.DateTimeField('created_at', default=timezone.now)

    gender = models.CharField('gender', blank=False, null=False, choices=(('Male','Male'),('Female','Female')), max_length=10)

    password = models.CharField('password', blank=False, null=False, max_length=255)

    token = models.CharField('token', blank=False, null=False, max_length=500)

    token_expires = models.DateTimeField('token_expiration_date', blank=True, null=True)

    def __str__(self):
        return self.first_name 


