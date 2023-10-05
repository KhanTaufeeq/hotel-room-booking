from django.db import models
from apps.user.models import User 
from django.utils import timezone
from apps.room.models import Room
# Create your models here.

class Booking(models.Model):

    class Meta(object):
        db_table = 'booking'

    user = models.ForeignKey(User, on_delete=models.CASCADE,related_name='booking_user')

    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='booking_room')

    check_in = models.DateTimeField('check_in', auto_now=True, default = timezone.now)

    check_out = models.DateTimeField('check_out', auto_now=True, default=timezone.now)
