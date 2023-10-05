from django.db import models
from cloudinary.models import CloudinaryField

class Room(models.Model):

    categories = [
        ('single','single'),
        ('double', 'double'),
        ('twin', 'twin'),
        ('suite', 'suite')
    ]

    room_number = models.IntegerField('room_number',blank=False, null=False, defaullt = 0)

    image = CloudinaryField('img', blank=False, null=False)

    title = models.CharField('title',blank=False, null=False, db_index=True)

    description = models.TextField('description', max_length=2000, blank=False,null=False)

    capacity = models.IntegerField('capacity', blank=False, null=False, db_index=True, default=0,choices=categories)

    occupied = models.BooleanField('occupied', null=False, blank=False, db_index=True)

    price = models.IntegerField('price', blank=False, null=False, default=0) 

    room_type = models.CharField('room_type', null=False, blank=False, choices=categories, max_length=15)

    room_area = models.IntegerField('room_area',null=False, blank=False, default = 0)

    def __str__(self):
        return self.title
