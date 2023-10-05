from . models import User 
from rest_framework import serializers 
from django.contrib.auth.hashers import make_password, check_password 
from secrets import token_hex 
import datetime 

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User 
        fields = ('id', 'first_name', 'last_name','age','email','phone','token','token_expires')

class UserSignUpSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required = True)
    email = serializers.EmailField(required = True) 
    age = serializers.IntegerField(required = True)
    phone = serializers.CharField(required = True)
    password = serializers.CharField(write_only = True, required = True) 
    token = serializers.CharField(read_only = True) 
    token_expires = serializers.DateTimeField(read_only = True) 

    class Meta:
        model = User 
        fields = ('id','name','first_name','last_name','email','password','token','token_expires')
        
    # overwrite create() 
    def create(self, validated_data):

       """
       The create() method in the ModelSerializer class in Django REST Framework is used
       to create a new instance of the model that the serializer is associated with. 
       The method takes a single argument, validated_data, which is a dictionary of data 
       that has been validated by the serializer. The method then creates a 
       new instance of the model and saves it to the database.
       """


       if User.objects.filter(data=validated_data['email']).exists():
           raise serializers.ValidationError({'email':['The email is already taken']})
       
       # Encrypt password
       validated_data['password'] = make_password(validated_data['password'])

       """
       The make_password() function in the Django REST framework is used
        to hash a password for storing in the database.

        The purpose of hashing passwords is to protect them from unauthorized access. 
        If a password is stored in cleartext (i.e., in its original form), then anyone 
        who has access to the database could easily read it. By hashing the password, 
        it becomes much more difficult to read, even if someone has access to the database.
       """

       # create a token
       validated_data['token'] = token_hex(30) 
       validated_data['token_expires'] = datetime.datetime.now() + datetime.timedelta(days=7) 

       return super().create(validated_data)
    
class UserSignInSerializer(serializers.ModelSerializer):

    email = serializers.EmailField(write_only = True)
    password = serializers.CharField(write_only = True )
    token = serializers.CharField(read_only = True)
    token_expires = serializers.DateTimeField(read_only=True)

    class Meta:
        model = User
        fields = ('id','email','password','token','token_expires')

    def create(self, validated_data):

        """
        
        A QuerySet in Django is a collection of objects that are retrieved from a database. 
        QuerySets are created by calling the objects method on a model class.
        QuerySets can be filtered, ordered, and sliced.

        The filter() method in Django is used to filter a QuerySet. 
        The filter() method takes a dictionary of keyword arguments as its argument. 
        The keys of the dictionary are the field names, and the values of the dictionary are the values 
        that the fields should match.

        The filter() method in Django returns a list of objects that match the filter criteria. 

        The first element in the list returned by the filter() method in Django is the first object
        that matches the filter criteria.
        """
        
        user = User.objects.filter(email=validated_data['email']).first()

        if len(user)>0 and check_password(validated_data['password'], user.password):
            user.token = token_hex(30)
            user.token_expires = datetime.datetime.now() + datetime.timedelta(days = 7)
            user.save() 

            return user
        
        else: 
            raise serializers.ValidationError({'error':'The email or password is incorrect'})
