from rest_framework import serializers
from .models import MyUser

from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from accounts.utils import util

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2=serializers.CharField(style={'input_type':'password'},
                                    write_only=True)
    class Meta:
        model= MyUser
        fields=['email','name','tc','password','password2']
        extra_kwargs={'password':{
            'write_only':True}
        }

    def validate(self, attrs):
        print('inside attrs',attrs)
        password=attrs.get('password')
        password2=attrs.get('password2')
        if password!=password2:
            raise serializers.ValidationError('password and confirm password are not match')
        return super().validate(attrs)
    
    # when we use a custom model that time we need to override the create method to create the new user.
    def create(self, validated_data):
        print('validate_ data',validated_data)
        user = MyUser.objects.create(
            email=validated_data['email'],
            name=validated_data['name'],
            tc=validated_data['tc'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
    
class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(error_messages={'errors':'sorry your email doesnt match'})
    class Meta:
        model= MyUser
        fields=['email','password']    

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=MyUser
        fields=['id','email','name']

class UserChangePasswordSerializer(serializers.ModelSerializer):
    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=MyUser
        fields=['password','password2']
        extra_kwargs={'password':{
            'write_only':True
        }}

    def validate(self,attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        user=self.context.get('user')
        if password != password2:
            raise serializers.ValidationError('password and password2 did not match')
        else:
            user.set_password(password)
            user.save()
            return attrs

class SendUserPasswordResetEmailSerializer(serializers.ModelSerializer):
    email=serializers.EmailField()
    class Meta:
        model=MyUser
        fields=['email']
        # extra_kwargs={'email':{
        #     'write_only':True
        # }}

    def validate(self,attrs):
        email=attrs.get('email')
        if MyUser.objects.filter(email=email).exists():
            user= MyUser.objects.get(email=email)
            print(f'user-- {user}     user.email-- {user.email}    force_byte id-- {force_bytes(user.id)}')
            uid=urlsafe_base64_encode(force_bytes(user.id))
            print('uid',uid)
            token=PasswordResetTokenGenerator().make_token(user)
            print('token',token)
            link = 'http://127.0.0.1:3000/api/user/reset/' + uid + '/' + token
            # link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
            print('link',link)
            # send email
            body="CLICK THE LINK AND RESET YOU PASSWORD\n" + link
            data={
                'subject':'Please Reset Your Email ',
                'body':body,
                'to_email':user.email,
            }
            return attrs
        else:
            raise serializers.ValidationError('your are not a registered user')

class UserPasswordResetSerializer(serializers.ModelSerializer):

    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=MyUser
        fields=['password','password2']
        extra_kwargs={'password':{
            'write_only':True
        }}

    def validate(self,attrs):
        try:
            password=attrs.get('password')
            password2=attrs.get('password2')
            uid=self.context.get('uid')
            token=self.context.get('token')
            if password != password2:
                raise serializers.ValidationError('password and password2 did not match')
            id=smart_str(urlsafe_base64_decode(uid))
            # print(f'id {id}  urlsafe_decode {urlsafe_base64_decode(uid)}')
            user= MyUser.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise serializers.ValidationError('TOKEN IS NOT VALID OR EXPIRED')
            user.set_password(password)
            user.save()
            return attrs    
        #  this is an extra layer of security ..   
        # IF YOU WANT TO ADD TIME-STAMP IN LINK FO TO SETTING.PY 
        except DjangoUnicodeDecodeError:
            PasswordResetTokenGenerator(user,token)
            raise serializers.ValidationError('TOKEN IS NOT VALID OR EXPIRED')    

class UserDeleteSerializer(serializers.ModelSerializer):
    class Meta:
        model=MyUser
        fields=['id']
    # def validate(self,attrs):
    #     email=attrs.get('email')
    #     if MyUser.objects.filter(email=email):
    #         pass
    #     else:
    #         raise serializers.ValidationError('this is not registerited email')
