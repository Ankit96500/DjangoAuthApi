from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import generics 
from django.http import JsonResponse
from .serializers import UserRegistrationSerializer,UserLoginSerializer,UserProfileSerializer,UserChangePasswordSerializer,SendUserPasswordResetEmailSerializer,UserPasswordResetSerializer,UserDeleteSerializer
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from accounts.renderer import customrenderer
from accounts.models import MyUser
# Create your views here.
'''.
subject = 'welcome to GFG world'
message = f'Hi {user.username}, thank you for registering in geeksforgeeks.'
email_from = settings.EMAIL_HOST_USER
recipient_list = [user.email, ]
send_mail( subject, message, email_from, recipient_list )
'''

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    # renderer_classes=[customrenderer]
    def post(self, request, format=None):
        serializer=UserRegistrationSerializer(data= request.data)
        if serializer.is_valid(raise_exception=True):
            user= serializer.save()
            print('user',user)
            token=get_tokens_for_user(user)
            return Response({'msg':'your registration has successfully done !','token':token},status=status.HTTP_200_OK)
        print(serializer.errors)
        return Response({'errors':{'non_field_errors':['email is used already']}},status=status.HTTP_400_BAD_REQUEST)
    
class UserLoginView(APIView):
    # renderer_classes=[custom_renderer]
    authentication_classes=[JWTAuthentication]
    def post(self,request,format=None):
        serializer=UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # print('serializer-->',serializer.data)
        email=serializer.data.get('email')
        password= serializer.data.get('password')
        user=authenticate(email=email,password=password)
        if user is not None:
            token=get_tokens_for_user(user)
            return Response({'msg':'you successfully Login to dashboard','token':token},status=status.HTTP_200_OK)
        else:
            print(serializer.errors)
            return Response({'errors':{'non_fields_error':['login not successfully']}},status=status.HTTP_401_UNAUTHORIZED)

class UserProfileView(APIView):
    # renderer_classes=[custom_renderer]   # its show None
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self,request,format=None):
        print('--->',request.user)
        serializer=UserProfileSerializer(request.user)
        return Response(serializer.data,status=status.HTTP_202_ACCEPTED)

class UserChangePasswordView(APIView):
    authentication_classes=[JWTAuthentication] 
    permission_classes=[IsAuthenticated]
    def post(self,request,format=None):
        serializer=UserChangePasswordSerializer(data=request.data,context={'user':request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'password changed done successfully'},status=status.HTTP_207_MULTI_STATUS)
        
class SendUserPasswordResetEmailView(APIView):
    def post(self,request,format=None):
        serializer=SendUserPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'password reset link send. Please check your mail'})

class UserPasswordResetView(APIView):
    def post(self,request,uid,token,format=None):
        print(f'uid {uid} token {token}')
        serializer=UserPasswordResetSerializer(data=request.data,context={'uid':uid,'token':token})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'password changed successsfully '})

class UserDeleteView(generics.DestroyAPIView):
    queryset = MyUser.objects.all()
    serializer_class = UserDeleteSerializer
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context={'MSG':'DATA DELETED'}
        # Add any additional context data here if needed
        return context
    
    def render_to_response(self, context, **response_kwargs):
        # Customize the response here
        custom_data = {'message': 'DATA DELETED.'}
        return JsonResponse(custom_data)