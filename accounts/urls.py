from django.urls import path,include
from accounts import views


urlpatterns = [
    path('UserRegistrationView',views.UserRegistrationView.as_view(),name='UserRegistration'),
    path("UserLoginView",views.UserLoginView.as_view(), name="UserLogin"),
    path("UserProfileView",views.UserProfileView.as_view(), name="UserProfile"),
    path("UserChangePasswordView",views.UserChangePasswordView.as_view(), name="UserChangePassword"),
    path("SendUserPasswordResetEmailView",views.SendUserPasswordResetEmailView.as_view(), name="SendUserPasswordResetEmail"),
    path("UserPasswordResetView/<uid>/<token>/",views.UserPasswordResetView.as_view(), name="UserPasswordReset"),
    path("UserDeleteView/<int:pk>",views.UserDeleteView.as_view(),name="UserDelete"),

]
