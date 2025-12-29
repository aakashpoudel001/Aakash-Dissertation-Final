from django.urls import path
from .views import RegisterView, LoginView, LogoutView, ForgotPasswordView, ResetPasswordConfirmView, predict_image, PredictionHistoryView,PredictionDeleteView 

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', ResetPasswordConfirmView.as_view(), name='password_reset_confirm'),
     path('predict/', predict_image, name='predict_image'),
     path('predictions/', PredictionHistoryView.as_view(), name='prediction_history'), # NEW: History endpoint
    path('predictions/<int:pk>/', PredictionDeleteView.as_view(), name='prediction_delete'), 
]

