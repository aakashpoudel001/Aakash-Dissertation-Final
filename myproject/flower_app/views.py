import os
import io
import numpy as np
from PIL import Image
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from tensorflow.keras.models import load_model
from django.core.mail import send_mail 
# Import your new model and serializer
from .models import Prediction
from .serializers import PredictionSerializer

# Load model and class names
flower_model = None
class_names = []

try:
    model_path = getattr(settings, 'KERAS_MODEL_PATH', None)
    if model_path and os.path.exists(model_path):
        flower_model = load_model(model_path)
        print(f"DEBUG: Model loaded successfully from: {model_path}")
    else:
        print(f"ERROR: Model path not found or invalid: {model_path}")
except Exception as e:
    print(f"ERROR: Failed to load model: {e}")

# Use class names from settings
class_names = getattr(settings, 'FLOWER_CLASS_NAMES', [])
print(f"DEBUG: Class names loaded: {class_names}")


# ------------------------ AUTH VIEWS ------------------------

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        if not username or not email or not password:
            return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return Response({"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, email=email, password=password)
        return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            token, _ = Token.objects.get_or_create(user=user)
            return Response({
                "message": "Login successful",
                "token": token.key,
                "username": user.username
            }, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        request.user.auth_token.delete()
        logout(request)
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)


# ------------------------ PASSWORD RESET VIEWS ------------------------

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "If an account with that email exists, a reset link has been sent."},
                            status=status.HTTP_200_OK)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = f"http://localhost:3000/reset-password/{uid}/{token}/"

        email_subject = "Password Reset Request"
        email_body = render_to_string('password_reset_email.txt', {
            'user': user,
            'reset_link': reset_link,
        })

        print("--- PASSWORD RESET EMAIL ---")
        print(f"To: {user.email}")
        print(f"Subject: {email_subject}")
        print(f"Body:\n{email_body}")
        print("--- END EMAIL ---")

      
        send_mail(email_subject, email_body, settings.DEFAULT_FROM_EMAIL, [user.email])

        return Response({"message": "If an account with that email exists, a reset link has been sent."},
                        status=status.HTTP_200_OK)


class ResetPasswordConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except Exception:
            user = None

        if user and default_token_generator.check_token(user, token):
            new_password = request.data.get('new_password')
            if not new_password:
                return Response({"error": "New password required"}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(new_password)
            user.save()
            return Response({"message": "Password has been reset successfully"}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid or expired reset link"}, status=status.HTTP_400_BAD_REQUEST)


# ------------------------ FLOWER PREDICTION VIEW ------------------------

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def predict_image(request):
    if flower_model is None:
        return Response({"error": "Model not loaded"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    if not class_names:
        return Response({"error": "Class names not loaded"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    if 'image' not in request.FILES:
        return Response({"error": "No image uploaded"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        image_file = request.FILES['image']
        img = Image.open(io.BytesIO(image_file.read()))

        if img.mode != 'RGB':
            img = img.convert('RGB')

        input_shape = flower_model.input_shape[1:3]
        img = img.resize(input_shape)
        img_array = np.array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = img_array / 255.0

        predictions = flower_model.predict(img_array)
        predicted_index = np.argmax(predictions[0])
        confidence = float(predictions[0][predicted_index])

        if 0 <= predicted_index < len(class_names):
            predicted_class = class_names[predicted_index]
        else:
            predicted_class = "Unknown"

        # --- Save the prediction to the database ---
        prediction_record = Prediction.objects.create(
            user=request.user,
            image=image_file, # Django will handle saving the file to MEDIA_ROOT
            prediction_text=predicted_class,
            confidence=confidence
        )
        # You can optionally return the ID of the saved prediction if needed
        # print(f"DEBUG: Saved prediction ID: {prediction_record.id}")

        return Response({
            "prediction": predicted_class,
            "confidence": round(confidence * 100, 2)
        }, status=status.HTTP_200_OK)

    except Exception as e:
        print(f"ERROR during prediction or saving: {e}")
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ------------------------ PREDICTION HISTORY VIEW (NEW) ------------------------

class PredictionHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Fetch predictions for the authenticated user, ordered by newest first
        predictions = Prediction.objects.filter(user=request.user).order_by('-timestamp')
        # Serialize the queryset using your PredictionSerializer
        serializer = PredictionSerializer(predictions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    


class PredictionDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        try:
            prediction = Prediction.objects.get(pk=pk, user=request.user)
            # Optionally, delete the image file from storage
            if prediction.image:
                if os.path.isfile(prediction.image.path):
                    os.remove(prediction.image.path) # Deletes the file from MEDIA_ROOT
            prediction.delete() # Deletes the record from the database
            return Response(status=status.HTTP_204_NO_CONTENT) # 204 means successful, no content
        except Prediction.DoesNotExist:
            return Response({"error": "Prediction not found or you don't have permission to delete it."},
                            status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"ERROR: Failed to delete prediction: {e}")
            return Response({"error": f"Failed to delete prediction: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)   