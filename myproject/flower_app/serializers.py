# In your_app_name/serializers.py (e.g., api/serializers.py)
from rest_framework import serializers
from .models import Prediction

class PredictionSerializer(serializers.ModelSerializer):
    # Use image_url property defined in the model
    image_url = serializers.ReadOnlyField(source='image.url')

    class Meta:
        model = Prediction
        fields = ['id', 'user', 'image_url', 'prediction_text', 'confidence', 'timestamp']
        read_only_fields = ['user', 'timestamp'] # User and timestamp are set by the server