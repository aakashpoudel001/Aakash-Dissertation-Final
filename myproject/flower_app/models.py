
from django.db import models
from django.contrib.auth.models import User # Import User model

class Prediction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='predictions')
    image = models.ImageField(upload_to='prediction_images/') # Stores the image file
    prediction_text = models.CharField(max_length=255) # Stores the predicted class name
    confidence = models.FloatField(null=True, blank=True) # Stores prediction confidence
    timestamp = models.DateTimeField(auto_now_add=True) # Auto-adds creation time

    def __str__(self):
        return f"Prediction by {self.user.username}: {self.prediction_text}"

    @property
    def image_url(self):
        # This will return the full URL to the image if MEDIA_URL is configured
        if self.image:
            return self.image.url
        return None