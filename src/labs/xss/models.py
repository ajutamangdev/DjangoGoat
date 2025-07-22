from django.db import models
from django.utils import timezone

class Comment(models.Model):
    """
    Model for storing user comments in the Stored XSS lab.
    """
    name = models.CharField(max_length=100)
    comment = models.TextField()
    date = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-date']

    def __str__(self):
        return f"Comment by {self.name} on {self.date.strftime('%Y-%m-%d %H:%M')}"