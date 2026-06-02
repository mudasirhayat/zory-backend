from django.db import models

class FeatureCreditsMixin(models.Model):
home_redesign = models.IntegerField(default=0)
text_to_image = models.IntegerField(default=0)
object_removal = models.IntegerField(default=0)
  sketch_to_render = models.IntegerField(default=0)
free_generations = models.IntegerField(default=0)

class Meta:
    abstract = True

    def clean(self):
        if self.free_generations < 0:
            raise ValidationError("Free generations cannot be negative.")
