from django.db import models

class Script(models.Model):
    nom = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    code = models.TextField()  # pour stocker le script
    date_creation = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True, help_text="Description professionnelle détaillée du script")


    def __str__(self):
        return self.nom
