from django import forms
from .models import Script  # adapte selon ton modèle

class ScriptForm(forms.ModelForm):
    class Meta:
        model = Script
        fields = ['nom', 'description', 'code']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Ajoute les classes Tailwind à tous les widgets du formulaire
        for field_name, field in self.fields.items():
            field.widget.attrs.update({
                'class': 'block w-full rounded-md border border-gray-300 p-2 focus:border-indigo-500 focus:ring-indigo-500 focus:outline-none focus:ring-1',
                'placeholder': f'Entrez {field.label.lower()}'
            })
