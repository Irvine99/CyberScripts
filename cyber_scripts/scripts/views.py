from django.views.generic import TemplateView, ListView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from .models import Script
from .forms import ScriptForm
import subprocess
from django.views import View
from django.shortcuts import render, get_object_or_404
from django.db.models import Q
from django.contrib.auth.mixins import LoginRequiredMixin

class IndexView(TemplateView):
    template_name = 'index.html'


class ScriptListView(ListView):
    model = Script
    template_name = 'scripts/liste.html'
    context_object_name = 'scripts'
    paginate_by = 5

    def get_queryset(self):
        qs = super().get_queryset()
        query = self.request.GET.get('q')
        if query:
            qs = qs.filter(Q(nom__icontains=query) | Q(description__icontains=query))
        return qs


class ScriptManageListView(LoginRequiredMixin, ListView):
    model = Script
    template_name = 'scripts/manage.html'
    context_object_name = 'scripts'


class ScriptCreateView(LoginRequiredMixin, CreateView):
    model = Script
    form_class = ScriptForm
    template_name = 'scripts/script_form.html'
    success_url = reverse_lazy('scripts:manage_scripts')


class ScriptUpdateView(LoginRequiredMixin, UpdateView):
    model = Script
    form_class = ScriptForm
    template_name = 'scripts/script_form.html'
    success_url = reverse_lazy('scripts:manage_scripts')


class ScriptDeleteView(LoginRequiredMixin, DeleteView):
    model = Script
    template_name = 'scripts/script_confirm_delete.html'
    success_url = reverse_lazy('scripts:manage_scripts')


class ScriptRunView(View):
    template_name = 'scripts/script_run.html'

    def get(self, request, pk):
        script = get_object_or_404(Script, pk=pk)
        return render(request, self.template_name, {'script': script, 'output': None})

    def post(self, request, pk):
        script = get_object_or_404(Script, pk=pk)
        try:
            process = subprocess.run(
                ['python', '-c', script.code],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = process.stdout or process.stderr
        except Exception as e:
            output = f"Erreur lors de l'exécution: {e}"

        return render(request, self.template_name, {'script': script, 'output': output})
    
class ScriptListView(ListView):
    model = Script
    template_name = 'scripts/liste.html'
    context_object_name = 'scripts'
    paginate_by = 5  # par ex. 5 scripts par page

from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect

def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')  # Redirige vers la page de login après inscription
    else:
        form = UserCreationForm()
    return render(request, 'registration/signup.html', {'form': form})