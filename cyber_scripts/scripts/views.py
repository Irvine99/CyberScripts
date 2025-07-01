from django.views.generic import (
    TemplateView, ListView, CreateView, UpdateView, DeleteView, DetailView
)
from django.views import View
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.contrib.auth.forms import UserCreationForm
from .models import Script
from .forms import ScriptForm
import subprocess
import re

# =====================
# VUES PUBLIQUES
# =====================

class IndexView(TemplateView):
    template_name = 'index.html'


class ScriptListView(ListView):
    model = Script
    template_name = 'scripts/liste.html'
    context_object_name = 'scripts'
    paginate_by = 5

    def get_queryset(self):
        queryset = super().get_queryset()
        query = self.request.GET.get('q')
        if query:
            queryset = queryset.filter(
                Q(nom__icontains=query) | Q(description__icontains=query)
            )
        return queryset


class ScriptDetailView(DetailView):
    model = Script
    template_name = 'scripts/script_detail.html'
    context_object_name = 'script'


# =====================
# AUTHENTIFICATION
# =====================

def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = UserCreationForm()
    return render(request, 'registration/signup.html', {'form': form})


# =====================
# GESTION DES SCRIPTS (REQUIERT LOGIN)
# =====================

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


# =====================
# EXÉCUTION DE SCRIPTS
# =====================

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


# =====================
# OUTILS – NMAP
# =====================

import re
import subprocess
from django.views import View
from django.shortcuts import render


class NmapScanView(View):
    template_name = 'scripts/nmap.html'

    def is_valid_target(self, target):
        ip_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_regex = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(ip_regex, target) or re.match(domain_regex, target)

    def parse_arguments(self, args_str):
        ALLOWED_NMAP_ARGS = ['-sV', '-p', '-Pn', '-T4', '-sS', '-O', '-A']
        args = args_str.split()
        clean_args = []

        for i, arg in enumerate(args):
            if arg in ALLOWED_NMAP_ARGS:
                clean_args.append(arg)
            elif any(arg.startswith(prefix) for prefix in ['-p']):
                clean_args.append(arg)
            elif i > 0 and args[i - 1] in ALLOWED_NMAP_ARGS:
                clean_args.append(arg)
            else:
                raise ValueError(f"Argument non autorisé : {arg}")
        return clean_args

    def parse_nmap_output(self, output):
        """
        Parse la sortie texte Nmap pour extraire la liste des ports ouverts.
        Renvoie une liste de dicts avec clés : port, state, service, version.
        """
        ports = []
        lines = output.splitlines()
        capture = False

        for line in lines:
            if re.match(r'^PORT\s+STATE\s+SERVICE', line):
                capture = True
                continue
            if capture:
                if line.strip() == '' or line.startswith('Service detection performed'):
                    break
                parts = re.split(r'\s+', line, maxsplit=3)
                if len(parts) >= 3:
                    port = parts[0]
                    state = parts[1]
                    service = parts[2]
                    version = parts[3] if len(parts) == 4 else ''
                    ports.append({
                        'port': port,
                        'state': state,
                        'service': service,
                        'version': version
                    })
        return ports

    def get(self, request):
        return render(request, self.template_name, {'result': None})

    def post(self, request):
        target = request.POST.get('target')
        arguments = request.POST.get('arguments', '-sV')

        if not target or not self.is_valid_target(target):
            return render(request, self.template_name, {
                'result': "Cible invalide. Veuillez saisir une IP ou un domaine valide.",
                'target': target,
                'arguments': arguments,
                'ports': []
            })

        try:
            parsed_args = self.parse_arguments(arguments)
            command = ['docker', 'run', '--rm', 'nmap-container'] + parsed_args + [target]
            output = subprocess.check_output(
                command,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=60
            )
            ports = self.parse_nmap_output(output)

        except subprocess.CalledProcessError as e:
            output = f"Erreur Nmap : {e.output}"
            ports = []
        except Exception as e:
            output = f"Erreur système : {str(e)}"
            ports = []

        return render(request, self.template_name, {
            'result': output,
            'target': target,
            'arguments': arguments,
            'ports': ports
        })

# =====================
# OUTILS – Gobuster
# =====================

class GobusterScanView(View):
    template_name = 'scripts/gobuster.html'

    def is_valid_target(self, target):
        # Simple validation pour un domaine ou URL basique
        domain_regex = r'^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
        return re.match(domain_regex, target)

    def parse_arguments(self, args_str):
        # Autorise ces options : -w wordlist, -t threads, -u url, -x extensions
        ALLOWED_ARGS = ['-w', '-t', '-x', '-u', '-s', '-e']  # Exemples d’options autorisées
        args = args_str.split()
        clean_args = []

        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ALLOWED_ARGS:
                clean_args.append(arg)
                # Certaines options ont un argument suivant
                if i + 1 < len(args):
                    clean_args.append(args[i+1])
                    i += 1
            else:
                # Pour des flags sans arguments, on peut autoriser ici si besoin
                raise ValueError(f"Argument non autorisé : {arg}")
            i += 1
        return clean_args

    def get(self, request):
        return render(request, self.template_name, {'result': None})

    def post(self, request):
        target = request.POST.get('target')
        arguments = request.POST.get('arguments', '-w /usr/share/wordlists/dirb/common.txt -t 50')

        if not target or not self.is_valid_target(target):
            return render(request, self.template_name, {
                'result': "Cible invalide. Veuillez saisir une URL ou un domaine valide.",
                'target': target,
                'arguments': arguments
            })

        try:
            parsed_args = self.parse_arguments(arguments)
            # Injecter l’url (target) en option -u si pas déjà dans les arguments
            if '-u' not in parsed_args:
                parsed_args += ['-u', target]

            command = ['docker', 'run', '--rm', 'gobuster-container'] + parsed_args

            output = subprocess.check_output(
                command,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=120  # timeout un peu plus long que nmap
            )
        except subprocess.CalledProcessError as e:
            output = f"Erreur Gobuster : {e.output}"
        except Exception as e:
            output = f"Erreur système : {str(e)}"

        return render(request, self.template_name, {
            'result': output,
            'target': target,
            'arguments': arguments
        })
