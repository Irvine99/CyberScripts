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
import requests

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
    def get(self, request):
        scripts_quick_links = [
            {
                'url_name': 'scripts:nmap_scan',
                'icon_path': 'M13 16h-1v-4h-1m4 4v-4a1 1 0 00-1-1h-4a1 1 0 00-1 1v4m10 4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v12a2 2 0 01-2 2z',
                'label': 'Lancer un scan Nmap',
            },
            {
                'url_name': 'scripts:dirbuster',
                'icon_path': 'M3 4a1 1 0 011-1h3.586a1 1 0 01.707.293l1.414 1.414A1 1 0 0010.414 5H20a1 1 0 011 1v13a1 1 0 01-1 1H4a1 1 0 01-1-1V4z',
                'label': 'Lancer un Gobuster',
            },
            {
                'url_name': 'scripts:ipcalculator',
                'icon_path': 'M3 4a1 1 0 011-1h3.586a1 1 0 01.707.293l1.414 1.414A1 1 0 0010.414 5H20a1 1 0 011 1v13a1 1 0 01-1 1H4a1 1 0 01-1-1V4z',
                'label': 'Lancer un Calculator IP',
            },
            {
                'url_name': 'scripts:cve_checker',
                'icon_path': 'M3 4a1 1 0 011-1h3.586a1 1 0 01.707.293l1.414 1.414A1 1 0 0010.414 5H20a1 1 0 011 1v13a1 1 0 01-1 1H4a1 1 0 01-1-1V4z',
                'label': 'Lancer un CveChecker',
            },
            {
                'url_name': 'scripts:web_recon',
                'icon_path': 'M3 4a1 1 0 011-1h3.586a1 1 0 01.707.293l1.414 1.414A1 1 0 0010.414 5H20a1 1 0 011 1v13a1 1 0 01-1 1H4a1 1 0 01-1-1V4z',
                'label': 'Lancer un WebRecon',
            },
            {
                'url_name': 'scripts:dashboard',
                'icon_path': 'M3 4a1 1 0 011-1h3.586a1 1 0 01.707.293l1.414 1.414A1 1 0 0010.414 5H20a1 1 0 011 1v13a1 1 0 01-1 1H4a1 1 0 01-1-1V4z',
                'label': 'Lancer un Dashboard MultiTools',
            },
        ]

        # Ici tu récupères ta liste de scripts personnalisés depuis ta BDD ou autre
        scripts = []  # Exemple : Model.objects.all()

        context = {
            'scripts_quick_links': scripts_quick_links,
            'scripts': scripts,
        }
        return render(request, self.template_name, context)

class ScriptDetailView(DetailView):
    model = Script
    template_name = 'scripts/script_details.html'
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
# OUTILS – Dirbuster
# =====================


class DirbusterScanView(View):
    template_name = 'scripts/dirbuster.html'

    def is_valid_target(self, target):
        # Vérifie si la cible est une URL valide avec http:// ou https://
        url_regex = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/\S*)?$'
        # Vérifie si la cible est une IP valide
        ip_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
        # Vérifie si la cible est un domaine valide sans préfixe
        domain_regex = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        return re.match(url_regex, target) or re.match(ip_regex, target) or re.match(domain_regex, target)

    def get(self, request):
        # Rendu du formulaire au départ
        return render(request, self.template_name, {
            'result': None,
            'target': '',
            'wordlist': '/DirBuster-0.12/directory-list-2.3-medium.txt',
        })

    def post(self, request):
        target = request.POST.get('target')
        wordlist = request.POST.get('wordlist', '/DirBuster-0.12/directory-list-2.3-medium.txt')

        # Ajoutez http:// si l'URL ne commence pas par http:// ou https://
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        # Vérification de la validité de la cible
        if not target or not self.is_valid_target(target):
            return render(request, self.template_name, {
                'result': "Cible invalide. Veuillez saisir une IP ou un domaine valide.",
                'target': target,
                'wordlist': wordlist,
            })

        try:
            # Commande Docker pour lancer DirBuster avec les paramètres
            command = [
                'docker', 'run', '--rm',
                'hypnza/dirbuster',
                '-u', target,
                '-l', wordlist
            ]

            # Exécution de la commande Docker
            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode != 0:
                output = f"Erreur Dirbuster : {result.stderr}"
            else:
                output = result.stdout

        except Exception as e:
            output = f"Erreur système : {str(e)}"

        return render(request, self.template_name, {
            'result': output,
            'target': target,
            'wordlist': wordlist,
        })

# =====================
# OUTILS – IpCalculator
# =====================
        
import ipaddress     
        
class IPCalculatorView(View):
    template_name = 'scripts/ipcalculator.html'

    def get_ip_class(self, ip_str):
        first_octet = int(ip_str.split('.')[0])
        if 1 <= first_octet <= 126:
            return 'A'
        elif 128 <= first_octet <= 191:
            return 'B'
        elif 192 <= first_octet <= 223:
            return 'C'
        elif 224 <= first_octet <= 239:
            return 'D (Multicast)'
        elif 240 <= first_octet <= 254:
            return 'E (Expérimental)'
        else:
            return 'Invalide'

    def is_private(self, ip_str):
        return ipaddress.IPv4Address(ip_str).is_private

    def get_wildcard_mask(self, netmask):
        # Masque inversé = 255.255.255.255 - masque
        mask_int = int(ipaddress.IPv4Address(netmask))
        wildcard_int = 0xFFFFFFFF ^ mask_int
        return str(ipaddress.IPv4Address(wildcard_int))

    def calculate_subnets(self, network, new_prefix):
        # Découpe en sous-réseaux plus petits (optionnel)
        if new_prefix <= network.prefixlen:
            return []
        return list(network.subnets(new_prefix=new_prefix))

    def get(self, request):
        return render(request, self.template_name, {'data': None})

    def post(self, request):
        ip_input = request.POST.get('ip', '').strip()
        subnet_input = request.POST.get('subnet', '').strip()
        new_subnet_input = request.POST.get('new_subnet', '').strip()  # pour découpage subnets (optionnel)

        data = None
        error = None

        try:
            subnet_int = int(subnet_input)
            if not (0 <= subnet_int <= 32):
                raise ValueError("Le masque CIDR doit être entre 0 et 32.")

            network = ipaddress.IPv4Network(f"{ip_input}/{subnet_int}", strict=False)

            hosts = list(network.hosts())
            first_host = hosts[0] if hosts else None
            last_host = hosts[-1] if hosts else None
            broadcast = network.broadcast_address
            netmask = network.netmask
            gateway = first_host

            # Calcul nombre d'hôtes (traitement spécial pour /31 et /32)
            if subnet_int == 31:
                hosts_count = 2  # point à point, 2 adresses utilisables
            elif subnet_int == 32:
                hosts_count = 1  # une seule adresse
            else:
                hosts_count = max(network.num_addresses - 2, 0)

            ip_class = self.get_ip_class(ip_input)
            is_private = self.is_private(ip_input)
            wildcard_mask = self.get_wildcard_mask(netmask)

            # Découpage en sous-réseaux plus petits (optionnel)
            subnets = []
            if new_subnet_input:
                new_prefix = int(new_subnet_input)
                if new_prefix > subnet_int and new_prefix <= 32:
                    subnets = self.calculate_subnets(network, new_prefix)
                else:
                    error = "Le nouveau préfixe doit être plus grand que le masque actuel et <= 32."

            data = {
                'ip': ip_input,
                'subnet': subnet_int,
                'netmask': str(netmask),
                'network': str(network.network_address),
                'broadcast': str(broadcast),
                'first_host': str(first_host) if first_host else 'N/A',
                'last_host': str(last_host) if last_host else 'N/A',
                'gateway': str(gateway) if gateway else 'N/A',
                'hosts_count': hosts_count,
                'ip_class': ip_class,
                'is_private': is_private,
                'wildcard_mask': wildcard_mask,
                'subnets': subnets,  # liste d’objets IPv4Network
            }

        except Exception as e:
            error = f"Erreur : {str(e)}"

        return render(request, self.template_name, {
            'data': data,
            'error': error,
            'ip_input': ip_input,
            'subnet_input': subnet_input,
            'new_subnet_input': new_subnet_input,
        })

# =====================
# OUTILS – CVEChecker
# =====================

class CVECheckerView(View):
    template_name = 'scripts/cve_checker.html'

    def get(self, request):
        return render(request, self.template_name, {'results': None, 'query': ''})

    def post(self, request):
        query = request.POST.get('query', '').strip()
        results = []
        error = None

        if not query:
            error = "Veuillez saisir un logiciel ou une version."
        else:
            try:
                url = 'https://vulners.com/api/v3/search/lucene/'
                payload = {'query': query}
                headers = {'Content-Type': 'application/json'}
                response = requests.post(url, json=payload, headers=headers, timeout=10)
                response.raise_for_status()
                data = response.json()
                print(data)  # debug

                documents = data.get('data', {}).get('search', [])

                for hit in documents:
                    source = hit.get('_source', {})
                    results.append({
                        'title': source.get('description', 'Pas de titre'),
                        'cvelist': [],  # Ici à adapter si tu trouves une liste de CVE dans la réponse
                        'published': source.get('lastseen', 'N/A'),
                        'cvss': source.get('cvss', 'N/A'),  # à vérifier si la clé existe
                        'href': f"https://vulners.com/cve/{hit.get('_id')}",  # exemple de lien CVE
                    })

            except requests.RequestException as e:
                error = f"Erreur lors de la connexion à l'API : {str(e)}"
            except Exception as e:
                error = f"Erreur inattendue : {str(e)}"

        return render(request, self.template_name, {
            'results': results if results else None,
            'query': query,
            'error': error,
        })

# =====================
# OUTILS – WebRecon
# =====================

from bs4 import BeautifulSoup
from urllib.parse import urljoin

class WebReconView(View):
    template_name = 'scripts/web_recon.html'

    def get(self, request):
        return render(request, self.template_name, {
            'url': '',
            'headers': None,
            'robots_txt': None,
            'sitemap_xml': None,
            'cms_detected': None,
            'status_code': None,
            'error': None,
        })

    def post(self, request):
        url = request.POST.get('url', '').strip()
        context = {
            'url': url,
            'headers': None,
            'robots_txt': None,
            'sitemap_xml': None,
            'cms_detected': [],
            'status_code': None,
            'error': None,
        }

        if not url:
            context['error'] = "Veuillez saisir une URL."
            return render(request, self.template_name, context)

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        def detect_cms(headers, content):
            cms = []
            if headers.get('X-Powered-By', '').lower().find('wordpress') != -1 or 'wp-content' in content:
                cms.append('WordPress')
            if 'joomla' in content.lower() or headers.get('X-Generator', '').lower().find('joomla') != -1:
                cms.append('Joomla')
            if 'drupal' in content.lower() or headers.get('X-Generator', '').lower().find('drupal') != -1:
                cms.append('Drupal')
            return cms

        def fetch_file(base_url, filename):
            try:
                full_url = urljoin(base_url, filename)
                r = requests.get(full_url, timeout=5)
                if r.status_code == 200:
                    return r.text
            except requests.RequestException:
                pass
            return None

        try:
            r = requests.get(url, timeout=10)
            context['status_code'] = r.status_code
            headers = r.headers
            content = r.text.lower()
            context['headers'] = dict(headers)
            context['cms_detected'] = detect_cms(headers, content)

            context['robots_txt'] = fetch_file(url, 'robots.txt')
            context['sitemap_xml'] = fetch_file(url, 'sitemap.xml')

        except requests.RequestException as e:
            context['error'] = f"Erreur lors de la connexion au site : {str(e)}"

        return render(request, self.template_name, context)


# =====================
# OUTILS – Dashboard multiOutils
# =====================

import socket
import dns.resolver
import whois
import requests
import ssl
import OpenSSL
import subprocess

class ReconDashboardView(View):
    template_name = "scripts/dashboard.html"

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        target = request.POST.get('target')
        context = {'target': target}

        if not target:
            context['error'] = "Veuillez saisir un domaine ou une IP."
            return render(request, self.template_name, context)

        # DNS Lookup
        try:
            answers = dns.resolver.resolve(target, 'A')
            context['dns_records'] = [rdata.to_text() for rdata in answers]
        except Exception as e:
            context['dns_error'] = str(e)

        # Whois
        try:
            w = whois.whois(target)
            context['whois'] = w
        except Exception as e:
            context['whois_error'] = str(e)

        # HTTP Headers
        try:
            r = requests.get(f"http://{target}", timeout=5)
            context['http_headers'] = dict(r.headers)
            context['status_code'] = r.status_code
        except Exception as e:
            context['http_error'] = str(e)

        # CMS Detection (très basique)
        cms = []
        try:
            r_text = r.text.lower()
            if 'wp-content' in r_text or 'wordpress' in r_text:
                cms.append('WordPress')
            if 'joomla' in r_text:
                cms.append('Joomla')
            if 'drupal' in r_text:
                cms.append('Drupal')
        except:
            pass
        context['cms_detected'] = cms

        # Port scanning (simple scan des ports communs avec socket)
        ports = [80, 443, 21, 22, 25, 53, 3306, 8080]
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        context['open_ports'] = open_ports

        # SSL info (si port 443 ouvert)
        ssl_info = {}
        if 443 in open_ports:
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
                    s.settimeout(3)
                    s.connect((target, 443))
                    cert = s.getpeercert()
                    ssl_info['issuer'] = dict(x[0] for x in cert['issuer'])
                    ssl_info['subject'] = dict(x[0] for x in cert['subject'])
                    ssl_info['notBefore'] = cert['notBefore']
                    ssl_info['notAfter'] = cert['notAfter']
            except Exception as e:
                ssl_info['error'] = str(e)
        context['ssl_info'] = ssl_info

        # Reputation (exemple très simple avec Shodan, nécessite clé API)
        # A adapter ensuite avec ta clé API et gestion complète
        shodan_api_key = 'mfIjK4RvNkuoWea361scJTPsdUJhzsCh'
        try:
            import json
            import requests as req
            headers = {'Accept': 'application/json'}
            url = f"https://api.shodan.io/shodan/host/{target}?key={shodan_api_key}"
            shodan_response = req.get(url, headers=headers, timeout=5)
            if shodan_response.status_code == 200:
                context['shodan_data'] = shodan_response.json()
            else:
                context['shodan_error'] = f"Shodan API error: {shodan_response.status_code}"
        except Exception as e:
            context['shodan_error'] = str(e)

        return render(request, self.template_name, context)