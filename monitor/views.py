from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login as auth_login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.core.cache import cache
from .apicall import get_cves, get_cve_details, scan_file_virustotal
from .models import FavoriteCVE, CVEComment, VirusScan, ScanInfo
from datetime import datetime, timedelta
import requests

def home_redirect(request):
    return redirect('login')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    error = None
    success = None
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            success = "Successfully logged in."
            auth_login(request, user)
            return redirect('dashboard')
        else:
            error = 'Invalid username or password.'
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form, 'error': error, 'success': success})

@login_required
def dashboard_view(request):
    start = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    end = datetime.now().strftime("%Y-%m-%d")
    keyword = request.GET.get('keyword')
    if not keyword:
        keyword=''
    start_date = request.GET.get('start_date') or start
    end_date = request.GET.get('end_date') or end
    severity = request.GET.get('severity')
    cwe=request.GET.get('cwe_id', '').strip()

    error_message = None
    if cwe:
        cwe_id=get_cve_details(cwe)
        if cwe_id and 'id' in cwe_id:
            return redirect('aboutcve', cve_id=cwe_id['id'])
        else:
            error_message = f"No results for: {cwe}"
   
    cache_key = f'cves_{keyword}_{f"{start_date}T00:00:00.000"}_{f"{end_date}T00:00:00.000"}_{severity}'
    cves = cache.get(cache_key)
    if not cves:
        cves = get_cves(keyword, start_date=f"{start_date}T00:00:00.000", last_date=f"{end_date}T00:00:00.000", severity=severity)
        cache.set(cache_key, cves, 600)
    page_number = request.GET.get('page', 1)
    paginator = Paginator(cves, 10)
    page_obj = paginator.get_page(page_number)
    return render(request, 'dashboard.html', {
        'user': request.user,
        'page_obj': page_obj,
        'keyword': keyword,
        'start_date': start_date,
        'end_date': end_date,
        'severity': severity,
        'cwe_id': cwe,
        'error_message': error_message
    })

def aboutcve_view(request, cve_id):
    user = request.user
    if request.method == 'POST' and 'favorite' in request.POST and user.is_authenticated:
        fav, created = FavoriteCVE.objects.get_or_create(user=user, cve_id=cve_id)
        if not created:
            fav.delete()
    if request.method == 'POST' and 'comment' in request.POST and user.is_authenticated:
        comment_text = request.POST.get('comment', '').strip()
        if comment_text:
            CVEComment.objects.create(user=user, cve_id=cve_id, comment=comment_text)
    details = get_cve_details(cve_id)
    if details.get('published'):
        details['published'] = datetime.fromisoformat(details['published'].replace('Z', '+00:00'))
    if details.get('last_modified'):
        details['last_modified'] = datetime.fromisoformat(details['last_modified'].replace('Z', '+00:00'))
    is_favorite = FavoriteCVE.objects.filter(user=user, cve_id=cve_id).exists()
    comments = CVEComment.objects.filter(cve_id=cve_id).select_related('user').order_by('-created_at')
    return render(request, 'aboutcve.html', {
        'cve_id': cve_id,
        'details': details,
        'is_favorite': is_favorite,
        'comments': comments,
    })


@login_required
def settings_view(request):
    user = request.user
    success = None
    error = None
    edit_username = False
    edit_email = False
    edit_password = False
    if request.method == 'POST':
        if 'edit_username' in request.POST:
            edit_username = True
        elif 'cancel_edit' in request.POST:
            edit_username = False
        elif 'update_username' in request.POST:
            username = request.POST.get('username', '').strip()
            if username and username != user.username:
                if User.objects.filter(username=username).exclude(pk=user.pk).exists():
                    error = 'Username already taken.'
                    edit_username = True
                else:
                    user.username = username
                    user.save()
                    success = 'Username updated successfully.'
            else:
                edit_username = False


        elif 'edit_email' in request.POST:
            edit_email = True
        elif 'cancel_edit_email' in request.POST:
            edit_email = False
        elif 'update_email' in request.POST:
            email = request.POST.get('email', '').strip()
            if email != user.email:
                if email and User.objects.filter(email=email).exclude(pk=user.pk).exists():
                    error = 'Email already taken.'
                    edit_email = True
                else:
                    user.email = email
                    user.save()
                    success = 'Email updated successfully.'
            else:
                edit_email = False


        elif 'edit_password' in request.POST:
            edit_password = True
        elif 'cancel_edit_password' in request.POST:
            edit_password = False
        elif 'update_password' in request.POST:
            password = request.POST.get('password', '').strip()
            if password:
                user.set_password(password)
                user.save()
                update_session_auth_hash(request, user)
                success = 'Password updated successfully.'
                edit_password = False
            else:
                error = 'Password cannot be empty.'
                edit_password = True

                
    return render(request, 'settings.html', {
        'user': user,
        'success': success,
        'error': error,
        'edit_username': edit_username,
        'edit_email': edit_email,
        'edit_password': edit_password
    })

@login_required
def favorites_view(request):
    user = request.user
    favorites = FavoriteCVE.objects.filter(user=user).order_by('-added_at')
    return render(request, 'favorites.html', {'favorites': favorites})

@login_required
def virus_scan_view(request):
    if request.method == 'POST' and request.FILES.get('file'):
        file_obj = request.FILES['file']
        scan_result = scan_file_virustotal(file_obj)
        if scan_result and not scan_result.get('error'):
            scan_info, _ = ScanInfo.objects.get_or_create(
                sha256=scan_result.get('sha256'),
                defaults={
                    'file_name': scan_result.get('file_name'),
                    'type': scan_result.get('type'),
                    'size': scan_result.get('size'),
                    'md5': scan_result.get('md5'),
                    'sha1': scan_result.get('sha1'),
                    'last_analysis_stats': scan_result.get('last_analysis_stats'),
                    'last_analysis_date': scan_result.get('last_analysis_date'),
                    'signature': scan_result.get('signature'),
                    'virustotal_link': scan_result.get('virustotal_link'),
                }
            )
            VirusScan.objects.create(
                user=request.user,
                file_name=file_obj.name,
                scan_info=scan_info
            )
            scan_instance = VirusScan.objects.filter(user=request.user, scan_info=scan_info).order_by('-scanned_at').first()
            return redirect('virus_scan_detail', file_name=scan_instance.file_name)
    scans = VirusScan.objects.filter(user=request.user).order_by('-scanned_at')[:10]
    return render(request, 'virus.html', {'scans': scans})

@login_required
def virus_scan_detail_view(request, file_name):
    scan = VirusScan.objects.filter(file_name=file_name, user=request.user).order_by('-scanned_at').first()
    sha = scan.scan_info.sha256
    api_url = request.build_absolute_uri(f"/api/scaninfos/{sha}/")
    scan_info_data = None
    response = requests.get(api_url)
    if response.status_code == 200:
        results = response.json()
        scan_info_data = {
            'id': results[0].get("id"),
            'sha256': results[0].get("sha256"),
            'file_name': results[0].get("file_name"),
            'type': results[0].get("type"),
            'size': results[0].get("size"),
            'md5': results[0].get("md5"),
            'sha1': results[0].get("sha1"),
            'last_analysis_stats': results[0].get("last_analysis_stats"),
            'last_analysis_date': results[0].get("last_analysis_date"),
            'signature': results[0].get("signature"),
            'virustotal_link': results[0].get("virustotal_link")
            }
    return render(request, 'virus_scan_detail.html', {
        'scan': scan,
        'scan_info_data': scan_info_data,
    })
