import requests
from django.conf import settings
import hashlib
from datetime import datetime as dt

def get_cves(keyword=None, start_date=None, last_date=None, severity=None):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {
        'startIndex': 0,
        'resultsPerPage': 100,
    }
    if keyword:
        params['keywordSearch'] = keyword
    if severity:
        params['cvssV3Severity'] = severity
    if start_date and last_date:
        params['pubStartDate'] = start_date
        params['pubEndDate'] = last_date
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        return []
    results = []
    for cve in data.get('vulnerabilities', []):
        cve_id = cve['cve']['id']
        description = cve['cve']['descriptions'][0]['value']
        published = cve['cve'].get('published', None)
        results.append({'id': cve_id, 'description': description, 'published': published})
    return [
        {'id': r['id'], 'description': r['description']}
        for r in results
    ]

def get_cve_details(cve_id):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {'cveId': cve_id}
    result = {
        'id': cve_id,
        'description': 'Description not available.',
        'published': '',
        'last_modified': '',
        'cvss_v31_base_score': '',
        'cvss_v31_base_severity': '',
        'references': [],
        'weaknesses': [],
    }
    try:
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        cve = data['vulnerabilities'][0]['cve']
        descs = cve.get('descriptions', [])
        for desc in descs:
            if desc.get('lang') == 'en':
                result['description'] = desc.get('value', result['description'])
                break
       
        result['published'] = cve.get('published', '')
        result['last_modified'] = cve.get('lastModified', '')

        v31 = cve.get('metrics',{}).get('cvssMetricV31', [])
        v30 = cve.get('metrics',{}).get('cvssMetricV30', [])
        v20 = cve.get('metrics',{}).get('cvssMetricV2', [])
        if v31:
            cvss = v31[0].get('cvssData', {})
            result['cvss_v31_base_score'] = cvss.get('baseScore', '')
            result['cvss_v31_base_severity'] = cvss.get('baseSeverity', '')
        elif v30:
            cvss = v30[0].get('cvssData', {})
            result['cvss_v31_base_score'] = cvss.get('baseScore', '')
            result['cvss_v31_base_severity'] = cvss.get('baseSeverity', '')
        elif v20:
            cvss = v20[0].get('cvssData', {})
            result['cvss_v31_base_score'] = cvss.get('baseScore', '')
            result['cvss_v31_base_severity'] = v20[0].get('baseSeverity', '')

        refs = cve.get('references', [])
        result['references'] = [r.get('url') for r in refs if r.get('url')]

        weaknesses = cve.get('weaknesses', [])
        cwe_list = []
        for w in weaknesses:
            for d in w.get('description', []):
                if d.get('lang') == 'en':
                    cwe_list.append(d.get('value'))
        result['weaknesses'] = cwe_list

    except Exception:
        return None
    return result

def scan_file_virustotal(file_obj):
    api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
    
    file_obj.seek(0)
    sha256 = hashlib.sha256(file_obj.read()).hexdigest()
    file_obj.seek(0)
    url = f'https://www.virustotal.com/api/v3/files/{sha256}'
    headers = {
        "accept": "application/json",
        'x-apikey': api_key
    }
    def ts(tsval):
        try:
            return dt.fromtimestamp(tsval).strftime('%Y-%m-%d %H:%M')
        except Exception:
            return ''
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            scan_result = response.json()
            attr = scan_result['data'].get('attributes', {})
            return {
                'sha256': scan_result['data'].get('id'),
                'file_name': attr.get('meaningful_name') or (attr.get('names') or ['Unknown'])[0],
                'type': attr.get('type_description') or attr.get('type_extension'),
                'size': attr.get('size'),
                'md5': attr.get('md5'),
                'sha1': attr.get('sha1'),
                'last_analysis_stats': attr.get('last_analysis_stats'),
                'last_analysis_date': ts(attr.get('last_analysis_date')),
                'signature': attr.get('signature_info', {}).get('signers'),
                'virustotal_link': f"https://www.virustotal.com/gui/file/{scan_result['data'].get('id')}"
            }
        elif response.status_code == 404:
            return {'error': 'File not found in VirusTotal database. Free API cannot upload new files.'}
        else:
            return {'error': f'VirusTotal error: {response.status_code} {response.text}'}
    except Exception as e:
        return {'error': str(e)}
    