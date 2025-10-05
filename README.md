# Check this out! vulntracker.up.railway.app

# VulnTracker 🔍
VulnTracker is a web application developed using Python with  Django framework. Its main purpose is to help users find and manage information about software security vulnerabilities, known as CVEs (Common Vulnerabilities and Exposures).
The app also allows users to upload files (up to 650 MB) and scan them using the VirusTotal service, which checks the file against multiple antivirus engines. After the scan, users can view the results to see if any threats were detected.
In addition to scanning, users can browse a list of vulnerabilities, save important CVEs to their favorites for quick access, and post comments to discuss solutions or share opinions with others.
The application uses a PostgreSQL database provided by Supabase for storing data and handling user authentication.

## ✨ Features
- 🔍 Search and filter CVEs by ID, keywords, severity, or publication date.
- 📌 Save CVEs to favorites for quick access.

- 💬 Comment on individual CVEs to share insights or discuss mitigation strategies.
- 🧪 Scan suspicious files (up to 650MB) via the VirusTotal API.

- 📄 View scan history and detailed detection scores.

- 🔐 User authentication powered by Supabase.

- ⚙️ Edit account info: username, email, and password.

## 🧪 REST API Endpoints
- GET /api/scaninfos — Returns all scan records.

- GET /api/scaninfos/hash — Returns details for a specific scan based on the SHA256 hash.

## 🧰 Technologies Used
- Django – Web framework

- Django REST Framework – API support

- Supabase – User authentication and PostgreSQL backend

- VirusTotal API – Malware scanning

- Railway.app – Hosting

## 📚 External APIs
- NVD CVE API – For vulnerability data

- VirusTotal API – For file scanning

## 📥 Installation
### Clone the repository:

```bash
git clone https://github.com/viorel0/vulntracker.git
```

## 🚀 Running the App


### Install dependencies:

```bash
pip install -r requirements.txt
```
### Create and configure a .env file in the root directory with the following values:
```bash
POSTGRES_HOST=your_postgres_host
POSTGRES_PORT=your_postgres_port
POSTGRES_DB=your_database_name
POSTGRES_USER=your_username
POSTGRES_PASSWORD=your_password
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

### Apply migrations and run the server:

```bash
python manage.py migrate
python manage.py runserver
```
### Open your browser and navigate to:

```
http://127.0.0.1:8000/
```

## Screenshots from webpage
<img width="1919" height="1039" alt="login_page" src="https://github.com/user-attachments/assets/61664121-7be1-43fc-b896-54056854694c" />
<img width="1919" height="1040" alt="register_page" src="https://github.com/user-attachments/assets/eedc8ae9-6202-432d-9736-c5f4995929bb" />
<img width="1919" height="1037" alt="registration_successful_page" src="https://github.com/user-attachments/assets/2775d8fd-6741-4678-b700-4e8b589cecb4" />
<img width="1919" height="1035" alt="dashboard" src="https://github.com/user-attachments/assets/21757d66-6390-4ec7-b401-19bc1981494d" />
<img width="1917" height="1037" alt="cve_detail_page" src="https://github.com/user-attachments/assets/d66f6a0e-48c2-4727-b5ce-85768b60f516" />
<img width="1919" height="1038" alt="faorites_cve" src="https://github.com/user-attachments/assets/416f22e1-87ee-4467-9e3c-5a908b5b0536" />
<img width="1919" height="1038" alt="virus_scan_page" src="https://github.com/user-attachments/assets/efd21fa2-1401-4d8c-ae08-c5c2943fc567" />
<img width="1919" height="1035" alt="virus_scan_detailscan" src="https://github.com/user-attachments/assets/53286f5a-ea36-4d04-beef-6c8bd039bb1e" />
<img width="1919" height="1036" alt="settings_page" src="https://github.com/user-attachments/assets/b14e1890-15a4-4f6f-b2f8-b12852ecb18d" />



