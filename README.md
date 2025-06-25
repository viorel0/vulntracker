# VulnTracker 🔍
VulnTracker is a Django-based web application designed for tracking software vulnerabilities. It uses Supabase for authentication and stores vulnerability data in a PostgreSQL database. This tool helps teams organize, analyze, and visualize CVE-related data for better vulnerability management.

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
