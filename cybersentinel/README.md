# CyberSentinel – Automated Vulnerability Scanner & Security Report Generator

Final year project website (Flask + SQLite + ReportLab + Chart.js) with:
- Login/Signup + session auth
- Cybersecurity dashboard UI
- Simulated vulnerability scanning (Web App / Network)
- Results dashboard with charts + severity progress bars
- Detailed report page
- PDF + HTML report downloads
- Simple admin panel (users + reports + delete)

## Run locally (Windows)

Open PowerShell in this folder:
`d:\newcyber\cybersentinel`

1) Create & activate venv:

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

2) Install dependencies:

```powershell
pip install -r requirements.txt
```

3) Start the server:

```powershell
python app.py
```

Open:
`http://localhost:5000`

## Default admin

- Email: `admin@cybersentinel.local`
- Password: `Admin@123`

## Optional admin registration code

On the Register page, you can enter:
`CYBERADMIN2026`

## Notes

- Database file is created automatically at `database/cybersentinel.db`
- Downloaded reports are also saved under `reports/`

