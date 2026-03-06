import os
import time
from datetime import datetime
from functools import wraps
from io import BytesIO

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file,
)
from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
mongodb = client["cybersentinel"]
scan_collection = mongodb["scans"]
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
    BASE_DIR, "database", "cybersentinel.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship("Scan", backref="user", lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    total_vulns = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)

    vulnerabilities = db.relationship(
        "Vulnerability", backref="scan", lazy=True, cascade="all, delete-orphan"
    )


class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default="Open")


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapper


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        user = User.query.get(session["user_id"])
        if not user or not user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        admin_code = request.form.get("admin_code", "").strip()

        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("login"))

        user = User(email=email)
        user.set_password(password)
        # Simple admin option: if a correct code is provided, mark as admin
        if admin_code == "CYBERADMIN2026":
            user.is_admin = True

        db.session.add(user)
        db.session.commit()

        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

        session["user_id"] = user.id
        session["user_email"] = user.email
        session["is_admin"] = bool(user.is_admin)
        flash(f"Welcome back, {user.email}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    user = User.query.get(user_id)

    total_scans = Scan.query.filter_by(user_id=user_id).count()
    total_vulns = (
        db.session.query(Vulnerability)
        .join(Scan)
        .filter(Scan.user_id == user_id)
        .count()
    )

    high_count = (
        db.session.query(Vulnerability)
        .join(Scan)
        .filter(Scan.user_id == user_id, Vulnerability.severity == "High")
        .count()
    )
    medium_count = (
        db.session.query(Vulnerability)
        .join(Scan)
        .filter(Scan.user_id == user_id, Vulnerability.severity == "Medium")
        .count()
    )
    low_count = (
        db.session.query(Vulnerability)
        .join(Scan)
        .filter(Scan.user_id == user_id, Vulnerability.severity == "Low")
        .count()
    )

    recent_scans = (
        Scan.query.filter_by(user_id=user_id)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "dashboard.html",
        user=user,
        total_scans=total_scans,
        total_vulns=total_vulns,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        recent_scans=recent_scans,
    )


@app.route("/start-scan", methods=["GET", "POST"])
@login_required
def start_scan():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        scan_type = request.form.get("scan_type", "Web App Scan")
        permission = request.form.get("permission")

        if not target:
            flash("Target URL or IP is required.", "danger")
            return redirect(url_for("start_scan"))

        if not permission:
            flash("You must confirm you have permission to scan this target.", "warning")
            return redirect(url_for("start_scan"))

        # Simulate scanning delay
        time.sleep(2)

        scan = Scan(
            user_id=session["user_id"],
            target=target,
            scan_type=scan_type,
        )
        db.session.add(scan)
        db.session.flush()  # assign id

        simulated_vulns = generate_simulated_vulnerabilities(scan_type)
        high = medium = low = 0

        for vuln in simulated_vulns:
            v = Vulnerability(
                scan_id=scan.id,
                name=vuln["name"],
                severity=vuln["severity"],
                description=vuln["description"],
                recommendation=vuln["recommendation"],
                status="Open",
            )
            db.session.add(v)
            if vuln["severity"] == "High":
                high += 1
            elif vuln["severity"] == "Medium":
                medium += 1
            elif vuln["severity"] == "Low":
                low += 1

        scan.total_vulns = high + medium + low
        scan.high_count = high
        scan.medium_count = medium
        scan.low_count = low
        # Save scan log in MongoDB
        scan_data = {
            "target": target,
            "scan_type": scan_type,
            "date": datetime.now(),
            "status": "completed"
        }
        scan_collection.insert_one(scan_data)
        db.session.commit()

        flash("Scan completed successfully.", "success")
        return redirect(url_for("scan_results", scan_id=scan.id))

    return render_template("start_scan.html")


def generate_simulated_vulnerabilities(scan_type: str):
    base_vulns = [
        {
            "name": "SQL Injection",
            "severity": "High",
            "description": "User input is not properly sanitized before being used in SQL queries.",
            "recommendation": "Use parameterized queries and ORM, validate and sanitize user input.",
        },
        {
            "name": "Cross-Site Scripting (XSS)",
            "severity": "Medium",
            "description": "Reflected user input is rendered without proper output encoding.",
            "recommendation": "Apply context-aware output encoding and input validation.",
        },
        {
            "name": "Open Ports Detected",
            "severity": "Low",
            "description": "Multiple network ports are open and accessible from the internet.",
            "recommendation": "Close unused ports and restrict access using firewalls and security groups.",
        },
        {
            "name": "Missing Security Headers",
            "severity": "Medium",
            "description": "Important security headers like CSP, X-Frame-Options, and HSTS are not configured.",
            "recommendation": "Add and configure standard security headers at the web server or application level.",
        },
    ]

    if scan_type == "Network Scan":
        base_vulns.append(
            {
                "name": "Weak SSH Configuration",
                "severity": "High",
                "description": "SSH allows password authentication and older protocol versions.",
                "recommendation": "Disable password auth, use key-based auth, and restrict allowed ciphers.",
            }
        )

    return base_vulns


@app.route("/scan/<int:scan_id>")
@login_required
def scan_results(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != session["user_id"] and not session.get("is_admin"):
        flash("You do not have access to this scan.", "danger")
        return redirect(url_for("dashboard"))

    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()

    return render_template(
        "scan_results.html",
        scan=scan,
        vulnerabilities=vulns,
    )


@app.route("/report/<int:scan_id>")
@login_required
def report_detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != session["user_id"] and not session.get("is_admin"):
        flash("You do not have access to this report.", "danger")
        return redirect(url_for("dashboard"))

    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()
    return render_template("report_detail.html", scan=scan, vulnerabilities=vulns)


@app.route("/reports")
@login_required
def reports():
    user_id = session["user_id"]
    scan_list = (
        Scan.query.filter_by(user_id=user_id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    return render_template("reports.html", scans=scan_list)


@app.route("/download_pdf/<int:scan_id>")
@login_required
def download_pdf(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != session["user_id"] and not session.get("is_admin"):
        flash("You do not have access to this report.", "danger")
        return redirect(url_for("dashboard"))

    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    title = f"CyberSentinel – Automated Security Report"
    elements.append(Paragraph(title, styles["Title"]))
    elements.append(Spacer(1, 12))

    meta = f"Target: {scan.target}<br/>Scan Type: {scan.scan_type}<br/>Date: {scan.created_at.strftime('%Y-%m-%d %H:%M:%S')}"
    elements.append(Paragraph(meta, styles["Normal"]))
    elements.append(Spacer(1, 12))

    summary = (
        f"Total Vulnerabilities: {scan.total_vulns} "
        f"(High: {scan.high_count}, Medium: {scan.medium_count}, Low: {scan.low_count})"
    )
    elements.append(Paragraph("Executive Summary", styles["Heading2"]))
    elements.append(Paragraph(summary, styles["Normal"]))
    elements.append(Spacer(1, 12))

    data = [
        ["Name", "Severity", "Description", "Recommendation", "Status"],
    ]
    for v in vulns:
        data.append(
            [
                v.name,
                v.severity,
                v.description,
                v.recommendation,
                v.status,
            ]
        )

    table = Table(data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.gray),
            ]
        )
    )

    elements.append(Paragraph("Vulnerability Details", styles["Heading2"]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    filename = f"CyberSentinel_Report_{scan.id}.pdf"

    # Also save a copy into reports/ folder for history
    reports_dir = os.path.join(BASE_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    file_path = os.path.join(reports_dir, filename)
    with open(file_path, "wb") as f:
        f.write(buffer.getvalue())

    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )


@app.route("/download_html/<int:scan_id>")
@login_required
def download_html(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != session["user_id"] and not session.get("is_admin"):
        flash("You do not have access to this report.", "danger")
        return redirect(url_for("dashboard"))

    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()
    rendered = render_template("report_detail.html", scan=scan, vulnerabilities=vulns)

    filename = f"CyberSentinel_Report_{scan.id}.html"
    reports_dir = os.path.join(BASE_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    file_path = os.path.join(reports_dir, filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(rendered)

    return send_file(
        BytesIO(rendered.encode("utf-8")),
        as_attachment=True,
        download_name=filename,
        mimetype="text/html",
    )


@app.route("/admin")
@admin_required
def admin_panel():
    users = User.query.order_by(User.created_at.desc()).all()
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("admin.html", users=users, scans=scans)


@app.route("/admin/delete_scan/<int:scan_id>", methods=["POST"])
@admin_required
def admin_delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    flash("Scan and its vulnerabilities deleted.", "info")
    return redirect(url_for("admin_panel"))


def ensure_admin_user():
    """Optional helper to auto-create a default admin account for testing."""
    admin_email = "admin@cybersentinel.local"
    if not User.query.filter_by(email=admin_email).first():
        admin = User(email=admin_email, is_admin=True)
        admin.set_password("Admin@123")
        db.session.add(admin)
        db.session.commit()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_admin_user()
    app.run(host="0.0.0.0", port=5000, debug=True)

