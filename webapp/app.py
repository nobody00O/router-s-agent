"""
webapp/app.py

The consumer-facing website:
  GET/POST /signup           -> create account
  GET/POST /login            -> log in
  GET      /logout           -> log out
  GET/POST /router/setup     -> register/update router specs (the core ask)
  GET      /dashboard         -> devices + alerts for the logged-in user
  GET      /agent             -> download page + instructions for the local scanning agent
  POST     /api/report        -> local agent posts scan results here (API-key authenticated)
  GET      /api/dashboard-data -> JSON for the dashboard page's live refresh

Run: python3 webapp/app.py
Then open http://127.0.0.1:5070
"""
from __future__ import annotations
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, session, redirect, url_for, jsonify, render_template, flash

from webapp.db import init_db, DB_PATH
from webapp.auth import (signup as do_signup, login as do_login, AuthError, get_user_by_api_key,
                          regenerate_api_key, verify_email_token, resend_verification)
from webapp.email_sender import send_verification_email
from webapp.router_config import save_router_config, get_router_config, ConfigError
from webapp.scan_ingest import ingest_scan_report, get_recent_alerts, get_latest_devices

app = Flask(__name__)
app.secret_key = os.environ.get("NETGUARD_SECRET_KEY", "dev-only-secret-change-me")

init_db(DB_PATH)


def current_user_id():
    return session.get("user_id")


def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user_id():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    if current_user_id():
        return redirect(url_for("dashboard"))
    return render_template("home.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        try:
            user = do_signup(request.form["email"], request.form["password"])
            verify_url = url_for("verify_email", token=user["verify_token"], _external=True)
            send_verification_email(user["email"], verify_url)
            flash("Account created! Check your email for a verification link before logging in.", "success")
            return redirect(url_for("login"))
        except AuthError as e:
            flash(str(e), "error")
    return render_template("signup.html")


@app.route("/verify/<token>")
def verify_email(token):
    if verify_email_token(token):
        flash("Email verified! You can log in now.", "success")
    else:
        flash("That verification link is invalid or has already been used.", "error")
    return redirect(url_for("login"))


@app.route("/resend-verification", methods=["POST"])
def resend_verification_route():
    email = request.form.get("email", "")
    new_token = resend_verification(email)
    if new_token:
        verify_url = url_for("verify_email", token=new_token, _external=True)
        send_verification_email(email, verify_url)
    # Same message either way -- doesn't reveal whether that email has an
    # account or is already verified, which is the correct, safe behavior.
    flash("If that email has a pending account, a new verification link was sent.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            user = do_login(request.form["email"], request.form["password"])
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))
        except AuthError as e:
            flash(str(e), "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/router/setup", methods=["GET", "POST"])
@login_required
def router_setup():
    if request.method == "POST":
        try:
            known_devices = []
            macs = request.form.getlist("device_mac")
            names = request.form.getlist("device_name")
            for mac, name in zip(macs, names):
                if mac.strip():
                    known_devices.append({"mac": mac.strip().upper(), "name": name.strip() or "Unnamed device"})

            blocklist = [d.strip() for d in request.form.get("blocklist_domains", "").split(",") if d.strip()]

            save_router_config(
                current_user_id(),
                subnet=request.form["subnet"], interface=request.form["interface"],
                router_ip=request.form["router_ip"], router_model=request.form.get("router_model", ""),
                known_devices=known_devices, blocklist_domains=blocklist,
            )
            flash("Router configuration saved.", "success")
            return redirect(url_for("dashboard"))
        except ConfigError as e:
            flash(str(e), "error")

    existing = get_router_config(current_user_id())
    return render_template("router_setup.html", existing=existing)


@app.route("/dashboard")
@login_required
def dashboard():
    cfg = get_router_config(current_user_id())
    return render_template("dashboard.html", has_config=cfg is not None)


@app.route("/agent")
@login_required
def agent_download():
    from webapp.db import get_db
    with get_db() as conn:
        row = conn.execute("SELECT api_key FROM users WHERE id=?", (current_user_id(),)).fetchone()
    return render_template("agent.html", api_key=row["api_key"])


@app.route("/agent/regenerate", methods=["POST"])
@login_required
def agent_regenerate():
    new_key = regenerate_api_key(current_user_id())
    flash("New API key issued and the old one is now dead. View it below and update local_agent.py.", "success")
    return redirect(url_for("agent_download"))


@app.route("/api/report", methods=["POST"])
def api_report():
    api_key = request.headers.get("X-API-Key", "")
    user = get_user_by_api_key(api_key)
    if not user:
        return jsonify({"error": "invalid or missing API key"}), 401

    payload = request.get_json(force=True, silent=True) or {}
    try:
        result = ingest_scan_report(
            user["id"], devices=payload.get("devices", []), dns_events=payload.get("dns_events", [])
        )
        return jsonify(result), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/dashboard-data")
@login_required
def api_dashboard_data():
    devices = get_latest_devices(current_user_id())
    alerts = get_recent_alerts(current_user_id(), limit=30)
    return jsonify({"devices": devices, "alerts": alerts})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5070, debug=False)
