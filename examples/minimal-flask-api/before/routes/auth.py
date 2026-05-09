import os
from flask import Blueprint, request, jsonify, session
from db import get_conn

auth_bp = Blueprint("auth", __name__)


# VULNERABILITY: High WeakRateLimiting — no rate limiting on the login endpoint
# An attacker can brute-force credentials with no throttle. flask-limiter backed by Redis
# is required here.
@auth_bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username") or request.json.get("username", "")
    password = request.form.get("password") or request.json.get("password", "")

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, password FROM users WHERE username = %s",
                (username,),
            )
            user = cur.fetchone()
    finally:
        conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    # VULNERABILITY: Critical SecretsExposure — plaintext password comparison; passwords stored and compared in cleartext
    # Passwords must be hashed at rest (argon2id / bcrypt). Storing and comparing plaintext means
    # any database read is a full credential compromise.
    if user[2] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user[0]

    # Note: the session cookie flags (Secure, SameSite) are misconfigured in app.py — see there.
    return jsonify({"ok": True})


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})
