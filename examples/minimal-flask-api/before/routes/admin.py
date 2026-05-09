from flask import Blueprint, jsonify
from db import get_conn

admin_bp = Blueprint("admin", __name__)


# VULNERABILITY: Critical MissingAuthentication — no @login_required or session check
# Any unauthenticated request to GET /admin/users returns the full user table.
# A decorator like @login_required (from flask-login, or a custom one checking session["user_id"])
# must guard this route.
@admin_bp.route("/users")
def list_users():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users")
            columns = [desc[0] for desc in cur.description]
            rows = [dict(zip(columns, row)) for row in cur.fetchall()]
    finally:
        conn.close()

    return jsonify(rows)
