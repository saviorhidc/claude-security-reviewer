from flask import Blueprint, jsonify, session
from db import get_conn

orders_bp = Blueprint("orders", __name__)


# GET /orders/<id>
#
# VULNERABILITY: Critical SQLInjection — the order id is interpolated directly into an f-string SQL query.
# An attacker passes  1 OR 1=1  or  1; DROP TABLE orders; --  via the URL path segment.
# Fix: use a parameterized query: cur.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
#
# VULNERABILITY: Critical BrokenAuthorization (IDOR) — the query fetches any order by its integer id
# with no ownership constraint. A logged-in user can read any other user's order by guessing IDs.
# Fix: add AND user_id = %s with session["user_id"] as the second parameter.
@orders_bp.route("/<int:order_id>")
def get_order(order_id):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # VULNERABILITY: Critical SQLInjection
            cur.execute(
                f"SELECT * FROM orders WHERE id = {order_id}"
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "Not found"}), 404
            columns = [desc[0] for desc in cur.description]
            order = dict(zip(columns, row))
    finally:
        conn.close()

    # VULNERABILITY: Critical BrokenAuthorization — returned without verifying order["user_id"]
    # matches session["user_id"]
    return jsonify(order)
