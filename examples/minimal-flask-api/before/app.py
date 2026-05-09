import traceback

from flask import Flask, jsonify
from flask_cors import CORS

from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.orders import orders_bp

app = Flask(__name__)

# SECRET_KEY is required for Flask sessions. Using a hardcoded dev value here
# is a SecretsExposure issue, but the primary examples are in db.py and the routes.
app.secret_key = "dev-secret-do-not-use-in-prod"

# VULNERABILITY: High CORSMisconfiguration — wildcard origin combined with supports_credentials=True
# Browsers reject this combination per the CORS spec, but the intent is wrong: any origin can
# make credentialed requests if the browser (or non-browser client) accepts it.
CORS(
    app,
    origins="*",
    supports_credentials=True,
    methods=["GET", "POST", "PUT", "DELETE"],
)

# VULNERABILITY: High InsecureCookie — session cookie flags not hardened
# SESSION_COOKIE_HTTPONLY defaults to True in Flask >= 1.0, but SECURE defaults to False
# and SAMESITE is not set, leaving the cookie exposed to HTTP and CSRF.
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None
# SESSION_COOKIE_HTTPONLY is intentionally not set (defaults True, but SECURE + SAMESITE are the gaps)

# VULNERABILITY: Medium InputValidation — MAX_CONTENT_LENGTH not configured
# Flask will accept arbitrarily large request bodies unless this is set.
# app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # intentionally commented out

app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(admin_bp, url_prefix="/admin")
app.register_blueprint(orders_bp, url_prefix="/orders")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# VULNERABILITY: Medium ErrorLeakage — str(e) and full traceback returned to the client
@app.errorhandler(Exception)
def handle_error(e):
    return jsonify({
        "error": str(e),
        "traceback": traceback.format_exc(),
    }), 500


if __name__ == "__main__":
    app.run(port=3000, debug=False)
