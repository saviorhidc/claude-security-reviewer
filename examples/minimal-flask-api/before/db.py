import psycopg2

# VULNERABILITY: Critical SecretsExposure — hardcoded DB password committed to source
# The password belongs in an env var (os.environ["DB_PASSWORD"]), not here.
_conn_params = {
    "host": "localhost",
    "port": 5432,
    "dbname": "appdb",
    "user": "appuser",
    "password": "changeme",  # VULNERABILITY: Critical SecretsExposure — plaintext credential in source file
}


def get_conn():
    """Return a new psycopg2 connection using the hardcoded params above."""
    return psycopg2.connect(**_conn_params)
