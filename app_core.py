import os
import decimal

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail_sendgrid import MailSendGrid
from flask_socketio import SocketIO

from addresswatcher import AddressWatcher
from timer import Timer

class ReverseProxied(object):
    """
    Because we are reverse proxied from an aws load balancer
    use environ/config to signal https
    since flask ignores preferred_url_scheme in url_for calls
    """

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # if one of x_forwarded or preferred_url is https, prefer it.
        forwarded_scheme = environ.get("HTTP_X_FORWARDED_PROTO", None)
        preferred_scheme = app.config.get("PREFERRED_URL_SCHEME", None)
        if "https" in [forwarded_scheme, preferred_scheme]:
            environ["wsgi.url_scheme"] = "https"
        return self.app(environ, start_response)

# Create Flask application
app = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)
app.config.from_pyfile("config.py")
if os.getenv("DEBUG"):
    app.config["DEBUG"] = True
if os.getenv("DEBUG_REQUESTS"):
    app.config["DEBUG_REQUESTS"] = True
if os.getenv("DEBUG_SQL"):
    app.config["SQLALCHEMY_ECHO"] = True
else:
    app.config["SQLALCHEMY_ECHO"] = False
app.config["TESTNET"] = True
app.config["BRONZE_ADDRESS"] = "https://test.bronze.exchange"
app.config["ASSET_ID"] = "CgUrFtinLXEbJwJVjwwcppk4Vpz1nMmR3H5cQaDcUcfe"
if os.getenv("PRODUCTION"):
    app.config["TESTNET"] = False
    app.config["BRONZE_ADDRESS"] = "https://bronze.exchange"
    app.config["ASSET_ID"] = "9R3iLi4qGLVWKc16Tg98gmRvgg1usGEYd7SgC1W5D6HB"
if os.getenv("DATABASE_URL"):
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
if os.getenv("SERVER_NAME"):
    app.config["SERVER_NAME"] = os.getenv("SERVER_NAME")
if os.getenv("SESSION_KEY"):
    app.config["SECRET_KEY"] = os.getenv("SESSION_KEY")
if os.getenv("PASSWORD_SALT"):
    app.config["SECURITY_PASSWORD_SALT"] = os.getenv("PASSWORD_SALT")
if os.getenv("SENDGRID_API_KEY"):
    app.config["MAIL_SENDGRID_API_KEY"] = os.getenv("SENDGRID_API_KEY")
if os.getenv("BRONZE_API_KEY"):
    app.config["BRONZE_API_KEY"] = os.getenv("BRONZE_API_KEY")
if os.getenv("BRONZE_API_SECRET"):
    app.config["BRONZE_API_SECRET"] = os.getenv("BRONZE_API_SECRET")
app.config["INVOICE_EMAIL_SECONDS"] = 600
if os.getenv("INVOICE_EMAIL_SECONDS"):
    app.config["INVOICE_EMAIL_SECONDS"] = int(os.getenv("INVOICE_EMAIL_SECONDS"))
app.config["INVOICE_WS_SECONDS"] = 60
if os.getenv("INVOICE_WS_SECONDS"):
    app.config["INVOICE_WS_SECONDS"] = int(os.getenv("INVOICE_WS_SECONDS"))
if os.getenv("CLIENT_ID"):
    app.config["CLIENT_ID"] = os.getenv("CLIENT_ID")
if os.getenv("CLIENT_SECRET"):
    app.config["CLIENT_SECRET"] = os.getenv("CLIENT_SECRET")

db = SQLAlchemy(app)
mail = MailSendGrid(app)
socketio = SocketIO(app)

aw = AddressWatcher(app.config["TESTNET"])
timer = Timer(60)
