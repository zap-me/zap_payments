import os
import decimal

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail_sendgrid import MailSendGrid
from flask_socketio import SocketIO
import pywaves

from addresswatcher import AddressWatcher
from timer import Timer

# Create Flask application
app = Flask(__name__)
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
    # fix heroku stuck on 'postgres' dialect (https://stackoverflow.com/a/66787229/206529)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
if os.getenv("SERVER_NAME"):
    app.config["SERVER_NAME"] = os.getenv("SERVER_NAME")
if os.getenv("ZAP_ADDRESS"):
    app.config["ZAP_ADDRESS"] = os.getenv("ZAP_ADDRESS")
if os.getenv("ZAP_SEED"):
    app.config["ZAP_SEED"] = os.getenv("ZAP_SEED")
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
app.config["INVOICE_EXPIRY_SECONDS"] = 600
app.config["TIMER_SECONDS"] = 60
app.config["WAVES_CONFIRMATIONS"] = 20
if os.getenv("CLIENT_ID"):
    app.config["CLIENT_ID"] = os.getenv("CLIENT_ID")
if os.getenv("CLIENT_SECRET"):
    app.config["CLIENT_SECRET"] = os.getenv("CLIENT_SECRET")

db = SQLAlchemy(app)
mail = MailSendGrid(app)
socketio = SocketIO(app, cors_allowed_origins="*")

aw = AddressWatcher(app.config["ZAP_ADDRESS"], app.config["TESTNET"])
timer = Timer(60)
