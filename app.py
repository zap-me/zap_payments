#!/usr/bin/python3
import os
import logging
import sys
import json
import time
import requests

from flask import url_for, redirect, render_template, request, abort, jsonify
from flask_security.utils import encrypt_password
from flask_socketio import Namespace, emit, join_room, leave_room
from flask_security import current_user

from app_core import app, db, socketio
from models import security, user_datastore, Role, User, Invoice
import admin
from utils import check_hmac_auth, generate_key

logger = logging.getLogger(__name__)
ws_invoices = {}
ws_sids = {}

#
# Helper functions
#

def setup_logging(level):
    # setup logging
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter("[%(name)s %(levelname)s] %(message)s"))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

def add_user(email, password):
    with app.app_context():
        user = User.from_email(db.session, email)
        if user:
            #logger.error("user already exists")
            #return
            user.password = encrypt_password(password)
        else:
            user = user_datastore.create_user(email=email, password=encrypt_password(password))
        db.session.commit()

def create_role(name, desc):
    role = Role.from_name(db.session, name)
    if not role:
        role = Role(name=name, description=desc)
    else:
        role.description = desc
    db.session.add(role)
    return role

def add_role(email, role_name):
    with app.app_context():
        user = User.from_email(db.session, email)
        if not user:
            logger.error("user does not exist")
            return
        role = create_role(role_name, None)
        if role not in user.roles:
            user.roles.append(role)
        else:
            logger.info("user already has role")
        db.session.commit()

def check_auth(token, nonce, sig, body):
    invoice = Invoice.from_token(db.session, token)
    if not invoice:
        return False, "not found", None
    res, reason = check_hmac_auth(invoice, nonce, sig, body)
    if not res:
        return False, reason, None
    # update invoice nonce
    db.session.commit()
    return True, "", invoice

def bad_request(message):
    response = jsonify({"message": message})
    response.status_code = 400
    return response

#
# Flask views
#

@app.before_request
def before_request_func():
    if "DEBUG_REQUESTS" in app.config:
        print("URL: %s" % request.url)
        print(request.headers)

@app.route("/")
def index():
    return render_template("index.html")

#
# Test
#

@app.route("/test/invoice/<token>")
def test_invoice(token):
    if not app.config["DEBUG"]:
        return abort(404)
    invoice = Invoice.from_token(db.session, token)
    if token in ws_invoices:
        print("sending invoice update %s" % token)
        socketio.emit("info", invoice.to_json(), json=True, room=token)
    if invoice:
        return jsonify(invoice.to_json())
    return abort(404)

@app.route("/test/ws")
def test_ws():
    if not app.config["DEBUG"]:
        return abort(404)
    return jsonify(ws_invoices)

#
# Websocket events
#

def alert_invoice_update(invoice):
    socketio.emit("update", invoice.to_json(), json=True, room=invoice.token)

class SocketIoNamespace(Namespace):
    def trigger_event(self, event, sid, *args):
        if sid not in self.server.environ:
            # we don't have record of this client, ignore this event
            return '', 400
        app = self.server.environ[sid]['flask.app']
        if "DEBUG_REQUESTS" in app.config:
            with app.request_context(self.server.environ[sid]):
                before_request_func()
        return super(SocketIoNamespace, self).trigger_event(event, sid, *args)

    def on_error(self, e):
        print(e)

    def on_connect(self):
        print("connect sid: %s" % request.sid)

    def on_auth(self, auth):
        # check auth
        res, reason, invoice = check_auth(auth["token"], auth["nonce"], auth["signature"], str(auth["nonce"]))
        if res:
            emit("info", "authenticated!")
            # join room and store user
            print("join room for invoice: %s" % auth["token"])
            join_room(auth["token"])
            ws_invoices[auth["token"]] = request.sid
            ws_sids[request.sid] = auth["token"]

    def on_disconnect(self):
        print("disconnect sid: %s" % request.sid)
        if request.sid in ws_sids:
            token = ws_sids[request.sid]
            if token in ws_invoices:
                print("leave room for invoice: %s" % token)
                leave_room(token)
                del ws_invoices[token]
            del ws_sids[request.sid]

socketio.on_namespace(SocketIoNamespace("/"))

#
# Public endpoints
#

@app.route("/bill")
def bill():
    #TODO: show the various utilities available to pay
    return render_template("bill")

if __name__ == "__main__":
    setup_logging(logging.DEBUG)

    # create tables
    db.create_all()
    create_role("admin", "super user")
    create_role("finance", "Can view/action settlements")
    db.session.commit()

    # process commands
    if len(sys.argv) > 1:
        if sys.argv[1] == "add_user":
            add_user(sys.argv[2], sys.argv[3])
        if sys.argv[1] == "add_role":
            add_role(sys.argv[2], sys.argv[3])
    else:
        # check config
        if "BRONZE_API_KEY" not in app.config:
            logger.error("BRONZE_API_KEY does not exist")
            sys.exit(1)
        if "BRONZE_API_SECRET" not in app.config:
            logger.error("BRONZE_API_SECRET does not exist")
            sys.exit(1)

        # Bind to PORT if defined, otherwise default to 5000.
        port = int(os.environ.get("PORT", 5000))
        print("binding to port: %d" % port)
        socketio.run(app, host="0.0.0.0", port=port)
