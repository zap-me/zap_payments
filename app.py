#!/usr/bin/python3
import os
import logging
import sys
import json
import time
import decimal
import hmac
import hashlib
import base64
import io
import re
import urllib.parse

from flask import url_for, redirect, render_template, request, abort, jsonify, Markup
from flask_security.utils import encrypt_password
from flask_socketio import Namespace, emit, join_room, leave_room
from flask_security import current_user
from flask_mail import Message
import werkzeug
import requests
import qrcode
import qrcode.image.svg

from app_core import app, db, mail, socketio, aw, timer
from models import security, user_datastore, Role, User, Invoice, Utility
import admin
from utils import check_hmac_auth, generate_key, is_email

logger = logging.getLogger(__name__)
ws_invoices = {}
ws_sids = {}
MAX_DETAIL_CHARS = 12

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

def hmac_sha256(secret, msg):
    sig = hmac.new(bytes(secret, 'latin-1'), msg=bytes(msg, 'latin-1'), digestmod=hashlib.sha256).digest()
    return base64.b64encode(sig)

def bronze_request(endpoint, params):
    params["key"] = app.config["BRONZE_API_KEY"]
    params["nonce"] = int(time.time() * 1000)
    body = json.dumps(params)
    # create hmac sha256 signature of body
    signature = hmac_sha256(app.config["BRONZE_API_SECRET"], body)
    # create request
    headers = {"Content-Type": "application/json", "X-Signature": signature}
    url = app.config["BRONZE_ADDRESS"] + "/api/v1/" + endpoint
    #print(":: requesting %s.." % url)
    r = requests.post(url, headers=headers, data=body)
    try:
        r.raise_for_status()
    except:
        print("ERROR: response http status %d (%s)" % (r.status_code, r.content))
        return None, r.content.decode("utf-8")
    return r, None

def bronze_order_status(invoice):
    # create request body
    params = dict(token=invoice.bronze_broker_token)
    # create request
    r, err = bronze_request("BrokerStatus", params)
    if not r:
        return None
    return r.json()

def bronze_order_accept(invoice):
    # create request body
    params = dict(token=invoice.bronze_broker_token)
    # create request
    r, err = bronze_request("BrokerAccept", params)
    if not r:
        return None
    return r.json()

def transfer_tx_callback(tokens, tx):
    txt = json.dumps(tx)
    print("transfer_tx_callback: tx %s" % txt)
    for token in tokens:
        invoice = Invoice.from_token(db.session, token)
        if invoice:
            order = bronze_order_status(invoice)
            if order:
                try:
                    attachment = json.loads(tx["attachment"])
                    invoice_id = attachment["InvoiceId"]
                    amount_zap = int(tx["amount"] * 100)
                    if invoice_id == order["invoiceId"] and amount_zap >= invoice.amount_zap:
                        print("marking invoice (%s) as seen" % token)
                        invoice.tx_seen = True
                        db.session.add(invoice)
                        db.session.commit()
                except:
                    pass
        print("sending 'tx' event to room %s" % token)
        socketio.emit("tx", txt, json=True, room=token)

def ws_invoices_timer_callback():
    #print("ws_invoices_timer_callback()..")
    for token in ws_invoices.keys():
        #print("ws_invoices_timer_callback: token: {}".format(token))
        invoice = Invoice.from_token(db.session, token)
        if invoice:
            order = bronze_order_status(invoice)
            if order:
                socketio.emit("order_status", order["status"], room=token)

def email_invoices_timer_callback():
    print("email_invoices_timer_callback()..")
    with app.app_context():
        invoices = Invoice.all_with_email_and_not_terminated(db.session)
        for invoice in invoices:
            order = bronze_order_status(invoice)
            if order:
                if invoice.status != order["status"]:
                    invoice_url = url_for("invoice", token=invoice.token)
                    hostname = urllib.parse.urlparse(invoice_url).hostname
                    sender = "no-reply@" + hostname
                    formatted_amount = '{0:0.2f}'.format(invoice.amount/100.0)
                    # send email
                    msg = Message('ZAP bill payment status updated', sender=sender, recipients=[invoice.email])
                    msg.html = 'Invoice <a href="{}">{}</a> has updated the {} invoice with the amount of ${} to status "{}"'.format(invoice_url, invoice.token, invoice.bank_name, formatted_amount, order["status"])
                    msg.body = 'Invoice {} has updated the {} invoice with the amount of ${} to status {}'.format(invoice_url, invoice.bank_name, formatted_amount, order["status"])
                    mail.send(msg)
                    # update invoice object
                    invoice.status = order["status"]
                    db.session.commit()

def qrcode_svg_create(data):
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(data, image_factory=factory)
    output = io.BytesIO()
    img.save(output)
    svg = output.getvalue().decode('utf-8')
    return svg

@app.before_first_request
def start_address_watcher():
    aw.transfer_tx_callback = transfer_tx_callback
    aw.start()
    timer.add_timer(ws_invoices_timer_callback, app.config["INVOICE_WS_SECONDS"])
    timer.add_timer(email_invoices_timer_callback, app.config["INVOICE_EMAIL_SECONDS"])
    timer.start()

def bad_request(message):
    response = jsonify({"message": message})
    response.status_code = 400
    return response

def find_urls(string): 
    # findall() has been used  
    # with valid conditions for urls in string 
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex,string)       
    return [x[0] for x in url] 

@app.template_filter("urls_to_links")
def urls_to_links(s):
    urls = find_urls(s)
    if not urls:
        return s
    for url in urls:
        link = '<a href="{}" target="_blank">{}</a>'.format(url, url)
        s = s.replace(url, link)
    return Markup(s)

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

    def on_invoice(self, token):
        print("join room for invoice: %s" % token)
        join_room(token)
        ws_invoices[token] = request.sid
        ws_sids[request.sid] = token
        emit("info", "joined room for invoice: %s" % token)

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

@app.route("/utilities")
def utilities():
    utilities = Utility.all_alphabetical(db.session)
    return render_template("utilities.html", utilities=utilities)

def validate_amount(amount):
    try:
        # check amount
        amount = decimal.Decimal(amount)
    except:
        return "amount must be a valid number"
    if amount <= 0:
        return "amount must be greater then zero"
    return None

def validate_email(email):
    if email and not is_email(email):
        return "invalid email address"
    return None

def validate_values(bank_description_item, values):
    for field in bank_description_item["fields"]:
        name = field["label"]
        value = values[name]
        if not value and (not "allow_empty" in field or not field["allow_empty"]):
            return "please enter a value for '%s'" % name
        type_ = field["type"].lower()
        if type_ == "number" and value:
            num = int(value)
            if "min" in field and num < field["min"]:
                return "value for '%s' has a minimum of %d" % (name, field["min"])
            if "max" in field and num > field["max"]:
                return "value for '%s' has a maximum of %d" % (name, field["max"])
        if type_ == "string":
            if "min_chars" in field and len(value) < field["min_chars"]:
                return "value for '%s' has a minimum number of characters of %d" % (name, field["min_chars"])
        max_chars = MAX_DETAIL_CHARS
        if isinstance(field["target"], list):
            max_chars = MAX_DETAIL_CHARS * len(field["target"])
        if len(value) > max_chars:
            return "value for '%s' is too long" % name
    return None

def bank_transaction_details(bank_description_item, values):
    details = dict(bank_account = bank_description_item["account_number"])
    for field in bank_description_item["fields"]:
        target = field["target"]
        name = field["label"]
        value = values[name]
        if isinstance(target, list):
            for t in target:
                details[t], value = value[:MAX_DETAIL_CHARS], value[MAX_DETAIL_CHARS:]
        else:
            details[target] = value
    return details

def invoice_create(utility, details, email, amount, bank_name):
    # init bank recipient params
    bank_account = details["bank_account"]
    reference = details["reference"] if "reference" in details else ""
    code = details["code"] if "code" in details else ""
    particulars = details["particulars"] if "particulars" in details else ""
    # request params
    recipient_params = dict(reference=reference, code=code, particulars=particulars)
    params = dict(market="ZAPNZD", side="sell", amount=str(amount), amountasquotecurrency=True, recipient=bank_account, customrecipientparams=recipient_params)
    # create request
    r, err = bronze_request("BrokerCreate", params)
    if not r:
        return None, err
    # extract token and create invoice
    body = r.json()
    broker_token = body["token"]
    amount_cents_zap = int(decimal.Decimal(body["amountSend"]) * 100)
    amount_cents_nzd = int(decimal.Decimal(body["amountReceive"]) * 100)
    status = body["status"]
    invoice = Invoice(email, amount_cents_nzd, amount_cents_zap, broker_token, status, bank_name)
    db.session.add(invoice)
    db.session.commit()
    return invoice, None

@app.route("/utility", methods=["GET", "POST"])
def utility():
    STATUS_CREATE = "create"
    STATUS_CHECK = "check"

    utility_id = int(request.args.get("utility"))
    utility = Utility.from_id(db.session, utility_id)
    Utility.jsonify_bank_descriptions([utility])
    if request.method == "POST":
        bank_index = int(request.form.get("zbp_bank_index"))
        bank_desc = utility.bank_description_json[bank_index]
        status = request.form.get("zbp_state")
        email = request.form.get("zbp_email")
        amount = request.form.get("zbp_amount")
        bank_name = request.form.get("zbp_bank_name")
        values = request.form
        error = None
        if status == STATUS_CREATE:
            error = validate_email(email)
            if not error:
                error = validate_amount(amount)
            if not error:
                error = validate_values(bank_desc, values)
            if not error:
                status = STATUS_CHECK
        elif status == STATUS_CHECK:
            error = validate_email(email)
            if not error:
                error = validate_amount(amount)
            if not error:
                error = validate_values(bank_desc, values)
            if not error:
                details = bank_transaction_details(bank_desc, values)
                invoice, err = invoice_create(utility, details, email, amount, bank_name)
                if invoice:
                    return redirect(url_for("invoice", token=invoice.token))
                else:
                    error = "failed to create invoice ({})".format(err)
        return render_template("utility.html", utility=utility, selected_bank_name=bank_desc["name"], status=status, email=email, amount=amount, bank_name=bank_name, values=values, error=error)
    else:
        return render_template("utility.html", utility=utility, status=STATUS_CREATE, values=werkzeug.MultiDict())

@app.route("/invoice", methods=["GET", "POST"])
def invoice():
    error = None
    qrcode_svg = None
    url = None
    token = request.args.get("token")
    invoice = Invoice.from_token(db.session, token)
    if not invoice:
        return abort(404)
    order = bronze_order_status(invoice)
    if not order:
        return abort(400)
    if order["status"] == Invoice.STATUS_EXPIRED:
        error = "invoice expired"
        return render_template("invoice.html", invoice=invoice, order=order, error=error)
    if request.method == "POST":
        if order["status"] == Invoice.STATUS_CREATED:
            res = bronze_order_accept(invoice)
            if res:
                order = res
    if order["status"] == Invoice.STATUS_READY:
        # watch address
        print("watching address %s for %s" % (order["paymentAddress"], token))
        aw.watch(order["paymentAddress"], token)
        # prepare template
        invoice_id = order["invoiceId"]
        payment_address = order["paymentAddress"]
        attachment = json.dumps(dict(InvoiceId=invoice_id))
        url = "waves://{}?asset={}&amount={}&attachment={}".format(payment_address, app.config["ASSET_ID"], invoice.amount_zap, attachment)
        qrcode_svg = qrcode_svg_create(url)
        # change links to match zap app :/
        url = "zap" + url[5:]
    #TODO: other statuses..
    return render_template("invoice.html", invoice=invoice, order=order, error=error, qrcode_svg=qrcode_svg, url=url)

if __name__ == "__main__":
    setup_logging(logging.DEBUG)

    # create tables
    db.create_all()
    create_role("admin", "super user")
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
        if "SERVER_NAME" not in app.config:
            logger.error("SERVER_NAME does not exist")
            sys.exit(1)

        # Bind to PORT if defined, otherwise default to 5000.
        port = int(os.environ.get("PORT", 5000))
        print("binding to port: %d" % port)
        socketio.run(app, host="0.0.0.0", port=port)
        # stop addresswatcher
        if aw:
            aw.kill()
        # stop timer
        if timer:
            timer.kill()

