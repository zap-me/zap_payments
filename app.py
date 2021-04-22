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
import secrets
import datetime
import urllib.parse

from flask import url_for, redirect, render_template, request, abort, jsonify, Markup, flash, g
from flask_security.utils import encrypt_password
from flask_socketio import Namespace, emit, join_room, leave_room
from flask_security import current_user, login_user, logout_user, roles_accepted
from flask_security.core import AnonymousUser
from flask_mail import Message
import werkzeug
import requests
import qrcode
import qrcode.image.svg
import pywaves
from bronze import make_bronze_blueprint, bronze

from app_core import app, db, mail, socketio, aw, timer
from models import security, user_datastore, Role, User, Invoice, Spin, BronzeData
import admin
from utils import check_hmac_auth, generate_key, is_email

logger = logging.getLogger(__name__)
NAMESPACE = "/invoice"
ws_invoices = {} #TODO: can remove?
ws_sids = {} # TODO: can remove?

bronze_blueprint = make_bronze_blueprint('userinfo kyc', redirect_url='/bronze_oauth_complete')
app.register_blueprint(bronze_blueprint, url_prefix='/bronze_login')

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
    #logger.info(":: requesting %s.." % url)
    r = requests.post(url, headers=headers, data=body)
    try:
        r.raise_for_status()
    except:
        logger.error("ERROR: response http status %d (%s)" % (r.status_code, r.content))
        return None, r.content.decode("utf-8")
    return r, None

def get_json_params(json_content, param_names):
    param_values = []
    param_name = ''
    try:
        for param in param_names:
            param_name = param
            param_values.append(json_content[param])
    except Exception as e: # pylint: disable=broad-except
        logger.error("'%s' not found", param_name)
        logger.error(e)
        return param_values, bad_request(f"'{param_name}' not found")
    return param_values, None

def is_address(val):
    try:
        return pywaves.validateAddress(val)
    except: # pylint: disable=bare-except
        return False

def create_transaction_waves(recipient, amount, attachment):
    # set pywaves to online mode and testnet
    pywaves.setOnline()
    if app.config["TESTNET"]:
        pywaves.setNode('https://testnode1.wavesnodes.com', 'testnet')
    logger.info('chain: %s, node: %s', pywaves.getChain(), pywaves.getNode())
    # send funds
    asset_fee = 1
    if not recipient:
        short_msg = "recipient is null or an empty string"
        logger.error(short_msg)
        err = Exception(short_msg)
        raise err
    if not is_address(recipient):
        short_msg = "recipient is not a valid address"
        logger.error(short_msg)
        err = Exception(short_msg)
        raise err
    recipient = pywaves.Address(recipient)
    asset = pywaves.Asset(app.config['ASSET_ID'])
    pw_address = pywaves.Address(seed=app.config['ZAP_SEED'])
    res = pw_address.sendAsset(recipient, asset, amount, attachment, feeAsset=asset, txFee=asset_fee)
    if not res:
        return None
    return res['id']

def transfer_tx_callback(tx):
    txt = json.dumps(tx)
    logger.info("transfer_tx_callback: tx %s" % txt)
    try:
        txid = tx["id"]
        amount = int(tx["amount"] * 100)
        attachment = json.loads(tx["attachment"])
        invoice_id = attachment["InvoiceId"]
        invoice = Invoice.from_token(db.session, invoice_id)
        if invoice and amount >= invoice.amount:
            logger.info("marking invoice (%s) as seen" % invoice.token)
            invoice.txid = txid
            invoice.tx_seen = True
            db.session.add(invoice)
            db.session.commit()
            logger.info("sending 'tx' event to room %s" % invoice.token)
            socketio.emit("tx", txt, json=True, room=invoice.token, namespace=NAMESPACE)
    except:
        pass

def check_invoices():
    logger.info("check_invoices()..")
    with app.app_context():
        invoices = Invoice.all_with_email_and_not_terminated(db.session)
        updated_invoices = []
        height = aw.block_height()
        if not height:
            logger.info("error: unable to get block height")
            return
        for invoice in invoices:
            if invoice.txid:
                confs = aw.tx_confirmations(height, invoice.txid)
                if confs > 0:
                    if invoice.status == Invoice.STATUS_READY:
                        invoice.status = Invoice.STATUS_INCOMING
                        db.session.add(invoice)
                        updated_invoices.append(invoice)
                    elif invoice.status == Invoice.STATUS_INCOMING and confs > app.config["WAVES_CONFIRMATIONS"]:
                        invoice.status = Invoice.STATUS_CONFIRMED
                        db.session.add(invoice)
                        updated_invoices.append(invoice)
        db.session.commit()
        for invoice in updated_invoices:
            alert_invoice_update(invoice)

def expire_invoices():
    logger.info("expire_invoices()..")
    with app.app_context():
        now = datetime.datetime.now()
        invoices = Invoice.all_with_email_and_not_terminated(db.session)
        for invoice in invoices:
            if (invoice.status == Invoice.STATUS_CREATED or invoice.status == Invoice.STATUS_READY) and not invoice.tx_seen and invoice.expiry.timestamp() < now.timestamp():
                logger.info("expire invoice %s", invoice.token)
                invoice.status = Invoice.STATUS_EXPIRED
                db.session.add(invoice)
                db.session.commit()
                alert_invoice_update(invoice)

def email_invoices_update():
    logger.info("email_invoices_update()..")
    with app.app_context():
        invoices = Invoice.all_with_email_and_not_terminated(db.session)
        for invoice in invoices:
            old_status = invoice.status
            status = invoice_check_status(invoice) #TODO: implement this
            if invoice.status != old_status:
                invoice_url = url_for("invoice", token=invoice.token)
                hostname = urllib.parse.urlparse(invoice_url).hostname
                sender = "no-reply@" + hostname
                formatted_amount = '{0:0.2f}'.format(invoice.amount/100.0)
                # send email
                msg = Message('ZAP bill payment status updated', sender=sender, recipients=[invoice.email])
                msg.html = 'Invoice <a href="{}">{}</a> has updated the {} invoice with the amount of ${} to status "{}"'.format(invoice_url, invoice.token, invoice.utility_name, formatted_amount, status)
                msg.body = 'Invoice {} has updated the {} invoice with the amount of ${} to status {}'.format(invoice_url, invoice.utility_name, formatted_amount, status)
                mail.send(msg)
                # update invoice object
                invoice.status = status
                db.session.add(invoice)
                db.session.commit()

def timer_callback():
    try:
        check_invoices()
    except Exception as e:
        logger.error(e)
    try:
        expire_invoices()
    except Exception as e:
        logger.error(e)
    try:
        #email_invoices_update()
        pass
    except Exception as e:
        logger.error(e)

def qrcode_svg_create(data):
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(data, image_factory=factory)
    output = io.BytesIO()
    img.save(output)
    svg = output.getvalue().decode('utf-8')
    return svg

def add_update_bronze_data(user):
    kyc = bronze_blueprint.session.get('AccountKyc')
    if kyc.ok:
        kyc = kyc.json()
        level = int(kyc['level'])
        validated = level >= 2
        if user.bronze_data:
            user.bronze_data.kyc_validated = validated
        else:
            user.bronze_data = BronzeData(user, validated)
        db.session.add(user.bronze_data)
        db.session.commit()
        return True
    return False

def check_bronze_auth(flash_it=False):
    logger.info('current_user: {0}'.format(current_user))
    if not hasattr(current_user, 'bronze_data') or not current_user.bronze_data:
        if bronze.authorized:
            userinfo = bronze_blueprint.session.get('UserInfo')
            if userinfo.ok:
                userinfo = userinfo.json()
                email = userinfo['email']
                user = user_datastore.find_user(case_insensitive=True, email=email)
                if not user:
                    logger.info('user does not exist with email "{0}"'.format(email))
                    user = user_datastore.create_user(email=email)
                    user_datastore.add_role_to_user(user, 'bronze')
                    user_datastore.activate_user(user)
                if not add_update_bronze_data(user):
                    if flash_it:
                        flash('Unable to update user KYC data', 'danger')
                    return False
                login_user(user, remember=True)
                db.session.commit()
            else:
                if flash_it:
                    flash('Unable to update user email', 'danger')
                return False
        else:
            if flash_it:
                flash('Not logged in to Bronze', 'danger')
            return False
    else:
        if not add_update_bronze_data(current_user):
            if flash_it:
                flash('Unable to update user KYC data', 'danger')
            return False

    return True

def check_bronze_kyc_level():
    if not hasattr(current_user, 'bronze_data') or not current_user.bronze_data:
        return False;
    # if not kyc validated check again with bronze to see if updated
    if not current_user.bronze_data.kyc_validated:
        add_update_bronze_data(current_user)
    return current_user.bronze_data.kyc_validated

@app.before_first_request
def start_address_watcher():
    aw.transfer_tx_callback = transfer_tx_callback
    aw.start()
    timer.add_timer(timer_callback, app.config["TIMER_SECONDS"])
    timer.start()

def bad_request(message, code=400):
    response = jsonify({"message": message})
    response.status_code = code
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
    # set bronze vars
    g.bronze_authorized = bronze.authorized
    g.bronze_kyc_url = app.config["BRONZE_ADDRESS"] + '/Manage/Kyc'
    # debug requests
    if "DEBUG_REQUESTS" in app.config:
        logger.info("URL: %s" % request.url)
        logger.info(request.headers)

@app.route("/")
def index_ep():
    return render_template("index.html")

#
# Test
#

@app.route("/test/invoice/<token>")
def test_invoice_ep(token):
    if not app.config["DEBUG"]:
        return abort(404)
    invoice = Invoice.from_token(db.session, token)
    if token in ws_invoices:
        logger.info("sending invoice update %s" % token)
        socketio.emit("info", invoice.to_json(), json=True, room=token, namespace=NAMESPACE)
    if invoice:
        return jsonify(invoice.to_json())
    return abort(404)

@app.route("/test/ws")
def test_ws_ep():
    if not app.config["DEBUG"]:
        return abort(404)
    return jsonify(ws_invoices)

#
# Websocket events
#

def alert_invoice_update(invoice):
    socketio.emit("update", invoice.to_json(), json=True, room=invoice.token, namespace=NAMESPACE)

class SocketIoNamespace(Namespace):
    def on_error(self, e):
        logger.error(e)

    def on_connect(self):
        logger.info("connect sid: %s" % request.sid)

    def on_invoice(self, token):
        logger.info("join room for invoice: %s" % token)
        join_room(token)
        ws_invoices[token] = request.sid
        ws_sids[request.sid] = token
        emit("info", "joined room for invoice: %s" % token)

    def on_disconnect(self):
        logger.info("disconnect sid: %s" % request.sid)
        if request.sid in ws_sids:
            token = ws_sids[request.sid]
            if token in ws_invoices:
                logger.info("leave room for invoice: %s" % token)
                leave_room(token)
                del ws_invoices[token]
            del ws_sids[request.sid]

socketio.on_namespace(SocketIoNamespace(namespace=NAMESPACE))

#
# Public endpoints
#

@app.route("/kyc_incomplete")
def kyc_incomplete_ep():
    return render_template('kyc_incomplete.html')

def validate_amount(amount):
    try:
        # check amount
        amount = decimal.Decimal(amount)
    except:
        return "amount must be a valid number"
    if amount <= 0:
        return "amount must be greater then zero"
    return None

def validate_multiplier(multiplier):
    try:
        # check multiplier
        multiplier = int(multiplier)
    except:
        return "amount must be a valid number"
    if multiplier != 2 and multiplier != 5 and multiplier != 10:
        return "multiplier must be 2, 5 or 10"
    return None

def validate_email(email):
    if not email or not is_email(email):
        return "invalid email address"
    return None

def invoice_create(email, amount):
    invoice = Invoice(email, amount, Invoice.STATUS_CREATED)
    db.session.add(invoice)
    return invoice

def spin_create(email, amount, multiplier):
    invoice = invoice_create(email, amount)
    spin = Spin(amount, multiplier, invoice)
    db.session.add(spin)
    return spin, invoice

@app.route("/spin", methods=["GET", "POST"])
def spin_ep():
    email = amount = multiplier = None
    if request.method == "POST":
        email = request.form.get("email")
        amount = request.form.get("amount")
        multiplier = request.form.get("multiplier")
        #error = validate_email(email)
        #if not error:
        error = validate_amount(amount)
        if not error:
            error = validate_multiplier(multiplier)
        if not error:
            amount_cents = int(float(amount) * 100)
            multiplier = int(multiplier)
            spin, invoice = spin_create(email, amount_cents, multiplier)
            db.session.commit()
            return redirect(url_for("invoice_ep", token=invoice.token))
        else:
            flash(error, 'danger')
    if not email:
        email = ''
    if not amount:
        amount = 0
    if not multiplier:
        multiplier = 2
    return render_template("spin.html", email=email, amount=amount, multiplier=int(multiplier))

@app.route("/spin_execute/<token>")
def spin_execute_ep(token):
    invoice = Invoice.from_token(db.session, token)
    if not invoice:
        return abort(404)
    if not invoice.txid:
        return abort(400)
    spin = Spin.from_invoice(db.session, invoice)
    if not spin:
        return abort(404)
    if spin.result == None and spin.win == None:
        spin.result = secrets.randbelow(spin.multiplier - 1)
        spin.win = spin.result == 0
        db.session.add(spin)
        db.session.commit()
    url = None
    qrcode_svg = None
    if not spin.payout_txid:
        logger.info('request.url is %s', request.url)
        url_parts = urllib.parse.urlparse(request.url)
        scheme = url_parts.scheme
        if request.headers.get('X-Forwarded-Proto') == 'https':
            scheme = 'https'
        url = url_parts._replace(scheme='premiostagelink', path='/claim_payment/{}'.format(token), query='scheme={}'.format(scheme)).geturl()
        qrcode_svg = qrcode_svg_create(url)
    return render_template("spin_execute.html", spin=spin, invoice=invoice, url=url, qrcode_svg=qrcode_svg)

@app.route("/spin_test")
def spin_test_ep():
    return render_template("spin_test.html")

@app.route("/claim_payment/<token>", methods=["POST"])
def claim_payment(token):
    invoice = Invoice.from_token(db.session, token)
    if not invoice:
        return abort(404)
    if not invoice.txid:
        return abort(400)
    spin = Spin.from_invoice(db.session, invoice)
    if not spin:
        return abort(404)
    if not spin.win:
        return abort(400)
    if spin.payout_txid:
        return bad_request('payout already sent')

    content_type = request.content_type
    logger.info("claim_payment: content type - %s", content_type)
    recipient = ""
    asset_id = ""
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(content, ["recipient", "asset_id"])
    if err_response:
        return bad_request(err_response)
    recipient, asset_id = params
    try:
        txid = create_transaction_waves(recipient, spin.bet * spin.multiplier, '')
        if txid:
            spin.payout_txid = txid
            db.session.add(spin)
            db.session.commit()
            return 'ok'
        else:
            return bad_request('failed to send funds')
    except Exception as e:
        logger.error(e)
        return bad_request(str(e))

@app.route("/invoice", methods=["GET", "POST"])
def invoice_ep():
    qrcode_svg = None
    url = None
    token = request.args.get("token")
    invoice = Invoice.from_token(db.session, token)
    if not invoice:
        return abort(404)
    if invoice.status == Invoice.STATUS_EXPIRED:
        flash("invoice expired", "danger")
        return render_template("invoice.html", invoice=invoice)
    if request.method == "POST":
        if invoice.status == Invoice.STATUS_CREATED:
            logger.info("setting invoice status to READY")
            invoice.status = Invoice.STATUS_READY
            db.session.add(invoice)
            db.session.commit()
    if invoice.status == Invoice.STATUS_READY:
        # prepare template
        payment_address = app.config["ZAP_ADDRESS"]
        invoice_id = invoice.token
        attachment = json.dumps(dict(InvoiceId=invoice_id))
        url = "waves://{}?asset={}&amount={}&attachment={}".format(payment_address, app.config["ASSET_ID"], invoice.amount, attachment)
        qrcode_svg = qrcode_svg_create(url)
    if invoice.txid:
        if Spin.from_invoice(db.session, invoice):
            return redirect('/spin_execute/' + invoice.token)
        #TODO
        #if Jackpot.from_invoice(db.session, invoice):
        #    return redirect('/jackpot_execute/' + invoice.token)
    return render_template("invoice.html", invoice=invoice, qrcode_svg=qrcode_svg, url=url)

@app.route('/bronze_oauth')
def bronze_oauth_ep():
    if not bronze.authorized:
        return redirect(url_for('bronze.login'))
    return redirect(url_for('index_ep'))

@app.route('/bronze_oauth_complete')
def bronze_oauth_complete_ep():
    if bronze.authorized:
        check_bronze_auth(True)
    return redirect(url_for('index_ep'))

@app.route("/logout")
def logout_ep():
    if bronze_blueprint.token:
        del bronze_blueprint.token
    logout_user()
    return redirect(url_for('index_ep'))

if __name__ == "__main__":
    logger.info("app.py start..")
    setup_logging(logging.DEBUG)

    # create tables
    db.create_all()
    create_role("admin", "super user")
    create_role("bronze", "bronze user")
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
        if "ZAP_ADDRESS" not in app.config:
            logger.error("ZAP_ADDRESS does not exist")
            sys.exit(1)
        if "ZAP_SEED" not in app.config:
            logger.error("ZAP_SEED does not exist")
            sys.exit(1)

        # Bind to PORT if defined, otherwise default to 5000.
        port = int(os.environ.get("PORT", 5000))
        logger.info("binding to port: %d" % port)
        socketio.run(app, host="0.0.0.0", port=port)
        # stop addresswatcher
        if aw:
            aw.kill()
        # stop timer
        if timer:
            timer.kill()

