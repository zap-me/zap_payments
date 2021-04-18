import datetime
from datetime import timezone
import decimal
import logging
import io
import json

from flask import redirect, url_for, request, abort, flash, has_app_context, g
from flask_admin import expose
from flask_admin.actions import action
from flask_admin.babel import lazy_gettext
from flask_admin.model import filters
from flask_admin.contrib import sqla
from sqlalchemy import and_, or_
from flask_admin.contrib.sqla.filters import BaseSQLAFilter
from wtforms import ValidationError
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from marshmallow import Schema, fields
from markupsafe import Markup

from app_core import app, db
from utils import generate_key

logger = logging.getLogger(__name__)

#
# Define models
#

roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    @classmethod
    def from_name(cls, session, name):
        return session.query(cls).filter(cls.name == name).first()

    def __str__(self):
        return self.name

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    bronze_data = db.relationship('BronzeData', cascade='delete', backref=db.backref('user'), uselist=False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

    def __str__(self):
        return '%s' % self.email

class BronzeData(db.Model):
    __tablename__ = 'bronze_data'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    kyc_validated = db.Column(db.Boolean())

    def __init__(self, user, kyc_validated):
        self.user_id = user.id
        self.kyc_validated = kyc_validated

class InvoiceSchema(Schema):
    date = fields.Float()
    expiry = fields.Float()
    token = fields.String()
    nonce = fields.Integer()
    secret = fields.String()
    email = fields.String()
    amount = fields.Integer()
    status = fields.String()
    tx_seen = fields.Boolean()

class Invoice(db.Model):
    STATUS_CREATED = "Created"
    STATUS_READY = "Ready"
    STATUS_INCOMING = "Incoming"
    STATUS_CONFIRMED = "Confirmed"
    STATUS_EXPIRED = "Expired"

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(), nullable=False)
    expiry = db.Column(db.DateTime(), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    nonce = db.Column(db.Integer, nullable=False)
    secret = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255))
    amount = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(255))
    tx_seen = db.Column(db.Boolean, nullable=False)
    txid = db.Column(db.String(255))

    def __init__(self, email, amount, status):
        self.generate_defaults()
        self.email = email
        self.amount = amount
        self.status = status
        self.tx_seen = False
        self.txid = None

    def generate_defaults(self):
        self.date = datetime.datetime.now()
        delta = datetime.timedelta(seconds = app.config["INVOICE_EXPIRY_SECONDS"])
        self.expiry = self.date + delta
        self.token = generate_key(8)
        self.nonce = 0
        self.secret = generate_key(16)

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def all_with_email_and_not_terminated(cls, session):
        return session.query(cls).filter(and_(cls.email != None, or_(cls.status == None, and_(cls.status != cls.STATUS_CONFIRMED, cls.status != cls.STATUS_EXPIRED)))).all()

    def __repr__(self):
        return "<Invoice %r %r>" % (self.token, self.status)

    def to_json(self):
        schema = InvoiceSchema()
        return schema.dump(self).data

class Spin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(), nullable=False)
    bet = db.Column(db.Integer, nullable=False)
    multiplier = db.Column(db.Integer, nullable=False)
    result = db.Column(db.Integer, nullable=True)
    win = db.Column(db.Boolean, nullable=True)
    invoice_id = db.Column(db.Integer, db.ForeignKey(Invoice.id))
    invoice = db.relationship(Invoice, uselist=False)

    def __init__(self, bet, multiplier, invoice):
        self.generate_defaults()
        self.bet = bet
        self.multiplier = multiplier
        self.invoice = invoice

    def generate_defaults(self):
        self.date = datetime.datetime.now()

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def all(cls, session):
        return session.query(cls).all()

    @classmethod
    def from_id(cls, session, utility_id):
        return session.query(cls).filter(cls.id == utility_id).first()

    @classmethod
    def from_invoice(cls, session, invoice):
        return session.query(cls).filter(cls.invoice_id == invoice.id).first()

    def __repr__(self):
        return "<Spin %r>" % (self.name)

#
# Setup Flask-Security
#

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

#
# Define model views
#

def _format_amount(view, context, model, name):
    if name == 'amount':
        return Markup(model.amount / 100)

class ReloadingIterator:
    def __init__(self, iterator_factory):
        self.iterator_factory = iterator_factory

    def __iter__(self):
        return self.iterator_factory()

class BaseModelView(sqla.ModelView):
    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))

class RestrictedModelView(BaseModelView):
    can_create = False
    can_delete = False
    can_edit = False
    column_exclude_list = ['password', 'secret']

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role('admin'))

class UserModelView(RestrictedModelView):
    can_delete = True
    column_list = ['email', 'roles']
    column_editable_list = ['roles']

class InvoiceModelView(RestrictedModelView):
    column_formatters = dict(amount=_format_amount)
