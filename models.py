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
from sqlalchemy import and_
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
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

    def __str__(self):
        return '%s' % self.email

class InvoiceSchema(Schema):
    date = fields.Float()
    token = fields.String()
    nonce = fields.Integer()
    secret = fields.String()
    amount = fields.Integer()
    amount_zap = fields.Integer()
    bronze_broker_token = fields.String()
    tx_seen = fields.Boolean()

class Invoice(db.Model):
    STATUS_CREATED = "Created"
    STATUS_READY = "Ready"
    STATUS_EXPIRED = "Expired"

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    nonce = db.Column(db.Integer, nullable=False)
    secret = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    amount_zap = db.Column(db.Integer, nullable=False)
    bronze_broker_token = db.Column(db.String(255), nullable=False)
    tx_seen = db.Column(db.Boolean, nullable=False)

    def __init__(self, amount, amount_zap, bronze_broker_token):
        self.generate_defaults()
        self.amount = amount
        self.amount_zap = amount_zap
        self.bronze_broker_token = bronze_broker_token
        self.tx_seen = False

    def generate_defaults(self):
        self.date = datetime.datetime.now()
        self.token = generate_key(8)
        self.nonce = 0
        self.secret = generate_key(16)

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    def __repr__(self):
        return "<Invoice %r>" % (self.token)

    def to_json(self):
        schema = InvoiceSchema()
        return schema.dump(self).data

class Utility(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text())
    bank_description = db.Column(db.Text(), nullable=False)

    def __init__(self, name):
        self.generate_defaults()

    def generate_defaults(self):
        self.date = datetime.datetime.now()

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def all(cls, session):
        return session.query(cls).all()

    @classmethod
    def all_alphabetical(cls, session):
        return session.query(cls).order_by(cls.name).all()

    @classmethod
    def from_id(cls, session, utility_id):
        return session.query(cls).filter(cls.id == utility_id).first()

    @classmethod
    def jsonify_bank_descriptions(cls, utilities):
        for utility in utilities:
            utility.bank_description_json = json.loads(utility.bank_description)

    def __repr__(self):
        return "<Utility %r>" % (self.name)


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
    if name == 'amount_zap':
        return round((model.amount_zap / 100),2)

def fields_check(fields):
    TYPE = 'type'
    TARGET = 'target'
    mandatory = ['label', 'description', TYPE, TARGET]
    valid_types = ['number', 'text']
    valid_targets = ['reference', 'code', 'particulars']
    def target_check(target):
        if target not in valid_targets:
            raise ValidationError('"{}" is not one of "{}"'.format(target, valid_targets))
    def target_check_list(targets):
        if not targets:
            raise ValidationError('{} "{}" is empty'.format(TARGET, targets))
        for target in targets:
            target_check(target)
    valid_target_types = [(str, target_check), (list, target_check_list)]
    for item in fields:
        if not isinstance(item, dict):
            raise ValidationError('"{}" is not a dictionary'.format(item))
        for param in mandatory:
            if param not in item:
                raise ValidationError('"{}" is missing "{}" parameter'.format(item, param))
        if item[TYPE] not in valid_types:
            raise ValidationError('"{}" is not one of "{}"'.format(TYPE, valid_types))
        target = item[TARGET]
        valid_target_type = False
        for target_type, target_check_fn in valid_target_types:
            if isinstance(target, target_type):
                valid_target_type = True
                target_check_fn(target)
        if not valid_target_type:
            lst = [target_type for target_type, target_check_fn in valid_target_types]
            raise ValidationError('"{}" is not one of "{}"'.format(TARGET, lst))


def bank_description_check(form, field):
    ACCOUNT_NUMBER = 'account_number'
    FIELDS = 'fields'
    mandatory = ['name', ACCOUNT_NUMBER, FIELDS]
    try:
        json_data = json.loads(field.data)
    except:
        raise ValidationError('Invalid JSON')
    if not isinstance(json_data, list):
        raise ValidationError('Root object is not a list/array')
    for item in json_data:
        if not isinstance(item, dict):
            raise ValidationError('"{}" is not a dictionary'.format(item))
        for param in mandatory:
            if param not in item:
                raise ValidationError('"{}" is missing "{}" parameter'.format(item, param))
        if not isinstance(item[ACCOUNT_NUMBER], str):
            raise ValidationError('"{}" is not a string'.format(ACCOUNT_NUMBER))
        if not isinstance(item[FIELDS], list):
            raise ValidationError('"{}" is not a list/array'.format(FIELDS))
        fields_check(item[FIELDS])

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
    column_list = ['email', 'roles']
    column_editable_list = ['roles']

class InvoiceModelView(RestrictedModelView):
    column_formatters = dict(amount=_format_amount, amount_receive=_format_amount)
    column_labels = dict(amount='ZAP Amount', amount_receive='NZD Amount')

class UtilityModelView(RestrictedModelView):
    can_create = True
    can_delete = True
    can_edit = True

    form_widget_args = {
        'description': {
            'rows': 5
        },
        'bank_description': {
            'rows': 20,
            'style': 'font-family: monospace;'
        }
    }

    form_args = dict(
        bank_description = dict(validators=[bank_description_check])
    )
