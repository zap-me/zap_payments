from flask_dance.consumer import OAuth2ConsumerBlueprint
from functools import partial
from flask.globals import LocalProxy, _lookup_app_object
from app_core import app

try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

def make_bronze_blueprint(
    scope,
    redirect_url=None,
    redirect_to=None,
    login_url=None,
    authorized_url=None,
    session_class=None,
    storage=None,
):
    bronze_bp = OAuth2ConsumerBlueprint(
        "bronze",
        __name__,
        client_id=app.config["CLIENT_ID"],
        client_secret=app.config["CLIENT_SECRET"],
        scope=scope,
        base_url=app.config["BRONZE_ADDRESS"]+"/oauth/v1/",
        authorization_url=app.config["BRONZE_ADDRESS"]+"/oauth/v1/Auth",
        token_url=app.config["BRONZE_ADDRESS"]+"/oauth/v1/Token",
        token_url_params={"include_client_id": True},
        redirect_url=redirect_url,
        redirect_to=redirect_to,
        login_url=login_url,
        authorized_url=authorized_url,
        session_class=session_class,
        storage=storage,
    )

    @bronze_bp.before_app_request
    def set_applocal_session():
        ctx = stack.top
        ctx.bronze_oauth = bronze_bp.session

    return bronze_bp


bronze = LocalProxy(partial(_lookup_app_object, "bronze_oauth"))
