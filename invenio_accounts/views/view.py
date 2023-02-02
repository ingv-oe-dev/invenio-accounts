from flask import redirect, url_for
from flask_security.utils import login_user
from webargs import fields, validate
from .rest import RegisterView, user_already_authenticated, \
	unique_user_email, use_args, use_kwargs
from ..proxies import current_security
from ..utils import (
    register_user_notify_admin,
)

class IRegisterView(RegisterView):
	decorators = [user_already_authenticated]

	post_args = {
	    "email": fields.Email(required=True, validate=[unique_user_email]),
	    "password": fields.String(
	        required=True, validate=[validate.Length(min=6, max=128)]
	    ),
	}

	def success_response(self, user):
	    """Return a successful register response."""
	    return redirect(url_for('security.login'))

	@use_kwargs(post_args)
	def post(self, **kwargs):
	    """Register a user."""
	    if not current_security.registerable:
	        _abort(get_message("REGISTRATION_DISABLED")[0])

	    user = register_user_notify_admin(**kwargs)
	    return self.success_response(user)