# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2017-2018 CERN.
# Copyright (C)      2021 TU Wien.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio-accounts views."""

from flask import abort, current_app, redirect, request
from flask_security.utils import get_post_register_redirect
from flask_security.views import anonymous_user_required
from flask_security.views import login as base_login
from flask_security.views import register as base_register

from ..proxies import current_security
from ..utils import register_user_notify_admin
from .settings import blueprint


def _ctx(endpoint):
    return current_security._run_ctx_processor(endpoint)


@anonymous_user_required
@blueprint.route("/login")
def login(*args, **kwargs):
    """Disable login credential submission if local login is disabled."""
    local_login_enabled = current_app.config.get("ACCOUNTS_LOCAL_LOGIN_ENABLED", True)

    login_form_submitted = request.method == "POST"
    if login_form_submitted and not local_login_enabled:
        # only allow GET requests,
        # avoid credential submission/login via POST
        abort(404)

    return base_login(*args, **kwargs)


@anonymous_user_required
@blueprint.route("/signup")
def register(*args, **kwargs):
    register_form_submitted = request.method == "POST"
    if register_form_submitted and current_security.confirmable:
        form_class = current_security.confirm_register_form
        form = form_class(request.form)
        if form.validate_on_submit():
            user = register_user_notify_admin(**form.to_dict())
            form.user = user
        else:
            return current_security.render_template(
                current_app.config.get("SECURITY_REGISTER_USER_TEMPLATE"),
                register_user_form=form,
                **_ctx("register")
            )

        if not request.is_json:
            if 'next' in form:
                redirect_url = get_post_register_redirect(form.next.data)
            else:
                redirect_url = get_post_register_redirect()

            return redirect(redirect_url)

    return base_register(*args, **kwargs)


__all__ = ("blueprint", "login", "register")
