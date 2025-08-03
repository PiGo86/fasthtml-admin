from importlib import import_module
from importlib.util import find_spec

import datetime as dt
from typing import Optional

from fasthtml_admin.models import BaseConfirmToken, BaseUserCredentials, BaseSystemSetting

# if available, import peewee package as pw
# else, create a fake pw module
if find_spec('peewee'):
    pw = import_module('peewee')
else:
    class MockedPW:
        Model = type('Model', (), dict())
        CharField = type('CharField', (), {'__init__': lambda *args, **kwargs: None})
        DateTimeField = type('DateTimeField', (), {'__init__': lambda *args, **kwargs: None})
        BooleanField = type('BooleanField', (), {'__init__': lambda *args, **kwargs: None})
    pw = MockedPW()


db_proxy = pw.DatabaseProxy()


class BasePeeweeModel(pw.Model):
    class Meta:
        database = db_proxy


class ConfirmTokenPeewee(BaseConfirmToken, BasePeeweeModel):
    """
    Token for email confirmation.
    This class is designed to work with peewee database system.
    """
    token: str = pw.CharField(max_length=64, unique=True)
    email: str = pw.CharField(max_length=100)
    expiry: dt.datetime = pw.DateTimeField()
    is_used: bool = pw.BooleanField(default=False)


class UserCredentialPeewee(BaseUserCredentials, BasePeeweeModel):
    """
    Basic user credential class for authentication.
    This class is designed to work with peewee database system.

    This class can be extended by creating a subclass with additional fields
    before passing it to the UserManager constructor.
    """
    id: str = pw.CharField(primary_key=True)
    email: str = pw.CharField(max_length=100)
    pwd: str = pw.CharField(max_length=200)
    created_at: dt.datetime = pw.DateTimeField()
    is_confirmed: bool = pw.BooleanField(default=False)
    is_admin: bool = pw.BooleanField(default=False)
    last_login: Optional[dt.datetime] = pw.DateTimeField(null=True, default=None)


class SystemSettingPeewee(BaseSystemSetting, BasePeeweeModel):
    """
        System setting class for storing configuration values.
        This class is designed to work with peewee database system.
        """
    key: str = pw.CharField(primary_key=True, max_length=20)
    value: str = pw.CharField(max_length=20)
    updated_at: dt.datetime = pw.DateTimeField(null=True, default=None)
