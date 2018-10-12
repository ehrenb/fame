#! /usr/bin/env python

import os
import sys

sys.path.append(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from fame.core import fame_init
from web.auth.user_password.user_management import create_user as do_create_user
from utils import user_input, get_new_password


def create_user(admin=False, password=True):
    full_name = os.environ.get('FAME_ROOT_USER', None) or user_input("Full Name")
    email = os.environ.get('FAME_ROOT_USER', None) or user_input("Email Address")
    groups = os.environ.get('FAME_ROOT_USER_GROUPS', None) or user_input("Groups (comma-separated)", "cert")
    groups = groups.split(',')
    if admin:
        default_sharing = groups
        groups.append('*')
        permissions = ['*']
    else:
        default_sharing = user_input("Default Sharing Groups (comma-separated)").split(',')
        permissions = user_input("Permissions (comma-separated)").split(',')

    password = os.environ.get('FAME_ROOT_PASS', None) or get_new_password()
    # if password:
    #     password = get_new_password()
    # else:
    #     password = None

    do_create_user(full_name, email, groups, default_sharing, permissions, password)


if __name__ == '__main__':
    fame_init()
    create_user()
