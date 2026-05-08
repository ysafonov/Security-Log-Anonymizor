"""
Application configuration.

This file contains basic Flask API settings and switches for enabling
or disabling individual anonymization categories.
"""

# -----------------------------------------------------------------------------
# API / Flask settings
# -----------------------------------------------------------------------------

# IP address where the Flask application will listen.
# 127.0.0.1 means the API is available only locally on the same machine.
# Use 0.0.0.0 if the API should be reachable from other hosts.
API_IP = "127.0.0.1"

# TCP port used by the Flask application.
API_PORT = 5000


# -----------------------------------------------------------------------------
# Single data category anonymization settings
# -----------------------------------------------------------------------------
#
# These flags control which data categories are anonymized when using
# the single-category anonymization endpoint.
#
# True  = anonymization for this category is enabled
# False = anonymization for this category is disabled
# -----------------------------------------------------------------------------

# E-mail addresses, for example:
# user@example.com
EMAIL = False

# IPv4 addresses, for example:
# 192.168.1.10
IPV4 = True

# IPv6 addresses, for example:
# 2001:db8::1
IPV6 = False

# Link-local IPv6 addresses, for example:
# fe80::1
LINKLOCAL = False

# Domain names, for example:
# example.com
DOMAIN = False

# MAC addresses, for example:
# 00:1A:2B:3C:4D:5E
MAC = False

# URLs, for example:
# https://example.com/login
URL = False

# Windows filesystem paths, for example:
# C:\\Users\\Administrator\\Desktop\\file.txt
WINDOWS_DIR = False

# Hostnames, for example:
# workstation-01
HOSTNAME = False

# Usernames, for example:
# administrator, john.doe, DOMAIN\\user
USERNAME = False
