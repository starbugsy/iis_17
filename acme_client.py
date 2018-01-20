#!/usr/bin/env python

import base64
import logging

CA = "https://iisca.com"
LOGGER = logging.getLogger(__name__)

def cert_process(acc_key, csr, acme):

    def b64_help(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")