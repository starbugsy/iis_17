#!/usr/bin/env python

import base64
import logging

DEFAULT_CA = "https://iisca.com"
LOGGER = logging.getLogger(__name__)

def cert_process(acc_key, csr, acme_dir, log=LOGGER, CA=DEFAULT_CA):

    def b64_help(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")