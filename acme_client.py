#!/usr/bin/env python

import base64 # 64 bit encoding kacke
import logging # library welche uns logging ermöglich, logger z.B. log.info
import crypto # zu encodieren und decodieren
import json # für json in python (head, payload ....) , jegliche Communication mit Server
import requests # GET and POST

DEFAULT_CA = "https://iisca.com"
LOGGER = logging.getLogger(__name__)

def cert_process(acc_key, csr, acme_dir, log=LOGGER, CA=DEFAULT_CA):

    def b64_help(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])