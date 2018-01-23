#!/usr/bin/env python

import argparse
import subprocess
import json
import os
import sys
import base64
import binascii
import copy
import tempfile
import re
try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2

CA = "https://iisca.com"

def revoke_certificate(account_key, signed_certificate):

    nonce_req = urllib2.Request("{0}/directory".format(CA))
    nonce_req.get_method = lambda : 'HEAD'

    # tiny helper function base64 encoding
    def base_64(var_help):
        return base64.urlsafe_b64encode(var_help).decode('utf8').replace("=", "")


    # Step 1: Get account public key
    LOGGER.info("Parsing account key ...")
    process = subprocess.Popen(["openssl", "rsa", "-pubin", "-in", account_key, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    if process.returncode != 0:
        raise IOError("Error loading {0}".format(account_key))
    pub_hex, public_exponent = re.search("Modulus\:\s+00:([a-f0-9\:\s]+?)Exponent\: ([0-9]+)", out, re.MULTILINE|re.DOTALL).groups()
    pub_mod = binascii.unhexlify(re.sub("(\s|:)", "", pub_hex))
    pub_mod64 = _base_64(pub_mod)
    public_exponent = int(public_exponent)
    public_exponent = "{0:x}".format(public_exponent)
    public_exponent = "0{0}".format(public_exponent) if len(public_exponent) % 2 else public_exponent
    public_exponent = binascii.unhexlify(public_exponent)
    header = {
        "alg": "RS256",
        "jwk": {
            "e": base_64(binascii.unhexlify(public_exponent.encode("utf-8"))),
            "kty": "RSA",
            "n": pub_mod64,
        },
    }
    sys.stderr.write("Found public key!\n".format(header))

    # Step 2: Generate the payload that needs to be signed
    # revocation request
    process = subprocess.Popen(["openssl", "x509", "-in", signed_certificate, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    crt_der, err = process.communicate()
    crt_der64 = _base_64(crt_der)
    crt_raw = json.dumps({
        "resource": "revoke-cert",
        "certificate": crt_der64,
    }, sort_keys=True, indent=4)
    crt_b64 = _base_64(crt_raw)
    crt_protected = copy.deepcopy(header)
    crt_protected.update({"nonce": urllib2.urlopen(nonce_req).headers['Replay-Nonce']})
    crt_protected64 = _base_64(json.dumps(crt_protected, sort_keys=True, indent=4))
    crt_file = tempfile.NamedTemporaryFile(dir=".", prefix="revoke_", suffix=".json")
    crt_file.write("{0}.{1}".format(crt_protected64, crt_b64))
    crt_file.flush()
    crt_file_name = os.path.basename(crt_file.name)
    crt_file_sig = tempfile.NamedTemporaryFile(dir=".", prefix="revoke_", suffix=".sig")
    crt_file_sig_name = os.path.basename(crt_file_sig.name)

    # Step 3: Ask the user to sign the revocation request
    sys.stderr.write("""\
STEP 1: You need to sign a file (replace 'user.key' with your user private key)
openssl dgst -sha256 -sign user.key -out {0} {1}
""".format(crt_file_sig_name, crt_file_name))

    temp_stdout = sys.stdout
    sys.stdout = sys.stderr
    raw_input("Press Enter when you've run the command above in a new terminal window...")
    sys.stdout = temp_stdout

    # Step 4: Load the signature and send the revocation request
    sys.stderr.write("Requesting revocation...\n")
    crt_file_sig.seek(0)
    crt_sig64 = _base_64(crt_file_sig.read())
    crt_data = json.dumps({
        "header": header,
        "protected": crt_protected64,
        "payload": crt_b64,
        "signature": crt_sig64,
    }, sort_keys=True, indent=4)
    try:
        resp = urllib2.urlopen("{0}/acme/revoke-cert".format(CA), crt_data)
        signed_der = resp.read()
    except urllib2.HTTPError as e:
        sys.stderr.write("Error: crt_data:\n")
        sys.stderr.write(crt_data)
        sys.stderr.write("\n")
        sys.stderr.write(e.read())
        sys.stderr.write("\n")
        raise
    sys.stderr.write("Certificate revoked!\n")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'Parsing arguments for revoking a signed TLS certificate')
    parser.add_argument("-p", "--public-key", required=True, help="path to your account public key")
    parser.add_argument("crt_path", help="path to your signed certificate")

    args = parser.parse_args()
    revoke_certificate(args.public_key, args.crt_path)
