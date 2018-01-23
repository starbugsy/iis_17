#!/usr/bin/env python

import argparse # for parsing the arguments
import subprocess # similar to fork in c
import json # for using json
import os
import sys
import base64 # for encoding in utf urlsafe base64
import binascii
import time
import hashlib
import re # for regexes
import copy
import textwrap
import logging
try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2

# our client was build on the parent acme_tiny.py
# author: Sandro Letter

CA = "https://iisca.com"

def get_certificate(account_key, domain_csr, acme_dir):
    # tiny helper function base64 encoding
    def base_64(var_help):
        print("\nOutput von base_64 {}\n" .format(base64.urlsafe_b64encode(var_help).decode('utf8').replace("=", "")))
        return base64.urlsafe_b64encode(var_help).decode('utf8').replace("=", "")

    print("Parsing account key ...")

    process = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate() # used for deadlock prevention
    if process.returncode != 0: # an error occured
        raise IO_Error("OpenSSL Error: {}".format(error))

    print("Das ist der output {}" .format(output))

    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        output.decode('utf8'), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}" .format(int(pub_exp))
    print("Das ist der Public Exponent 0x{}" .format(pub_exp))
    print("pub_exp laenge {}" .format(len(pub_exp)))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp # vermutlich aenderbar
    print pub_exp
    print ("pub_hex {}" .format(pub_hex))

    header = {
        "alg": "RS256",
        "jwk": {
            "e": base_64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": base_64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    account_key_json = json.dumps(header['jwk'], sort_keys = True, separators = (',', ':'))
    print ("account key json {}" .format(account_key_json))
    thumbprint = base_64(hashlib.sha256(account_key_json.encode('utf8')).digest())

    #helper function for signed requests
    def send_signed_request(url, payload):
        payload_64 = base_64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        print ("Der HEADER {}" .format(protected))
        #protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
        protected_64 = base_64(json.dumps(protected).encode('utf8'))
        process = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", account_key],
                                   stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        output, error = process.communicate("{0}.{1}" .format(protected_64, payload_64).encode('utf8'))
        if process.returncode != 0:
            raise IO_Error("OpenSSL Error: {}" .format(error))
        print ("Output: {}" .format(process.returncode))
        data = json.dumps({
            "header": header,
            "protected": protected_64,
            "payload": payload_64,
            "signature": base_64(output),
        })
        try:
            resp = urlopen(url, data.encode('utf8'))
            return resp.getcode(), resp.read()
        except IO_Error as checker:
            return get_attr(checker, "code", None), get_attr(checker, "read", checker.__str__)()

    # find domains
    print("Parsing CSR...")
    process = subprocess.Popen(["openssl", "req", "-in", domain_csr, "-noout", "-text"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    if process.returncode != 0:
        raise IO_Error("Error loading {0}: {1}" .format(domain_csr, err))
    domains = set([])
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", output.decode('utf8'))
    print ("Common Name: {}" .format(common_name))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", output.decode('utf8'),
                                  re.MULTILINE | re.DOTALL)
    if subject_alt_names is not None: # first san not sure if checker works
        for checker in subject_alt_names.group(1).split(", "):
            if checker.startswith("DNS:"):
                domains.add(checker[4:])
    print ("Domains: {}" .format(domains))

    # get the certificate domains and expiration
    print("Registering account...")



    code, result = send_signed_request(CA + "/acme/new-reg", {
        "resource": "new-reg",
        "agreement": json.loads(urlopen(CA + "/directory").read().decode('utf8'))['meta']['terms-of-service'],
    })
    if code == 201:
        print("Registered!")
    elif code == 409:
        print("Already registered!")
    else:
        raise Value_Error("Error registering : {0} {1}" .format(code, result))

    #verify each domain
    for domain in domains:
        print("Verifying {}..." .format(domain))

        # get new challenge
        code, result = send_signed_request(CA + "/acme/new-authz", {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            raise Value_Error("Error requesting challenges: {0} {1}" .format(code, result))

        # make the challenge file
        challenge = [checker for checker in json.loads(result.decode('utf8'))['challenges'] if checker ['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        key_authorization = "{0}.{1}".format(token, thumbprint)

        # creating the file
        wellknown_path = os.path.join(acme_dir, token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(key_authorization)

        # after creating, check location
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}" .format(domain, token)
        try:
            resp = urlopen(wellknown_url)
            resp_data = resp.read().decode('utf8').strip()
            assert resp_data == key_authorization
        except (IO_Error, Assertion_Error):
            os.remove(wellknown_path) # delete file
            raise Value_Error("Wrote file to {0}, but couldn't download {1}" .format(
                wellknown_path, wellknown_url
            ))

        # notifying that the challenge is done
        code, result = send_signed_request(challenge['uri'], {
            "resource": "challenge",
            "keyAuthorization": key_authorization,
        })
        if code != 202: # boulder needs 202
            raise Value_Error("Error in challenge: {0} {1}" .format(code, result))

        # wait for the verifying
        while True:
            try:
                resp = urlopen(challenge['uri'])
                challenge_status = json.loads(resp.read().decode('utf8'))
            except IO_Error as checker:
                raise Value_Error("Error checking challenge: {0} {1}" .format(
                    checker.code, json.loads(checker.read().decode('utf8'))))
            if challenge_status['status'] == "valid":
                print("{} verified!" .format(domain))
                os.remove(wellknown_path) # delete file
                break
            else:
                raise Value_Error("{0} challenge did not pass: {1}" .format(domain, challenge_status))

    # get the new certificate
    print("Signing certificate...")
    process = subprocess.Popen(["openssl", "req", "-in", domain_csr, "-outform", "DER"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    domain_csr_der, error = process.communicate()
    code, result = _send_signed_request(CA + "/acme/new-cert", {
        "resource": "new-cert",
        "csr": _b64(domain_csr_der),
    })
    if code != 201:
        raise Value_Error("Error signing certificate: {0} {1}".format(code, result))

    # return signed certificate
    print("Certificate signed!")
    return """-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n""" .format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64)))


def main(argv):
    parser = argparse.ArgumentParser(description = 'Parsing arguments for getting a signed TLS certificate')
    parser.add_argument("--account-key", required = True, help = "path to your private key")
    parser.add_argument("--domain-csr", required = True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required = True, help="path to the .well-known/acme-challenge/ directory")

    arguments = parser.parse_args(argv)

    print(arguments)

    signed_certificate = get_certificate(arguments.account_key, arguments.domain_csr, arguments.acme_dir)
    print(signed_certificate)

if __name__ == '__main__':
    main(sys.argv[1:])
