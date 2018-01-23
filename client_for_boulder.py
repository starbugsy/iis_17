#!/usr/bin/env python
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging

try:
    from urllib.request import urlopen  # Python 3
except ImportError:
    from urllib2 import urlopen  # Python 2

# based on the open source acme_tiny.py and adapted for boulder

# DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"
DEFAULT_CA = "https://iisca.com"

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


def get_crt(account_key, domain_csr, acme_dir, CA=DEFAULT_CA):
    # helper function base64 encode for jose spec
    def base_64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # parse account key to get public key
    LOGGER.info("Parsing account key...")

    process = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    if process.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(error))
    public_hexadecimal, public_exponent = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        output.decode('utf8'), re.MULTILINE | re.DOTALL).groups()
    public_exponent = "{0:x}".format(int(public_exponent))
    public_exponent = "0{0}".format(public_exponent) if len(public_exponent) % 2 else public_exponent
    header = {
        "alg": "RS256",
        "jwk": {
            "e": base_64(binascii.unhexlify(public_exponent.encode("utf-8"))),
            "kty": "RSA",
            "n": base_64(binascii.unhexlify(re.sub(r"(\s|:)", "", public_hexadecimal).encode("utf-8"))),
        },
    }
    accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
    thumbprint = base_64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # helper function make signed requests
    def _send_signed_request(url, payload):
        payload_64 = base_64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
        protected_64 = base_64(json.dumps(protected).encode('utf8'))
        process = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", account_key],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate("{0}.{1}".format(protected_64, payload_64).encode('utf8'))
        if process.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(error))
        data = json.dumps({
            "header": header, "protected": protected_64,
            "payload": payload_64, "signature": base_64(output),
        })
        try:
            checker = urlopen(url, data.encode('utf8'))
            return checker.getcode(), checker.read()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)()

    # find domains
    LOGGER.info("Parsing CSR...")
    process = subprocess.Popen(["openssl", "req", "-in", domain_csr, "-noout", "-text"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    if process.returncode != 0:
        raise IOError("Error loading {0}: {1}".format(domain_csr, error))
    domains = set([])
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", output.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", output.decode('utf8'),
                                  re.MULTILINE | re.DOTALL)
    if subject_alt_names is not None:
        for checker in subject_alt_names.group(1).split(", "):
            if checker.startswith("DNS:"):
                domains.add(checker[4:])

    # get the certificate domains and expiration
    LOGGER.info("Registering account...")
    code, result = _send_signed_request(CA + "/acme/new-reg", {
        "resource": "new-reg",
        "agreement": json.loads(urlopen(CA + "/directory").read().decode('utf8'))['meta']['terms-of-service'],
    })
    if code == 201:
        LOGGER.info("Registered!")
    elif code == 409:
        LOGGER.info("Already registered!")
    else:
        raise ValueError("Error registering: {0} {1}".format(code, result))

    # verify each domain
    for domain in domains:
        LOGGER.info("Verifying {0}...".format(domain))

        # get new challenge
        code, result = _send_signed_request(CA + "/acme/new-authz", {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

        # make the challenge file
        challenge = [c for c in json.loads(result.decode('utf8'))['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        wellknown_path = os.path.join(acme_dir, token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)

        # check that the file is in place
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
        try:
            checker = urlopen(wellknown_url)
            checker_data = checker.read().decode('utf8').strip()
            assert checker_data == keyauthorization
        except (IOError, AssertionError):
            os.remove(wellknown_path)
            raise ValueError("Wrote file to {0}, but couldn't download {1}".format(
                wellknown_path, wellknown_url))

        # notify challenge are met
        code, result = _send_signed_request(challenge['uri'], {
            "resource": "challenge",
            "keyAuthorization": keyauthorization,
        })
        if code != 202:
            raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

        # wait for challenge to be verified
        while True:
            try:
                checker = urlopen(challenge['uri'])
                challenge_status = json.loads(checker.read().decode('utf8'))
            except IOError as e:
                raise ValueError("Error checking challenge: {0} {1}".format(
                    e.code, json.loads(e.read().decode('utf8'))))
            if challenge_status['status'] == "pending":
                time.sleep(2)
            elif challenge_status['status'] == "valid":
                LOGGER.info("{0} verified!".format(domain))
                os.remove(wellknown_path)
                break
            else:
                raise ValueError("{0} challenge did not pass: {1}".format(
                    domain, challenge_status))

    # get the new certificate
    LOGGER.info("Signing certificate...")
    process = subprocess.Popen(["openssl", "req", "-in", domain_csr, "-outform", "DER"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    domain_csr_der, error = process.communicate()
    code, result = _send_signed_request(CA + "/acme/new-cert", {
        "resource": "new-cert",
        "csr": base_64(domain_csr_der),
    })
    if code != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(code, result))

    # return signed certificate!
    LOGGER.info("Certificate signed!")
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64)))


def main(argv):
    parser = argparse.ArgumentParser(
        description = "just a tiny_client"
    )
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--domain-csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--ca", default=DEFAULT_CA, help="certificate authority, default is Let's Encrypt")

    arguments = parser.parse_args(argv)

    LOGGER.setLevel(arguments.quiet or LOGGER.level)
    signed_crt = get_crt(arguments.account_key, arguments.domain_csr, arguments.acme_dir, CA=arguments.ca)
    sys.stdout.write(signed_crt)


if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
