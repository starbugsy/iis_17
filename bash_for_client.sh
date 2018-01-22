#!/bin/bash

NUMBER = 4096

ACCOUNT_KEY = account.key
DOMAIN_KEY = iissite.com.key.pem
DOMAIN_CSR = domain.csr
ROOT_CERT_PEM = root.cert.pem

###### root.cert.pem eingeben ######
sudo cp -u /home/iis/certs/$ROOT_CERT_PEM /usr/local/share/ca-certificates

###### root.cert.pem umbenenennen ######
sudo mv /usr/local/share/ca-certificates/root.cert.pem /usr/local/share/ca-certificates/root.cert.crt

###### update certificate ######
sudo update-ca certificates

###### account key ######
openssl genrsa $NUMBER > $ACCOUNT_KEY

###### domain key ######
openssl genrsa $NUMBER > $DOMAIN_KEY

###### domain csr ######
openssl req -new -sha256 -key $DOMAIN_KEY -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:iissite.com,DNS:iissite.com")) > $DOMAIN_CSR

###### boulder activate ######
./bash_for_bolder.sh

##### python script ######
python acme_tiny.py --account-key ./$ACCOUNT_KEY --csr ./$DOMAIN_CSR --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > iissite.com.cert.pem
