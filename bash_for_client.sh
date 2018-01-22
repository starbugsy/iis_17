#!/bin/bash

###### root.cert.pem eingeben ######
sudo cp -u /home/iis/certs/root.cert.pem /usr/local/share/ca-certificates

###### root.cert.pem umbenenennen ######
sudo mv /usr/local/share/ca-certificates/root.cert.pem /usr/local/share/ca-certificates/root.cert.crt

###### update certificate ######
sudo update-ca-certificates

###### account key ######
openssl genrsa 4096 > account.key

###### domain key ######
openssl genrsa 4096 > iissite.com.key.pem

###### domain csr ######
openssl req -new -sha256 -key iissite.com.key.pem -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:iissite.com,DNS:iissite.com")) > domain.csr

###### boulder activate ######
#gnome-terminal -e bash bash_for_bolder.sh

##### python script ######
python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /var/www/html/.well-known/acme-challenge/ > iissite.com.cert.pem

##### final destination ######
sudo cp -u ./iissite.com.key.pem /home/iis/certs/iissite
sudo cp -u ./iissite.com.cert.pem /home/iis/certs/iissite

##### reboot apache ######
sudo systemctl restart apache2
