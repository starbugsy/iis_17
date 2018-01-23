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
openssl req -new -sha256 -key iissite.com.key.pem -subj "/CN=iissite.com" > domain.csr

##### python script ######
python client_for_boulder.py --account-key ./account.key --domain-csr ./domain.csr --acme-dir /var/www/html/.well-known/acme-challenge/ > iissite.com.cert.pem

##### final destination ######
sudo cp -u ./iissite.com.key.pem /home/iis/certs/iissite
sudo cp -u ./iissite.com.cert.pem /home/iis/certs/iissite

##### reboot apache ######
sudo systemctl restart apache2
