#!/bin/bash

###### root.cert.pem eingeben ######
sudo cp -u /home/iis/certs/root.cert.pem /usr/local/share/ca-certificates
sleep 5

###### root.cert.pem umbenenennen ######
sudo mv /usr/local/share/ca-certificates/root.cert.pem /usr/local/share/ca-certificates/root.cert.crt
sleep 5

###### update certificate ######
sudo update-ca-certificates
sleep 5

###### account key ######
openssl genrsa 4096 > account.key
sleep 5

###### domain key ######
openssl genrsa 4096 > iissite.com.key.pem
sleep 5

###### domain csr ######
openssl req -new -sha256 -key iissite.com.key.pem -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:iissite.com,DNS:iissite.com")) > domain.csr
sleep 5

##### python script ######
python client_for_boulder.py --account-key ./account.key --domain-csr ./domain.csr --acme-dir /var/www/html/.well-known/acme-challenge/ > iissite.com.cert.pem
sleep 5

##### final destination ######
sudo cp -u ./iissite.com.key.pem /home/iis/certs/iissite
sleep 5
sudo cp -u ./iissite.com.cert.pem /home/iis/certs/iissite
sleep 5

##### reboot apache ######
sudo systemctl restart apache2
