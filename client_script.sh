#!/bin/bash

###### root.cert.pem eingeben ######
sudo cp -u /home/iis/certs/root.cert.pem /usr/local/share/ca-certificates
wait

###### root.cert.pem umbenenennen ######
sudo mv /usr/local/share/ca-certificates/root.cert.pem /usr/local/share/ca-certificates/root.cert.crt
wait

###### update certificate ######
sudo update-ca-certificates
wait

###### account key ######
openssl genrsa 4096 > account.key
wait

###### domain key ######
openssl genrsa 4096 > iissite.com.key.pem
wait

###### domain csr ######
openssl req -new -sha256 -key iissite.com.key.pem -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:iissite.com,DNS:iissite.com")) > domain.csr
wait

##### python script ######
python client_for_boulder.py --account-key ./account.key --domain-csr ./domain.csr --acme-dir /var/www/html/.well-known/acme-challenge/ > iissite.com.cert.pem
wait

##### final destination ######
sudo cp -u ./iissite.com.key.pem /home/iis/certs/iissite
wait
sudo cp -u ./iissite.com.cert.pem /home/iis/certs/iissite
wait

##### reboot apache ######
sudo systemctl restart apache2
