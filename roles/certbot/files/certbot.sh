#!/bin/bash -x

cp /home/dave/bin/001-ashtangayoga.ie-ssl.conf.no-proxy /etc/apache2/sites-available/001-ashtangayoga.ie-ssl.conf
/bin/systemctl restart apache2
/usr/bin/certbot renew 
cp /home/dave/bin/001-ashtangayoga.ie-ssl.conf.proxy /etc/apache2/sites-available/001-ashtangayoga.ie-ssl.conf
/bin/systemctl restart apache2
