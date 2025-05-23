#!/bin/bash
rm -rvf /etc/postfix/certs/*
cd /etc/letsencrypt/live
rm /etc/postfix/sni
touch /etc/postfix/sni
for X in $(ls | grep -v 'README\|0001'); do 
    domain=$(echo $X | sed 's/www\.//')
    echo $domain
    if [ ! -d "/etc/postfix/certs/$domain" ]; then
        mkdir -vp /etc/postfix/certs/$domain
        cat $X/privkey.pem > /etc/postfix/certs/$domain/chain.pem
        cat $X/fullchain.pem >> /etc/postfix/certs/$domain/chain.pem
        echo "$domain /etc/postfix/certs/$domain/chain.pem" >> /etc/postfix/sni
    fi
done
/usr/sbin/postmap -F hash:/etc/postfix/sni
/bin/systemctl restart postfix