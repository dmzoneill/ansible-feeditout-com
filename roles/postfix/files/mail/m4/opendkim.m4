INPUT_MAIL_FILTER(`opendkim',
        `S=local:/run/opendkim/opendkim.sock, F=, T=S:4m;R:4m;E:10m')dnl
