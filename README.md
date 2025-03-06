# sm
KISS cli mail client, in Python

## WARNING
**I don't recommand using this as-is.** This a PoC, usable by me because I know what I want to do with it.

## Help
```
sm - Simple Mail client
=======================
~/.config/sm/init.json => {"accounts": [ACCOUNT_INFOS, ACCOUNT_INFOS, ...]}  - ACCOUNT_INFOS = {
    "name": "XX"
    "imap_ssl_host": "XX"
    "imap_ssl_port": 993
    "username": "XX"
    "password": "XX"
    "pinned_imap_certificate_sha256": "XX"
    "smtp_ssl_host": "XX"
    "smtp_ssl_port": 587
    "pinned_smtp_certificate_sha256": "XX"
    "local_store_path": "XX"=======================
- sm send recipient=c4ffein@gmail.com subject=title body=something file=/optional/path ==> send a mail
=======================
You need to generate an app specific password for gmail or other mail clients
```
