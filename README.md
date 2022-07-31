# go-auth

[LIBRARY] A simple JWT service to check and parse a validation element


```bash
# to generate a simple ssl key
# https://stackoverflow.com/a/10176685
DEFAULT="req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365"
SECURITY=-nodes # to disable a password to this
openssl DEFAULT $SECURITY
```
