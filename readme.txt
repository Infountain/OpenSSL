This Repository will contain examples for OpenSSL 

most source files will be in C.

I will be updating relevent documents which will explain how code is working.

In case of any clarification please contact me on infountain28@gmail.com

Some useful openSSL commands to generate Private-Public key pair :
Private key generation :
    $ openssl genrsa -des3 -out private.pem 2048
    After this you will be asked for a passphrase(twice for confirmation). REMEMBER THIS.

Public key generation (from generated private key):
    $ openssl rsa -in private.pem -outform PEM -pubout -out public.pem
    again you will be asked for passphrase for private key

For tutorial purpose we will be using unencrypted private key. To do so, use this command
    $ openssl rsa -in private.pem -out unenc_private.pem


test commit
