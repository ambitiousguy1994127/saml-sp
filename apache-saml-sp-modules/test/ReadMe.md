## Set up test saml sp & idp
### Set up IDP Test Configuration
* [screenshot](https://alexanderlesin.github.io/screenshots/idp.png)
### Set up SP Test Configuration
```
git clone https://github.com/OpenIAM/saml-sp.git
cd saml-sp/test
autoreconf -ivf
./configure	
make
sudo make install
```
* `saml` `ErrorDocument` folder will be placed in /var/www/html.
* `saml-sp.conf` file will be placed in /etc/httpd/conf.d.
* hit http://localhost/saml

## Private Key & Self-Signed Certificate.
### Private Key
* Usage:
	+ This private key is used for sign SAML Response
* Generating it using Openssl Command:
	+ openssl genrsa -des3 -out rsaprivkey.pem 1024

### Self-Signed Certificate
* What is it?
	+ A self-signed certificate is an identity certificate that is signed by the same entity whose identity it certificates. In technical terms a self-signed certificate is one signed with its own private key.
* Generating it using Openssl Command:
	+ openssl req -key rsaprivkey.pem -new -x509 -days 365 -out rsacert.pem
### Generate them together
	openssl req \
       -newkey rsa:2048 -nodes -keyout rsaprivkey.pem \
       -x509 -days 365 -out rsacert.pem
