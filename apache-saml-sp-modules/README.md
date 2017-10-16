# About This Module

To put it briefly, this module run on the same server where the resource is located and make this resource
act like Service Provider. Enable Single Sign On functionality.
OpenIAM IDP acts like Identifier Provider.

In more details, this this module check the auth cookie from user's browser whether it is valid or not.
If not, it redirects user to OpenIAM IDP with SAML2.0 Request.
OpenIAM IDP send the SAML2.0 Response to Service Provider.
When the user is authenticated, he or she can access service provider.

# Installation
## 1. Installing from Git Repository
```
  yum install http[apt-get install apache2]
  git clone https://github.com/OpenIAM/saml-sp.git
  cd src/
  autoreconf -ivf
  ./configure
  make
  [sudo] make install
```

### Notes
* KNOWN ISSUES: Autoconf does not work well on code freshly checked out of git. Autoconf artifacts must be rebuilt using this command.
```
  autoreconf -ivf
```

* ErrorDocument: Specify the absolute path in which ErrorDcouments are placed.
If not specified, the default is /var/www/html
```
  ./configure ErrorDocument=/var/www/html/saml
```

### Tips: 
* Some development packages should be pre-installed. 
```
  yum install httpd-devel [apt-get install apache2-dev]
  yum install libxml2-devel [apt-get install libxml2-dev]
  yum install xmlsec1-openssl-devel [apt-get install libxmlsec1-dev]
```

* If not, you can get some of errors while configuration.
```
  checking for apxs... no
  checking for apxs2... no
  configure: error: cannot find apxs or apxs2

  You can get this error if no apxs found
```

```
  checking for Dependencies... no
  configure: error: Package requirements (libxml-2.0 >= 2.6 xmlsec1-openssl >= 1.2.20) were not met:
  No package 'libxml-2.0' found

  You can get this error if no libxml development package
```

```
  checking for Dependencies... no
  configure: error: Package requirements (libxml-2.0 >= 2.6 xmlsec1-openssl >= 1.2.20) were not met:
  No package 'xmlsec1-openssl' found

  You can get this error if no xmlsec1-openssl development package
```

## 2. Dependencies

mod_saml_sp has a few dependencies:

* `mod_session` for using session 
* `mod_session_cookie` for storing session data in cookie
* `mod_session_crypto` for encrypting session data
* `apr-util-openssl` is required for using `mod_session_crypto`
```
  yum install mod_session [a2enmod session session_cookie session_crypto]
  sudo yum install apr-util-openssl
```
### Tips: 
Please make sure that the session_crypto_module is loaded. By default this module is not loaded. 

# About Configuration

## Configuration overview
All configurations have directory context.

* OPENIAM_SSOEnable:
	+ Enable or Disable this module. 
 	+ `on: Enable` `off: Disable`  
 	+ Default is `off` if not specified
* OPENIAM_SignatureEnable:
  + Indicate whether signature is included in SAMLResponse. 
  + `on: Enable` `off: Disable`  
  + Default is `off` if not specified
* OPENIAM_ExpirationTime:
	+ Auth Cookie expires in 20mins when it is set to 20. 
	+ Default is `30` if not specified.
* OPENIAM_AddtionalHeader:
	+ Set additional request header if it is enabled. 
	+ `on: Enable` `off: Disable`. 
	+ Not used for now.
* OPENIAM_SP_Name:
	+ Specify the name of service provider. This is used in SAMLRequest as a value of `ProviderName`. 
	+ Default is `null`.
* OPENIAM_SP_Issuer:
  + Specify unique identifier of the Identity Provider. It must be equal to Request Issuer on IDP side.. 
  + This attribute is `Mandatory`.
* OPENIAM_SP_LogoutURI:
	+ Specify the logout uri of the Service Provider. When the user hit this uri, it redirect user to IdP Logout Page after clearing auth cookie. 
	+ This attribute is `Mandatory`.
* OPENIAM_SP_LoginURI: 
	+ Specify the login uri of the Service Provider. This is the location to which the SAMLResponse message MUST be returned. This is used in SAMLRequest as a value of `AssertionConsumerServiceURL`. 
	+ This attribute is `Mandatory`.
* OPENIAM_IDP_LogoutURI: 
	+ Speicify the logout uri of the IdP. This is the location to which the user is redirected after clearing auth cookie. 
	+ This attribute is `Mandatory`.
* OPENIAM_IDP_LoginURI: 
	+ Speicify the login uri of the IdP. This is the location to which the SAMLRequest is sent. 
	+ This attribute is `Mandatory`.	
* OPENIAM_PrefixURI: 
	+ This uri on the resources don't need authentication. 
	+ Format should be like `/img/*` or `/img/`.
* OPENIAM_Cert_FILE: 
	+ Certificate file of IdP for validationg SAML Response.
* ErrorDocument xxx: 
	+ The location of HTTP Error Document.

## Tips: 
We need to add additional set of configurations so that our `error pages` and `certificiate file` cannot be requested directly by clients. To implement this behavior, we'll need to add a `Files` block for each of our custom pages and certificate file. Inside, we can test whether the `REDIRECT_STATUS` environmental variable is set. This should only be set when the ErrorDocument directive processes a request. If the environmental variable is empty, we'll serve a 404 error:

## Configuration Example
	html
    ├── saml
    │   ├── public.pem          # Certificate file of IdP
    │   └── ...
    │
    ├── ErrorDocuments      # ErrorDocuments
    │   ├── HTTP400.html
    │   ├── HTTP401.html
    │   ├── HTTP404.html
    │   └── ...
    └── ...
### Tips: 
* The certificate file can be placed anywhere in file system. But in this example it is placed in service provider directory.
* [saml-sp.conf](https://alexanderlesin.github.io/conf/apache-conf/saml-sp.conf)
