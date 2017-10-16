# About This Module

To put it briefly, this module run on the same server where the resource is located and make this resource
act like Service Provider. Enable Single Sign On functionality.
OpenIAM IDP acts like Identifier Provider.

In more details, this this module check the auth cookie from user's browser whether it is valid or not.
If not, it redirects user to OpenIAM IDP with SAML2.0 Request.
OpenIAM IDP send the SAML2.0 Response to Service Provider.
When the user is authenticated, he or she can access service provider.

# Installation
## 1. Installing Nginx
* [Installing Nginx Open Source](https://www.nginx.com/resources/admin-guide/installing-nginx-open-source/)
* [Installing Nginx Plus](https://www.nginx.com/resources/admin-guide/installing-nginx-plus/)
## 2. Compile Static Module
```
  ./configure --user=nginx --group=nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --add-module=/pathTo/nginx-saml-sp-module
  make
  sudo make install
  sudo nginx -s stop
  sudo nginx
```
## 3. Compile Dynamic Module
* Compile module
```
  ./configure --user=nginx --group=nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --add-dynamic-module=/pathTo/nginx-saml-sp-module
  make
  make modules
  sudo make install
```
* When you make some changes in the source file, 
```
  make modules
  sudo make install - Just do NOT run this command in Nginx Plus

```
* Load Module in configuration file(/etc/nginx/nginx.conf)
```
load_module modules/ngx_http_saml_sp_module.so;
```
# About Configuration

## Configuration overview
All configurations have main, server, location context.

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

Configurations example. [saml-sp.conf](https://alexanderlesin.github.io/conf/nginx-conf/saml-sp.conf)
