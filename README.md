# cerberus
A Common Lisp Kerberos (version 5) implementation.

This is an implementation of the Kerberos v5 authentication protocol in Common Lisp. The intention is to provide 
a robust, reliable and portable (across both Lisp implementations and host OSs) Kerberos authentication system. 
It has been developed/tested against the Windows KDC (i.e. active directory) running on SBCL under both Windows and Linux.

## 1. Introduction
Kerberos is the de facto standard method of authentication over a network, notably in Microsoft Windows environments.

The basic principal of Kerberos is there is a trusted central authority which stores credentials (password equivalents)
for each principal (user account). This is known as the Key Distribution Centre (KDC). 
A client can prove its identity to an application server by requesting a message from the KDC 
which is encrypted with the server's private key. Only the server (and the KDC) have the knowledge to decrypt this message,
the client itself does not. The client forwards this message to the server, who decrypts it and examines 
the contents of the message. Inside it will be some proof (e.g. a recent timestamp) that the client is who they say they are. 

In its simplest form, the Kerberos protocol consists of the following sequence of exchanges:
* Client sends a message to authentication server (AS) component of the KDC requesting a ticket for the ticket-granting server (TGS).
* The AS responds with a message encrypted with the client's private key, only the client can decrypt this message.
* The client sends a request to the TGS for a ticket for the desired principal (application server).
* The client sends this ticket to the application server using the relevant application protocol.
* The application server validates the ticket and approves access to the client.

The details get more complicated, but that is the general idea.

## 2. Project aims
- [x] Be able to encode/decode all the relevant DER-encoded ASN.1 messages 
- [x] Support a suffiently wide range of encryption profiles to be useful. In practise this means the ones supported by
Microsoft. 
- [x] Send AS-REQ messages to the KDC to get TGTs 
- [x] Send TGS-REQ messages to the KDC to get credentials for application servers
- [x] Encode/decode AP-REQ messages to send to application servers
- [x] Validate AP-REQ messages to authenticate clients
- [x] Wrap AP-REQ messages with the KRB5 OID, as required for GSS
- [x] Some sort of GSSAPI integration (sort of there, some polishing required)
- [ ] Long term aim: write a KDC server

## 3. Usage

Users should first "logon" by providing credentials and IP address of the KDC (Domain controller):
```
(logon-user "username@realm" "password" :kdc-address "10.1.1.1")
```
This modifies the global `*CURRENT-USER*` variable. Alternatively you may rebind this variable 
if you require a local change of user.
```
(with-current-user ((logon-user "username@realm" "Pasword" :kdc-address "10.1.1.1"))
  body)
```

Services, which do not require initial authentication with the KDC, should use 
```
(logon-service "service/host.name.com@realm" keylist)
```
where `KEYLIST` is a list of keys as returned from either `GENERATE-KEYLIST` or `LOAD-KEYTAB`.

### 3.1 GSSAPI
Kerberos authentication is then performed using the GSSAPI as provided by the [glass](https://github.com/fjames86/glass) 
package. 


```
;; ---------- client --------
CL-USER> (logon-user "username@realm" "password" :kdc-address "10.1.1.1")
;; acquire a client credential structure for the current user
CL-USER> (defparameter *client-creds* (gss:acquire-credentials :kerberos "service/host.name.com@realm"))
*CLIENT-CREDS*
;; initialize a context and generate a token buffer to send to the server
CL-USER> (multiple-value-bind (context buffer) (gss:initialize-security-context *client-creds* :mutual t)
	   (defvar *client-context* context)
	   (defvar *buffer* buffer))
*BUFFER*

;; -------- on the server -----
CL-USER> (logon-service "service/host.name.com@realm" *keylist*)
;; acquire a crednetial structure for the current user
CL-USER> (defparameter *server-creds* (gss:acquire-credentials :kerberos nil))
*SERVER-CREDS*
;; accept the context and generate a response token (if required)
CL-USER> (multiple-value-bind (context buffer) (gss:accept-security-context *server-creds* *buffer*)
	   (defvar *server-context* context)
	   (defvar *response-buffer* buffer))
*RESPONSE-BUFFER*

;; -------- client -----------
;; pass the token back to the client so it can validate the server
CL-USER> (gss:initialize-security-context *client-context* :buffer *response-buffer*)
```

## 4. Encryption profiles
Cerberus supports a set of encryption "profiles", which are implemented by specializing a set of generic functions.

- [x] The simple DES-based profiles are all implemented and appear to be working, DES-CBC-MD5, DES-CBC-MD4 and DES-CBC-CRC.
- [x] The Microsoft profile RC4-HMAC is working correctly. RC4-HMAC-EXP has an unknown problem and is not working correctly.
It has temporarily been disabled.
- [x] The triple-des profile, DES3-CBC-SHA1-KD, is implemented and looks like it's working. 
- [x] The AES128 and AES256 profiles are working correctly.

## 5. Keytab files
You can load keytab files (as output from other Kerberos implementations, such from ktpass utility) using 
```
CL-USER> (cerberus:load-keytab "my.keytab")
```
This returns a list of KEYTAB-ENTRY structures, which include information about the principal as well as the 
encryption key. 

Note: there currently is no way to use the contents of a keytab file.

## 6. TODO
- [ ] Need to be able to renew tickets (written the function but does it work?)
- [x] Somehow need to be able to use this in an application that requires GSS support.
- [x] Need to support encrypting application messages using the (sub)session key.
- [x] Some sort of credential cache, i.e. database of TGTs and tickets for other principals.
- [ ] Support cross-realm requests and tickets.
- [ ] Need to support sub-session keys. At the moment it is assumed only the session key is available.
- [ ] A persistent credential cache? Could use the serializer to write the tickets out to a file.

## 7. Notes
* Both the DER serializer and the encryption functions cons A LOT.
* The ASN.1 serializer is specific to this project and NOT a generalized ASN.1 (DER) serializer. It makes certain assumptions which are valid
in the context of Kerberos messages, but are not generally applicable. Perhaps it could form the basis of one in the future.
* This was developed and tested against the Windows KDC (i.e. active directory). It should work with other KDCs such as MIT and Heimdal, 
but I've not tried.
* Need to understand the MS-PAC structures, these contain authorization data that is likely to be very useful. 

## 8. License
Licensed under the terms of the MIT license.

Frank James 
April 2015.

