# cerberus
A Kerberos implementation.

This is an implementation of the Kerberos v5 authentication protocol in Common Lisp.

## 1. Introduction
Kerberos is the de facto standard method of authentication over a network, notably in Microsoft Windows envrionments.
If you want to write robust and secure networked services, you need a robust and secure authentication system: Kerberos 
most likely the thing you need.

The basic principal of Kerberos is there is a trusted central authority which stores credentials (essentially passwords)
for each principal (user account). A client can prove its identity to a server by requesting a message from the KDC 
which is encrypted with the server's private key. Only the server (and the KDC) have the knowledge to decrypt this message.
The client forwards this message to the server, who decrypts it and examines the contents of the message. Inside it will be 
some proof (e.g. a recent timestamp) that the client is who they say they are. 

In its simplest form, the Kerberos protocol consists of the following sequence of exchanges:
* Client sends a message to authentication service component of the KDC requesting a ticket for the ticket-granting server (TGS)
* The AS responds with a message encrypted with the client's private key, only the client can decrypt this message.
* The client sends a request to the TGS for a ticket to the desired principal (application server).
* The client sends this ticket to the application server using whatever application protocol is required.
* The application server validates the ticket and approves access to the client.

The details get more complicated, but that is the general idea.

## 2. Aims
The first stage is for clients and application servers to mutually authenticate each other. This means:
* Clients need to be able to login to the authentication server (AS) and request a ticket-granting ticket (TGT) for 
the ticket-granting service (TGS).
* Clients need to be able to use their TGT to request tickets for any other principal they require.
* Application servers need to be able to authenticate tickets that are presented to them.

In the long term, it would be good to have a full key-distribution center (KDC) included. This is much bigger task
because now you need to have some secure database of principals/keys etc. Accessing the database would probably
entail some form of LDAP access, which is a massive task in itself. This can wait until a later date.

## 3. Usage
The public API is not finalized yet, but at the moment you can do something like:

```
;; login to the authenticaiton server and get a TGT
CL-USER> (defparameter *token* (login "username" "password" "realm" :kdc-address "10.1.0.1"))
;; request a ticket to the application server using the TGT
CL-USER> (defparameter *ticket* (request-ticket *token* (principal "service" :instance "hostname" :type :srv-inst)))
CL-USER> ;; profit????
```

## 4. Encryption profiles
* The simple ones (DES-CBC-MD5, DES-CBC-MD4 and DES-CBC-CRC) are all implemented and working.
* Looks like we need the RC4-HMAC profile which Microsoft uses. Without this we can't decrypt the 
tickets you are most likely to get from Microsoft KDC.
* Will need the stronger AES based profiles at some stage.
* There is a horrible "derive-key" function which is poorly specified. How do we implement it?

## 5. Notes
* Encryption functions provided by the ironclad package.
* The ASN.1 serializer is specific to this project and NOT a generalized Lisp ASN.1 serializer. Perhaps it could form
the basis of one in the future.
* Some of the algorithms specified in the RFCs are vague and poorly defined. 

## 6. License
Licensed under the terms of the MIT license.

Frank James 
April 2015.

