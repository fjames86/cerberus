;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; This file contains the function to talk to the KDC (to request tickets)
;;; and related function to talk to application servers.

(in-package #:cerberus)

;; ------------------ kdc ----------------------------------

(defun process-req-response (buffer)
  "Examine the response, will either be a reply or an error"
  (let ((code (unpack #'decode-identifier buffer)))
    (ecase code
      (30 ;; error
       (let ((err (unpack #'decode-krb-error buffer)))
         (krb-error err)))
      (11 ;; as-rep
       (unpack #'decode-as-rep buffer))
      (13 ;; tgs-rep
       (unpack #'decode-tgs-rep buffer)))))

;; UDP doesn't seem very useful. Whenever I've called it I've got 
;; a "response would be too large to fit in UDP" error. Seems like TCP
;; is the way to do it.  
(defun send-req-udp (msg host &optional port)
  "Send a message to the KDC using UDP"
  (let ((socket (usocket:socket-connect host (or port 88)
					:protocol :datagram
					:element-type '(unsigned-byte 8))))
    (unwind-protect 
	 (progn
	   (usocket:socket-send socket msg (length msg))
	   (if (usocket:wait-for-input (list socket) :timeout 1 :ready-only t)
           (multiple-value-bind (buffer count) (usocket:socket-receive socket (nibbles:make-octet-vector 1024) 1024)
             (when (or (= count -1) (= count #xffffffff))
               (error "recvfrom returned -1"))
             (process-req-response buffer))
           (error "timeout")))
      (usocket:socket-close socket))))

(defun as-req-udp (kdc-host client realm &key options till-time renew-time host-addresses
                                       pa-data tickets authorization-data)
  (send-req-udp (pack #'encode-as-req 
                  (make-as-request client realm
                                   :options options
                                   :till-time till-time
                                   :renew-time renew-time
                                   :host-addresses host-addresses
                                   :encryption-types (list-all-profiles)
                                   :pa-data pa-data
                                   :tickets tickets
                                   :authorization-data authorization-data))
            kdc-host))

;; tcp
(defun send-req-tcp (msg host &optional port)
  "Send a message to the KDC using TCP"
  (let ((socket (usocket:socket-connect host (or port 88)
                                        :element-type '(unsigned-byte 8))))
    (unwind-protect 
         (let ((stream (usocket:socket-stream socket)))
           (nibbles:write-ub32/be (length msg) stream)
           (write-sequence msg stream)
           (force-output stream)
           ;; read from the stream
           (if (usocket:wait-for-input (list socket) :timeout 1 :ready-only t)
               (let* ((n (nibbles:read-ub32/be stream))
                      (buffer (nibbles:make-octet-vector n)))
                 (read-sequence buffer stream)
                 (process-req-response buffer))
               (error "timeout")))
      (usocket:socket-close socket))))

(defun as-req-tcp (kdc-host client realm &key options till-time renew-time host-addresses
                                       pa-data tickets authorization-data)
  (send-req-tcp (pack #'encode-as-req 
                  (make-as-request client realm
                                   :options options
                                   :till-time till-time
                                   :renew-time renew-time
                                   :host-addresses host-addresses
                                   :encryption-types (list-all-profiles)
                                   :pa-data pa-data
                                   :tickets tickets
                                   :authorization-data authorization-data))
            kdc-host))

;; notes: in the case of a :preauth-required error, the edata field of the error object contains a 
;; list of pa-data objcets which specify the acceptable pa-data types. 
;; a pa-data object of type 19 provides a list of etype-info2-entry structures


(defun time-from-now (&key hours days weeks years)
  "Compute the time from the current time."
  (+ (get-universal-time) 
     (if hours (* 60 60 hours) 0)
     (if days (* 60 60 24 days) 0)
     (if weeks (* 60 60 24 7 weeks) 0)
     (if years (* 60 60 24 365 years) 0)))

;; this is used to store the details of where the kdc is so we can request more tickets
(defstruct login-token 
  address 
  rep
  tgs
  user
  realm)

(defmethod print-object ((token login-token) stream)
  (print-unreadable-object (token stream :type t)
    (format stream ":USER ~S :REALM ~S" 
            (principal-name-name (login-token-user token))
            (login-token-realm token))))

(defvar *kdc-address* nil 
  "The address of the default KDC.")

(defun login (username password realm &key kdc-address till-time (etype :des-cbc-md5))
  "Login to the authentication server to reqest a ticket for the Ticket-granting server. Returns a LOGIN-TOKEN
structure which should be used for requests for further tickets.

USERNAME ::= username of principal to login.
PASSWORD ::= the password to use.
REALM ::= the realm we are loggin in to.

KDC-ADDRESS ::= the IP address of the KDC.
TILL-TIME ::= how long the ticket should be valid for, defaults to 6 weeks from present time.
ETYPE ::= encryption profile name to use for pre-authentication.
"
  (cond
    (kdc-address 
     (setf *kdc-address* kdc-address))
    ((not *kdc-address*) (error "Must first set *kdc-address*"))
    (t (setf kdc-address *kdc-address*)))
  (let ((key (string-to-key etype
                            password
                            (format nil "~A~A" (string-upcase realm) username)))
        (principal (principal username)))
    (let ((as-rep 
           (as-req-tcp kdc-address
                       principal
                       realm
                       :pa-data (list (pa-timestamp key etype))
                       :till-time (or till-time (time-from-now :weeks 6)))))
      ;; we need to decrypt the enc-part of the response to verify it
      ;; FIXME: need to know, e.g. the nonce that we used in the request
      (let ((enc (unpack #'decode-enc-as-rep-part 
                         (decrypt-data (kdc-rep-enc-part as-rep) key))))
        ;; should really validate the reponse here, e.g. check nonce etc.
        ;; lets just descrypt it and replace the enc-part with the decrypted enc-part 
        (setf (kdc-rep-enc-part as-rep) enc))

      ;; the return value
      (make-login-token :address *kdc-address*
                        :rep as-rep
                        :tgs (kdc-rep-ticket as-rep)
                        :user principal
                        :realm realm))))

;; this worked. I got a ticket for the principal named
(defun request-ticket (token server &key till-time)  
  "Request a ticket for the named principal using the TGS ticket previously requested.

Returns a KDC-REP structure."  
  (declare (type login-token token)
           (type principal-name server))
  (let* ((as-rep (login-token-rep token))
         (ekey (enc-kdc-rep-part-key (kdc-rep-enc-part as-rep))))
    (let ((rep (send-req-tcp 
                (pack #'encode-tgs-req 
                      (make-kdc-request (login-token-user token)
                                        :type :tgs
                                        :options '(:renewable :enc-tkt-in-skey)
                                        :realm (login-token-realm token)
                                        :server-principal server
                                        :nonce (random (expt 2 32))
                                        :till-time (or till-time (time-from-now :weeks 6))
                                        :encryption-types (list (encryption-key-type ekey))
                                        :pa-data (list (pa-tgs-req (login-token-tgs token)
                                                                   (encryption-key-value ekey)
                                                                   (login-token-user token)
                                                                   (encryption-key-type ekey)))))
			   (login-token-address token))))
    ;; if we got here then the response is a kdc-rep structure (for tgs)
    ;; we need to decrypt the enc-part of the response to verify it
    ;; FIXME: need to know, e.g. the nonce that we used in the request
    (let ((enc (unpack #'decode-enc-as-rep-part 
                       (decrypt-data (kdc-rep-enc-part rep)
                                     (encryption-key-value ekey)))))
      ;; should really validate the reponse here, e.g. check nonce etc.
      ;; lets just descrypt it and replace the enc-part with the decrypted enc-part 
      (setf (kdc-rep-enc-part rep) enc))

      rep)))





;; next stage: need to package up an AP-REQ to be sent to the application server
;; typically this message will be encapsualted in the application protocol, so we don't do any direct 
;; networking for this, just return a packed octet buffer
(defun pack-ap-req (cname etype key ticket &optional mutual)
  (pack #'encode-ap-req 
        (make-ap-req :options (when mutual '(:mutual-required))
                     :ticket ticket
                     :authenticator 
                     (encrypt-data etype
                                   (pack #'encode-authenticator 
                                         (make-authenticator :crealm (ticket-realm ticket)
                                                             :cname cname
                                                             :ctime (get-universal-time)
                                                             :cusec 0))
                                   key))))

;; this would be used by the server to examine the authenticator and validate the request
(defun unpack-ap-req (buffer key)
  (let ((req (unpack #'decode-ap-req buffer)))
    ;; the authenticator is an encrypted data, we need to decrypt it first 
    (setf (ap-req-authenticator req)
          (decrypt-data (ap-req-authenticator req)
                        key))
    req))






;; --------------- application server -------------------------

(defun decrypt-ticket (key ticket)
  "Decrypt the enc-part of the ticket."
  (let ((enc (ticket-enc-part ticket)))
    (decrypt-data enc key :usage :ticket)))

(defun valid-ticket-p (key ticket enc-auth)
  "Decrypt the ticket and check its contents against the authenticator."
  (declare (type ticket ticket)
	   (type encrypted-data enc-auth))
  ;; start by modifying the enc-part to be decrypted
  (let ((enc (decrypt-ticket key ticket)))
    ;; now decrypt the authenticator using the session key we got from the ticket
    (let ((a (decrypt-data enc-auth (enc-ticket-part-key enc)
			   :usage :ap-req)))
      (declare (ignore a))
      ;; check the contents of the authenticator against the ticket....
      ;; FIXME: for now we just assume it's ok
      t)))

;; --------------------------------------------------------------

;; I just decrypted a ticket encryped with the rc4-hmac ! 
;; (unpack #'decode-enc-ticket-part 
;;   (decrypt-data (ticket-enc-part (kdc-rep-ticket *myticket*)) 
;;  			(string-to-key :rc4-hmac "password" nil)
;;			:usage (key-usage :ticket)))
;; where *myticket* is a tgs-rep structure
;; 
