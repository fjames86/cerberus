;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; This file contains the function to talk to the KDC (to request tickets)
;;; and related function to talk to application servers.

(in-package #:cerberus)

;; ------------------ kdc ----------------------------------

(defun process-req-response (buffer)
  "Examine the response from the KDC, will either be a reply or an error"
  (let ((code (unpack #'decode-identifier buffer)))
    (ecase code
      (30 ;; error
       (let ((err (unpack #'decode-krb-error buffer)))
         (krb-error err)))
      (11 ;; as-rep
       (unpack #'decode-as-rep buffer))
      (13 ;; tgs-rep
       (unpack #'decode-tgs-rep buffer)))))

;; tcp (note: udp seems to be pretty useless... when I called it I just
;; kept getting "response would not fit in a udp packet, try tcp" error (RESPONSE-TOO-BIG)
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
  realm
  keylist)

(defmethod print-object ((token login-token) stream)
 (print-unreadable-object (token stream :type t :identity t)
   (format stream "~A" (principal-string (login-token-user token)
					 (login-token-realm token)))))

(defvar *kdc-address* nil 
  "The address of the default KDC.")

(defvar *default-realm* nil
  "The name of the default realm.")

(defvar *tgt-cache* nil)

(defun find-tgt (principal realm)
  (find-if (lambda (tgt)
	     (and (string= (login-token-realm tgt) realm)
		  (every #'string= 
			 (principal-name-name (login-token-user tgt))
			 (principal-name-name principal))))
	   *tgt-cache*))

(defun request-tgt (principal password realm &key kdc-address till-time (etype :des-cbc-md5))
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
  (cond 
    ((and realm (not *default-realm*))
     (setf *default-realm* realm))
    ((and *default-realm* (not realm))
     (setf realm *default-realm*))
    (t (error "Must specify a realm if not set default.")))
     
  (let* ((salt (format nil "~A~A" 
		       (string-upcase realm) 
		       (with-output-to-string (s)
			 (dolist (name (principal-name-name principal))
			   (princ name s)))))
	 (key (string-to-key etype
                            password
			    salt)))

    (let ((tgt (find-tgt principal realm)))
      (when tgt (return-from request-tgt tgt)))

    (let ((as-rep 
           (as-req-tcp kdc-address
                       principal
                       realm
                       :pa-data (list (pa-timestamp key etype))
                       :till-time (or till-time (time-from-now :weeks 6)))))
      ;; we need to decrypt the enc-part of the response to verify it
      ;; FIXME: need to know, e.g. the nonce that we used in the request
      (let ((enc (unpack #'decode-enc-as-rep-part 
                         (decrypt-data (kdc-rep-enc-part as-rep) 
				       (let ((e (kdc-rep-enc-part as-rep)))
					 (string-to-key (encrypted-data-type e)
							password
							salt))
				       :usage :as-rep))))
        ;; should really validate the reponse here, e.g. check nonce etc.
        ;; lets just descrypt it and replace the enc-part with the decrypted enc-part 
        (setf (kdc-rep-enc-part as-rep) enc))

      ;; store and return the value
      (let ((tgt (make-login-token :address *kdc-address*
				   :rep as-rep
				   :tgs (kdc-rep-ticket as-rep)
				   :user principal
				   :realm realm)))
	(push tgt *tgt-cache*)
	tgt))))

;; ---------------------------------------------------

(defvar *current-user*
  "The login token of the current user. Set with LOGON-USER (interactive mode) or dynamically rebind")

(defun logon-user (principal password &key mode kdc-address)
  "Logon the user by requesting a TGT from the KDC.
PRINCIPAL ::= a string naming the principal, e.g. user@realm, host/my.host.com@realm, service-name/my-host.com@realm
PASSWORD ::= a string containing the plaintext password
MODE ::= a symbol naming a logon mode, :INTERACTIVE implies modifying the *CURRENT-USER*, :NETWORK does not modify the environment.
If *CURRENT-USER* is nil, :INTERACTIVE is implied, otherwise :NETWORK is implied.
KDC-ADDRESS ::= IP of the KDC. This MUST be supplied in the first call.

Returns a login token."
  (declare (type string principal))
  (multiple-value-bind (p realm) (string-principal principal)
    (let ((tgt
	   (request-tgt p password 
			(or realm *default-realm*)
			:kdc-address (or kdc-address *kdc-address*))))
      ;; store the keylist for this user as well (comes in handy if we are running as a server!)
      (setf (login-token-keylist tgt)
	    (generate-keylist principal password))
      ;; modify the global if in interactive mode
      (cond
	((eq mode :interactive) 
	 (setf *current-user* tgt))
	((and (null *current-user*) (or (null mode) (eq mode :interactive)))
	 (setf *current-user* tgt)))
      
      tgt)))

(defun logon-service (principal keylist &key mode)
  (multiple-value-bind (p realm) (string-principal principal)
    (let ((token (make-login-token :user p
				   :realm realm
				   :keylist keylist)))
      (cond
	((eq mode :interactive) 
	 (setf *current-user* token))
	((and (null *current-user*) (or (null mode) (eq mode :interactive)))
	 (setf *current-user* token)))
      token)))

(defmacro with-current-user ((principal password &rest args) &body body)
  `(let ((*current-user* (logon-user ,principal ,password ,@args)))
     ,@body))

;; ------------------------------------------------------


(defvar *credential-cache* nil
  "List of tickets that have previously been granted. REQUEST-CREDENTIALS will return an
applicable ticket from this list if one is available.")

(defun find-credentials (principal realm)
  (find-if (lambda (cred)
	     (and (string= realm (kdc-rep-crealm cred))
		  (every #'string= 
			 (principal-name-name (kdc-rep-cname cred))
			 (principal-name-name principal))))
	   *credential-cache*))

;; this worked. I got a ticket for the principal named
(defun request-credentials (tgt server &key till-time)  
  "Request a ticket for the named principal using the TGS ticket previously requested.

TGT ::= a ticket-granting ticket as returned from REQUEST-TGT.

SERVER ::= a principal, as returned from PRINCIPAL. Can be a string, in which case it is 
converted to a principal.

Returns a KDC-REP structure."  
  (declare (type login-token tgt)
	   (type (or principal-name string) server))

  ;; if a string then convert to a principal
  (when (stringp server)
    (multiple-value-bind (p r) (string-principal server)
      (unless (string= r (login-token-realm tgt)) 
	(error "Cross-realm requests are not yet supported"))
      (setf server p)))
  
  (let ((cred (find-credentials (login-token-user tgt) (login-token-realm tgt))))
    (when cred (return-from request-credentials cred)))

  (let ((token tgt))
    (let* ((as-rep (login-token-rep token))
	   (ekey (enc-kdc-rep-part-key (kdc-rep-enc-part as-rep))))
      (let ((rep (send-req-tcp 
		  (pack #'encode-tgs-req 
			(make-kdc-request 
			 (login-token-user token)
			 :type :tgs
			 :options '(:renewable :enc-tkt-in-skey)
			 :realm (login-token-realm token)
			 :server-principal server
			 :nonce (random (expt 2 32))
			 :till-time (or till-time (time-from-now :weeks 6))
			 :encryption-types (list-all-profiles) ;;(list (encryption-key-type ekey))
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
					 (encryption-key-value ekey)
					 :usage :tgs-rep))))
	  ;; should really validate the reponse here, e.g. check nonce etc.
	  ;; lets just descrypt it and replace the enc-part with the decrypted enc-part 
	  (setf (kdc-rep-enc-part rep) enc))
	
	;; store in the credential cache
	(push rep *credential-cache*)

	rep))))

;; unknown whether this works. Is very similar to the request-credentials function
;; so shouldn't be too hard to get working.
(defun request-renewal (tgt credentials &key till-time)
  "Request the renewal of a ticket. The CREDENTIALS should be as returned from REQUEST-CREDENTIALS."
  (declare (type login-token tgt)
           (type kdc-rep credentials))
  (let ((token tgt))
    (let* ((as-rep (login-token-rep token))
	   (ekey (enc-kdc-rep-part-key (kdc-rep-enc-part as-rep)))
	   (ticket (kdc-rep-ticket credentials))
	   (server (enc-kdc-rep-part-sname (kdc-rep-enc-part credentials))))
      (let ((rep (send-req-tcp 
		  (pack #'encode-tgs-req 
			(make-kdc-request 
			 (login-token-user token)
			 :type :tgs
			 :options '(:renewable :enc-tkt-in-skey)
			 :realm (login-token-realm token)
			 :server-principal server
			 :nonce (random (expt 2 32))
			 :till-time (or till-time (time-from-now :weeks 6))
			 :encryption-types (list-all-profiles) 
			 :pa-data (list (pa-tgs-req (login-token-tgs token)
						    (encryption-key-value ekey)
						    (login-token-user token)
						    (encryption-key-type ekey)))
			 :tickets (list ticket)))
		  (login-token-address token))))
	;; if we got here then the response is a kdc-rep structure (for tgs)
	;; we need to decrypt the enc-part of the response to verify it
	;; FIXME: need to know, e.g. the nonce that we used in the request
	(let ((enc (unpack #'decode-enc-as-rep-part 
			   (decrypt-data (kdc-rep-enc-part rep)
					 (encryption-key-value ekey)
					 :usage :tgs-rep))))
	  ;; should really validate the reponse here, e.g. check nonce etc.
	  ;; lets just descrypt it and replace the enc-part with the decrypted enc-part 
	  (setf (kdc-rep-enc-part rep) enc))
	
	rep))))

;; the kdc might send an etype-info2 back which contains information we need to use when generating keys
;; e.g. with the aes-cts type encryption, it might send a s2kparams which indicates what the iteration-count should be 

;; next stage: need to package up an AP-REQ to be sent to the application server
;; typically this message will be encapsualted in the application protocol, so we don't do any direct 
;; networking for this, just return a packed octet buffer
(defun make-ap-request (credentials &key mutual seqno checksum)
  (declare (type kdc-rep credentials))
  (let ((ticket (kdc-rep-ticket credentials))
	(cname (kdc-rep-cname credentials))
	(key (enc-kdc-rep-part-key (kdc-rep-enc-part credentials))))
    (make-ap-req :options (when mutual '(:mutual-required))
		 :ticket ticket
		 :authenticator 
		 (encrypt-data (encryption-key-type key)
			       (pack #'encode-authenticator 
				     (make-authenticator :crealm (ticket-realm ticket)
							 :cname cname
							 :ctime (get-universal-time)
							 :cusec 0
							 :seqno seqno
							 :cksum checksum))
			       (encryption-key-value key)
			       :usage :ap-req))))

(defun pack-ap-request (credentials &key mutual)
  "Generate and pack an AP-REQ structure to send to the applicaiton server. CREDENTIALS should be 
credentials for the application server, as returned from a previous call to REQUEST-CREDENTIALS.

If MUTUAL is T, then mutual authentication is requested and the applicaiton server is expected to 
respond with an AP-REP structure.
"  
    (pack #'encode-ap-req 
	  (make-ap-request credentials :mutual mutual)))



(defun make-ap-response (session-key ap-req)
  (let ((time (authenticator-ctime (ap-req-authenticator ap-req)))
	(usec (authenticator-cusec (ap-req-authenticator ap-req))))
    (make-ap-rep :enc-part (encrypt-data (encryption-key-type session-key)
					 (pack #'encode-enc-ap-rep-part 
					       (make-enc-ap-rep-part :ctime time
								     :cusec usec))
					 (encryption-key-value session-key)
					 :usage :ap-rep))))

;; --------------- application server -------------------------

(defun decrypt-ticket-enc-part (keylist ticket)
  "Decrypt the enc-part of the ticket."
  (let ((enc (ticket-enc-part ticket)))
    (let ((key (find-if (lambda (k)
			  (eq (encryption-key-type k) (encrypted-data-type enc)))
			keylist)))
      (if key 
	  (unpack #'decode-enc-ticket-part 
		  (decrypt-data enc 
				(encryption-key-value key)
				:usage :ticket))
	  (error "No key for encryption type ~S" (encrypted-data-type enc))))))

(defun valid-ticket-p (keylist ap-req)
  "Decrypt the ticket and check its contents against the authenticator. 
If the input is an opaque buffer, it is parsed into an AP-REQ strucutre. 
Alternatively, the input may be a freshly parsed AP-REQ structure. The encrypted parts must still be encrypted, 
they will be decrypted and examined by this function.

Returns the modifed AP-REQ structure, with enc-parts replaced with decrypted versions."
  ;; if the input is a packed buffer then unpack it 
  (when (typep ap-req 'vector)
    (setf ap-req (unpack #'decode-ap-req ap-req)))

  (let ((ticket (ap-req-ticket ap-req))
	(enc-auth (ap-req-authenticator ap-req)))
    ;; start by decrypting the ticket to get the session key 
    (let ((enc (decrypt-ticket-enc-part keylist ticket)))
      (setf (ticket-enc-part ticket) enc)
      
      (let ((key (enc-ticket-part-key enc)))
	;; now decrypt the authenticator using the session key we got from the ticket
	(let ((a (decrypt-data enc-auth (encryption-key-value key)
			       :usage :ap-req)))
	  ;; check the contents of the authenticator against the ticket....
	  ;; FIXME: for now we just assume it's ok
	  
	  ;; fixup the ap-req and return that
	  (setf (ap-req-ticket ap-req) ticket
		(ap-req-authenticator ap-req) (unpack #'decode-authenticator a))
	  
	  ap-req)))))

(defun ap-req-session-key (req)
  "Extract the session key from the AP request, so that clients may use it to wrap/unwrap messages."
  (declare (type ap-req req))
  (enc-ticket-part-key (ticket-enc-part (ap-req-ticket req))))

;; --------------------------------------------------------------

(defun generate-keylist (principal password)
  "Generate keys for all the registered profiles."
  (multiple-value-bind (p realm) (string-principal principal)
    (let ((salt (with-output-to-string (s)
		  (when realm
		    (princ (string-upcase realm) s))
		  (dolist (name (principal-name-name p))
		    (princ name s)))))
      (mapcar (lambda (type)
		(make-encryption-key :type type
				     :value (string-to-key type password salt)))
	      (list-all-profiles)))))

;; ---------------------------------------
;; for initial conrtext creation (I.e. GSS)

;; this is an equivalent to GSS_Init_sec_context()
(defun pack-initial-context-token (message)
  (pack #'encode-initial-context-token message))
	
;; this is like GSS_Accept_sec_context
(defun unpack-initial-context-token (buffer)
  (let ((res (unpack #'decode-initial-context-token buffer)))
    (typecase res
      (krb-error (krb-error res))
      (otherwise res))))

;; GSS_Acquire_cred is like REQUEST-CREDENTIALS 
;; GSS_Process_context is like VALID-TICKET-P 

;; ----------------------------------------
;; for sending KRB-PRIV messages

;; for encrypting/decrypting user message data in KRB-PRIV structures
(defun wrap-message (key octets local-address)
  "Encrypt a message and sign with the current timestamp.

KEY ::= an encryption-key structure defining the key to use.
OCTETS ::= an octet array containing the plaintext to encrypt.
LOCAL-ADDRESS ::= a HOST-ADDRESS structure naming the local server that is sending the message.
"
  (declare (type encryption-key key)
	   (type (vector (unsigned-byte 8)) octets)
	   (type host-address local-address))
  (let ((data (pack #'encode-enc-krb-priv-part 
		    (make-enc-krb-priv-part :data octets
					    :timestamp (get-universal-time)
					    :saddr local-address))))
    (pack #'encode-krb-priv
	  (make-krb-priv :enc-part 
			 (encrypt-data (encryption-key-type key)
				       data
				       (encryption-key-value key)
				       :usage :krb-priv)))))

(defun unwrap-message (key octets)
  "Decrypt the message and validate the timestamp."
  (declare (type encryption-key key)
	   (type (vector (unsigned-byte 8)) octets))
  (let ((enc (krb-priv-enc-part (unpack #'decode-krb-priv octets))))
    ;; validate the key types match
    (unless (eq (encryption-key-type key) (encrypted-data-type enc))
      (error "Key type ~S doesn't match encrypted data type ~S"
	     (encryption-key-type key) (encrypted-data-type enc)))
    (let ((data (decrypt-data enc (encryption-key-value key)
			      :usage :krb-priv)))
      (let ((priv (unpack #'decode-enc-krb-priv-part data)))
	;; FIXME: validate the timestamp
	(enc-krb-priv-part-data priv)))))



