;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; This file contains the codes necessary to wrap the underlying
;;; kerberos calls in a gss-like API
;;; 

(in-package #:cerberus)


;; FIXME: this whole file needs a complete rethink/overhaul
;;
;; 1. What is the purpose of ACQUIRE-CREDENTIAL? 
;; For a Kerberos client, this should be (essentially) returning a KDC-REP structure 
;; but in order to do this, we need to know the relevant TGT. So this needs to be passed in
;; somehow as well. But for a Kerberos application server, this is completely different. In that
;; case, we should simply be returning a keylist (either by computing it directly using 
;; GENERATE-KEYLIST or by parsing a keytab file). 
;; So the conclusion is that the result of this function should be different depending on whether
;; we are running in an application server or client.
;; 
;; 2. INITIALIZE-SECURITY-CONTEXT and ACCEPT-SECURITY-CONTEXT should both return "context"
;; instances, but they have different meanings. The former is only for the client, the later only
;; for the server. 
;; 
;; 3. For kerberos the exchange is either 1-way (client->server) or at most 2-way (client->server->client).
;; For other protocols (e.g. NTLM) it can be 3-way (client->server->client->server).
;; In order to support multiple exhanges, INITIALIZE-SECURITY-CONTEXT should accept and optional buffer
;; which contains the authentication token received from the peer. For Kerberos, this means clients which request
;; mutual authentication (i.e. the application server authenticating itself back to the client). 
;; Other systems might require ACCEPT-SECURITY-CONTEXT to be called a second time.
;;
;; 4. GSS adds a whole level of crap that isn't really helpful but somehow we need to support it. 
;; 
;; 5. How should we signal errors? GSS has a whole system of major/minor statuses, we could just signal
;; conditions, but do we really need to? I guess some APIs require it (we definitely need it do 
;; RPCSEC_GSS in frpc). 
;; 

;; This is just one example of the bs that is involved in the GSS adventure game.
;; Kerberos already does everything we need (even checksummed encrypted messages via KRB_PRIV)
;; What is the point of all this? 
;; 
;; gss requires us to encode a structure to put into the checksum of the authenticator 
;; the checksum type is #x8003 (see rfc1964 sec 1.1.1)
;; (defun encode-gss-checksum ()
;;   (flexi-streams:with-output-to-sequence (s)
;;     (nibbles:write-ub32/le 16 s) ;; length of bind field
;;     ;; md5 hash of channel bindings
;;     ;; flags

   

;; -------------------- for everyone ------------
;; everyone calls this, but the semantics are different if you are a server or client 

(defclass kerberos-credential ()
  ())

(defclass kerberos-client-credential (kerberos-credential)
  ((tgt :initarg :tgt :reader client-credential-tgt)
   (creds :initarg :creds :reader client-credential-creds)))

(defclass kerberos-server-credential (kerberos-credential)
  ((keylist :initarg :keylist :reader server-credential-keylist)))

(defmethod print-object ((cred kerberos-credential) stream)
  (print-unreadable-object (cred stream :type t :identity t)))


;; it is assumed the user has already logged in using LOGON-USER
(defmethod glass:acquire-credentials ((mech-type (eql :kerberos)) principal &key)
  (cond
    ((null *current-user*)
     (error 'glass:gss-error :major :no-cred))
    ((null principal)
     ;; application server providing keylist
     (make-instance 'kerberos-server-credential 
		    :keylist (login-token-keylist *current-user*)))
    (principal 
     (multiple-value-bind (principal realm) (string-principal principal)
       ;; try to get a tgt we already have
       (let ((tgt *current-user*))		      
	 ;; check the realms match because we don't support cross-realm requests yet
	 (unless (or (null realm) (string= realm (login-token-realm tgt)))
	   (error "Cross-realm requests not currently supported"))
	 (let ((creds (request-credentials tgt principal)))
	   (make-instance 'kerberos-client-credential
			  :tgt tgt
			  :creds creds)))))))
    
;; ----------- for the client ---------------


(defclass kerberos-context ()
  ((req :initarg :req :initform nil :accessor kerberos-context-req)
   (key :initform nil :accessor kerberos-context-key)
   (seqno :initform 0 :accessor kerberos-context-seqno)))

(defclass kerberos-client-context (kerberos-context)
  ())

(defmethod print-object ((context kerberos-context) stream)
  (print-unreadable-object (context stream :type t :identity t)))
      
;; FIXME: need some mechanism to indicate whether more exhanges are required
(defmethod glass:initialize-security-context ((credentials kerberos-client-credential) &key mutual)
  (let ((context (make-instance 'kerberos-client-context)))				
    (let* ((req (make-ap-request (client-credential-creds credentials)
				 :mutual mutual
				 :seqno (kerberos-context-seqno context))) ;; FIXME: also need the special packed checksum!
	   (buffer (pack-initial-context-token req)))
    (setf (kerberos-context-req context) req
	  (kerberos-context-key context)
	  ;; the session key can be found in the crednetials (which is a kdc-rep)
	  (enc-kdc-rep-part-key (kdc-rep-enc-part (client-credential-creds credentials))))
    (values context buffer))))

(defmethod glass:initialize-security-context ((context kerberos-client-context) &key buffer)
  ;; the buffer contains a packed ap-rep structure
  (let ((ap-rep (unpack-initial-context-token buffer)))
    (declare (ignore ap-rep))
    ;; FIXME: validate the timestamps in the ap-rep match those we sent in the ap-req 
    context))

;; ---------- for the application server -----------

(defclass kerberos-server-context (kerberos-context)
  ())

(defmethod glass:accept-security-context ((credentials kerberos-server-credential) buffer &key)
  (let ((ap-req (unpack-initial-context-token buffer)))
    (let ((cxt 
           (make-instance 'kerberos-server-context 
                          :req (valid-ticket-p (server-credential-keylist credentials) ap-req))))
      (setf (kerberos-context-key cxt) 
	    (enc-ticket-part-key (ticket-enc-part (ap-req-ticket ap-req))))
      ;; if mutual authentication required then we need to pack a response buffer (an AP-REP structure)
      ;; to reply with
      (if (member :mutual-required (ap-req-options ap-req))
	  (values cxt (pack-initial-context-token 
		       (make-ap-response (kerberos-context-key cxt)
					 ap-req)))
	  (values cxt nil)))))

;; this is for context deletion, do we need it?
;;(defgeneric gss-process-context-token (mech-type context &key)
;;  (:documentation "CONTEXT is returned from ACCEPT-SECURITY-CONTEXT. c.f. GSS_Process_context_token"))

;; ------------------ per-message calls --------------------------

(defmethod glass:get-mic ((context kerberos-context) message &key)
  (let* ((req (kerberos-context-req context))
	 (session-key (kerberos-context-key context))
	 (key (subseq (encryption-key-value session-key) 0 8))
	 (initiator (typep context 'kerberos-client-context))
	 (message (concatenate '(vector (unsigned-byte 8)) message)))
    (pack-initial-context-token 
     (flexi-streams:with-output-to-sequence (s)
       (write-sequence '(1 1) s) ;; TOK_ID == getmic
       (write-sequence '(0 0) s) ;; SGN_ALG == DES MAC MD5
       (write-sequence '(#xff #xff #xff #xff) s) ;; filler
       
       (let ((cksum (des-mac (md5 message)
			     nil
			     key))) 
	 
	 ;; write the ap-req seqno
	 (let ((seqno (if initiator 
			  ;; we are the client, we store our own seqno
			  (kerberos-context-seqno context)
			  ;; the seqno can be found in the authenticator 
			  (authenticator-seqno (ap-req-authenticator req)))))
	   (unless seqno (error "Seqno is mandatory for GSS"))
	   (let ((bytes (concatenate '(vector (unsigned-byte 8)) 
				     (let ((v (nibbles:make-octet-vector 4)))
				       (setf (nibbles:ub32ref/be v 0) seqno)
				       v)
				     (if initiator '(0 0 0 0) '(#xff #xff #xff #xff)))))
	     (write-sequence (encrypt-des-cbc key 
					      bytes
					      :initialization-vector (subseq cksum 0 8))
			     s)))
	 ;; write the checksum 
	 (write-sequence cksum s))))))
  
(defmethod glass:verify-mic ((context kerberos-context) message message-token &key)
  (let* ((req (kerberos-context-req context))
	 (tok (unpack-initial-context-token message-token))
	 (session-key (ap-req-session-key req))
	 (key (subseq (encryption-key-value session-key) 0 8))
	 (message (concatenate '(vector (unsigned-byte 8)) message))
	 (initiator (typep context 'kerberos-client-context)))
    ;; start by getting the checksum and seqno fields
    (let ((seqno (subseq tok 8 16))
	  (cksum (subseq tok 16 24))
	  (the-cksum (des-mac (md5 message) nil key)))
      ;; compare the checksums
      (unless (equalp cksum the-cksum) (error 'checksum-error))
      ;; decrypt the seqno
      (let ((sq (decrypt-des-cbc key seqno :initialization-vector (subseq the-cksum 0 8))))
	(every #'= 
	       sq 
	       (concatenate '(vector (unsigned-byte 8)) 
			    (let ((v (nibbles:make-octet-vector 4)))
			      (setf (nibbles:ub32ref/be v 0) (authenticator-seqno (ap-req-authenticator req)))
			      v)
			    (if (not initiator) '(0 0 0 0) '(#xff #xff #xff #xff))))))))

;; context handle is the ap-req 
(defmethod glass:wrap ((context kerberos-context) message &key)   
  (let* ((req (kerberos-context-req context))
	 (session-key (subseq (encryption-key-value (kerberos-context-key context))
			      0 8))
	 (initiator (typep context 'kerberos-client-context))
	 (message (concatenate '(vector (unsigned-byte 8)) message)))
    ;; start by padding the message
    (let* ((len (length message))
	   (msg (concatenate '(vector (unsigned-byte 8))
			     (loop :for i :below 8 :collect (random 256)) ;; confounder 
			     message
			     (unless (zerop (mod len 8)) ;; padding 
			       (loop :for i :below (- 8 (mod len 8)) :collect (- 8 (mod len 8))))))
	   (key (map '(vector (unsigned-byte 8)) 
		     (lambda (x) (logxor x #xf0))
		     session-key))
	   (cksum (des-mac (md5 msg) ;;message)
			     nil
			     session-key))
	   (seqno (encrypt-des-cbc session-key 
				   (concatenate '(vector (unsigned-byte 8)) 
						(let ((v (nibbles:make-octet-vector 4)))
						  (setf (nibbles:ub32ref/be v 0)
							(if initiator
							    (kerberos-context-seqno context)
							    (authenticator-seqno (ap-req-authenticator req))))
						  v)
						(if initiator '(0 0 0 0) '(#xff #xff #xff #xff)))
				   :initialization-vector (subseq cksum 0 8))))
	         
    (pack-initial-context-token 
     (flexi-streams:with-output-to-sequence (s)
       (write-sequence '(2 1) s) ;; TOK_ID 
       (write-sequence '(0 0) s) ;; sgn_alg == des mac md5
       (write-sequence '(0 0) s) ;; seal_alg == des
       (write-sequence '(#xff #xff) s) ;; filler
       ;; encrypted seqno field
       (write-sequence seqno s)
       ;; checksum
       (write-sequence cksum s)
       ;; encrypted body
       (write-sequence (encrypt-des-cbc key msg) s))))))

(defmethod glass:unwrap ((context kerberos-context) buffer &key)
  ;; start by extracting the token from the buffer
  (let* ((tok (unpack-initial-context-token buffer))
	 (req (kerberos-context-req context))
	 (session-key (subseq (encryption-key-value (kerberos-context-key context))
			      0 8))
	 (initiator (typep context 'kerberos-client-context)))
    ;; get the seqno, cksum and encrypted body
    (let ((eseqno (subseq tok 8 16))
	  (cksum (subseq tok 16 24))
	  (emsg (subseq tok 24))
	  (key (map '(vector (unsigned-byte 8)) 
		    (lambda (x) (logxor x #xf0))
		    session-key)))
      ;; start by decrypting the body
      (let* ((msg (decrypt-des-cbc key emsg))
	     (message (subseq msg 8))) ;; drop the confounder 
	;; compute the checksum
	(let ((the-cksum (des-mac (md5 msg) ;;message)
				  nil
				  session-key)))
	  ;; validate the checksums match
	  (unless (equalp cksum the-cksum) (error 'checksum-error))
	  ;; now decrypt the seqno
	  (let ((seqno (decrypt-des-cbc session-key
					eseqno
					:initialization-vector (subseq the-cksum 0 8))))
	    ;; check the seqnos match
	    (unless (equalp seqno
			    (concatenate '(vector (unsigned-byte 8))
					 (let ((v (nibbles:make-octet-vector 4)))
					   (setf (nibbles:ub32ref/be v 0) 
						 (if initiator
						     (kerberos-context-seqno context)
						     (authenticator-seqno (ap-req-authenticator req))))
					   v)
					 (if (not initiator) '(0 0 0 0) '(#xff #xff #xff #xff))))
	      (error "Seqnos don't match"))))
	;; return the decrypted message
	message))))
      
  
