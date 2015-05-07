;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; This file contains the codes necessary to wrap the underlying 
;;; kerberos calls in a gss-like API
;;; 

(in-package #:cerberus)

;; ----------- for the client ---------------

(defgeneric gss-acquire-credential (mech-type principal &key)
  (:documentation "Acquire credentials for the principal named. Returns CREDENTIALS, for input into INITIALIZE-SECURITY-CONTEXT. c.f. GSS_Acquire_cred."))

(defmethod gss-acquire-credential ((mech-type (eql :kerberos)) principal &key username password realm kdc-address till-time)
  (let ((tgt (if (and username password kdc-address)
		 (request-tgt username password realm 
			      :kdc-address kdc-address
			      :till-time till-time)
		 (find-if (lambda (tgt)
			    (string= (login-token-realm tgt) realm))
			  *tgt-cache*))))
    (unless tgt (error "No TGT for the specified user, login by providing user credentials."))
    (request-credentials tgt principal :till-time till-time)))

(defgeneric gss-initialize-security-context (mech-type credentials &key)
  (:documentation "Returns a security context to be sent to the application server. c.f. GSS_Init_sec_context"))

(defmethod gss-initialize-security-context ((mech-type (eql :kerberos)) credentials &key mutual)
  (pack-initial-context-token (make-ap-request credentials :mutual mutual)))

;; ---------- for the application server -----------

(defgeneric gss-accept-security-context (mech-type credentials context &key)
  (:documentation "CREDENTIALS are credentials for the server principal. CONTEXT is the packed 
buffer sent from the client. It should be as returned from INITIALIZE-SECURITY-CONTEXT.

c.f. GSS_Accept_sec_context
"))

(defmethod gss-accept-security-context ((mech-type (eql :kerberos)) credentials context &key)
  (let ((ap-req (unpack-initial-context-token context)))
    (valid-ticket-p credentials ap-req)))

;; this is for context deletion, do we need it?
;;(defgeneric gss-process-context-token (mech-type context &key)
;;  (:documentation "CONTEXT is returned from ACCEPT-SECURITY-CONTEXT. c.f. GSS_Process_context_token"))


;; ------------------ per-message calls --------------------------

;; Get_MIC()
(defgeneric gss-get-mic (mech-type context-handle message &key))

;; the context handle MUST be the kdc-rep i.e. the "credentials" that were passed into the initialize-context
(defmethod gss-get-mic ((mech-type (eql :kerberos)) context-handle message &key initiator)
  (declare (type ap-req context-handle))
  (let ((req context-handle)
	(session-key (ap-req-session-key context-handle)))
    (pack-initial-context-token 
     (flexi-streams:with-output-to-sequence (s)
       (write-sequence '(1 1) s) ;; TOK_ID == getmic
       (write-sequence '(0 0) s) ;; SGN_ALG == DES MAC MD5
       (write-sequence '(#xff #xff #xff #xff) s) ;; filler
       
       (let ((cksum (des-mac (md5 message)
			     nil
			     session-key))) ;;(enc-kdc-rep-part-key (kdc-rep-enc-part rep)))))
	 
	 ;; write the ap-req seqno
	 (let ((seqno (authenticator-seqno (ap-req-authenticator req))))
	   (unless seqno (error "Seqno is mandatory for GSS"))
	   (let ((bytes (concatenate '(vector (unsigned-byte 8)) 
				     (let ((v (nibbles:make-octet-vector 4)))
				       (setf (nibbles:ub32ref/be v 0) seqno)
				       v)
				     (if initiator '(0 0 0 0) '(#xff #xff #xff #xff)))))
	     (write-sequence (encrypt-des-cbc session-key ;;(enc-kdc-rep-part-key (kdc-rep-enc-part context-handle)) 
					      bytes
					      :initialization-vector (subseq cksum 0 8))
			     s)))
	 ;; write the checksum 
	 (write-sequence cksum s))))))
  
;; GSS_VerifyMIC()
(defgeneric gss-verify-mic (mech-type context-handle message message-token &key))

(defmethod gss-verify-mic ((mech-type (eql :kerberos)) context-handle message message-token &key initiator)
  (declare (type ap-req context-handle))
  (let ((req context-handle)
	(tok (unpack-initial-context-token message-token))
	(session-key (ap-req-session-key context-handle)))
    ;; start by getting the checksum and seqno fields
    (let ((seqno (subseq tok 8 16))
	  (cksum (subseq tok 16 24))
	  (the-cksum (des-mac (md5 message) nil session-key)))
      ;; compare the checksums
      (unless (equalp cksum the-cksum) (error 'checksum-error))
      ;; decrypt the seqno
      (let ((sq (decrypt-des-cbc session-key seqno :initialization-vector (subseq the-cksum 0 8))))
	(every #'= 
	       sq 
	       (concatenate '(vector (unsigned-byte 8)) 
			    (authenticator-seqno (ap-req-authenticator req)) 
			    (if initiator '(0 0 0 0) '(#xff #xff #xff #xff))))))))


;; ;; GSS_Wrap()
(defgeneric gss-wrap (mech-type context-handle message &key))

;; context handle is the ap-req 
(defmethod gss-wrap ((mech-type (eql :kerberos)) context-handle message &key initiator)   
  (declare (type ap-req context-handle))
  (let ((req context-handle)
	(session-key (ap-req-session-key context-handle)))
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
	   (cksum (des-mac (md5 message)
			     nil
			     session-key))
	   (seqno (encrypt-des-cbc session-key 
				   (concatenate '(vector (unsigned-byte 8)) 
						(let ((v (nibbles:make-octet-vector 4)))
						  (setf (nibbles:ub32ref/be v 0) 
							(authenticator-seqno (ap-req-authenticator req)))
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


;; ;; GSS_Unwrap()
(defgeneric gss-unwrap (mech-type context-handle buffer &key))

(defmethod gss-unwrap ((mech-type (eql :kerberos)) context-handle buffer &key initiator)
  ;; start by extracting the token from the buffer
  (declare (type ap-req context-handle))
  (let ((tok (unpack-initial-context-token buffer))
	(req context-handle)
	(session-key (ap-req-session-key context-handle)))
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
	(let ((the-cksum (des-mac (md5 message)
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
						 (authenticator-seqno (ap-req-authenticator req)))
					   v)
					 (if initiator '(0 0 0 0) '(#xff #xff #xff #xff))))
	      (error "Seqnos don't match"))))
	;; return the decrypted message
	message))))
      
  
