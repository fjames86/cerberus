;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:cerberus)

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
                                       encryption-types pa-data tickets authorization-data)
  (send-req-udp (pack #'encode-as-req 
                  (make-as-request client realm
                                   :options options
                                   :till-time till-time
                                   :renew-time renew-time
                                   :host-addresses host-addresses
                                   :encryption-types encryption-types
                                   :pa-data pa-data
                                   :tickets tickets
                                   :authorization-data authorization-data))
            kdc-host))

;; tcp
(defun send-req-tcp (msg host &optional port)
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
                                       encryption-types pa-data tickets authorization-data)
  (send-req-tcp (pack #'encode-as-req 
                  (make-as-request client realm
                                   :options options
                                   :till-time till-time
                                   :renew-time renew-time
                                   :host-addresses host-addresses
                                   :encryption-types encryption-types
                                   :pa-data pa-data
                                   :tickets tickets
                                   :authorization-data authorization-data))
            kdc-host))

;; notes: in the case of a :preauth-required error, the edata field of the error object contains a 
;; list of pa-data objcets which specify the acceptable pa-data types. 
;; a pa-data object of type 19 provides a list of etype-info2-entry structures


;; -------------------

(defun time-from-now (&key hours days weeks years)
  (+ (get-universal-time) 
     (if hours (* 60 60 hours) 0)
     (if days (* 60 60 24 days) 0)
     (if weeks (* 60 60 24 7 weeks) 0)
     (if years (* 60 60 24 365 years) 0)))

;; this worked!!!1!
;;(as-req-tcp "MYKDC-IP" (principal "MYUSERNAME") "MYDOMAIN" :pa-data (list (pa-timestamp)) :encryption-types '(:des-cbc-md5) :till-time (encode-universal-time 0 0 0 1 6 2015 0))

;; various globals to keep track of things
(defvar *kdc-address* nil)
(defvar *as-rep* nil)
(defvar *tgs-ticket* nil)
(defvar *user-principal* nil)
(defvar *realm* nil)

(defun login (username password realm &key kdc-address till-time)
  (cond
    (kdc-address 
     (unless *kdc-address* (setf *kdc-address* kdc-address)))
    ((not *kdc-address*) (error "Must first set *kdc-address*"))
    (t (setf kdc-address *kdc-address*)))
  (setf *user-principal* (principal username)
	*realm* realm)
  (let ((key (string-to-key :des 
			    password
			    :salt (format nil "~A~A" (string-upcase realm) username))))
    (let ((as-rep 
	   (as-req-tcp kdc-address
		       *user-principal*
		       realm
		       :pa-data (list (pa-timestamp key)) 
		       :encryption-types '(:des-cbc-md5) 
		       :till-time (or till-time (time-from-now :weeks 6)))))
      ;; we need to decrypt the enc-part of the response to verify it
      ;; FIXME: need to know, e.g. the nonce that we used in the request
      (let ((enc (unpack #'decode-enc-as-rep-part 
			 (decrypt-data (kdc-rep-enc-part as-rep) key))))
	;; should really validat ethe reponse here, e.g.y check nonce etc.
	;; lets just descrypt it and replace the enc-part with the decrypted enc-part 
	(setf (kdc-rep-enc-part as-rep) enc))
      (setf *tgs-ticket* (kdc-rep-ticket as-rep)
	    *as-rep* as-rep)
      as-rep)))

;; this doesn't work yet -- I got a "kdc error: kdc-pa-nosupp" 
(defun request-ticket (server &key till-time)  
  "Request a ticket for the named principal using the TGS ticket previously requested"
  (declare (type principal-name server))
  (unless *kdc-address* (error "must have set the kdc address"))
  (unless *as-rep* (error "Must first login"))
  (let ((rep (send-req-tcp (pack #'encode-tgs-req 
				 (make-kdc-request *user-principal*
						   :type :tgs
						   :realm *realm*
						   :server-principal server
						   :nonce (random (expt 2 32))
						   :till-time (or till-time (time-from-now :weeks 6))
						   :encryption-types '(:des-cbc-md5)
						   :tickets (list *tgs-ticket*)
						   :pa-data (list (pa-timestamp (encryption-key-value 
										 (enc-kdc-rep-part-key (kdc-rep-enc-part *as-rep*)))
										(encryption-key-type 
										 (enc-kdc-rep-part-key (kdc-rep-enc-part *as-rep*)))))))
			   *kdc-address*)))
    ;; if we got here then the response is a kdc-rep structure (for tgs)
    rep))

