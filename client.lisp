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

;; this should send a request to the TGS for a ticket to talk to a specific host/service/etc
(defun tgs-req-tcp (username realm ticket)
  (make-kdc-request (principal username)
		    :type :tgs
		    :realm realm
		    :tickets (list ticket)))


;; notes: in the case of a :preauth-required error, the edata field of the error object contains a 
;; list of pa-data objcets which specify the acceptable pa-data types. 
;; a pa-data object of type 19 provides a list of etype-info2-entry structures


;; -------------------

;; this worked!!!1!
;;(as-req-tcp "MYKDC-IP" (principal "MYUSERNAME") "MYDOMAIN" :pa-data (list (pa-timestamp)) :encryption-types '(:des-cbc-md5) :till-time (encode-universal-time 0 0 0 1 6 2015 0))

(defvar *tgs-ticket* nil)

(defun login (kdc-address username password realm)
  (let ((key (string-to-key :des 
			    password
			    :salt (format nil "~A~A" (string-upcase realm) username))))
    (let ((as-rep 
	   (as-req-tcp kdc-address
		       (principal username) 
		       realm
		       :pa-data (list (pa-timestamp key)) 
		       :encryption-types '(:des-cbc-md5) 
		       :till-time (encode-universal-time 0 0 0 1 1 1970 0))))
      ;; we need to decrypt the enc-part of the response to verify it
;;      (decrypt-des-cbc-md5 key (encrypted-data-cipher (kdc-rep-enc-part as-rep)))
      (setf *tgs-ticket* (kdc-rep-ticket as-rep))
      as-rep)))

;; this should use the *tgs-ticket* to request a ticket for a specific host/service/etc
;;(defun get-ticket ()
  
