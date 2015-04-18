;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:cerberus)

;; ----- -------------------------------

;; looks like the "checksum" profile amount to defining two functions, 
;; a get-mic, which returns the checksum, and verify-mic, which verifies it.

(defvar *checksum-types* nil)
(defun defchecksum (name value)
  (let ((entry (assoc name *checksum-types*)))
    (if entry 
	(setf (second entry) value)
	(push (list name value) *checksum-types*)))
  name)
(defun list-all-checksums ()
  (mapcar #'car *checksum-types*))

(defgeneric get-mic (name msg &key))
(defgeneric verify-mic (name octets msg &key))

;; -------------------------------

(defchecksum :rsa-md5 7)
(defmethod get-mic ((name (eql :rsa-md5)) msg &key)
  (md5 msg))
(defmethod verify-mic ((name (eql :rsa-md5)) octets msg &key)
  (equalp (md5 msg) octets))

;; ------------------------------

(defchecksum :rsa-md4 2)
(defmethod get-mic ((name (eql :rsa-md4)) msg &key)
  (md4 msg))
(defmethod verify-mic ((name (eql :rsa-md4)) octets msg &key)
  (equalp (md4 msg) octets))

;; ---------------------------------

(defchecksum :crc32 1)
(defmethod get-mic ((name (eql :crc32)) msg &key)
  (crc32 msg))
(defmethod verify-mic ((name (eql :crc32)) octets msg &key)
  (equalp (crc32 msg) octets))
  

;; ---------------------------------

(defchecksum :rsa-md5-des 8)
(defmethod get-mic ((name (eql :rsa-md5-des)) msg &key key confounder)
  (encrypt-des-cbc (map '(vector (unsigned-byte 8))
			(lambda (octet)
			  (logxor octet #xf0))
			key)
		   (usb8 confounder 
			 (md5 (usb8 confounder msg)))))
(defmethod verify-mic ((name (eql :rsa-md5-des)) octets msg &key key)
  (let ((buffer (decrypt-des-cbc key octets)))
    (equalp (subseq buffer 0 8) ;; confounder
	    (md5 (usb8 (subseq buffer 0 8) msg)))))

;; ------------------------------------

(defchecksum :rsa-md4-des 3)
(defmethod get-mic ((name (eql :rsa-md4-des)) msg &key key confounder)
  (encrypt-des-cbc (map '(vector (unsigned-byte 8))
			(lambda (octet)
			  (logxor octet #xf0))
			key)
		   (usb8 confounder 
			 (md4 (usb8 confounder msg)))))
(defmethod verify-mic ((name (eql :rsa-md4-des)) octets msg &key key)
  (let ((buffer (decrypt-des-cbc key octets)))
    (equalp (subseq buffer 0 8) ;; confounder
	    (md4 (usb8 (subseq buffer 0 8) msg)))))

;; ------------------------------------

(defun des-mac (msg confounder key)
  (let ((ciphertext
	 (encrypt-des-cbc key 
			  (usb8 confounder 
				msg 
				(unless (zerop (mod (length msg) 8))
				  (loop :for i :below (- 8 (mod (length msg) 8))
				     :collect 0))))))
    (subseq ciphertext (- (length ciphertext) 8))))
			  
(defchecksum :des-mac 4)
(defmethod get-mic ((name (eql :des-mac)) msg &key key confounder)
  (encrypt-des-cbc (map '(vector (unsigned-byte 8))
			(lambda (octet)
			  (logxor octet #xf0))
			key)
		   (usb8 confounder 
			 (des-mac msg confounder key))))
(defmethod verify-mic ((name (eql :des-mac)) octets msg &key key)
  (let ((buffer (decrypt-des-cbc (map '(vector (unsigned-byte 8))
				      (lambda (o) (logxor o #xf0))
				      key)
				 octets)))
    (equalp (subseq buffer 0 8)
	    (des-mac (subseq buffer 8) (subseq buffer 0 8) key))))


;; ---------------------------------------------

(defchecksum :des-mac-k 5)
(defmethod get-mic ((name (eql :des-mac-k)) msg &key key)
  (let ((ciphertext (encrypt-des-cbc key 
				     (usb8 msg 
					   (unless (zerop (mod (length msg) 8))
					     (make-list (- 8 (mod (length msg) 8)) :initial-element 0)))
				     :initialization-vector key)))
    (subseq ciphertext (- (length ciphertext) 8))))
(defmethod verify-mic ((name (eql :des-mac-k)) octets msg &key key)
  (equalp octets (get-mic name msg :key key)))

;; ----------------------------------------------

;; NOTE: the msg octets MUST be prepended with the message type integer,
;; encoded as a 4-octet little-endian integer	  
(defchecksum :hmac-md5 -135)
(defmethod get-mic ((name (eql :hmac-md5)) msg &key key)
  (hmac-md5 (hmac-md5 (usb8 (babel:string-to-octets "signaturekey") '(0))
		      key)
	    (md5 msg)))
(defmethod verify-mic ((name (eql :hmac-md5)) octets msg &key key)
  (equalp (get-mic name msg :key key)
	  octets))

