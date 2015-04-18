;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:cerberus)

;; It would be nice to have a pair of generic functions which dispatch on cipher type.
;; The "encrypt" function should take an octet array and return a ENCRYPTED-DATA structure.
;; the "decrypt" should take an ENCRYPTED-DATA structue and return the decryptred octets

(defgeneric encrypt-data-profile (type octets key &key))
(defgeneric decrypt-data-profile (type octets key &key))

;; the main fucntions that should be called
(defun encrypt-data (type octets key &key)
  "Encrypt the octets using the key with cipher type. Returns an ENCRYPTED-DATA structure."
  (make-encrypted-data :type type
		       :cipher (encrypt-data-profile type octets key)))

(defun decrypt-data (ed key &key)
  "Takes an ENCRYPTED-DATA structure and returns the decrypted result."
  (declare (type encrypted-data ed))
  (decrypt-data-profile (encrypted-data-type ed)
			(encrypted-data-cipher ed)
			key))

;; ------------ des-cbc-md5 ----------

(defmethod encrypt-data-profile ((type (eql :des-cbc-md5)) octets key &key)
  (encrypt-des-cbc-md5 key octets))

(defmethod decrypt-data-profile ((type (eql :des-cbc-md5)) octets key &key)
  (decrypt-des-cbc-md5 key octets))

;; ------------ des-cbc-md4 ------------

(defmethod encrypt-data-profile ((type (eql :des-cbc-md4)) octets key &key)
  (des-encrypt octets
	       (lambda (data)
		 (encrypt-des-cbc key data))
	       (lambda (data)
		 (md4 data))))
(defmethod decrypt-data-profile ((type (eql :des-cbc-md4)) octets key &key)
  (des-decrypt octets
	       (lambda (data)
		 (decrypt-des-cbc key data))
	       (lambda (data)
		 (md4 data))))

;; --------------------------------------

;; should really define some other encryption profiles, e.g. the sha1 ones
