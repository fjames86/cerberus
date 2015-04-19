;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:cerberus)

;; this file is for defining "encryption profiles", as described in the rfc
;; this amounts to a set of functions which should be dispatched to depending on
;; the encrpyion type

(defvar *profiles* nil
  "A list of symbols naming available encryption type profiles.")
(defun defprofile (name)
  (pushnew name *profiles*))
(defun list-all-profiles ()
  *profiles*)

(defgeneric profile-encrypt-data (type octets key &key))
(defgeneric profile-decrypt-data (type octets key &key))

(defgeneric string-to-key (type password salt))
(defgeneric random-to-key (type octets &key))
(defgeneric pseudo-random (type key octets &key))

;; the main fucntions that should be called
(defun encrypt-data (type octets key &key)
  "Encrypt the octets using the key with cipher type. Returns an ENCRYPTED-DATA structure."
  (make-encrypted-data :type type
		       :cipher (profile-encrypt-data type octets key)))

(defun decrypt-data (ed key &key)
  "Takes an ENCRYPTED-DATA structure and returns the decrypted result."
  (declare (type encrypted-data ed))
  (profile-decrypt-data (encrypted-data-type ed)
			(encrypted-data-cipher ed)
			key))

;; ------------ des-cbc-md5 ------------

(defprofile :des-cbc-md5)

(defmethod profile-encrypt-data ((type (eql :des-cbc-md5)) octets key &key)
  (des-encrypt octets
	       (lambda (data)
		 (encrypt-des-cbc key data))
	       #'md5))

(defmethod profile-decrypt-data ((type (eql :des-cbc-md5)) octets key &key)
  (des-decrypt octets
	       (lambda (data)
		 (decrypt-des-cbc key data))
	       #'md4))

(defmethod string-to-key ((type (eql :des-cbc-md5)) password salt)
  (des-string-to-key password (or salt "")))

(defmethod random-to-key ((type (eql :des-cbc-md5)) octets &key)
  (des-random-to-key octets))

(defmethod pseudo-random ((type (eql :des-cbc-md5)) key octets &key)
  (encrypt-des-cbc key (md5 octets)))

;; ------------ des-cbc-md4 ------------

(defprofile :des-cbc-md4)

(defmethod profile-encrypt-data ((type (eql :des-cbc-md4)) octets key &key)
  (des-encrypt octets
	       (lambda (data)
		 (encrypt-des-cbc key data))
	       #'md4))

(defmethod profile-decrypt-data ((type (eql :des-cbc-md4)) octets key &key)
  (des-decrypt octets
	       (lambda (data)
		 (decrypt-des-cbc key data))
	       #'md4))

(defmethod string-to-key ((type (eql :des-cbc-md4)) password salt)
  (des-string-to-key password (or salt "")))

(defmethod random-to-key ((type (eql :des-cbc-md4)) octets &key)
  (let ((result (nibbles:make-octet-vector (length octets))))
    (dotimes (i (length octets))
      (setf (aref result i) (aref octets i)))
    (fix-parity result)
    result))

;; note: uses MD5 is in PRF, even though this is the MD4 profile
(defmethod pseudo-random ((type (eql :des-cbc-md4)) key octets &key)
  (encrypt-des-cbc key (md5 octets)))

;; ---------------- des-cbc-crc -----------------

(defprofile :des-cbc-crc)

(defmethod profile-encrypt-data ((type (eql :des-cbc-crc)) octets key &key)
  (des-encrypt octets
	       (lambda (data)
		 (encrypt-des-cbc key data :initialization-vector key))
	       #'crc32
	       :cksum-len 4))

(defmethod profile-decrypt-data ((type (eql :des-cbc-crc)) octets key &key)
  (des-decrypt octets
	       (lambda (data)
		 (decrypt-des-cbc key data :initialization-vector key))
	       #'crc32
	       :cksum-len 4))

(defmethod string-to-key ((type (eql :des-cbc-crc)) password salt)
  (des-string-to-key password (or salt "")))

(defmethod random-to-key ((type (eql :des-cbc-crc)) octets &key)
  (let ((result (nibbles:make-octet-vector (length octets))))
    (dotimes (i (length octets))
      (setf (aref result i) (aref octets i)))
    (fix-parity result)
    result))

;; note: uses MD5 is in PRF, even though this is the CRC32 profile
(defmethod pseudo-random ((type (eql :des-cbc-crc)) key octets &key)
  (encrypt-des-cbc key (md5 octets)))

;; --------------------------------------

;; should really define some other encryption profiles, e.g. the sha1 ones

(defmethod string-to-key ((type (eql :rc4)) password salt)
  (rc4-string-to-key password))
