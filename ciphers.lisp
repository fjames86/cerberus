;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:cerberus)

;; this file is for defining "encryption profiles", as described in the rfc
;; this amounts to a set of functions which should be dispatched to depending on
;; the encrpyion type

;; FIXME: add more profiel functions to get other info, e.g. cipher key size, cipher block size etc

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

(defmethod profile-encrypt-data ((type (eql :des-cbc-md5)) octets key &key initialization-vector)
  (des-encrypt octets
	       (lambda (data)
		 (encrypt-des-cbc key data :initialization-vector initialization-vector))
	       #'md5))

(defmethod profile-decrypt-data ((type (eql :des-cbc-md5)) octets key &key initialization-vector)
  (des-decrypt octets
	       (lambda (data)
		 (decrypt-des-cbc key data :initialization-vector initialization-vector))
	       #'md5))

(defmethod string-to-key ((type (eql :des-cbc-md5)) password salt)
  (des-string-to-key password (or salt "")))

(defmethod random-to-key ((type (eql :des-cbc-md5)) octets &key)
  (des-random-to-key octets))

(defmethod pseudo-random ((type (eql :des-cbc-md5)) key octets &key)
  (encrypt-des-cbc key (md5 octets)))

;; ------------ des-cbc-md4 ------------

(defprofile :des-cbc-md4)

(defmethod profile-encrypt-data ((type (eql :des-cbc-md4)) octets key &key initialization-vector)
  (des-encrypt octets
	       (lambda (data)
		 (encrypt-des-cbc key data :initialization-vector initialization-vector))
	       #'md4))

(defmethod profile-decrypt-data ((type (eql :des-cbc-md4)) octets key &key initialization-vector)
  (des-decrypt octets
	       (lambda (data)
		 (decrypt-des-cbc key data :initialization-vector initialization-vector))
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

(defmethod profile-encrypt-data ((type (eql :des-cbc-crc)) octets key &key initialization-vector)
  (des-encrypt octets
	       (lambda (data)
		 (encrypt-des-cbc key data :initialization-vector (or initialization-vector key)))
	       #'crc32
	       :cksum-len 4))

(defmethod profile-decrypt-data ((type (eql :des-cbc-crc)) octets key &key initialization-vector)
  (des-decrypt octets
	       (lambda (data)
		 (decrypt-des-cbc key data :initialization-vector (or initialization-vector key)))
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



;; ---------------- des3-cbc-hmac-sha1-kd -----------------

;; FIXME
(defprofile :des3-cbc-hmac-sha1-kd)

;; FIXME -- doesn't use 3des
(defmethod profile-encrypt-data ((type (eql :des3-cbc-hmac-sha1-kd)) octets key &key initialization-vector)
  (des-encrypt octets
	       (lambda (data)
		 (encrypt-des3 key data :initialization-vector initialization-vector))
	       #'sha1
	       :cksum-len 4))

(defmethod profile-decrypt-data ((type (eql :des3-cbc-hmac-sha1-kd)) octets key &key initialization-vector)
  (des-decrypt octets
	       (lambda (data)
		 (decrypt-des3 key data :initialization-vector initialization-vector))
	       #'sha1
	       :cksum-len 4))

;; does this work????
(defun des3-random-to-key (octets)
  (declare (type (vector (unsigned-byte 8) 7) octets))
  (let ((v (nibbles:make-octet-vector 8)))
    (dotimes (i 7)
      (setf (aref v i) (reverse-octet (aref octets i))))
    (setf (aref v 7)
	  (logior (ash (mod (aref octets 6) 2) -7)
		  (ash (mod (aref octets 5) 2) -6)
		  (ash (mod (aref octets 4) 2) -5)
		  (ash (mod (aref octets 3) 2) -4)
		  (ash (mod (aref octets 2) 2) -3)
		  (ash (mod (aref octets 1) 2) -2)
		  (ash (mod (aref octets 0) 2) -1)))
    (des-random-to-key v)
    v))

;; this dones't work
(defun des3-string-to-key (password salt)
  (let ((octets (n-fold (usb8 (babel:string-to-octets password)
			      (babel:string-to-octets salt))
			168)))
    ;; start by converting the 168-bit (i.e. 21 bytes) into 3 sets of 7 bytes
    (let ((tmpkey (usb8 (des3-random-to-key (subseq octets 0 7))
			(des3-random-to-key (subseq octets 7 14))
			(des3-random-to-key (subseq octets 14 21)))))
      (derive-key :des3-cbc-hmac-sha1-kd 
		  tmpkey 
		  (babel:string-to-octets "kerberos")
		  :k 168))))

	
(defmethod string-to-key ((type (eql :des3-cbc-hmac-sha1-kd)) password salt)
  (des3-string-to-key password salt))

(defmethod random-to-key ((type (eql :des3-cbc-hmac-sha1-kd)) octets &key)
  (usb8 (des3-random-to-key (subseq octets 0 7))
			(des3-random-to-key (subseq octets 7 14))
			(des3-random-to-key (subseq octets 14 21))))

;; FIXME: what for this? it's not specified in the rfc
;; Answer: look in th "simplified profile", it's something like
;; tmp1 = H(octet), tmp2 = truncate tmp1 to multiple of m
;; pseudo-random = E(DK(key, constant, tmp2))
;;(defmethod pseudo-random ((type (eql :des3-cbc-hmac-sha1-kd)) key octets &key)
;;  (encrypt-des-cbc key (md5 octets)))
;; 

;; ------------

;; I don't think this works correctly 
(defun derive-key (type key constant &key (k 64) (blk-size 64))
  (flet ((dr (constant)
	   ;; n-fold the constant into blk-size bits if it is too small
	   (when (< (* 8 (length constant)) blk-size)
	     (setf constant (n-fold constant blk-size)))
	   (k-truncate 
	    (flexi-streams:with-output-to-sequence (v)
	      (do ((i 0)
		   (prev nil))
		  ((>= i k))
		(let ((ki (profile-encrypt-data type 
						(or prev constant)
					       key)))
		  (write-sequence ki v)
		  (incf i (* 8 (length ki)))
		 (setf prev ki))))
	    k)))
    (random-to-key type 
		   (dr (etypecase constant
			 (integer (let ((v (nibbles:make-octet-vector 4)))
				    (setf (nibbles:sb32ref/be v 0) constant)
				    v))
			 (vector constant))))))

	    
	 
