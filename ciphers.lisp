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

(defgeneric profile-block-size (type)
  (:documentation "Returns number of bits the block size uses"))
(defgeneric profile-key-seed-length (type)
  (:documentation "Returns the number of bits the key uses (called k in the rfc)"))
(defgeneric profile-check-sum-size (type)
  (:documentation "Returns the number of bits the checksum returns"))

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

(defmethod profile-block-size ((type (eql :des-cbc-md5))) 64)
(defmethod profile-key-seed-length ((type (eql :des-cbc-md5))) 64)
(defmethod profile-check-sum-size ((type (eql :des-cbc-md5))) (* 16 8))

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

(defmethod profile-block-size ((type (eql :des-cbc-md4))) 64)
(defmethod profile-key-seed-length ((type (eql :des-cbc-md4))) 64)
(defmethod profile-check-sum-size ((type (eql :des-cbc-md4))) (* 16 8))


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

(defmethod profile-block-size ((type (eql :des-cbc-crc))) 64)
(defmethod profile-key-seed-length ((type (eql :des-cbc-crc))) 64)
(defmethod profile-check-sum-size ((type (eql :des-cbc-crc))) (* 4 8))

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

;; --------------------- rc4-hmac -----------------

;;(defprofile :rc4-hmac)
;;(defprofile :rc4-hmac-exp) ???

(defmethod profile-block-size ((type (eql :rc4-hmac))) 1)
(defmethod profile-key-seed-length ((type (eql :rc4-hmac))) 1) ;; ???
(defmethod profile-check-sum-size ((type (eql :rc4-hmac))) (* 16 8))

;; copied from the apple codes
(defun rc4-translate-usage (usage)
  (case usage
    (3 8) ;; ap-rep encrypted part 
    (9 8) ;; tgs-rep encrypted part 
    (23 13) ;; sign-wrap token
    (otherwise usage)))
    
(defun encrypt-rc4 (key data &key export (usage 0))
  ;; translate the usage
  (setf usage (rc4-translate-usage usage))

  (let ((l40 (usb8 (babel:string-to-octets "fortybits") '(0 0 0 0 0)))
        (k1 nil)
        (k2 nil)
        (k3 nil))
    (if export 
        (setf (nibbles:ub32ref/le l40 10) usage
              k1 (hmac-md5 l40 key))
        (setf k1 (hmac-md5 (let ((v (nibbles:make-octet-vector 4)))
                             (setf (nibbles:ub32ref/le v 0) usage)
                             v)
                           key)))
    (setf k2 (subseq k1 0 16))
    (when export
      (dotimes (i 9)
        (setf (aref k1 (+ i 7)) #xab)))
    (let ((result (nibbles:make-octet-vector (+ 8 (length data)))))
      ;; set the confounder 
      (setf (nibbles:ub64ref/be result 0) (random (expt 2 64)))
      ;; copy the data
      (dotimes (i (length data))
        (setf (aref result (+ i 8)) (aref data i)))
      ;; compute the checksum 
      (let ((cksum (hmac-md5 result k2)))
	(setf k3 (hmac-md5 cksum k1))
	(let ((cipher (ironclad:make-cipher :arcfour 
					    :key k3
					    :mode :stream)))
	  ;; encrypt the result  
	  (ironclad:encrypt-in-place cipher result))
      (usb8 cksum result)))))
      
(defun decrypt-rc4 (key data &key export (usage 0))
  ;; translate the usage
  (setf usage (rc4-translate-usage usage))

  (let ((l40 (usb8 (babel:string-to-octets "fortybits") '(0 0 0 0 0)))
        (k1 nil)
        (k2 nil)
        (k3 nil))
    (if export 
        (setf (nibbles:ub32ref/le l40 10) usage
              k1 (hmac-md5 l40 key))
        (setf k1 (hmac-md5 (let ((v (nibbles:make-octet-vector 4)))
                             (setf (nibbles:ub32ref/le v 0) usage)
                             v)
                           key)))
    (setf k2 (subseq k1 0 16))
    (when export 
      (dotimes (i 9)
        (setf (aref k1 (+ i 7)) #xab)))
    (setf k3 (hmac-md5 (subseq data 0 16) k1))

    (let ((cksum (subseq data 0 16))
          (confounder nil)
          (plaintext nil))
      ;; decrypt the confounder 
      (let ((cipher (ironclad:make-cipher :arcfour 
                                          :key k3
                                          :mode :stream)))
        (let ((result (nibbles:make-octet-vector (- (length data) 16))))
          (ironclad:decrypt cipher data result
			    :ciphertext-start 16)
          (setf confounder (subseq result 0 8)
		plaintext (subseq result 8))))

      ;; validate the checksum 
      (unless (equalp (hmac-md5 (usb8 confounder plaintext) k2)
                      cksum)
;;        (warn "checksums don't match"))
        (error "checksums don't match"))
      plaintext)))
      
(defmethod profile-encrypt-data ((type (eql :rc4-hmac)) octets key &key usage)
  (encrypt-rc4 key octets :usage usage))

(defmethod profile-decrypt-data ((type (eql :rc4-hmac)) octets key &key usage)
  (decrypt-rc4 key octets :usage usage))

;; for microsoft we need some extra encyption types -
(defun rc4-string-to-key (password)
  (md4 (babel:string-to-octets password 
			       :encoding :ucs-2
			       :use-bom nil)))

(defmethod string-to-key ((type (eql :rc4-hmac)) password salt)
  (rc4-string-to-key password))

;; what is this for the rc4 system?
;;(defmethod random-to-key ((type (eql :rc4-hmac)) octets &key))

(defmethod pseudo-random ((type (eql :rc4-hmac)) key octets &key)
  (let ((h (ironclad:make-hmac key :sha1)))
    (ironclad:update-hmac h octets)
    (ironclad:hmac-digest h)))

;; ---------------- des3-cbc-sha1-kd -----------------

;; the rfc uses both des3-cbc-hmac-sha1-kd and des3-cbc-sha1-kd to refer to this 
;; profile. we use the shorter version of the name 

(defprofile :des3-cbc-sha1-kd)

(defmethod profile-block-size ((type (eql :des3-cbc-sha1-kd))) 64)
(defmethod profile-key-seed-length ((type (eql :des3-cbc-sha1-kd))) 168)
(defmethod profile-check-sum-size ((type (eql :des3-cbc-sha1-kd))) (* 20 8))

(defmethod profile-encrypt-data ((type (eql :des3-cbc-sha1-kd)) octets key &key initialization-vector)
  (des-encrypt octets
	       (lambda (data)
		 (encrypt-des3 key data :initialization-vector initialization-vector))
	       #'sha1
	       :cksum-len 20))

(defmethod profile-decrypt-data ((type (eql :des3-cbc-sha1-kd)) octets key &key initialization-vector)
  (des-decrypt octets
	       (lambda (data)
		 (decrypt-des3 key data :initialization-vector initialization-vector))
	       #'sha1
	       :cksum-len 20))

;; I think this works
(defun des3-random-to-key (octets)
  (declare (type (vector (unsigned-byte 8) 7) octets))
  (let ((v (nibbles:make-octet-vector 8)))
    (dotimes (i 7)
      (setf (aref v i) (reverse-octet (aref octets i))
	    (aref v 7) (logior (aref v 7) 
			       (ash (if (logtest (aref octets i) #x80)
					1
					0)
				    (1+ i)))))
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
      (format t "~X" tmpkey)
      (derive-key :des3-cbc-sha1-kd 
		  tmpkey 
		  (babel:string-to-octets "kerberos")))))

	
(defmethod string-to-key ((type (eql :des3-cbc-sha1-kd)) password salt)
  (des3-string-to-key password salt))

(defmethod random-to-key ((type (eql :des3-cbc-sha1-kd)) octets &key)
  (usb8 (des3-random-to-key (subseq octets 0 7))
	(des3-random-to-key (subseq octets 7 14))
	(des3-random-to-key (subseq octets 14 21))))

;; FIXME: what for this? it's not specified in the rfc
;; Answer: look in th "simplified profile", it's something like
;; tmp1 = H(octet), tmp2 = truncate tmp1 to multiple of m
;; pseudo-random = E(DK(key, constant, tmp2))
;;(defmethod pseudo-random ((type (eql :des3-cbc-sha1-kd)) key octets &key)
;;  (encrypt-des-cbc key (md5 octets)))
;; 

;; ------------

(defun derive-random (type key constant)
  ;; n-fold the constant into blk-size bits if it is too small
  (let ((blk-size (profile-block-size type))
	(k (profile-key-seed-length type)))
    (when (< (* 8 (length constant)) blk-size)
      (setf constant (n-fold constant blk-size)))
    (k-truncate (flexi-streams:with-output-to-sequence (v)
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

;; the rfc suggets we need to concatenate some constants with the constant
;; there are 3 of them
;; I don't think this works correctly 
(defun derive-key (type key constant)
  (random-to-key type 
		 (derive-random type 
				key
				(etypecase constant
				  (integer (let ((v (nibbles:make-octet-vector 4)))
					     (setf (nibbles:sb32ref/be v 0) constant)
					     v))
				  (vector constant)))))

	    
	 
;;#(#xdc #xe0 #x6b #x1f #x64 #xc8 #x57 #xa1 #x1c #x3d #xb5 #x7c #x51 #x89 #x9b #x2c #xc1 #x79 #x10 #x08 #xce #x97 #x3b #x92)
