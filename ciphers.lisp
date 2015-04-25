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
  (:documentation "Returns number of bytes the block size uses"))
(defgeneric profile-key-seed-length (type)
  (:documentation "Returns the number of bytes the key uses (k in the rfc = 8*this)"))
(defgeneric profile-check-sum-size (type)
  (:documentation "Returns the number of bytes the checksum returns"))

;; basic encryption routines. only required for simple profiles 
;; i.e. those which use the derive-key function
(defgeneric profile-encrypt (type key octets))
(defgeneric profile-decrypt (type key octets))

;; encrypt messages, including checksums+confounders
(defgeneric profile-encrypt-data (type octets key &key))
(defgeneric profile-decrypt-data (type octets key &key))

;; key generation routines
(defgeneric string-to-key (type password salt &key))
(defgeneric random-to-key (type octets &key))
(defgeneric pseudo-random (type key octets &key))

;; the simplified profile requires a specified hmac function
(defgeneric profile-hmac (type key octets))
(defgeneric profile-hmac-length (type))


;; --------------------------------------------------------


(defun key-usage (name)
  "Convert a symbol naming a usage scenario into a usage number"
  (ecase name 
    (:pa-enc-timestamp 1) ;; pa-enc-timestamp 
    (:ticket 2) ;; enc-part of a ticket
    (:as-rep 3) ;; enc-part of a as-rep message
    (:tgs-session 4) ;; as above but when the session key is used
    (:tgs-sub-session 5) ;; subsession key used when encrypting the enc-auth-data part of a tgs-req
    (:authenticator-tgs-req 6) ;; in a pa-tgs-req ap-data field
    (:pa-tgs-req 7) ;; enctypred authenticator in a pa-tgs-req 
    (:tgs-rep 8) ;; enc-part of a tgs-rep if using session key 
    (:tgs-rep-subkey 9) ;; enc-part of tgs-rep if using authenticator subkey
    (:authenticator-cksum 10) ;; in normal messages
    (:ap-req 11) ;; encrypted authenticator in an ap-req 
    (:ap-rep 12) ;; enc-part of a enc-ap-rep-part 
    (:krb-priv 13) ;; enc-part of a krb-priv message
    (:krb-cred 14) ;; enc-part of a krb-cred message
    (:krb-safe 15) ;; checksum of a krb-safe message
    (:kdc-issued 19) ;; kdc-issued message checksum
    ))

;; encrypt a message and return a kerberos EncryptedData structure
(defun encrypt-data (type octets key &key usage)
  "Encrypt the octets using the key with cipher type. Returns an ENCRYPTED-DATA structure."
  (make-encrypted-data :type type
		       :cipher (profile-encrypt-data type octets key 
						     :usage (key-usage usage))))

(defun decrypt-data (ed key &key usage)
  "Takes an ENCRYPTED-DATA structure and returns the decrypted result."
  (declare (type encrypted-data ed))
  (profile-decrypt-data (encrypted-data-type ed)
			(encrypted-data-cipher ed)
			key
			:usage (key-usage usage)))

;; ------------ des-cbc-md5 ------------

(defprofile :des-cbc-md5)

(defmethod profile-block-size ((type (eql :des-cbc-md5))) 8)
(defmethod profile-key-seed-length ((type (eql :des-cbc-md5))) 8)
(defmethod profile-check-sum-size ((type (eql :des-cbc-md5))) 16)

(defmethod profile-encrypt ((type (eql :des-cbc-md5)) key octets)
  (encrypt-des-cbc key octets))
(defmethod profile-decrypt ((type (eql :des-cbc-md5)) key octets)
  (decrypt-des-cbc key octets))

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

(defmethod string-to-key ((type (eql :des-cbc-md5)) password salt &key)
  (des-string-to-key password (or salt "")))

(defmethod random-to-key ((type (eql :des-cbc-md5)) octets &key)
  (des-random-to-key octets))

(defmethod pseudo-random ((type (eql :des-cbc-md5)) key octets &key)
  (encrypt-des-cbc key (md5 octets)))

;; ------------ des-cbc-md4 ------------

(defprofile :des-cbc-md4)

(defmethod profile-block-size ((type (eql :des-cbc-md4))) 8)
(defmethod profile-key-seed-length ((type (eql :des-cbc-md4))) 8)
(defmethod profile-check-sum-size ((type (eql :des-cbc-md4))) 16)

(defmethod profile-encrypt ((type (eql :des-cbc-md4)) key octets)
  (encrypt-des-cbc key octets))
(defmethod profile-decrypt ((type (eql :des-cbc-md4)) key octets)
  (decrypt-des-cbc key octets))

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

(defmethod string-to-key ((type (eql :des-cbc-md4)) password salt &key)
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

(defmethod profile-block-size ((type (eql :des-cbc-crc))) 8)
(defmethod profile-key-seed-length ((type (eql :des-cbc-crc))) 8)
(defmethod profile-check-sum-size ((type (eql :des-cbc-crc))) 4)

(defmethod profile-encrypt ((type (eql :des-cbc-crc)) key octets)
  (encrypt-des-cbc key octets))
(defmethod profile-decrypt ((type (eql :des-cbc-crc)) key octets)
  (decrypt-des-cbc key octets))

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

(defmethod string-to-key ((type (eql :des-cbc-crc)) password salt &key)
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

;; the RC4-HMAC profile, needed for Windows

(defprofile :rc4-hmac)
(defprofile :rc4-hmac-exp) 

(defmethod profile-block-size ((type (eql :rc4-hmac))) 1)
(defmethod profile-key-seed-length ((type (eql :rc4-hmac))) 1) ;; ???
(defmethod profile-check-sum-size ((type (eql :rc4-hmac))) 16)

(defmethod profile-block-size ((type (eql :rc4-hmac-exp))) 1)
(defmethod profile-key-seed-length ((type (eql :rc4-hmac-exp))) 1) ;; ???
(defmethod profile-check-sum-size ((type (eql :rc4-hmac-exp))) 16)

;; copied from the apple codes
(defun rc4-translate-usage (usage)
  (case usage
    (3 8) ;; ap-rep encrypted part 
    (9 8) ;; tgs-rep encrypted part 
    (23 13) ;; sign-wrap token
    (otherwise usage)))
    
(defmethod profile-encrypt ((type (eql :rc4-hmac)) key octets)
  (let ((cipher (ironclad:make-cipher :arcfour 
				      :key key
				      :mode :stream))
	(result (nibbles:make-octet-vector (length octets))))
    (ironclad:encrypt cipher octets result)
    result))

(defmethod profile-decrypt ((type (eql :rc4-hmac)) key octets)
  (let ((cipher (ironclad:make-cipher :arcfour 
				      :key key
				      :mode :stream))
	(result (nibbles:make-octet-vector (length octets))))
    (ironclad:decrypt cipher octets result)
    result))

(defmethod profile-encrypt ((type (eql :rc4-hmac-exp)) key octets)
  (let ((cipher (ironclad:make-cipher :arcfour 
				      :key key
				      :mode :stream))
	(result (nibbles:make-octet-vector (length octets))))
    (ironclad:encrypt cipher octets result)
    result))

(defmethod profile-decrypt ((type (eql :rc4-hmac-exp)) key octets)
  (let ((cipher (ironclad:make-cipher :arcfour 
				      :key key
				      :mode :stream))
	(result (nibbles:make-octet-vector (length octets))))
    (ironclad:decrypt cipher octets result)
    result))


(defun encrypt-rc4 (key data &key export (usage 0))
  ;; translate the usage
  (setf usage (rc4-translate-usage usage))

  (let ((l40 (usb8 (babel:string-to-octets "fortybits") '(0 0 0 0 0)))
        (k1 nil)
        (k2 nil)
        (k3 nil))
    (if export 
        (setf (nibbles:ub32ref/le l40 10) (or usage 0)
              k1 (hmac-md5 l40 key))
        (setf k1 (hmac-md5 (let ((v (nibbles:make-octet-vector 4)))
                             (setf (nibbles:ub32ref/le v 0) (or usage 0))
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
        (setf (nibbles:ub32ref/le l40 10) (or usage 0)
              k1 (hmac-md5 l40 key))
        (setf k1 (hmac-md5 (let ((v (nibbles:make-octet-vector 4)))
                             (setf (nibbles:ub32ref/le v 0) (or usage 0))
                             v)
                           key)))
    (setf k2 (subseq k1 0 16))
    (when export 
      (dotimes (i 9)
        (setf (aref k1 (+ i 7)) #xab)))

    (let ((cksum (subseq data 0 16))
          (plaintext nil))
      ;; compute the k3 from the checksum
      (setf k3 (hmac-md5 cksum k1))

      ;; decrypt the ciphertext
      (let ((cipher (ironclad:make-cipher :arcfour 
                                          :key k3
                                          :mode :stream)))
        (let ((result (nibbles:make-octet-vector (- (length data) 16))))
          (ironclad:decrypt cipher data result
			    :ciphertext-start 16)
          (setf plaintext (subseq result 8))

	  ;; validate the checksum 
	  (unless (equalp (hmac-md5 result k2) cksum)
	    (error 'checksum-error))))
      plaintext)))
      
(defmethod profile-encrypt-data ((type (eql :rc4-hmac)) octets key &key usage)
  (encrypt-rc4 key octets :usage usage))

(defmethod profile-decrypt-data ((type (eql :rc4-hmac)) octets key &key usage)
  (decrypt-rc4 key octets :usage usage))

(defmethod profile-encrypt-data ((type (eql :rc4-hmac-exp)) octets key &key usage)
  (encrypt-rc4 key octets :usage usage :export t))

(defmethod profile-decrypt-data ((type (eql :rc4-hmac-exp)) octets key &key usage)
  (decrypt-rc4 key octets :usage usage :export t))

(defun rc4-string-to-key (password)
  (md4 (babel:string-to-octets password 
			       :encoding :ucs-2
			       :use-bom nil)))

(defmethod string-to-key ((type (eql :rc4-hmac)) password salt &key)
  (rc4-string-to-key password))

(defmethod string-to-key ((type (eql :rc4-hmac-exp)) password salt &key)
  (rc4-string-to-key password))

;; what is this for the rc4 system? maybe we don't need it 
;;(defmethod random-to-key ((type (eql :rc4-hmac)) octets &key))

(defmethod pseudo-random ((type (eql :rc4-hmac)) key octets &key)
  (let ((h (ironclad:make-hmac key :sha1)))
    (ironclad:update-hmac h octets)
    (ironclad:hmac-digest h)))

(defmethod pseudo-random ((type (eql :rc4-hmac-exp)) key octets &key)
  (let ((h (ironclad:make-hmac key :sha1)))
    (ironclad:update-hmac h octets)
    (ironclad:hmac-digest h)))

;; ---------------- des3-cbc-sha1-kd -----------------

;; the rfc uses both des3-cbc-hmac-sha1-kd and des3-cbc-sha1-kd to refer to this 
;; profile. we use the shorter version of the name 

(defprofile :des3-cbc-sha1-kd)

(defmethod profile-block-size ((type (eql :des3-cbc-sha1-kd))) 8)
(defmethod profile-key-seed-length ((type (eql :des3-cbc-sha1-kd))) 21)
(defmethod profile-check-sum-size ((type (eql :des3-cbc-sha1-kd))) 20)

(defmethod profile-encrypt ((type (eql :des3-cbc-sha1-kd)) key octets)
  (encrypt-des3 key octets))
(defmethod profile-decrypt ((type (eql :des3-cbc-sha1-kd)) key octets)
  (decrypt-des3 key octets))

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
      (setf (aref v i) (aref octets i) 
	    (aref v 7) (logior (aref v 7) 
			       (ash (if (logtest (aref octets i) #x1)
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
;;      (format t "~X" tmpkey)
      (derive-key :des3-cbc-sha1-kd 
		  tmpkey 
		  (babel:string-to-octets "kerberos")))))

(defmethod string-to-key ((type (eql :des3-cbc-sha1-kd)) password salt &key)
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
  "The DR() function specified in the rfc."
  ;; n-fold the constant into blk-size bits if it is too small
  (let ((blk-size (profile-block-size type))
	(k (profile-key-seed-length type)))
    (when (< (length constant) blk-size)
      (setf constant (n-fold constant (* blk-size 8))))
    (k-truncate (flexi-streams:with-output-to-sequence (v)
		  (do ((i 0)
		       (prev nil))
		      ((>= i k))
		    (let ((ki (profile-encrypt type key (or prev constant))))
		      (write-sequence ki v)
		      (incf i (length ki))
		      (setf prev ki))))
		(* k 8))))

(defun derive-key (type key constant)
  "The DK() function specified in the rfc."
  (let ((rand
	 (derive-random type 
			key
			(etypecase constant
			  (integer (let ((v (nibbles:make-octet-vector 4)))
				     (setf (nibbles:sb32ref/be v 0) constant)
				     v))
			  (vector constant)))))
;;    (format t "dr: ~X~%" rand)
    (random-to-key type rand)))

;; this works with the des3-cbc-sha1-kd profile!
(defun simplified-profile-derive-keys (type key usage)
  "Computes the 3 keys from the base protocol key. Returns (values Kc Ke Ki) where
Kc ::= used for the get-mic function
Ke ::= used for encryption
Ki ::= used for the encryption checksum."
  (let ((u (nibbles:make-octet-vector 4)))
    (setf (nibbles:ub32ref/be u 0) usage)
    (values (derive-key type key (usb8 u '(#x99)))
	    (derive-key type key (usb8 u '(#xaa)))
	    (derive-key type key (usb8 u '(#x55))))))

(defun simplified-profile-encrypt (type key octets usage)
  "Encrypt message data for a simplified profile system."
  (let ((blk-size (profile-block-size type)))
    (let ((data (usb8 (loop :for i :below blk-size :collect (random 256))
		      octets
		      ;; padding 
		      (unless (zerop (mod (length octets) blk-size))
			(make-list (- blk-size (mod (length octets) blk-size))
				   :initial-element 0)))))
    (multiple-value-bind (kc ke ki) (simplified-profile-derive-keys type key usage)
      (declare (ignore kc))
      (usb8 (profile-encrypt type ke data)
	    (profile-hmac type ki data))))))

(defun simplified-profile-decrypt (type key octets usage)
  "Decrypt message data for a simplified profile system."
  (let ((ciphertext (subseq octets 0 (- (length octets) (profile-hmac-length type))))
	(hmac (subseq octets (- (length octets) (profile-hmac-length type)))))
    (multiple-value-bind (kc ke ki) (simplified-profile-derive-keys type key usage)
      (declare (ignore kc))
      (let ((plaintext (profile-decrypt type ke ciphertext)))
	(unless (equalp hmac (profile-hmac type ki plaintext))
	  (error 'checksum-error))
	;; drop the random confounder
	(subseq plaintext (profile-block-size type))))))

;; ---------------- aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96 -----------------

;; these don't seem to work. I always get a "invalid checksum" error back from the KDC
(defprofile :aes128-cts-hmac-sha1-96)
(defprofile :aes256-cts-hmac-sha1-96)

(defmethod profile-block-size ((type (eql :aes128-cts-hmac-sha1-96))) 16) ;; ??? shouldn't it be 1?
(defmethod profile-key-seed-length ((type (eql :aes128-cts-hmac-sha1-96))) 16)
(defmethod profile-check-sum-size ((type (eql :aes128-cts-hmac-sha1-96))) 12) 

;; we need cipher-text stealing cbc mode encryption rather than standard cbc mode
;; This works
(defmethod profile-encrypt ((type (eql :aes128-cts-hmac-sha1-96)) key octets)
  (let* ((cipher (ironclad:make-cipher :aes
				       :mode :cbc
				       :key key
				       :initialization-vector (nibbles:make-octet-vector 16)))
	 (len (length octets))
	 (result (nibbles:make-octet-vector (+ len
					       (if (zerop (mod len 16))
						   0
						   (- 16 (mod len 16)))))))

    ;; when the plaintext is a single block just encrypt and return as normal
    (when (<= len 16)
      (when (< len 16)
	(setf octets (usb8 octets (make-list (- 16 (mod len 16)) :initial-element 0))))
      (ironclad:encrypt cipher octets result)
      (return-from profile-encrypt result))

    ;; if the last block is too small, pad with zeros
    (unless (zerop (mod len 16))
      (setf octets (usb8 octets (make-list (- 16 (mod len 16)) :initial-element 0))))

    (ironclad:encrypt cipher octets result)
    ;; swap last two blocks
    (let ((base (- (length octets) 32)))
      (dotimes (i 16)
	(rotatef (aref result (+ base i)) (aref result (+ base 16 i)))))
    (subseq result 0 len)))

;; this works
(defmethod profile-decrypt ((type (eql :aes128-cts-hmac-sha1-96)) key octets)
  (let* ((cipher (ironclad:make-cipher :aes
				       :mode :cbc
				       :key key
				       :initialization-vector (nibbles:make-octet-vector 16)))
	 (len (length octets))
	 (extra (mod len 16))
	 (result (nibbles:make-octet-vector len))
	 (cn-1 (subseq octets (- len 16 (if (zerop extra) 16 extra)) 
		       (- len (if (zerop extra) 16 extra))))
	 (cn (subseq octets (- len (if (zerop extra) 16 extra)))))

    ;; if the ciphertext is 1 block then just decrtypt it and return
    (when (<= len 16)
      (ironclad:decrypt cipher octets result)
      (return-from profile-decrypt result))

    ;; start by decrypting up to the last 2 blocks
    (ironclad:decrypt cipher octets result :ciphertext-end (- len 16 (if (zerop extra) 16 extra)))

    ;; we now need to decrypt the penultimate block, but using an empty IV
    (unless (zerop extra)
      (setf cn
	    (usb8 cn
		  (subseq (let ((c (ironclad:make-cipher :aes
							 :mode :cbc
							 :key key
							 :initialization-vector (nibbles:make-octet-vector 16)))
				(r (nibbles:make-octet-vector 16)))
			    (ironclad:decrypt c cn-1 r)
			    r)
			  extra))))
    ;; decrypt in swapped order
    (ironclad:decrypt cipher cn result :plaintext-start (- len 16 (if (zerop extra) 16 extra)))
    (let ((r (nibbles:make-octet-vector 16))
	  (e (if (zerop extra) 16 extra)))
      (ironclad:decrypt cipher cn-1 r)
      (dotimes (i e)
	(setf (aref result (+ (- len e) i)) (aref r i))))
    result))

(defmethod profile-encrypt-data ((type (eql :aes128-cts-hmac-sha1-96)) octets key &key usage)
  (simplified-profile-encrypt :aes128-cts-hmac-sha1-96 
			      key 
			      octets
			      usage))

(defmethod profile-decrypt-data ((type (eql :aes128-cts-hmac-sha1-96)) octets key &key usage)
  (simplified-profile-decrypt :aes128-cts-hmac-sha1-96
			      key
			      octets
			      usage))

;; this works
(defmethod string-to-key ((type (eql :aes128-cts-hmac-sha1-96)) password salt &key iteration-count)
  (derive-key :aes128-cts-hmac-sha1-96
	      (pbkdf2 password salt
		      :key-length (profile-key-seed-length type)
		      :iteration-count (or iteration-count 4096))
	      (babel:string-to-octets "kerberos")))

(defmethod random-to-key ((type (eql :aes128-cts-hmac-sha1-96)) octets &key)
  ;; just copy the octets
  (map '(vector (unsigned-byte 8)) #'identity octets))

(defmethod profile-hmac ((type (eql :aes128-cts-hmac-sha1-96)) key octets)
  (subseq (hmac-sha1 key octets) 0 12))

(defmethod profile-hmac-length ((type (eql :aes128-cts-hmac-sha1-96))) 12) 
      
;;(defmethod pseudo-random ((type (eql :des3-cbc-sha1-kd)) key octets &key)
;;  (encrypt-des-cbc key (md5 octets)))





(defmethod profile-block-size ((type (eql :aes256-cts-hmac-sha1-96))) 16) ;; ??? shouldn't it be 1?
(defmethod profile-key-seed-length ((type (eql :aes256-cts-hmac-sha1-96))) 32)
(defmethod profile-check-sum-size ((type (eql :aes256-cts-hmac-sha1-96))) 12) 

(defmethod profile-encrypt ((type (eql :aes256-cts-hmac-sha1-96)) key octets)
  (profile-encrypt :aes128-cts-hmac-sha1-96 key octets))

;; this works
(defmethod profile-decrypt ((type (eql :aes256-cts-hmac-sha1-96)) key octets)
  (profile-decrypt :aes128-cts-hmac-sha1-96 key octets))

(defmethod profile-encrypt-data ((type (eql :aes256-cts-hmac-sha1-96)) octets key &key usage)
  (simplified-profile-encrypt type
			      key 
			      octets
			      usage))

(defmethod profile-decrypt-data ((type (eql :aes256-cts-hmac-sha1-96)) octets key &key usage)
  (simplified-profile-decrypt type
			      key
			      octets
			      usage))

(defmethod string-to-key ((type (eql :aes256-cts-hmac-sha1-96)) password salt &key iteration-count)
  (derive-key type
	      (pbkdf2 password salt
		      :key-length (profile-key-seed-length type)
		      :iteration-count (or iteration-count 4096))
	      (babel:string-to-octets "kerberos")))

(defmethod random-to-key ((type (eql :aes256-cts-hmac-sha1-96)) octets &key)
  ;; just copy the octets
  (map '(vector (unsigned-byte 8)) #'identity octets))

(defmethod profile-hmac ((type (eql :aes256-cts-hmac-sha1-96)) key octets)
  (subseq (hmac-sha1 key octets) 0 12))

(defmethod profile-hmac-length ((type (eql :aes256-cts-hmac-sha1-96))) 12)



