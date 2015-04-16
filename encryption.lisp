;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:cerberus)

(defun usb8 (&rest sequences)
  (apply #'concatenate 
	 '(vector (unsigned-byte 8))
	 sequences))

(defun md4 (sequence)
  (ironclad:digest-sequence (ironclad:make-digest :md4) sequence))

(defun md5 (sequence)
  (ironclad:digest-sequence (ironclad:make-digest :md5) sequence))

(defun hmac-md5 (octets key)
  (let ((h (ironclad:make-hmac key :md5)))
    (ironclad:update-hmac h octets)
    (ironclad:hmac-digest h)))

(declaim (type (simple-array (unsigned-byte 32) (256)) +crc32-table+))
(alexandria:define-constant +crc32-table+
    (make-array 256 
		:element-type '(unsigned-byte 32)
		:initial-contents 
'(#x00000000 #x77073096 #xEE0E612C #x990951BA #x076DC419 #x706AF48F
#xE963A535 #x9E6495A3 #x0EDB8832 #x79DCB8A4 #xE0D5E91E #x97D2D988
#x09B64C2B #x7EB17CBD #xE7B82D07 #x90BF1D91 #x1DB71064 #x6AB020F2
#xF3B97148 #x84BE41DE #x1ADAD47D #x6DDDE4EB #xF4D4B551 #x83D385C7
#x136C9856 #x646BA8C0 #xFD62F97A #x8A65C9EC #x14015C4F #x63066CD9
#xFA0F3D63 #x8D080DF5 #x3B6E20C8 #x4C69105E #xD56041E4 #xA2677172
#x3C03E4D1 #x4B04D447 #xD20D85FD #xA50AB56B #x35B5A8FA #x42B2986C
#xDBBBC9D6 #xACBCF940 #x32D86CE3 #x45DF5C75 #xDCD60DCF #xABD13D59
#x26D930AC #x51DE003A #xC8D75180 #xBFD06116 #x21B4F4B5 #x56B3C423
#xCFBA9599 #xB8BDA50F #x2802B89E #x5F058808 #xC60CD9B2 #xB10BE924
#x2F6F7C87 #x58684C11 #xC1611DAB #xB6662D3D #x76DC4190 #x01DB7106
#x98D220BC #xEFD5102A #x71B18589 #x06B6B51F #x9FBFE4A5 #xE8B8D433
#x7807C9A2 #x0F00F934 #x9609A88E #xE10E9818 #x7F6A0DBB #x086D3D2D
#x91646C97 #xE6635C01 #x6B6B51F4 #x1C6C6162 #x856530D8 #xF262004E
#x6C0695ED #x1B01A57B #x8208F4C1 #xF50FC457 #x65B0D9C6 #x12B7E950
#x8BBEB8EA #xFCB9887C #x62DD1DDF #x15DA2D49 #x8CD37CF3 #xFBD44C65
#x4DB26158 #x3AB551CE #xA3BC0074 #xD4BB30E2 #x4ADFA541 #x3DD895D7
#xA4D1C46D #xD3D6F4FB #x4369E96A #x346ED9FC #xAD678846 #xDA60B8D0
#x44042D73 #x33031DE5 #xAA0A4C5F #xDD0D7CC9 #x5005713C #x270241AA
#xBE0B1010 #xC90C2086 #x5768B525 #x206F85B3 #xB966D409 #xCE61E49F
#x5EDEF90E #x29D9C998 #xB0D09822 #xC7D7A8B4 #x59B33D17 #x2EB40D81
#xB7BD5C3B #xC0BA6CAD #xEDB88320 #x9ABFB3B6 #x03B6E20C #x74B1D29A
#xEAD54739 #x9DD277AF #x04DB2615 #x73DC1683 #xE3630B12 #x94643B84
#x0D6D6A3E #x7A6A5AA8 #xE40ECF0B #x9309FF9D #x0A00AE27 #x7D079EB1
#xF00F9344 #x8708A3D2 #x1E01F268 #x6906C2FE #xF762575D #x806567CB
#x196C3671 #x6E6B06E7 #xFED41B76 #x89D32BE0 #x10DA7A5A #x67DD4ACC
#xF9B9DF6F #x8EBEEFF9 #x17B7BE43 #x60B08ED5 #xD6D6A3E8 #xA1D1937E
#x38D8C2C4 #x4FDFF252 #xD1BB67F1 #xA6BC5767 #x3FB506DD #x48B2364B
#xD80D2BDA #xAF0A1B4C #x36034AF6 #x41047A60 #xDF60EFC3 #xA867DF55
#x316E8EEF #x4669BE79 #xCB61B38C #xBC66831A #x256FD2A0 #x5268E236
#xCC0C7795 #xBB0B4703 #x220216B9 #x5505262F #xC5BA3BBE #xB2BD0B28
#x2BB45A92 #x5CB36A04 #xC2D7FFA7 #xB5D0CF31 #x2CD99E8B #x5BDEAE1D
#x9B64C2B0 #xEC63F226 #x756AA39C #x026D930A #x9C0906A9 #xEB0E363F
#x72076785 #x05005713 #x95BF4A82 #xE2B87A14 #x7BB12BAE #x0CB61B38
#x92D28E9B #xE5D5BE0D #x7CDCEFB7 #x0BDBDF21 #x86D3D2D4 #xF1D4E242
#x68DDB3F8 #x1FDA836E #x81BE16CD #xF6B9265B #x6FB077E1 #x18B74777
#x88085AE6 #xFF0F6A70 #x66063BCA #x11010B5C #x8F659EFF #xF862AE69
#x616BFFD3 #x166CCF45 #xA00AE278 #xD70DD2EE #x4E048354 #x3903B3C2
#xA7672661 #xD06016F7 #x4969474D #x3E6E77DB #xAED16A4A #xD9D65ADC
#x40DF0B66 #x37D83BF0 #xA9BCAE53 #xDEBB9EC5 #x47B2CF7F #x30B5FFE9
#xBDBDF21C #xCABAC28A #x53B39330 #x24B4A3A6 #xBAD03605 #xCDD70693
#x54DE5729 #x23D967BF #xB3667A2E #xC4614AB8 #x5D681B02 #x2A6F2B94
#xB40BBE37 #xC30C8EA1 #x5A05DF1B #x2D02EF8D))
  :test #'equalp)

;; this works
(defun crc32 (octets)
  "We have to use our own CRC32 because the kerberos spec requires a modification. Otherwise I'd use the ironclad one."
  (do ((c 0)
       (i 0 (1+ i)))
      ((= i (length octets))
       (let ((v (nibbles:make-octet-vector 4)))
	 (setf (nibbles:ub32ref/le v 0) c)
	 v))
    (let ((idx (logand (logxor (aref octets i) c) 
		       #xff)))
      (setf c (ash c -8))
      (setf c (logxor c (aref +crc32-table+ idx))))))

(defun encrypt-des-cbc (key octets &key initialization-vector)
  (let ((result (nibbles:make-octet-vector (length octets))))
    (ironclad:encrypt (ironclad:make-cipher :des 
					    :mode :cbc
					    :key key
					    :initialization-vector 
					    (or initialization-vector 
						(nibbles:make-octet-vector 8)))
		      octets
		      result)
    result))

(defun decrypt-des-cbc (key octets &key initialization-vector)
  (let ((result (nibbles:make-octet-vector (length octets))))
    (ironclad:decrypt (ironclad:make-cipher :des
					    :mode :cbc
					    :key key 
					    :initialization-vector 
					    (or initialization-vector 
						(nibbles:make-octet-vector 8)))
		      octets
		      result)
    result))

;; --------------

;; This is copied/ported from the C codes found here 
;; http://opensource.apple.com/source/Kerberos/Kerberos-62/KerberosFramework/Kerberos5/Sources/lib/crypto/nfold.c
;; this works
(defun n-fold (octets n)
  "The horrific n-fold function as specifed in the rfc."
  (let ((inbytes (ash (* (length octets) 8) -3))
	(outbytes (ash n -3)))
    (let ((lcm (lcm inbytes outbytes))
	  (out (nibbles:make-octet-vector outbytes)))
      (do ((i (1- lcm) (1- i))
	   (byte 0))
	  ((< i 0)
	   (progn
	     (unless (zerop byte)
	       (do ((i (1- outbytes) (1- i)))
		   ((< i 0))
		 (incf byte (aref out i))
		 (setf (aref out i) (logand byte #xff))
		 (setf byte (ash byte -8))))
	     out))
	(let ((msbit (mod (+ (1- (ash inbytes 3))
			     (* (+ (ash inbytes 3) 13) 
				(truncate i inbytes))
			     (ash (- inbytes (mod i inbytes)) 3))
			  (ash inbytes 3))))
	  (incf byte
		(logand 
		 (ash 
		  (logior 
		   (ash (aref octets (mod (- (1- inbytes) (ash msbit -3))
					  inbytes))
			8)
		   (aref octets (mod (- inbytes (ash msbit -3))
				     inbytes)))
		  (- (1+ (logand msbit 7))))
		 #xff))
	  (incf byte (aref out (mod i outbytes)))
	  (setf (aref out (mod i outbytes))
		(logand byte #xff))
	  (setf byte (ash byte -8)))))))

(defun k-truncate (octets k)
  "k is the number of bits"
  (let ((result (subseq octets 0 (1+ (truncate k 8)))))
    ;; FIXME: shouild also clear the high bits of the final octet if
    ;; k is not a multiple of 8. when that code is added, remove the assert
    (assert (zerop (mod k 8)))
    result))

(defun derive-key (encrypt-fn constant-octets k)
  (when (< k (length constant-octets))
    (setf constant-octets (n-fold constant-octets k)))
  (do ((octets constant-octets)
       (len 0)
       (result nil))
      ((>= len k) 
       (k-truncate (coerce result '(vector (unsigned-byte 80)))
		   k))
    (let ((blk (funcall encrypt-fn octets)))
      (incf len (length blk))
      (setf octets blk
	    result (append result (coerce blk 'list))))))





;; ---------------- des stuff -----------------


(defun reverse-bits (octet)
  (the (unsigned-byte 7)
       (logior (ash (logand octet #x01) 6) 
	       (ash (logand octet #x02) 4) 
	       (ash (logand octet #x04) 2) 
	       (ash (logand octet #x08) 0) 
	       (ash (logand octet #x10) -2)
	       (ash (logand octet #x20) -4)
	       (ash (logand octet #x40) -6))))

(defun fix-parity (key)
  (dotimes (i 8)
    (let ((octet (aref key i)))
      (let ((parityp (zerop (mod (logcount octet) 2)))
	    (evenp (zerop (mod (aref key i) 2))))
	(cond 
	  ((and parityp evenp)
	   ;; turn the parity bit on
	   (setf (aref key i)
		 (logior (aref key i) 1)))
	  ((and parityp (not evenp))
	   ;; turn the parity bit on
	   (setf (aref key i) 
		 (logand (aref key i) (lognot 1))))))))
  key)

;; the 4 weak and 12 semi-weak keys as specified in DESI81 specification
;; I got this list from opensource.apple.com/source/Kerberos/Kerberos-62/KerberosFramework/Kerberos5/Sources/lib/crypto/des/weak_key.c
(defparameter *des-weak-keys*
  '(
    ;; wweak
    #(#x01 #x01 #x01 #x01 #x01 #x01 #x01 #x01)
    #(#xfe #xfe #xfe #xfe #xfe #xfe #xfe #xfe)
    #(#x1f #x1f #x1f #x1f #x0e #x0e #x0e #x0e)
    #(#xe0 #xe0 #xe0 #xe0 #xf1 #xf1 #xf1 #xf1)
    ;; semi-weak
    #(#x01 #xfe #x01 #xfe #x01 #xfe #x01 #xfe)
    #(#xfe #x01 #xfe #x01 #xfe #x01 #xfe #x01)
    
    #(#x1f #xe0 #x1f #xe0 #x0e #xf1 #x0e #xf1)
    #(#xe0 #x1f #xd0 #x1f #xf1 #x0e #xf1 #x0e)
    
    #(#x01 #xe0 #x01 #xe0 #x01 #xf1 #x01 #xf1)
    #(#xe0 #x01 #xe0 #x01 #xf0 #x01 #xf0 #x01)
    
    #(#x01 #x1f #x01 #x1f #x01 #x0e #x01 #x0e)
    #(#x1f #x01 #x1f #x01 #x0e #x01 #x0e #x01)
    
    #(#xe0 #xfe #xe0 #xfe #xf1 #xfe #xf1 #xfe)
    #(#xfe #xe0 #xfe #xe0 #xfe #xf1 #xfe #xf1)))

(defun des-weak-key-p (key)
  (member key *des-weak-keys*
	  :test #'equalp))

(defun correct-weak-key (key)
  (when (des-weak-key-p key)
    (setf (aref key 7)
	  (logxor (aref key 7) #xf0)))
  key)

;; this works
(defun des-string-to-key (password salt)
  (let ((octets (concatenate 'list
			     (etypecase password
			       (string (babel:string-to-octets password))
			       (vector password))
			     (etypecase salt 
			       (string (babel:string-to-octets salt))
			       (vector salt))))
	(key (nibbles:make-octet-vector 8)))
    ;; pad with zeros so it's a multiple of 8
    (let ((length (mod (length octets) 8)))
      (unless (zerop (mod length 8))
	(setf octets (append octets (make-list (- 8 length) :initial-element 0)))))
    ;; remove most significant bit and reverse the bits
    (do ((%octets octets (nthcdr 8 %octets))
	 (odd t (not odd)))
	((null %octets))
      (let ((8octets (subseq %octets 0 8)))
	;; remove the most sig bit from each byte
	(dotimes (i 8)
	  (setf (nth i 8octets) 
		(the (unsigned-byte 7)
		     (logand (nth i 8octets) (lognot #x80)))))
	;; unless odd, reverse the bits
	(unless odd
	  (setf 8octets (reverse 8octets))
	  (dotimes (i 8)
	    (setf (nth i 8octets) (reverse-bits (nth i 8octets)))))
	;; xor into the key
	(dotimes (i 8)
	  (setf (aref key i)
		(the (unsigned-byte 7)
		     (logxor (aref key i)
			     (nth i 8octets)))))))
    ;; left shift and add a parity bit
    (dotimes (i 8)
      (let ((octet (aref key i)))
	(let ((parityp (zerop (mod (logcount octet) 2))))
	  (setf (aref key i)
		(the (unsigned-byte 8)
		     (logior (ash octet 1)
			     (if parityp 1 0)))))))
    ;; if the key is weak/semi-weak then xor the last octet with #xf0
    (correct-weak-key key)

    ;; intermediate key
;;    (format t "~X~%" key)
    (let ((enc (encrypt-des-cbc key 
			(make-array (length octets) 
				    :element-type '(unsigned-byte 8)
				    :initial-contents octets)
			:initialization-vector 
			(let ((v (nibbles:make-octet-vector 8)))
			  (dotimes (i 8)
			    (setf (aref v i) (aref key i)))
			  v))))
      (setf key (subseq enc (- (length enc) 8)))
      (fix-parity key)
      (correct-weak-key key)
      key)))
    
(defun des-random-to-key (octets)
  (fix-parity octets)
  (correct-weak-key octets)
  octets)

;; encrpytion requires computing checksums

(defun des-encrypt (msg encrypt-fn cksum-fn &key confounder (cksum-len 16))
  (let ((len (length msg)))
    (let ((buffer (nibbles:make-octet-vector (+ 8 ;; confounder
						cksum-len 
						len
						(if (zerop (mod len 8))
						    0
						    (- 8 (mod len 8)))))))
      ;; set a random confounder
      (setf (nibbles:ub64ref/be buffer 0)
	    (or confounder (random (expt 2 64))))
      ;; copy the msg octets
      (dotimes (i len)
	(setf (aref buffer (+ i 8 cksum-len)) (aref msg i)))
      (let ((cksum (funcall cksum-fn buffer)))
	(dotimes (i cksum-len)
	  (setf (aref buffer (+ i 8)) (aref cksum i))))
      (funcall encrypt-fn buffer))))
    
(defun des-decrypt (data decrypt-fn cksum-fn &key (cksum-len 16))
  (let ((buffer (funcall decrypt-fn data))
	(cksum (nibbles:make-octet-vector cksum-len)))
    (dotimes (i cksum-len)
      (setf (aref cksum i) (aref buffer (+ 8 i))
	    (aref buffer (+ 8 i)) 0))
    (unless (equalp (funcall cksum-fn buffer) cksum)
      (error "checksum's don't match"))
    (subseq buffer (+ 8 cksum-len))))

(defun encrypt-des-cbc-md5 (key msg)
  (des-encrypt msg 
	       (lambda (data)
		 (encrypt-des-cbc key data))
	       (lambda (data)
		 (md5 data))))

(defun decrypt-des-cbc-md5 (key data)
  (des-decrypt data 
	       (lambda (data)
		 (decrypt-des-cbc key data))
	       (lambda (data)
		 (md5 data))))

;;----------------------- ------------------
;; for microsoft we need some extra encyption types -
(defun rc4-string-to-key (password)
  (let ((octets (babel:string-to-octets password 
					:encoding :ucs-2
					:use-bom nil)))
    (md4 octets)))

;; rc4 == ironclad's arcfour 

;; -------------------------

;; we would like a generalized system for defining encryption sytstems
;; you need to be able to register new systems, list the ones defined etc

(defgeneric string-to-key (type password &key))

(defmethod string-to-key ((type (eql :des)) password &key salt)
  (des-string-to-key password (or salt "")))

(defmethod string-to-key ((type (eql :rc4)) password &key)
  (rc4-string-to-key password))

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


