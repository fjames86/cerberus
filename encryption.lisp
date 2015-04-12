

(in-package #:cerberus)

(defun md4 (sequence)
  (ironclad:digest-sequence (ironclad:make-digest :md4) sequence))

(defun md5 (sequence)
  (ironclad:digest-sequence (ironclad:make-digest :md5) sequence))

(defun crc32 (sequence)
  (ironclad:digest-sequence (ironclad:make-digest :crc32) sequence))


;; --------------

;; This is copied/ported from the C codes found here 
;; http://opensource.apple.com/source/Kerberos/Kerberos-62/KerberosFramework/Kerberos5/Sources/lib/crypto/nfold.c
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

(defun reverse-bits (octet)
  (the (unsigned-byte 7)
       (logior (ash (logand octet #x01) 6) 
	       (ash (logand octet #x02) 4) 
	       (ash (logand octet #x04) 2) 
	       (ash (logand octet #x08) 0) 
	       (ash (logand octet #x10) -2)
	       (ash (logand octet #x20) -4)
	       (ash (logand octet #x40) -6))))

(defun make-des-key (password salt)
  (let ((octets (concatenate 'list
			     (babel:string-to-octets password)
			     (babel:string-to-octets salt)))
	(key (nibbles:make-octet-vector 8)))
    ;; pad with zeros so it's a multiple of 8
    (let ((length (mod (length octets) 8)))
      (unless (zerop (mod length 8))
	(setf octets (append octets (make-list (- 8 length) :initial-element 0)))))
    (format t "~X~%" octets)
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
    (format t "~X~%" key)
    ;; left shift and add a parity bit
    (dotimes (i 8)
      (let ((octet (aref key i)))
	(let ((parityp (zerop (mod (logcount octet) 2))))
	  (setf (aref key i)
		(the (unsigned-byte 8)
		     (logior (ash octet 1)
			     (if parityp 1 0)))))))
    ;; FIXME: if the key is "weak" or "semi-weak" then XOR with #xF0.
    ;; the definitions of weak/semi-weak can be found in the DES specification
    (format t "~X~%" key)
    key))
    
;; salt:        "ATHENA.MIT.EDUraeburn"
;;                            415448454e412e4d49542e4544557261656275726e
;; password:    "password"    70617373776f7264
;; fan-fold result:           c01e38688ac86c2e
;; intermediate key:          c11f38688ac86d2f
;; DES key:                   cbc22fae235298e3
    

