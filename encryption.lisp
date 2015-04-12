

(in-package #:cerberus)

(defun md4 (sequence)
  (ironclad:digest-sequence (ironclad:make-digest :md4) sequence))

(defun md5 (sequence)
  (ironclad:digest-sequence (ironclad:make-digest :md5) sequence))

(defun crc32 (sequence)
  (ironclad:digest-sequence (ironclad:make-digest :crc32) sequence))


;; --------------

;; need n-fold function
(defun make-bit-vector (n)
  (make-array n :element-type 'bit))

(defun bv-int (bit-vector)
  "Create a positive integer from a bit-vector."
  (reduce #'(lambda (first-bit second-bit)
              (+ (* first-bit 2) second-bit))
          bit-vector))

(defun int-bv (integer)
  "Create a bit-vector from a positive integer."
  (labels ((integer->bit-list (int &optional accum)
             (cond ((> int 0)
                    (multiple-value-bind (i r) (truncate int 2)
                      (integer->bit-list i (push r accum))))
                   ((null accum) (push 0 accum))
		   (t accum))))
    (coerce (integer->bit-list integer) 'bit-vector)))

(defun rotate-bit-vector (bv n)
  (let ((length (length bv)))
    (let ((v (make-bit-vector length)))
      (dotimes (i length)
	(setf (bit v i)
	      (bit bv (mod (+ length i (- n)) length))))
      v)))
(defun add-bit-vector (bv1 bv2)
  "1's complement addition of bit vector"
  (let* ((len1 (length bv1))
	 (len2 (length bv2))
	 (length (max len1 len2)))
    (do ((carry 0)
	 (i 0 (1+ i))
	 (result (make-bit-vector length)))
	((= i length)
	 (if (= carry 1)
	     (add-bit-vector result #*1)
	     result))
      (let ((sum (+ (if (< i len1)
			(bit bv1 i)
			0)
		    (if (< i len2)
			(bit bv2 i)
			0)
		    carry)))
	(ecase sum
	  ((0 1) 
	   (setf (bit result i) sum
		 carry 0))
	  (2
	   (setf carry 1))
	  (3 
	   (setf (bit result i) 1
		 carry 1)))))))
(defun n-fold (bv n)
  (let ((lcm (lcm (length bv) n))
	(len (length bv)))
    (let ((result (make-bit-vector n))
	  (temp-sum (make-bit-vector lcm)))
      (do ((i 0 (1+ i)))
	  ((= i (truncate lcm len)) result)
	(let ((temp (rotate-bit-vector bv (* 13 i))))
	  (dotimes (j (length temp))
	    (setf (bit temp-sum (+ j (* i (length temp))))
		  (bit temp j)))))
      (let ((sum (make-bit-vector n))
	    (nfold (make-bit-vector n)))
	(dotimes (m (truncate lcm n))
	  (dotimes (o n)
	    (setf (bit sum o) (bit temp-sum (+ o (* m n)))))
	  (setf nfold (add-bit-vector nfold sum)))
	nfold))))

;; http://grepcode.com/file/repository.springsource.com/org.apache.directory/com.springsource.org.apache.directory.server.kerberos.shared/1.5.5/org/apache/directory/server/kerberos/shared/crypto/encryption/NFold.java#NFold.rotateRight%28byte%5B%5D%2Cint%2Cint%29

;; need to be able to do this	  
;; 64-fold(303132333435) = be072631276b1955
;; (format nil "~X" (bv-int (n-fold (int-bv #x303132333435) 64)))

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
    ;; remove most significant bit and reverse the bits
    (do ((%octets octets (nthcdr 8 %octets))
	 (odd t (not odd)))
	((null %octets))
      (let ((8octets (subseq %octets 0 8)))
	(dotimes (i 8)
	  (setf (aref key i)
		(the (unsigned-byte 7)
		     (logxor (aref key i)
			     (let ((7bit (logand (nth (- 7 i) 8octets) 
						 (lognot #x80))))
			       (if odd 
				   (reverse-bits 7bit)
				   7bit))))))))
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
    key))
    
    

