;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:cerberus)

;; --------------------------------------
;; The serialization codes here are copied verbatim from the XDR serializer 
;; used in FRPC. We're not doing XDR (mores the pity), but the technology is the same
;;

(defvar *xtypes* (make-hash-table))

(defun %defxtype (name reader writer)
  (setf (gethash name *xtypes*)
	(list reader writer)))

(defun xtype-reader (name) 
  (declare (type symbol name))
  (let ((fn (first (gethash name *xtypes*))))
    (if fn
	fn
	(error "No type ~S" name))))

(defun xtype-writer (name) 
  (declare (type symbol name))
  (let ((fn (second (gethash name *xtypes*))))
    (if fn
	fn
	(error "No type ~S" name))))

(defmacro defxtype (name (&rest options) ((reader-stream) &body reader-body) ((writer-stream obj) &body writer-body))
  (let ((reader (let ((n (cadr (assoc :reader options))))
		  (if n 
		      n
		      (alexandria:symbolicate 'decode- name))))
	(writer (let ((n (cadr (assoc :writer options))))
		  (if n
		      n 
		      (alexandria:symbolicate 'encode- name)))))
    `(progn
       (defun ,reader (,reader-stream)
	 ,@reader-body)
       (defun ,writer (,writer-stream ,obj)
	 ,@writer-body)
       (%defxtype ',name (function ,reader) (function ,writer)))))

(defmacro defxtype* (name (&rest options) type-name)
  (declare (ignore options))
  `(%defxtype ',name (xtype-reader ',type-name) (xtype-writer ',type-name)))

(defun read-xtype (type stream)
  (cond
    ((functionp type)
     (funcall type stream))
    (t 
     (funcall (xtype-reader type) stream))))

(defun write-xtype (type stream obj)
  (cond
    ((functionp type)
     (funcall type stream obj))
    (t 
     (funcall (xtype-writer type) stream obj))))

(defun pad-index (index)
  (let ((m (mod index 4)))
    (if (zerop m)
	index
	(+ index (- 4 m)))))

(defun pack (writer obj)
  "Write the object into an octet-buffer."
  (flexi-streams:with-output-to-sequence (v :element-type 'nibbles:octet)
    (funcall writer v obj)))

(defun unpack (reader buffer)
  "Read the object from an octet-buffer."
  (flexi-streams:with-input-from-sequence (v buffer)
    (funcall reader v)))

;; define an enum
(defmacro defxenum (name options &rest slots)
  (declare (ignore options))
  `(progn
     (defun ,(alexandria:symbolicate 'encode- name) (stream value)
       (encode-asn1-int32 stream
			  (case value
			    ,@(mapcar (lambda (slot)
					(destructuring-bind (slot-name slot-value) slot
					  `(,slot-name ,slot-value)))
				      slots)
			    (otherwise (if (integerp value)
					   value
					   (error "Unknown ~A type ~S" ',name value))))))
     (defun ,(alexandria:symbolicate 'decode- name) (stream)
       (let ((val (decode-asn1-int32 stream)))
	 (case val
	   ,@(mapcar (lambda (slot)
		       (destructuring-bind (slot-name slot-value) slot
			 `(,slot-value ,(if (listp slot-name)
					    (first slot-name)
					    slot-name))))
		     slots)
	   (otherwise val))))
     (%defxtype ',name #',(alexandria:symbolicate 'decode- name) #',(alexandria:symbolicate 'encode- name))))

;; ------------------------------------------------------

(defun encode-identifier (stream tag &key (class :universal) (primitive t))
  (declare (type (integer 0 30) tag))
  (write-byte (logior tag
		      (ash (ecase class
			     (:universal 0)
			     (:application 1)
			     (:context 2)
			     (:private 3))
			   6)
		      (if primitive 0 32))
	      stream))

(defun decode-identifier (stream)
  "Returns (values tag class primitive-p)."
  (let ((octet (read-byte stream)))
    (values (logand octet 31)
	    (ecase (ash octet -6)
	      (0 :universal)
	      (1 :application)
	      (2 :context)
	      (3 :private))
	    (if (zerop (logand octet 32))
		t
		nil))))

(defun encode-length (stream length)
  "Returns the number of bytes written."
  (cond
    ((<= length 127)
     (write-byte length stream)
     1)
    (t
     ;; if the length is >127, then we split
     ;; the length into the smallest number of octets, big-endian.
     ;; we write the number of octets|#80 then the octets
     (let (octets)
       ;; split into big-endian octets
       (do ((len length))
           ((zerop len))
         (push (the (unsigned-byte 8)
                 (logand len #xff))
               octets)
         (setf len (ash len -8)))
       (write-byte (logior (length octets) #x80) stream)
       (write-sequence octets stream)))))

(defun decode-length (stream)
  (let ((first (read-byte stream)))
    (cond
      ((zerop (logand first 128))
       first)
      (t 
       ;; the first octet is the number of octets|#x80
       (do ((n (logand first (lognot #x80)) (1- n))
            (len 0))
           ((zerop n) len)
         (let ((byte (read-byte stream)))
           (setf len (logior (ash len 8) byte))))))))

;; -------------- booleans ---------------

(defun encode-boolean (stream value)
  (encode-identifier stream 0)
  (encode-length stream 4)
  (write-byte (if value #xff 0) stream))

;; FIXME: validate the identifier and length values
(defun decode-boolean (stream)
  (decode-identifier stream)
  (decode-length stream)
  (let ((byte (read-byte stream)))
    (if (zerop byte)
	nil
	t)))

(defxtype asn1-boolean ()
  ((stream) (decode-boolean stream))
  ((stream value) (encode-boolean stream value)))

;; ---------------------------------------

(defxtype asn1-int32 ()
  ((stream)
   (decode-identifier stream)
   (let ((n (decode-length stream))
	 (v (nibbles:make-octet-vector 4)))
     (dotimes (i n)
       (setf (aref v (+ (- 4 n) i)) (read-byte stream)))
     ;; check the sign bit, if it's set then this is a -ve number
     ;; and we need to fill out the rest with #xff 
     (when (logtest (aref v (- 4 n)) #x80)
       ;; -ve number
       (dotimes (i (- 4 n))
	 (setf (aref v i) #xff)))
     (nibbles:sb32ref/be v 0)))
  ((stream int)
   (encode-identifier stream 2)
   (let ((v (nibbles:make-octet-vector 4)))
     (setf (nibbles:sb32ref/be v 0) int)
     ;; we need to use the minimal number of octets
     (let ((len
	    (cond
	      ((and (>= int (- (expt 2 7))) (< int (expt 2 7)))
	       1)
	      ((and (>= int (- (expt 2 15))) (< int (expt 2 15)))
	       2)
	      ((and (>= int (- (expt 2 23))) (< int (expt 2 23)))
	       3)
	      (t 4))))
       (encode-length stream len)
       (write-sequence v stream :start (- 4 len))))))

;; for backwards compatibility 
(defxtype* asn1-integer () asn1-int32)

(defxtype asn1-uint32 ()
  ((stream)
   (decode-identifier stream)
   (let ((n (decode-length stream))
	 (v (nibbles:make-octet-vector 4)))
     (dotimes (i n)
       (setf (aref v (+ (- 4 n) i)) (read-byte stream)))
     (nibbles:ub32ref/be v 0)))
  ((stream int)
   (encode-identifier stream 2)
   (let ((v (nibbles:make-octet-vector 4)))
     (setf (nibbles:ub32ref/be v 0) int)
     ;; we need to use the minimal number of octets
     (let ((len
	    (cond
	      ((< int (expt 2 8))
	       1)
	      ((< int (expt 2 16))
	       2)
	      ((< int (expt 2 24))
	       3)
	      (t 4))))
       (encode-length stream len)
       (write-sequence v stream :start (- 4 len))))))




;; ----------------------------------

(defun reverse-octet (octet)
  (let ((i 0))
    (dotimes (j 8)
      (setf i (logior (ash i 1) (mod octet 2))
	    octet (ash octet -1)))
    i))

;; bitstrings are in reversed ordering
;; so bit 7 of octet 0 is bit 0,
;; bit 0 of octet 0 is bit 7,
;; bit 0 of octet 1 is bit 8,
;; bit 7 of octet 1 is bit 15 
;; etc 
;; we need to conver the integer to little-endian order, 
;; then reverse the bits of each octet
(defun encode-bit-string (stream integer)
  (let ((octets (mapcar #'reverse-octet
                        (let ((octets (nibbles:make-octet-vector 4)))
                          (setf (nibbles:ub32ref/le octets 0) integer)
                          (coerce octets 'list)))))
    (encode-identifier stream 3)
    (encode-length stream (1+ (length octets)))
    (write-byte 0 stream) ;; the number of unused bits -- always zero for us since we write octets
    (dolist (octet octets)
      (write-byte octet stream))))

(defun decode-bit-string (stream)
  (decode-identifier stream)
  (let ((n (1- (decode-length stream))))
    (read-byte stream)
    (let ((octets (loop :for i :below n 
                     :collect (read-byte stream))))
      (nibbles:ub32ref/le (let ((v (nibbles:make-octet-vector 4)))
                            (dotimes (i n)
			      (setf (aref v i) (reverse-octet (nth i octets))))
                            v)
                          0))))
    
(defxtype asn1-bit-string ()
  ((stream) (decode-bit-string stream))
  ((stream value) (encode-bit-string stream value)))

;; ------------------------

(defun encode-octet-string (stream octets)
  (encode-identifier stream 4)
  (encode-length stream (length octets))
  (etypecase octets
    (vector 
     (dotimes (i (length octets))
       (write-byte (aref octets i) stream)))
    (list 
     (dolist (octet octets)
       (write-byte octet stream)))))

(defun decode-octet-string (stream)
  (decode-identifier stream)
  (let* ((n (decode-length stream))
	 (octets (nibbles:make-octet-vector n)))
    (dotimes (i n)
      (setf (aref octets i) (read-byte stream)))
    octets))

(defxtype asn1-octet-string ()
  ((stream) (decode-octet-string stream))
  ((stream value) (encode-octet-string stream value)))

;; --------------------------

(defun encode-null (stream)
  (encode-identifier stream 5)
  (encode-length stream 0))

(defun decode-null (stream)
  (decode-identifier stream)
  (decode-length stream))

(defxtype asn1-null ()
  ((stream) (decode-null stream))
  ((stream value) 
     (declare (ignore value))
     (encode-null stream)))

;; ------------------------

(defun encode-generalized-string (stream string)
  (encode-identifier stream 27)
  (let ((octets (babel:string-to-octets string)))
    (encode-length stream (length octets))
    (write-sequence octets stream)))

(defun decode-generalized-string (stream)
  (decode-identifier stream)
  (let ((length (decode-length stream)))
    (let ((octets (nibbles:make-octet-vector length)))
      (read-sequence octets stream)
      (babel:octets-to-string octets))))

(defxtype asn1-generalized-string ()
  ((stream) (decode-generalized-string stream))
  ((stream value) (encode-generalized-string stream value)))


;; -------------------------

(defun time-string (time)
  (multiple-value-bind (sec min hour day month year) (decode-universal-time time 0)
    (format nil "~4,'0D~2,'0D~2,'0D~2,'0D~2,'0D~2,'0D"
	    year month day hour min sec)))

;; FIXME: the string we are given may have a Z<timezone-offset> appended. 
;; if it does we should pass that to the encode-universal-time function.
(defun string-time (string)
  (let ((year (subseq string 0 4))
	(month (subseq string 4 6))
	(day (subseq string 6 8))
	(hour (subseq string 8 10))
	(min (subseq string 10 12))
	(sec (subseq string 12 14)))
    (encode-universal-time (parse-integer sec)
			   (parse-integer min)
			   (parse-integer hour)
			   (parse-integer day)
			   (parse-integer month)
			   (parse-integer year)
			   0)))

(defxtype generalized-time ()
  ((stream) 
   (decode-identifier stream)
   (let ((length (decode-length stream)))
     (let ((octets (nibbles:make-octet-vector length)))
       (read-sequence octets stream)
       (string-time (babel:octets-to-string octets)))))
  ((stream time)
   (encode-identifier stream 24)
   (let ((octets (babel:string-to-octets (time-string time))))
     (encode-length stream (length octets))
     (write-sequence octets stream))))

;; ---------------------------

;; object identifiers, these are sometimes needed as headers for other messages
;; when encapsulated in other protocols (e.g. gss???)


(defparameter *ms-kerberos-oid* #(1 2 840 48018 1 2 2))
(defparameter *kerberos-oid* #(1 2 840 113554 1 2 2))

;; https://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
(defun encode-oid (stream octets)
  (encode-identifier stream 6)
  (let ((bytes 
	 (flexi-streams:with-output-to-sequence (s)
	   (let ((b1 (aref octets 0))
		 (b2 (aref octets 1)))
	     (write-byte (logior (* b1 40) b2) s)
	     (dotimes (i (- (length octets) 2))
	       (let ((b (aref octets (+ i 2))))
		 (cond
		   ((<= b 127)
		    (write-byte b s))
		   (t 
		    ;; if > 127, then we write multiple 7-bit bytes, 1st byte or'd with #x80
		    (do ((bytes nil)
			 (i b (ash i -7)))
			((zerop i)
			 (write-byte (logior (car bytes) #x80) s)
			 (dolist (b (cdr bytes))
			   (write-byte b s)))
		      (push (logand i #x7f) bytes))))))))))
    (encode-length stream (length bytes))
    (write-sequence bytes stream)))

;; how to decode multiple bytes????
;; (defun decode-oid (stream)
;;   (decode-identifier stream)
;;   (let ((length (decode-length stream)))
;;     (let ((bytes (nibbles:make-octet-vector length)))
;;       (read-sequence bytes stream)
;;       (do ((oid (list (truncate (aref bytes 0) 40) (mod (aref bytes 1) 40)))
;; 	   (i 2 (1+ i)))
;; 	  ((= i length) oid)
;; 	(let ((b (aref bytes i)))
;; 	  (cond
;; 	    ((<= b 127)
;; 	     (setf oid (append oid (list b))))
;; 	    (t 
;; 	     ;; if > 127 then multiple 7-bit bytes, 1st byte or'd with #x80
;; 	     (
	
;; ----------------------------

(defun encode-sequence-of (stream type values &key (tag 16) (class :universal) (primitive nil))
  (let ((bytes (flexi-streams:with-output-to-sequence (s)
		 (dolist (value values)
		   (write-xtype type s value)))))
    (encode-identifier stream tag :class class :primitive primitive)
    (encode-length stream (length bytes))
    (write-sequence bytes stream)))

(defun decode-sequence-of (stream type)
  (decode-identifier stream)
  (let ((length (decode-length stream)))
    (let ((bytes (nibbles:make-octet-vector length)))
      (read-sequence bytes stream)
      (flexi-streams:with-input-from-sequence (s bytes)
	(do ((values nil))
	    ((not (listen s))
	     (nreverse values))
	  (push (read-xtype type s) values))))))


;; -------------------------

;; http://luca.ntop.org/Teaching/Appunti/asn1.html
;; https://msdn.microsoft.com/en-us/library/windows/desktop/bb648645(v=vs.85).aspx
(defmacro defsequence (name options &rest slots)
  (let ((struct-name (or (cadr (assoc :name options)) name)))
    `(progn
       ;; the structure 
       (defstruct ,struct-name
       ,@(mapcar (lambda (slot)
		   (destructuring-bind (slot-name slot-type &key initial-value &allow-other-keys) slot
		     (declare (ignore slot-type))
		     `(,slot-name ,initial-value)))
		 slots))
       ;; the encoder 
       (defun ,(alexandria:symbolicate 'encode- name) (stream value)
	 (let ((bytes (flexi-streams:with-output-to-sequence (s)
			,@(mapcar (lambda (slot)
				    (destructuring-bind (slot-name slot-type &key tag optional &allow-other-keys) slot 
				      `(let ((the-value (,(alexandria:symbolicate struct-name '- slot-name) value)))
					 (when ,(if optional 'the-value 't)
					   (let ((contents (flexi-streams:with-output-to-sequence (cs)
							     (write-xtype ',slot-type cs the-value))))
					     ;; write the tag, if any 
					     ,@(when tag
						     `((encode-identifier s ,tag :class :context :primitive nil)
						       (encode-length s (length contents))))
					     ;; write the contents
					     (write-sequence contents s))))))
				  slots))))
	   (let ((length-bytes (flexi-streams:with-output-to-sequence (s)
				 (encode-length s (length bytes)))))
	     ,@(when (assoc :tag options)
		     `((encode-identifier stream ,(cadr (assoc :tag options)) 
					  :class ,(or (cadr (assoc :class options)) :context)
					  :primitive nil)
		       (encode-length stream (+ 1 (length bytes) (length length-bytes)))))
	     (encode-identifier stream 16 :primitive nil)
	     (write-sequence length-bytes stream)
	     (write-sequence bytes stream))))
       ;; decoder
       (defun ,(alexandria:symbolicate 'decode- name) (stream)
	 ,@(when (assoc :tag options)
             `((decode-identifier stream)
	       (decode-length stream)))
	 (decode-identifier stream)
	 (let ((length (decode-length stream))
	       (value (,(alexandria:symbolicate 'make- struct-name))))
	   ,@(unless (some (lambda (slot) (member :tag slot)) slots)
	       `((declare (ignore length))))
	 ,(if (some (lambda (slot) (member :tag slot)) slots)
	      `(let ((contents (nibbles:make-octet-vector length)))
		 (read-sequence contents stream)
		 (flexi-streams:with-input-from-sequence (s contents)
		   (do ()
		       ((not (listen s)))
		     (let ((the-tag (decode-identifier s)))
		       (decode-length s)
		       (ecase the-tag 
			 ,@(mapcar (lambda (slot)
				     (destructuring-bind (slot-name slot-type &key tag &allow-other-keys) slot 
				       `(,tag (setf (,(alexandria:symbolicate struct-name '- slot-name) value)
						    (read-xtype ',slot-type s)))))
				   slots))))))
	      `(progn
		 ,@(mapcar (lambda (slot)
			     (destructuring-bind (slot-name slot-type &key &allow-other-keys) slot
			       `(setf (,(alexandria:symbolicate struct-name '- slot-name) value)
				      (read-xtype ',slot-type stream))))
			   slots)))
	 value))
     ;; define the type
     (%defxtype ',name
		#',(alexandria:symbolicate 'decode- name)
		#',(alexandria:symbolicate 'encode- name))

     ',name)))

(defxtype* realm () asn1-generalized-string)
(defxtype* kerberos-time () generalized-time)
(defxtype* microseconds () asn1-integer)

(defxtype* kerberos-string () asn1-generalized-string)

(defxtype kerberos-strings ()
  ((stream) (decode-sequence-of stream 'kerberos-string))
  ((stream values) (encode-sequence-of stream 'kerberos-string values)))

(defxtype asn1-integer-list ()
  ((stream) (decode-sequence-of stream 'asn1-integer))
  ((stream values) (encode-sequence-of stream 'asn1-integer values)))

(defxenum principal-name-type ()
  (:unknown 0)
  (:principal 1)
  (:srv-inst 2)
  (:srv-host 3)
  (:srv-xhost 4)
  (:uid 5)
  (:x500 6)
  (:smtp 7)
  (:enterprise 10))

(defsequence principal-name ()
  (type principal-name-type :tag 0)
  (name kerberos-strings :tag 1))

;; ----------------------------------------
;; host addresses 

(defxenum host-address-type ()
  (:ipv4 2)
  (:ipv6 24)
  (:decnet-phase-4 12)
  (:netbios 20)
  (:directional 3))

(defgeneric encode-host-address-name (type value))
(defgeneric decode-host-address-name (type buffer))
(defmethod encode-host-address-name (type value) value)
(defmethod decode-host-address-name (type buffer) buffer)

;; ipv4 -- host octets in big-endian order. should we convert to dotted-quad?
(defmethod encode-host-address-name ((type (eql :ipv4)) value)
  ;; if dotted quad then convert to vector
  (etypecase value
    (string (usocket:dotted-quad-to-vector-quad value))
    (vector value)))
(defmethod decode-host-address-name ((type (eql :ipv4)) buffer)
  buffer)

;; netbios -- a string of the name (with space character padding to 16 octets)
(defmethod encode-host-address-name ((type (eql :netbios)) value)
  (let ((octets (babel:string-to-octets value)))
    (usb8 octets (loop :for i :below (- 16 (length octets)) :collect (char-code #\space)))))
(defmethod decode-host-address-name ((type (eql :netbios)) buffer)
  (let ((str (babel:octets-to-string buffer)))
    (let ((p (position #\space str)))
      (if p
	  (subseq str 0 p)
	  str))))
    

(defsequence %host-address ((:name host-address))
  (type host-address-type :tag 0)
  (name asn1-octet-string :tag 1))

(defxtype host-address ()
  ((stream)
   ;; modfiy the name 
   (let ((ha (read-xtype '%host-address stream)))
     (setf (host-address-name ha) (decode-host-address-name (host-address-type ha)
							    (host-address-name ha)))
     ha))
  ((stream ha)
   ;; write a copy so we don't destructively modify the original host adress
   (write-xtype '%host-address 
		stream
		(make-host-address :type (host-address-type ha)
				   :name (encode-host-address-name (host-address-type ha)
								   (host-address-name ha))))))

(defxtype host-addresses ()
  ((stream) (decode-sequence-of stream 'host-address))
  ((stream values) (encode-sequence-of stream 'host-address values)))

;; -------------------------------------------
;; authorization data

(defxenum authorization-data-type ()
  (:ad-if-relevant 1)
  (:ad-intended-for-server 2)
  (:ad-inteded-for-application-class 3)
  (:ad-kdc-issued 4)
  (:ad-and-or 5)
  (:ad-mandatory-ticket-extensions 6)
  (:ad-in-ticket-extensions 7)
  (:ad-mandatory-for-kdc 8)
  (:osf-dce 64)
  (:sesame 65)
  (:ad-osf-dce-pki-certid 66)
  (:ad-win2k-pac 128)
  (:ad-etype-negotiation 129)
  (:kerb-local 142))

;; the real sequence
(defsequence %auth-data ((:name auth-data))
  (type authorization-data-type :tag 0)
  (data asn1-octet-string :tag 1))

(defgeneric encode-auth-data-data (type value))
(defgeneric decode-auth-data-data (type buffer))
(defmethod encode-auth-data-data (type value) value)
(defmethod decode-auth-data-data (type buffer) buffer)

(defmethod encode-auth-data-data ((type (eql :ad-kdc-issued)) value)
  (pack #'encode-ad-kdc-issued value))
(defmethod decode-auth-data-data ((type (eql :ad-kdc-issued)) buffer)
  (unpack #'decode-ad-kdc-issued buffer))

(defmethod encode-auth-data-data ((type (eql :ad-and-or)) value)
  (pack #'encode-ad-and-or value))
(defmethod decode-auth-data-data ((type (eql :ad-and-or)) buffer)
  (unpack #'decode-ad-and-or buffer))

(defmethod encode-auth-data-data ((type (eql :ad-mandatory-for-kdc)) value)
  (pack #'encode-authorization-data value))
(defmethod decode-auth-data-data ((type (eql :ad-mandatory-for-kdc)) buffer)
  (unpack #'decode-authorization-data buffer))

;; wrapper to dispatch on the type
(defxtype auth-data ()
  ((stream)
   ;; modify the data depending on the type
   (let ((ad (read-xtype '%auth-data stream)))
     (setf (auth-data-data ad) (decode-auth-data-data (auth-data-type ad)
						      (auth-data-data ad)))
     ad))
  ((stream ad)
   ;; write a copy to avoid destructively modifying the original
   (write-xtype '%auth-data
		stream
		(make-auth-data :type (auth-data-type ad)
				:data (encode-auth-data-data (auth-data-type ad)
							     (auth-data-data ad))))))

;; sequnce of auth-data structures
(defxtype authorization-data ()
  ((stream) (decode-sequence-of stream 'auth-data))
  ((stream values) (encode-sequence-of stream 'auth-data values)))

;; --------------------------------------------------
;; pre-authentication data requires us to dispatch on a decoder 
;; depending on the value of a type enum

;; pre-authentication types
(defxenum pa-data-types ()
  (:TGS-REQ                 1)
  (:ENC-TIMESTAMP           2)
  (:PW-SALT                 3)
  (:ENC-UNIX-TIME           5)
  (:SANDIA-SECUREID         6)
  (:SESAME                  7) 
  (:OSF-DCE                 8)   
  (:CYBERSAFE-SECUREID      9)   
  (:AFS3-SALT               10)   
  (:ETYPE-INFO              11)  
  (:SAM-CHALLENGE           12) 
  (:SAM-RESPONSE            13)
  (:PK-AS-REQ-OLD           14)
  (:PK-AS-REP-OLD           15)
  (:PK-AS-REQ               16)
  (:PK-AS-REP               17)
  (:PK-OCSP-RESPONSE        18)
  (:ETYPE-INFO2             19)
  ((:USE-SPECIFIED-KVNO :SVR-REFERRAL-INFO)     20) ;; duplicate???
  (:SAM-REDIRECT            21)
  ((:GET-FROM-TYPED-DATA :PADATA)    22) ;; duplicate???
  (:SAM-ETYPE-INFO          23)   
  (:ALT-PRINC               24)   
  (:SERVER-REFERRAL         25)   
  (:SAM-CHALLENGE2          30)   
  (:SAM-RESPONSE2           31)   
  (:EXTRA-TGT               41)   
  (:PKINIT-CMS-CERTIFICATES 101)  
  (:KRB-PRINCIPAL           102)  
  (:KRB-REALM               103)  
  (:TRUSTED-CERTIFIERS      104)  
  (:CERTIFICATE-INDEX       105)  
  (:APP-DEFINED-ERROR       106)  
  (:REQ-NONCE               107)  
  (:REQ-SEQ                 108)  
  (:DH-PARAMETERS           109)  
  (:CMS-DIGEST-ALGORITHMS   111)  
  (:CERT-DIGEST-ALGORITHMS  112)  
  (:PAC-REQUEST             128)  
  (:FOR-USER                129)  
  (:FOR-X509-USER           130)  
  (:FOR-CHECK-DUPS          131)  
  (:AS-CHECKSUM             132)  
  (:FX-COOKIE               133)  
  (:AUTHENTICATION-SET      134)  
  (:AUTH-SET-SELECTED       135)  
  (:FX-FAST                 136)  
  (:FX-ERROR                137)  
  (:ENCRYPTED-CHALLENGE     138)  
  (:OTP-CHALLENGE           141)  
  (:OTP-REQUEST             142)  
  (:OTP-CONFIRM             143)  
  (:OTP-PIN-CHANGE          144)  
  (:EPAK-AS-REQ             145)  
  (:EPAK-AS-REP             146)  
  (:PKINIT-KX               147)  
  (:PKU2U-NAME              148)  
  (:SUPPORTED-ETYPES        165)  
  (:EXTENDED-ERROR          166))
  
;; NOTE: no tag 0 present 
(defsequence %pa-data ((:name pa-data))
  (type pa-data-types :tag 1)
  (value asn1-octet-string :tag 2))

;; use eql-specialized generics to dispatch 
(defgeneric encode-pa-data-value (type buffer))
(defgeneric decode-pa-data-value (type buffer))

;; default methods leaves buffer untouched
(defmethod encode-pa-data-value (type value) value)
(defmethod decode-pa-data-value (type buffer) buffer)

;; etype-info2
(defmethod encode-pa-data-value ((type (eql :etype-info)) value)
  (pack #'encode-etype-info value))
(defmethod decode-pa-data-value ((type (eql :etype-info)) buffer)
  (unpack #'decode-etype-info buffer))

;; etype-info2
(defmethod encode-pa-data-value ((type (eql :etype-info2)) value)
  (pack #'encode-etype-info2 value))
(defmethod decode-pa-data-value ((type (eql :etype-info2)) buffer)
  (unpack #'decode-etype-info2 buffer))

;; enc-timestamp
(defmethod encode-pa-data-value ((type (eql :enc-timestamp)) value)
  ;; value MUST be an encrypted-data structure
  (pack #'encode-encrypted-data value))
(defmethod decode-pa-data-value ((type (eql :enc-timestamp)) buffer)
  (unpack #'decode-encrypted-data buffer))

;; pw-salt: the password salt value
(defmethod encode-pa-data-value ((type (eql :pw-salt)) value)
  (babel:string-to-octets value))
(defmethod decode-pa-data-value ((type (eql :pw-salt)) buffer)
  (babel:octets-to-string (usb8 buffer)))

;; tgs-req: an ap-req structure
(defmethod encode-pa-data-value ((type (eql :tgs-req)) value)
  (pack #'encode-ap-req value))
(defmethod decode-pa-data-value ((type (eql :tgs-req)) buffer)
  (unpack #'decode-ap-req buffer))

(defxtype pa-data ()
  ((stream)
   (let ((pa (read-xtype '%pa-data stream)))
     ;; modify the value if we know the type
     (setf (pa-data-value pa) (decode-pa-data-value (pa-data-type pa)
						    (pa-data-value pa)))
     pa))
  ((stream pa)
   ;; modify the value if we know the type, should use a copy since we don't 
   ;; want to destructively modify the value passed in
   (write-xtype '%pa-data 
		stream
		(make-pa-data :type (pa-data-type pa)
			      :value (encode-pa-data-value (pa-data-type pa)
							   (pa-data-value pa))))))

(defxtype pa-data-list ()
  ((stream) (decode-sequence-of stream 'pa-data))
  ((stream values) (encode-sequence-of stream 'pa-data values)))

;; -------------------------------------------------------

;; length is always at least 32 bits, i.e. 4 bytes. this is handled by the bit string encoder
(defxtype kerberos-flags ()
  ((stream) (read-xtype 'asn1-bit-string stream))
  ((stream value) (write-xtype 'asn1-bit-string stream value)))

(defsequence encrypted-data ()
  (type etype-enum :tag 0)
  (kvno asn1-uint32 :tag 1 :optional t)
  (cipher asn1-octet-string :tag 2))

(defsequence encryption-key ()
  (type etype-enum :tag 0)
  (value asn1-octet-string :tag 1))

(defsequence check-sum ()
  (type asn1-integer :tag 0)
  (sum asn1-octet-string :tag 1))

(defsequence ticket ((:tag 1) (:class :application))
  (vno asn1-integer :tag 0 :initial-value 5)
  (realm realm :tag 1)
  (sname principal-name :tag 2)
  (enc-part encrypted-data :tag 3)) ;; enc-ticket-part 

(defparameter *ticket-flags*
  '((:reserved #x1)
    (:forwardable #x2)
    (:forwarded #x4)
    (:proxiable #x8)
    (:proxy #x10)
    (:may-postdate #x20)
    (:postdated #x40)
    (:invalid #x80)
    (:renewable #x100)
    (:initial #x200)
    (:pre-authent #x400)
    (:hw-authent #x800)
    (:transited #x1000)
    (:ok-as-delegate #x2000)))

(defxtype ticket-flags ()
  ((stream) (unpack-flags (decode-bit-string stream) *ticket-flags*))
  ((stream flags) (encode-bit-string stream (pack-flags flags *ticket-flags*))))

(defsequence enc-ticket-part ((:tag 3) (:class :application))
  (flags ticket-flags :tag 0)
  (key encryption-key :tag 1)
  (crealm realm :tag 2)
  (cname principal-name :tag 3)
  (transited transited-encoding :tag 4)
  (authtime kerberos-time :tag 5)
  (starttime kerberos-time :tag 6 :optional t) ;; op
  (endtime kerberos-time :tag 7)
  (renew-till kerberos-time :tag 8 :optional t) ;; op
  (caddr host-addresses :tag 9 :optional t) ;; op
  (authorization-data authorization-data :tag 10 :optional t)) ;; op
  
(defsequence transited-encoding ()
  (type asn1-integer :tag 0)
  (contents asn1-octet-string :tag 1))

(defun pack-flags (flags flag-list)
  (let ((i 0))
    (dolist (flag flags)
      (setf i (logior i (cadr (assoc flag flag-list)))))
    i))
(defun unpack-flags (i flag-list)
  (let ((flags nil))
    (dolist (flag flag-list)
      (unless (zerop (logand i (cadr flag)))
	(push (car flag) flags)
	(setf i (logand i (lognot (cadr flag))))))
    flags))
    
(defxtype as-req ()
  ((stream)
   (decode-identifier stream)
   (let ((len (decode-length stream)))
     (let ((contents (nibbles:make-octet-vector len)))
       (read-sequence contents stream)
       (unpack (xtype-reader 'kdc-req) contents))))
  ((stream value)
   (encode-identifier stream 10 :class :application :primitive nil)
   (let ((contents (pack (xtype-writer 'kdc-req) value)))
     (encode-length stream (length contents))
     (write-sequence contents stream))))

(defxtype tgs-req ()
  ((stream)
   (decode-identifier stream)
   (let ((len (decode-length stream)))
     (let ((contents (nibbles:make-octet-vector len)))
       (read-sequence contents stream)
       (unpack (xtype-reader 'kdc-req) contents))))
  ((stream value)
   (encode-identifier stream 12 :class :application :primitive nil)
   (let ((contents (pack (xtype-writer 'kdc-req) value)))
     (encode-length stream (length contents))
     (write-sequence contents stream))))

(defxenum kdc-req-type ()
  (:as 10)
  (:tgs 12))

;; note: no tag 0
(defsequence kdc-req ()
  (pvno asn1-integer :tag 1 :initial-value 5)
  (type kdc-req-type :tag 2 :initial-value 10) ;; 10 == AS, 12 == TGS
  (data pa-data-list :tag 3 :optional t) ;; sequence-of 
  (req-body kdc-req-body :tag 4))

(defxtype ticket-list ()
  ((stream) (decode-sequence-of stream 'ticket))
  ((stream values) (encode-sequence-of stream 'ticket values)))

(defxenum etype-enum ()
  (:des-cbc-crc 1)
  (:des-cbc-md4 2)
  (:des-cbc-md5 3)
  (:des3-cbc-md5 5)
  (:des3-cbc-sha1 7) ;; deprecated, should use the -kd version instead
  (:des3-cbc-sha1-kd 16)
  (:aes128-cts-hmac-sha1-96 17)
  (:aes256-cts-hmac-sha1-96 18)
  (:rc4-hmac 23)
  (:rc4-hmac-exp 24)
  (:rc4-hmac-old-exp -135))

(defxtype etype-list ()
  ((stream) (decode-sequence-of stream 'etype-enum))
  ((stream values) (encode-sequence-of stream 'etype-enum values)))

(defsequence kdc-req-body ()
  (options kdc-options :tag 0)
  (cname principal-name :tag 1)
  (realm realm :tag 2)
  (sname principal-name :tag 3 :optional t)
  (from kerberos-time :tag 4 :optional t)
  (till kerberos-time :tag 5)
  (rtime kerberos-time :tag 6 :optional t)
  (nonce asn1-uint32 :tag 7)
  (etype etype-list :tag 8) 
  (addresses host-addresses :tag 9 :optional t)
  (enc-authorization-data encrypted-data :tag 10 :optional t)
  (additional-tickets ticket-list :tag 11 :optional t) ;; sequence-of
  )

;; kdc-options flags 
(defparameter *kdc-options*
  '((:reserved #x1)
    (:forwardable #x2)
    (:forwarded #x4)
    (:proxiable #x8)
    (:proxy #x10)
    (:allow-postdate #x20)
    (:postdated #x40)
    (:renewable #x100)
    (:opt-hardware-auth #x800)
    (:constrained #x4000) ;; not in rfc? got this from wireshark
    (:canonicalize #x8000) ;; not in rfc? got this from wireshark
    (:disable-transited-check #x4000000)
    (:renewable-ok #x8000000)
    (:enc-tkt-in-skey #x10000000)
    (:renew #x40000000)
    (:validate #x80000000)))

(defxtype kdc-options () 
  ((stream) (unpack-flags (decode-bit-string stream) *kdc-options*))
  ((stream flags) (encode-bit-string stream (pack-flags flags *kdc-options*))))

(defxtype as-rep ()
  ((stream)
   (decode-identifier stream)
   (let ((len (decode-length stream)))
     (let ((contents (nibbles:make-octet-vector len)))
       (read-sequence contents stream)
       (unpack (xtype-reader 'kdc-rep) contents))))
  ((stream value)
   (encode-identifier stream 11 :class :application :primitive nil)
   (let ((contents (pack (xtype-writer 'kdc-rep) value)))
     (encode-length stream (length contents))
     (write-sequence contents stream))))

(defxtype tgs-rep ()
  ((stream)
   (decode-identifier stream)
   (let ((len (decode-length stream)))
     (let ((contents (nibbles:make-octet-vector len)))
       (read-sequence contents stream)
       (unpack (xtype-reader 'kdc-rep) contents))))
  ((stream value)
   (encode-identifier stream 13 :class :application :primitive nil)
   (let ((contents (pack (xtype-writer 'kdc-rep) value)))
     (encode-length stream (length contents))
     (write-sequence contents stream))))

(defxenum kdc-rep-type ()
  (:as 11)
  (:tgs 13))

(defsequence kdc-rep ()
  (pvno asn1-integer :tag 0 :initial-value 5)
  (type kdc-rep-type :tag 1) ;; 11 == AS, 13 == TGS
  (data pa-data-list :tag 2 :optional t) ;; optional, sequence-of
  (crealm realm :tag 3)
  (cname principal-name :tag 4)
  (ticket ticket :tag 5)
  (enc-part encrypted-data :tag 6)) ;; enc-as-rep-part or enc-tgs-rep-part 

(defxtype enc-as-rep-part ()
  ((stream)
   (decode-identifier stream)
   (let ((len (decode-length stream)))
     (let ((contents (nibbles:make-octet-vector len)))
       (read-sequence contents stream)
       (unpack (xtype-reader 'enc-kdc-rep-part) contents))))
  ((stream value)
   (encode-identifier stream 25 :class :application :primitive nil)
   (let ((contents (pack (xtype-writer 'enc-kdc-rep-part) value)))
     (encode-length stream (length contents))
     (write-sequence contents stream))))

(defxtype enc-tgs-rep-part ()
  ((stream)
   (decode-identifier stream)
   (let ((len (decode-length stream)))
     (let ((contents (nibbles:make-octet-vector len)))
       (read-sequence contents stream)
       (unpack (xtype-reader 'enc-kdc-rep-part) contents))))
  ((stream value)
   (encode-identifier stream 26 :class :application :primitive nil)
   (let ((contents (pack (xtype-writer 'enc-kdc-rep-part) value)))
     (encode-length stream (length contents))
     (write-sequence contents stream))))

(defsequence enc-kdc-rep-part ()
  (key encryption-key :tag 0)
  (last-req last-req :tag 1)
  (nonce asn1-uint32 :tag 2)
  (key-expiration kerberos-time :tag 3 :optional t) ;; optional
  (flags ticket-flags :tag 4) 
  (authtime kerberos-time :tag 5)
  (starttime kerberos-time :tag 6 :optional t) ;; optional
  (endtime kerberos-time :tag 7)
  (renew-till kerberos-time :tag 8 :optional t) ;; optional
  (srealm realm :tag 9)
  (sname principal-name :tag 10)
  (caddr host-addresses :tag 11 :optional t)) ;; optional

;; ------------------------------------

(defxenum lreq-type ()
  (:none 0) ;; no info encoded in value
  (:last-tgt 1) ;; last initial request for a tgt
  (:last-init 2) ;; last initial request
  (:newest-tgt 3) ;; time of newest tgt
  (:last-renewal 4) ;; time of last renewal
  (:last-request 5) ;; time of last request of any type
  (:password-expire 6) ;; time when password will expire
  (:account-expire 7)) ;; time when account will expire

(defsequence lreq ()
  (type lreq-type :tag 0)
  (value kerberos-time :tag 1))

(defxtype last-req ()
  ((stream) (decode-sequence-of stream 'lreq))
  ((stream values) (encode-sequence-of stream 'lreq values)))

;; -------------------------------------

(defsequence ap-req ((:tag 14) (:class :application))
  (pvno asn1-integer :initial-value 5 :tag 0)
  (type asn1-integer :initial-value 14 :tag 1)
  (options ap-options :tag 2) 
  (ticket ticket :tag 3)
  (authenticator encrypted-data :tag 4)) ;; authenticator

(defparameter *ap-options* 
  '((:reserved #x1)
    (:use-session-key #x2)
    (:mutual-required #x4)))

(defxtype ap-options ()
  ((stream) (unpack-flags (decode-bit-string stream) *ap-options*))
  ((stream flags) (encode-bit-string stream (pack-flags flags *ap-options*))))

(defsequence authenticator ((:tag 2) (:class :application))
  (vno asn1-integer :initial-value 5 :tag 0)
  (crealm realm :tag 1)
  (cname principal-name :tag 2)
  (cksum checksum :tag 3 :optional t) ;; optional
  (cusec microseconds :tag 4)  
  (ctime kerberos-time :tag 5)
  (subkey encryption-key :tag 6 :optional t) ;; optional
  (seqno asn1-uint32 :tag 7 :optional t) ;;optional
  (authorization-data authorization-data :tag 8 :optional t) ;; optional
  )

(defsequence ap-rep ((:tag 15) (:class :application))
  (pvno asn1-integer :tag 0 :initial-value 5)
  (type asn1-integer :tag 1 :initial-value 15)
  (enc-part encrypted-data :tag 2))

(defsequence enc-ap-rep-part ((:tag 27) (:class :application))
  (ctime kerberos-time :tag 0)
  (cusec microseconds :tag 1)
  (subkey encryption-key :tag 2 :optional t) ;; optional
  (seqno asn1-uint32 :tag 3 :optional t) ;; optional
  )

(defsequence krb-safe ((:tag 20) (:class :application))
  (pvno asn1-integer :tag 0 :initial-value 5)
  (type asn1-integer :tag 1 :initial-value 20)
  (body krb-safe-body :tag 2)
  (ckdum check-sum :tag 3))

(defsequence krb-safe-body ()
  (data asn1-octet-string :tag 0)
  (timestamp kerberos-time :tag 1 :optional t) ;; optional
  (usec microseconds :tag 2 :optional t) ;; optional
  (seqno asn1-uint32 :tag 3 :optional t) ;; optional
  (saddr host-address :tag 4)
  (raddr host-address :tag 5 :optional t) ;; optional
  )

;; note: no tag 2
(defsequence krb-priv ((:tag 21) (:class :application))
  (pvno asn1-integer :tag 0 :initial-value 5)
  (type asn1-integer :tag 1 :initial-value 21)
  (enc-part encrypted-data :tag 3))

(defsequence enc-krb-priv-part ((:tag 28) (:class :application))
  (data asn1-octet-string :tag 0)
  (timestamp kerberos-time :tag 1 :optional t) ;; optional
  (usec microseconds :tag 2 :optional t) ;; optional
  (seqno asn1-uint32 :tag 3 :optional t) ;; optional
  (saddr host-address :tag 4)
  (raddr host-address :tag 5 :optional t) ;; optional
  )

(defsequence krb-cred ((:tag 22) (:class :application))
  (pvno asn1-integer :tag 0 :initial-value 5)
  (type asn1-integer :tag 1 :initial-value 22)
  (tickets ticket :tag 2) ;; sequence-of
  (enc-part encrypted-data :tag 3)) ;; enc-krb-cred-part 

(defsequence enc-krb-cred-part ((:tag 29) (:class :application))
  (info krb-cred-info :tag 0) ;; sequence
  (nonce asn1-uint32 :tag 1)
  (timestamp kerberos-time :tag 2 :optional t) ;; optional
  (usec microseconds :tag 3 :optional t) ;; optional
  (saddr host-address :tag 4) ;; optional
  (raddr host-address :tag 5) ;; optional
  )

(defsequence krb-cred-info ()
  (key encryption-key :tag 0)
  (prealm realm :tag 1 :optional t) ;; optional
  (pname principal-name :tag 2 :optional t) ;; optional
  (flags ticket-flags :tag 3 :optional t) ;; optional
  (authtime kerberos-time :tag 4 :optional t) ;; op
  (starttime kerberos-time :tag 5 :optional t) ;; op
  (endtime kerberos-time :tag 6 :optional t) ;; op
  (renew-till kerberos-time :tag 7 :optional t) ;; op
  (srealm realm :tag 8 :optional t) ;; op
  (sname principal-name :tag 9 :optional t) ;; op
  (caddr host-addresses :tag 10 :optional t) ;; op
  )

;; ----------------------------------------------------------------

(defsequence %krb-error ((:tag 30) (:class :application) (:name krb-error))
  (pvno asn1-integer :tag 0)
  (type asn1-integer :tag 1)
  (ctime kerberos-time :tag 2 :optional t) ;; op
  (cusec microseconds :tag 3 :optional t) ;; op
  (stime kerberos-time :tag 4)
  (susec microseconds :tag 5)
  (error-code krb-error-code :tag 6) ;; defined in errors.lisp
  (crealm realm :tag 7 :optional t) ;; op
  (cname principal-name :tag 8 :optional t) ;; op
  (realm realm :tag 9)
  (sname principal-name :tag 10)
  (etext kerberos-string :tag 11 :optional t) ;; op
  (edata asn1-octet-string :tag 12 :optional t) ;; op
  )

(defgeneric encode-krb-error-edata (type value))
(defgeneric decode-krb-error-edata (type buffer))
(defmethod encode-krb-error-edata (type value) value)
(defmethod decode-krb-error-edata (type buffer) buffer)

(defmethod encode-krb-error-edata ((type (eql :preauth-required)) value)
  ;; the value MUST be a list of pa-data structures
  (pack #'encode-pa-data-list value))
(defmethod decode-krb-error-edata ((type (eql :preauth-required)) buffer)
  (unpack #'decode-pa-data-list buffer))

(defmethod encode-krb-error-edata ((type (eql :preauth-failed)) value)
  ;; the value MUST be a list of pa-data structures
  (pack #'encode-pa-data-list value))
(defmethod decode-krb-error-edata ((type (eql :preauth-failed)) buffer)
  (unpack #'decode-pa-data-list buffer))


(defxtype krb-error ()
  ((stream)
   ;; modify the edata if we know the code 
   (let ((err (read-xtype '%krb-error stream)))
     (setf (krb-error-edata err) (decode-krb-error-edata (krb-error-error-code err)
							 (krb-error-edata err)))
     err))
  ((stream err)
   (let ((edata (krb-error-edata err)))
     (setf (krb-error-edata err) (encode-krb-error-edata (krb-error-error-code err) edata))
     (write-xtype '%krb-error stream err)
     (setf (krb-error-edata err) edata))))

;; ------------------------------------------------

;; sequence-of 
(defsequence tdata ()
  (type asn1-integer :tag 0)
  (value octet-string :tag 1))
(defxtype typed-data ()
  ((stream) (decode-sequence-of stream 'tdata))
  ((stream values) (encode-sequence-of stream 'tdata values)))

;; preauthentication

(defxtype* pa-enc-timestamp () encrypted-data) ;; pa-enc-ts-enc

(defsequence pa-enc-ts-enc ()
  (patimestamp kerberos-time :tag 0)
  (pausec microseconds :tag 1 :optional t) ;; op
  )

(defxtype etype-info ()
  ((stream) (decode-sequence-of stream 'etype-info-entry))
  ((stream values) (encode-sequence-of stream 'etype-info-entry values)))

(defsequence etype-info-entry ()
  (etype etype-enum :tag 0)
  (salt asn1-octet-string :tag 1 :optional t) ;; op
  )

(defsequence etype-info2-entry ()
  (etype etype-enum :tag 0)
  (salt kerberos-string :tag 1 :optional t) ;; op
  (s2kparams asn1-octet-string :tag 2 :optional t) ;; op
  )

(defxtype etype-info2 ()
  ((stream) (decode-sequence-of stream 'etype-info2-entry))
  ((stream values) (encode-sequence-of stream 'etype-info2-entry values)))

(defsequence ad-kdc-issued ()
  (cksum checksum :tag 0)
  (irealm realm :tag 1 :optional t) ;; op
  (iname principal-name :tag 2 :optional t) ;; op
  (elements authorization-data :tag 3))

(defsequence ad-and-or ()
  (count asn1-integer :tag 0)
  (elements authorization-data :tag 1))


;; ------------------------------------------------
;; GSS-related structures

;; gss requires us to wrap things with an OID
(defun encode-initial-context-token (stream message)
  (declare (type stream stream)
	   (type (or ap-req ap-rep krb-error) message))
  (let ((octets (flexi-streams:with-output-to-sequence (s)
		  (encode-oid s *kerberos-oid*)
		  (etypecase message
		    (ap-req 
		     (write-sequence #(01 00) s) ;; TOK_ID field
		     (encode-ap-req s message))
		    (ap-rep 
		     (write-sequence #(02 00) s) 
		     (encode-ap-rep s message))
		    (krb-error 
		     (write-sequence #(03 00) s) 
		     (encode-krb-error s message))))))
    (let ((bytes (flexi-streams:with-output-to-sequence (s)
		   (encode-identifier s 0 :primitive nil)
		   (encode-length s (length octets))
		   (write-sequence octets s))))
      (encode-identifier stream 0 :class :application :primitive nil)
      (encode-length stream (length bytes))
      (write-sequence bytes stream))))

;; need a decode-initial-context-token as well

