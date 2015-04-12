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
		      (alexandria:symbolicate 'encode- name))))
	(writer (let ((n (cadr (assoc :writer options))))
		  (if n
		      n 
		      (alexandria:symbolicate 'decode- name)))))
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

;; ------------------------------------------------------

(defvar *kerberos-oid* "1.2.840.48018.1.2.2")

(defun encode-identifier (stream tag &key (class :universal) (primitive t))
  (declare (type (integer 0 30) tag))
  (write-byte (logior tag
		      (ash (ecase class
			     (:universal 0)
			     (:application 1)
			     (:context 2)
			     (:private 3))
			   5)
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
     (let ((n (1+ (truncate length 256))))
       (write-byte (logand 128 n) stream)
       (do ((octets nil))
	   ((zerop length)
	    (dolist (octet octets)
	      (write-byte octet stream))
	    n)
	 (push (logand length #xffffffff) octets)
	 (setf length (ash length -8)))))))

(defun decode-length (stream)
  (let ((first (read-byte stream)))
    (cond
      ((zerop (logand first 128))
       first)
      (t 
       (do ((length 0)
	    (power 0 (+ power 8))
	    (n (logand first (lognot 128)) (1- n)))
	   ((zerop n) length)
	 (let ((byte (read-byte stream)))
	   (setf length (logand length (ash byte power)))))))))

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

(defun integer-octets (integer)
  (do ((octets nil))
      ((zerop integer)
       (or (nreverse octets)
	   '(0)))
    (push (logand integer #xff) octets)
    (setf integer (ash integer -8))))

(defun octets-integer (octets)
  (do ((power 0 (+ power 8))
       (o octets (cdr o))
       (i 0))
      ((null o) i)
    (setf i (logior i (ash (car o) power)))))

(defun encode-integer (stream integer)
  (encode-identifier stream 2)
  (let ((octets (integer-octets integer)))
    (encode-length stream (length octets))
    (dolist (o octets)
      (write-byte o stream))))

(defun decode-integer (stream)
  (decode-identifier stream)
  (let ((n (decode-length stream)))
    (octets-integer (loop :for i :below n :collect (read-byte stream)))))

(defxtype asn1-integer ()
  ((stream) (decode-integer stream))
  ((stream value) (encode-integer stream value)))

;; ----------------------------------

(defun encode-bit-string (stream integer)
  (let ((octets (integer-octets integer)))
    (when (< (length octets) 4)
      (dotimes (i (- 4 (length octets)))
	(push 0 octets)))
    (encode-identifier stream 3)
    (encode-length stream (1+ (length octets)))
    (write-byte 0 stream) ;; the number of unused bits -- always zero for us since we write octets
    (dolist (octet octets)
      (write-byte octet stream))))

(defun decode-bit-string (stream)
  (decode-identifier stream)
  (let ((n (1- (decode-length stream))))
    (read-byte stream)
    (octets-integer (loop :for i :below n 
		       :collect (read-byte stream)))))

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
  (multiple-value-bind (sec min hour day month year) (decode-universal-time time)
    (format nil "~4,'0D~2,'0D~2,'0D~2,'0D~2,'0D~2,'0D"
	    year month day hour min sec)))

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
			   (parse-integer year))))

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

;; ----------------------------

(defun encode-sequence-of (stream type values &key (tag 16) (class :universal) (primitive t))
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
  `(progn
     ;; the structure 
     (defstruct ,name 
       ,@(mapcar (lambda (slot)
		   (destructuring-bind (slot-name slot-type &key initial-value &allow-other-keys) slot
		     (declare (ignore slot-type))
		     `(,slot-name ,initial-value)))
		 slots))
     ;; the encoder 
     (defun ,(alexandria:symbolicate 'encode- name) (stream value)
       (encode-identifier stream 
			  ,(let ((tag (assoc :tag options)))
				    (if tag (cadr tag) 16))
			  :class ,(let ((class (assoc :class options)))
				    (if class (cadr class) :application))
			  :primitive nil)
       (let ((bytes (flexi-streams:with-output-to-sequence (s)
		      ,@(mapcar (lambda (slot)
				  (destructuring-bind (slot-name slot-type &key tag optional &allow-other-keys) slot 
				    `(let ((the-value (,(alexandria:symbolicate name '- slot-name) value)))
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
	 (encode-length stream (length bytes))
	 (write-sequence bytes stream)))
     ;; decoder
     (defun ,(alexandria:symbolicate 'decode- name) (stream)
       (decode-identifier stream)
       (let ((length (decode-length stream))
	     (value (,(alexandria:symbolicate 'make- name))))
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
				       `(,tag (setf (,(alexandria:symbolicate name '- slot-name) value)
						    (read-xtype ',slot-type s)))))
				   slots))))))
	      `(progn
		 ,@(mapcar (lambda (slot)
			     (destructuring-bind (slot-name slot-type &key &allow-other-keys) slot
			       `(setf (,(alexandria:symbolicate name '- slot-name) value)
				      (read-xtype ',slot-type stream))))
			   slots)))
	 value))
     ;; define the type
     (%defxtype ',name
		#',(alexandria:symbolicate 'decode- name)
		#',(alexandria:symbolicate 'encode- name))

     ',name))

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

(defsequence principal-name ()
  (type asn1-integer :tag 0)
  (name kerberos-strings :tag 1))

(defsequence host-address ()
  (type asn1-integer :tag 0)
  (name asn1-octet-string :tag 1))

(defxtype host-addresses ()
  ((stream) (decode-sequence-of stream 'host-address))
  ((stream values) (encode-sequence-of stream 'host-address values)))

(defsequence auth-data () 
  (type asn1-integer :tag 0)
  (data asn1-octet-string :tag 1))

;; sequnce of auth-data structures
(defxtype authorization-data ()
  ((stream) (decode-sequence-of stream 'auth-data))
  ((stream values) (encode-sequence-of stream 'auth-data values)))

;; NOTE: no tag 0 present 
(defsequence pa-data ()
  (type asn1-integer :tag 1)
  (value asn1-octet-string :tag 2))

(defxtype pa-data-list ()
  ((stream) (decode-sequence-of stream 'pa-data))
  ((stream values) (encode-sequence-of stream 'pa-data values)))

;; length is always at least 32 bits, i.e. 4 bytes. this is handled by the bit string encoder
(defxtype kerberos-flags ()
  ((stream) (read-xtype 'asn1-bit-string stream))
  ((stream value) (write-xtype 'asn1-bit-string stream value)))

(defsequence encrypted-data ()
  (type asn1-integer :tag 0)
  (kvno asn1-integer :tag 1 :optional t)
  (cipher asn1-octet-string :tag 2))

(defsequence encryption-key ()
  (type asn1-integer :tag 1)
  (value asn1-octet-string :tag 2))

(defsequence check-sum ()
  (type asn1-integer :tag 0)
  (sum asn1-octet-string :tag 1))

(defsequence ticket ((:tag 1) (:class :application))
  (vno asn1-integer :tag 0 :initial-value 5)
  (realm realm :tag 1)
  (sname principal-name :tag 2)
  (enc-part encrypted-data :tag 3)) ;; enc-ticket-part 

(defsequence enc-ticket-part ((:tag 3) (:class :application))
  (flags kerberos-flags :tag 0)
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
    
(defxtype as-req ()
  ((stream)
   (decode-identifier stream)
   (let ((len (decode-length stream)))
     (let ((contents (nibbles:make-octet-vector len)))
       (read-sequence contents stream)
       (unpack (xtype-reader 'kdc-req) contents))))
  ((stream value)
   (encode-identifier stream 10 :class :applicaiton :primitive nil)
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
   (encode-identifier stream 12 :class :applicaiton :primitive nil)
   (let ((contents (pack (xtype-writer 'kdc-req) value)))
     (encode-length stream (length contents))
     (write-sequence contents stream))))

;; note: no tag 0
(defsequence kdc-req ()
  (pvno asn1-integer :tag 1 :initial-value 5)
  (type asn1-integer :tag 2 :initial-value 10) ;; 10 == AS, 12 == TGS
  (data pa-data :tag 3 :optional t) ;; sequence-of 
  (req-body kdc-req-body :tag 4))

(defxtype ticket-list ()
  ((stream) (decode-sequence-of stream 'ticket))
  ((stream values) (encode-sequence-of stream 'ticket values)))

(defsequence kdc-req-body ()
  (options kdc-options :tag 0)
  (cname principal-name :tag 1)
  (realm realm :tag 2)
  (sname principal-name :tag 3 :optional t)
  (from kerberos-time :tag 4 :optional t)
  (till kerberos-time :tag 5)
  (rtime kerberos-time :tag 6 :optional t)
  (nonce asn1-integer :tag 7)
  (etype asn1-integer-list :tag 8) 
  (addresses host-addresses :tag 9 :optional t)
  (enc-authorization-data encrypted-data :tag 10 :optional t)
  (additional-tickets ticket-list :tag 11 :optional t) ;; sequnce-of
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
    (:opt-hardward-auth #x800)
    (:disable-transited-check #x4000000)
    (:renewable-ok #x8000000)
    (:enc-tkt-in-skey #x10000000)
    (:renew #x40000000)
    (:validate #x80000000)))

(defxtype kdc-options () 
  ((stream) (unpack-flags (decode-integer stream) *kdc-options*))
  ((stream flags) (encode-integer stream (pack-flags flags *kdc-options*))))

(defxtype as-rep ()
  ((stream)
   (decode-identifier stream)
   (let ((len (decode-length stream)))
     (let ((contents (nibbles:make-octet-vector len)))
       (read-sequence contents stream)
       (unpack (xtype-reader 'kdc-rep) contents))))
  ((stream value)
   (encode-identifier stream 11 :class :applicaiton :primitive nil)
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
   (encode-identifier stream 13 :class :applicaiton :primitive nil)
   (let ((contents (pack (xtype-writer 'kdc-rep) value)))
     (encode-length stream (length contents))
     (write-sequence contents stream))))

(defsequence kdc-rep ()
  (pvno asn1-integer :tag 0 :initial-value 5)
  (type asn1-integer :tag 1) ;; 11 == AS, 13 == TGS
  (data pa-data-list :tag 2) ;; optional, sequence-of
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
   (encode-identifier stream 25 :class :applicaiton :primitive nil)
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
   (encode-identifier stream 26 :class :applicaiton :primitive nil)
   (let ((contents (pack (xtype-writer 'enc-kdc-rep-part) value)))
     (encode-length stream (length contents))
     (write-sequence contents stream))))

(defsequence enc-kdc-rep-part ()
  (key encryption-key :tag 0)
  (last-req last-req :tag 1)
  (nonce asn1-integer :tag 2)
  (key-expriation kerberos-time :tag 3 :optional t) ;; optional
  (flags ticket-flags :tag 4) 
  (authtime kerberos-time :tag 5)
  (starttime kerberos-time :tag 6 :optional t) ;; optional
  (endtime kerberos-time :tag 7)
  (renew-till kerberos-time :tag 8 :optional t) ;; optional
  (srealm realm :tag 9)
  (sname principal-name :tag 10)
  (caddr host-addresses :tag 11 :optional t)) ;; optional

(defsequence lreq () 
  (type asn1-integer :tag 0)
  (value kerberos-time :tag 1))
(defxtype last-req ()
  ((stream) (decode-sequence-of stream 'lreq))
  ((stream values) (encode-sequence-of stream 'lreq values)))

(defsequence ap-req ((:tag 14) (:class :application))
  (pvno asn1-integer :initial-value 5 :tag 0)
  (type asn1-integer :initial-value 14 :tag 1)
  (options ap-options :tag 2) 
  (ticket ticket :tag 3)
  (authenticator encrypted-data :tag 4)) ;; authentiucator

(defparameter *ap-options* 
  '((:use-session-key #x1)
    (:mutual-required #x2)))
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
  (seqno asn1-integer :tag 7 :optional t) ;;optional
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
  (seqno asn1-integer :tag 3 :optional t) ;; optional
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
  (seqno asn1-integer :tag 3 :optional t) ;; optional
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
  (seqno asn1-integer :tag 3 :optional t) ;; optional
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
  (nonce asn1-integer :tag 1)
  (timestamp kerberos-time :tag 2 :optional t) ;; optional
  (usec microseconds :tag 3 :optional t) ;; optional
  (saddr host-address :tag 4) ;; optional
  (raddr host-address :tag 5) ;; optional
  )

(defsequence krb-cred-info ()
  (key encryption-key :tag 0)
  (prealm realm :tag 1 :optional t) ;; optional
  (pname principal-name :tag 2 :optional t) ;; optional
  (flags ticket-flags :tag 3 :optional t) ;; optinal
  (authtime kerberos-time :tag 4 :optional t) ;; op
  (starttime kerberos-time :tag 5 :optional t) ;; op
  (endtime kerberos-time :tag 6 :optional t) ;; op
  (renew-till kerberos-time :tag 7 :optional t) ;; op
  (srealm realm :tag 8 :optional t) ;; op
  (sname principal-name :tag 9 :optional t) ;; op
  (caddr host-addresses :tag 10 :optional t) ;; op
  )

(defsequence krb-error ((:tag 30) (:class :application))
  (pvno asn1-integer :tag 0)
  (type asn1-integer :tag 1)
  (ctime kerberos-time :tag 2 :optional t) ;; op
  (cusec microseconds :tag 3 :optional t) ;; op
  (stime kerberos-time :tag 4)
  (susec microseconds :tag 5)
  (error-code asn1-integer :tag 6)
  (crealm realm :tag 7 :optional t) ;; op
  (cname principal-name :tag 8 :optional t) ;; op
  (realm realm :tag 9)
  (sname principal-name :tag 10)
  (etext kerberos-string :tag 11 :optional t) ;; op
  (edata asn1-octet-string :tag 12 :optional t) ;; op
  )

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
  (etype asn1-integer :tag 0)
  (salt asn1-octet-string :tag 1 :optional t) ;; op
  )

(defsequence etype-info2-entry ()
  (etype asn1-integer :tag 0)
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


