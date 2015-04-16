

(in-package #:cerberus)

(defun principal (name &key instance (type :principal))
  (make-principal-name :type (ecase type
			       (:unknown 0)
			       (:principal 1)
			       (:srv-inst 2)
			       (:srv-host 3)
			       (:srv-xhost 4)
			       (:uid 5)
			       (:x500 6)
			       (:smtp 7)
			       (:enterprise 10))
		       :name (append (list name) (when instance (list instance)))))

(defun krbtgt-principal (realm)
  (principal "krbtgt" 
	     :instance realm 
	     :type :srv-inst))


;; ----------------------------------------

(defun host-address-type-integer (type)
  (case type
    (:ipv4 2)
    (:ipv6 24)
    (:decnet-phase-4 12)
    (:netbios 20)
    (:directional 3)
    (otherwise type)))

(defun host-address-integer-type (type)
  (case type
    (2 :ipv4)
    (24 :ipv6)
    (12 :decnet-phase-4)
    (20 :netbios)
    (3 :directional)
    (otherwise type)))

(defun host-address (name &optional (type :ipv4))
  (make-host-address 
   :type (host-address-type-integer type)
   :name 
   (case type
     (:ipv4 ;; 4 ocets
      (typecase name
	(string (usocket:dotted-quad-to-vector-quad name))
	(otherwise name)))
     (:ipv6 ;; 16 octets
      name)
     (:netbios 
      ;; 16 ocetets
      (let ((octets (babel:string-to-octets name)))
	(concatenate '(vector (unsigned-byte 8))
		     octets
		     (loop :for i :below (- 16 (length octets)) 
			:collect (char-code #\space)))))
     (otherwise name))))

;; ------------------------------------------
     
(defun etype-integer (etype)
  (case etype
    (:des-cbc-crc 1)
    (:des-cbc-md4 2)
    (:des-cbc-md5 3)
    (:des3-cbc-md5 5)
    (:des3-cbc-sha1 7)
    (:des3-cbc-sha1-kd 16)
    (:aes128-cts-hmac-sha1-96 17)
    (:aes256-cts-hamc-sha1-96 18)
    (:rc4-hmac 23)
    (:rc4-hamc-exp 24)
    (otherwise etype)))

(defun integer-etype (int)
  (case int
    (1 :des-cbc-crc)
    (2 :des-cbc-md4)
    (3 :des-cbc-md5)
    (5 :des3-cbc-md5)
    (7 :des3-cbc-sha1)
    (16 :des3-cbc-sha1-kd)
    (17 :aes128-cts-hmac-sha1-96)
    (18 :aes256-cts-hamc-sha1-96)
    (23 :rc4-hmac)
    (24 :rc4-hamc-exp)
    (otherwise int)))
  

(defun make-kdc-request (client-principal &key (type :as) options realm server-principal nonce
					    from-time till-time renew-time encryption-types host-addresses
					    authorization-data tickets pa-data)
  (make-kdc-req :type (ecase type
			(:as 10)
			(:tgs 12))
		:data pa-data
		:req-body (make-kdc-req-body :options options
					     :cname client-principal
					     :realm realm
					     :sname server-principal
					     :from from-time
					     :till (or till-time (encode-universal-time 0 0 0 1 1 1970))
					     :rtime renew-time
					     :nonce (or nonce (random (expt 2 32)))
					     :etype (mapcar #'etype-integer encryption-types)
					     :addresses host-addresses
					     :enc-authorization-data authorization-data
					     :additional-tickets tickets)))

(defun make-as-request (client realm &key options till-time renew-time host-addresses
				       encryption-types pa-data tickets authorization-data)
  (make-kdc-request client
		    :type :as
		    :options options
		    :realm realm
		    :server-principal (krbtgt-principal realm)
		    :till-time till-time
		    :renew-time renew-time
		    :encryption-types encryption-types
		    :host-addresses host-addresses
		    :pa-data pa-data
		    :tickets tickets
		    :authorization-data authorization-data))

(defun make-krb-ticket (principal realm octets)
  (make-ticket :realm realm
	       :sname principal
	       :enc-part (make-encrypted-data :type 0
					      :cipher octets)))
