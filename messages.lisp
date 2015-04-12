

(in-package #:cerberus)

(defun make-principal (name &key instance (type :principal))
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

(defun etype-integer (etype)
  (ecase etype
    (:des-cbc-crc 1)
    (:des-cbc-md4 2)
    (:des-cbc-md5 3)
    (:des3-cbc-md5 5)
    (:des3-cbc-sha1 7)
    (:des3-cbc-sha1-kd 16)
    (:aes128-cts-hmac-sha1-96 17)
    (:aes256-cts-hamc-sha1-96 18)
    (:rc4-hmac 23)
    (:rc4-hamc-exp 24)))

(defun make-kdc-request (client-principal &key (type :as) options realm server-principal nonce
					    from-time till-time renew-time encryption-types ip-list
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
					     :till (or till-time (error "Till-time is mandatory"))
					     :rtime renew-time
					     :nonce (or nonce (random #xffffffff))
					     :etype (mapcar #'etype-integer encryption-types)
					     :addresses (mapcar (lambda (ip)
								  (make-host-address :type 2 ;; IPv4
										     :name (etypecase ip
											     (string (babel:string-to-octets ip))
											     (vector ip))))
								ip-list)
					     :enc-authorization-data authorization-data
					     :additional-tickets tickets)))

