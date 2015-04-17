

(in-package #:cerberus)

(defun principal (name &key instance (type :principal))
  (make-principal-name :type type 
		       :name (append (list name) 
				     (when instance (list instance)))))

(defun krbtgt-principal (realm)
  (principal "krbtgt" 
	     :instance realm 
	     :type :srv-inst))
 
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
					     :etype encryption-types
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
