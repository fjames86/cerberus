;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


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
  (make-kdc-req :type type 
		:data pa-data
		:req-body (make-kdc-req-body :options options
					     :cname client-principal
					     :realm realm
					     :sname server-principal
					     :from from-time
					     :till (or till-time (encode-universal-time 0 0 0 1 1 1970 0))
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


(defun principal-string (names &optional realm)
  "Converts a list of names and a realm into a principal name string. 

Return ::= Each/Name@Realm
"
  (with-output-to-string (s)
    (let ((done nil))
      (dolist (name (etypecase names
		      (list names)
		      (string (list names))))
	(when done (format s "/"))
	(format s "~A" name)
	(setf done t)))
    (when realm
      (format s "@~A" realm))))

(defun string-principal (string)
  "Parses a principal name string. Returns (values names realm)."
  (let ((pos 0)
	(len (length string))
	(names nil)
	(realm nil))
    (do ((i pos (1+ i)))
	((or (= i len) (char= (char string i) #\@))
	 (push (subseq string pos i) names)
	 (setf pos i))
      (when (char= (char string i) #\/)
	(push (subseq string pos i) names)
	(setf pos (1+ i))))
    (when (< pos len)
      (setf realm (subseq string (1+ pos))))
    (values (reverse names) realm)))
