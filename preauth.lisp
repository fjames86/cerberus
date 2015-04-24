;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:cerberus)

;; This file should have the functions to generate the various pre-authentication 
;; types. There are LOTS of these.

;; ----------------

(defun pa-timestamp (key &optional (etype :des-cbc-md5))
  "Make a ENC-TIMESTAMP type pre-authentication data."
  (make-pa-data :type :enc-timestamp
		:value (encrypt-data etype
				     (pack #'encode-pa-enc-ts-enc 
					   (make-pa-enc-ts-enc :patimestamp (get-universal-time)
							       :pausec 0))
				     key
				     :usage :pa-enc-timestamp)))

(defun pa-tgs-req (ticket key cname &optional (etype :des-cbc-md5))
  (make-pa-data 
   :type :tgs-req
   :value
   (make-ap-req :options '(:use-session-key)
		:ticket ticket
		:authenticator 
		(encrypt-data etype
			      (pack #'encode-authenticator 
				    (make-authenticator :crealm (ticket-realm ticket)
							:cname cname
							:ctime (get-universal-time)
							:cusec 0))
			      key
			      :usage :pa-tgs-req))))

  
