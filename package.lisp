;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defpackage #:cerberus
  (:use #:cl)
  (:export #:string-to-key

	   ;; communication with the KDC
	   #:request-tgt
	   #:request-credentials
	   #:request-renewal
	   
	   ;; general utilities
	   #:principal
	   #:make-ap-request
	   #:valid-ticket-p
	   #:make-host-address
	   #:ap-req-session-key 

	   ;; key lists
	   #:generate-keylist
	   #:load-keytab

	   ;; user messages (for gss)
	   #:pack-initial-context-token
	   #:unpack-initial-context-token

	   ;; encrypt messages in a KRB-PRIV structure 
	   #:wrap-message
	   #:unwrap-message))







