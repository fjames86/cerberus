;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defpackage #:cerberus
  (:use #:cl)
  (:export #:string-to-key
	   #:request-tgt
	   #:request-credentials
	   #:request-renewal
	   
	   ;; general utilities
	   #:principal
	   #:pack-ap-req
	   #:valid-ticket-p
	   #:make-host-address
	   #:ap-req-session-key 

	   ;; key lists
	   #:generate-keylist
	   #:load-keytab

	   ;; user messages
	   #:pack-initial-context-token
	   #:unpack-initial-context-token

	   #:wrap-message
	   #:unwrap-message))







