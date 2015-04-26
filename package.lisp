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

	   ;; key lists
	   #:generate-keylist
	   #:load-keytab

	   ;; user messages
	   #:wrap-message
	   #:unwrap-message))







