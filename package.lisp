;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defpackage #:cerberus
  (:use #:cl)
  (:export #:string-to-key ;; should this be exported?

	   ;; communication with the KDC
	   #:request-tgt
	   #:request-credentials
	   #:request-renewal
	   
	   ;; general utilities
	   #:principal
	   #:string-principal
	   #:principal-string
	   
	   ;; should these be exported?
	   #:make-ap-request
	   #:valid-ticket-p
	   #:make-host-address
	   #:ap-req-session-key 

	   ;; main entry point function
	   #:logon-user
	   #:with-current-user
	   #:*current-user*

	   ;; key lists
	   #:generate-keylist
	   #:load-keytab

	   ;; user messages (for gss)
	   #:pack-initial-context-token
	   #:unpack-initial-context-token
	   
	   ;; encrypt messages in a KRB-PRIV structure 
	   #:wrap-message
	   #:unwrap-message))







