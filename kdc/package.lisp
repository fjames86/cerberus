;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defpackage #:cerberus-kdc
  (:use #:cl)
  (:import-from #:cerberus
		#:defxtype
		#:decode-sequence-of
		#:encryption-key
		#:encode-sequence-of
		#:defsequence
		#:asn1-generalized-string
		#:generate-keylist 
		#:make-krb-error
		#:krbtgt-principal
		#:encryption-key-type
		#:make-encryption-key
		#:random-to-key 
		#:profile-key-seed-length 
		#:principal-string
		#:string-principal
		#:principal-name 
		#:make-ticket 
		#:encryption-key-value 
		#:encode-enc-ticket-part 
		#:make-transited-encoding
		#:time-from-now 
		#:krb-error-t
		#:decode-pa-enc-ts-enc
		#:pa-enc-ts-enc-patimestamp
		#:kdc-req
		#:kdc-req-data
		#:kdc-req-req-body
		#:kdc-req-body-realm
		#:kdc-req-body-cname 
		#:kdc-req-body-sname 
		#:pa-data-type
		#:pa-data-value 
		#:kdc-req-body-etype
		#:encode-enc-as-rep-part 
		#:make-enc-kdc-rep-part 
		#:kdc-req-body-nonce 
		#:valid-ticket-p
		#:decode-ap-req
		#:usb8
		#:encrypt-data
		#:pack
		#:make-enc-ticket-part
		#:encrypted-data-type
		#:unpack
		#:decrypt-data
		#:make-kdc-rep
		#:encode-enc-tgs-rep-part
		#:decode-identifier
		#:decode-as-req
		#:decode-tgs-req
		#:kdc-req-type
		#:krb-error-err
		#:*default-realm*
		#:kdc-rep
		#:encode-as-rep
		#:encode-tgs-rep
		#:encode-krb-error
		#:krb-error)
  (:export #:start-kdc-server
	   #:stop-kdc-server
	   
	   #:spn-name
	   #:spn-keys

	   #:add-spn
	   #:remove-spn
	   #:find-spn
	   #:list-spn))

