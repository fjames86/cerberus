;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:cerberus)

;; This file should have the functions to generate the various pre-authentication 
;; types. There are LOTS of these.

;; ----------------

(defun pa-timestamp (key &key (etype :des-cbc-md5))
  "Make a ENC-TIMESTAMP type pre-authentication data."
  (make-pa-data :type :enc-timestamp
		:value (encrypt-data etype
				     (pack #'encode-pa-enc-ts-enc 
					   (make-pa-enc-ts-enc :patimestamp (get-universal-time)
							       :pausec 0))
				     key)))
