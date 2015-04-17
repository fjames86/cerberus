;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:cerberus)

;; ----------------


(defun encrypt-data (type data)
  (pack #'encode-encrypted-data
	(make-encrypted-data :type type
			     :cipher data)))

(defun pa-timestamp ()
  (pack #'encode-pa-enc-ts-enc 
	(make-pa-enc-ts-enc :patimestamp (get-universal-time)
			    :pausec 0)))

