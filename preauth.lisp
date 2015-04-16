;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:cerberus)

(defun pa-data-decode-transformer (pa)
  (setf (pa-data-value pa) 
	(decode-pa-data-value (pa-data-type pa) (pa-data-value pa)))
  pa)

(defgeneric decode-pa-data-value (type buffer))

;; default method leaves buffer untouched
(defmethod decode-pa-data-value (type buffer)
  buffer)

(defmethod decode-pa-data-value ((type (eql :etype-info2)) buffer)
  (decode #'decode-etype-info2 buffer))


;; ----------------


(defun encrypt-data (type data)
  (pack #'encode-encrypted-data
	(make-encrypted-data :type type
			     :cipher data)))

(defun pa-timestamp ()
  (pack #'encode-pa-enc-ts-enc 
	(make-pa-enc-ts-enc :patimestamp (get-universal-time)
			    :pausec 0)))

