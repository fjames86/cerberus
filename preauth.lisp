;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:cerberus)

;; ----------------

(defvar *user-key* nil)

(defun login-user (username password realm)
  (setf *user-key*
	(string-to-key :des 
		       password
		       :salt (format nil "~A~A" (string-upcase realm) username))))

(defun pa-timestamp (&optional key)
  (make-pa-data 
   :type :enc-timestamp
   :value 
   (make-encrypted-data 
    :type :des-cbc-md5 
    :cipher
    (encrypt-des-cbc-md5 (or key 
			     *user-key* 
			     (error "Must login or provide a key"))
			 (pack #'encode-pa-enc-ts-enc 
			       (make-pa-enc-ts-enc :patimestamp (get-universal-time)
						   :pausec 0))))))


