;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:cerberus)

;; this defines the database to store the principals and their keys

(defxtype db-key-list ()
  ((stream)
   (decode-sequence-of stream 'encryption-key))
  ((stream list)
   (encode-sequence-of stream 'encryption-key list)))

(defsequence db-entry ()
  (name asn1-generalized-string)
  (keys db-key-list))

(defvar *db* nil)
(defvar *db-path* (merge-pathnames "cerberus.dat" (user-homedir-pathname)))

(defconstant +default-count+ 64)
(defconstant +default-block-size+ 512)

(defun open-kdc-db ()
  (unless *db*
    (setf *db*
	  (pounds.db:open-db *db-path* #'decode-db-entry #'encode-db-entry
			     :count +default-count+
			     :block-size +default-block-size+))))

(defun close-kdc-db ()
  (when *db*
    (pounds.db:close-db *db*)
    (setf *db* nil)))

(defun add-spn (name password)
  (declare (type string name password))
  (open-kdc-db)
  (setf (pounds.db:find-entry name *db*
			      :test #'string-equal
			      :key #'db-entry-name)
	(make-db-entry :name name
		       :keys (generate-keylist name password))))

(defun find-spn (name)
  (declare (type string name))
  (open-kdc-db)
  (let ((entry (pounds.db:find-entry name *db*
				     :test #'string-equal
				     :key #'db-entry-name)))
    (when entry 
      (list :name (db-entry-name entry)
	    :keys (db-entry-keys entry)))))

(defun find-spn-keys (name)
  (let ((entry (find-spn name)))
    (when entry 
      (getf entry :keys))))

(defun remove-spn (name)
  (declare (type string name))
  (open-kdc-db)
  (pounds.db:remove-entry name *db*
			  :test #'string-equal
			  :key #'db-entry-name)
  nil)

(defun list-spn ()
  (open-kdc-db)
  (pounds.db:mapentries (lambda (entry)
			  (list :name (db-entry-name entry)
				:keys (db-entry-keys entry)))
			*db*))



