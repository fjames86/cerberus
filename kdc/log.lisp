;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:cerberus)

(defvar *kdc-log* nil)
(defvar *log-path* (merge-pathnames "kdc.log" (user-homedir-pathname)))

(defun open-kdc-log ()
  (unless *kdc-log*
    (setf *kdc-log*
	  (pounds.log:open-log :path *log-path*
			       :tag "KDC "))))

(defun close-kdc-log ()
  (when *kdc-log*
    (pounds.log:close-log *kdc-log*)
    (setf *kdc-log* nil)))

(defun kdc-log (level format &rest args)
  (unless *kdc-log* (open-kdc-log))
  (pounds.log:write-message *kdc-log* level 
			    (apply #'format nil format args)))



