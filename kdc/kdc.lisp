;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(defpackage #:cerberus-kdc
  (:use #:cl)
  (:export #:start-kdc-server
	   #:stop-kdc-server))


(in-package #:cerberus-kdc)

(defun start-kdc-server ()
  (cerberus::kdc-log :info "Starting KDC")
  (cerberus::start-kdc-server)
  (cerberus::kdc-log :info "KDC Started"))

(defun stop-kdc-server ()
  (cerberus::kdc-log :info "Stopping KDC")
  (cerberus::stop-kdc-server)
  (cerberus::kdc-log :info "KDC Stopped"))



