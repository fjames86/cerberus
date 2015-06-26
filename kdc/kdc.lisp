;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(defpackage #:cerberus-kdc
  (:use #:cl)
  (:export #:start-kdc-server
	   #:stop-kdc-server
	   
	   #:add-spn
	   #:remove-spn
	   #:find-spn
	   #:list-spn))


(in-package #:cerberus-kdc)

(defun start-kdc-server (realm)
  (setf cerberus::*default-realm* realm)
  (cerberus::kdc-log :info "Starting KDC")
  (cerberus::start-kdc-server)
  (cerberus::kdc-log :info "KDC Started")
  nil)

(defun stop-kdc-server ()
  (cerberus::kdc-log :info "Stopping KDC")
  (cerberus::stop-kdc-server)
  (cerberus::kdc-log :info "KDC Stopped")
  nil)

(defun find-spn (name)
  (cerberus::find-spn name))

(defun add-spn (name password)
  (cerberus::add-spn name password))

(defun remove-spn (name)
  (cerberus::remove-spn name))

(defun list-spn ()
  (cerberus::list-spn))


