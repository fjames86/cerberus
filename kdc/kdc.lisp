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

(defun start-kdc-server ()
  (cerberus::kdc-log :info "Starting KDC")
  (cerberus::start-kdc-server)
  (cerberus::kdc-log :info "KDC Started"))

(defun stop-kdc-server ()
  (cerberus::kdc-log :info "Stopping KDC")
  (cerberus::stop-kdc-server)
  (cerberus::kdc-log :info "KDC Stopped"))


(defun find-spn (name)
  (cerberus::find-spn name))

(defun add-spn (name)
  (cerberus::add-spn name password))

(defun remove-spn (name)
  (cerberus::remove-spn name))

(defun list-spn ()
  (cerberus::list-spn))


