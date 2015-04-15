;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:cerberus)

(defun send-req (msg &optional host port)
  (let ((socket (usocket:socket-connect host port 
					:protocol :datagram
					:element-type '(unsigned-byte 8))))
    (unwind-protect 
	 (progn
	   (usocket:socket-send socket msg (length msg))
	   (when (usocket:wait-for-input (list socket) :timeout 1 :ready-only t)
	     (usocket:socket-receive socket (nibbles:make-octet-vector 1024) 1024)))
      (usocket:socket-close socket))))

