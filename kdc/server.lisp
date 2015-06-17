;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:cerberus)

(defun generate-error (error-code realm &key ctime cusec cname etext edata)
  (make-krb-error :pvno 5
		  :type 30
		  :ctime ctime
		  :cusec cusec
		  :stime (get-universal-time)
		  :susec 0
		  :error-code error-code
		  :cname cname
		  :crealm realm
		  :realm realm
		  :sname (krbtgt-principal realm)
		  :etext etext
		  :edata edata))

;; this is to request a ticket for the TGS, i.e. krbtgt principal
(defun generate-as-rep (req)
  "Receive and authenticate an AS-REQ. Returns either an AS-REP or a KRB-ERROR."
  (let ((preauth (kdc-req-data req))
	(body (kdc-req-req-body req)))
    ;; try and find the principal
    (let ((srv (find-spn (principal-string (kdc-req-body-sname body) (kdc-req-body-realm body))))
	  (clt (find-spn (principal-string (kdc-req-body-cname body) (kdc-req-body-realm body))))
	  (realm (kdc-req-body-realm body)))
      (unless srv (error 'krb-error-t :err (generate-error :s-principal-unknown realm)))
      (unless clt (error 'krb-error-t :err (generate-error :c-principal-unknown realm)))
      (unless (string= (car (principal-name-name (kdc-req-body-sname body))) "krbtgt")
	(error 'krb-error-t :err (generate-error :badoption realm)))
      ;; one of the preauth MUST be a :PA-TIMESTAMP
      (let ((a (find-if (lambda (pa)
			  (eq (pa-data-type pa) :pa-timestamp))
			preauth)))
	(unless a (error 'krb-error-t :err (generate-error :preauth-failed realm)))
	;; validate the timestamp by decrypting it and checking against current time 
	;; FIXME: validate the timestamp 

	;; if we got here then all is good, generate the kdc-rep 
	;; the ticket is encryted with the TGS's key 
	;; the enc-part is encrypted with the client's key 
	(make-kdc-rep :type :as 
		      :crealm (kdc-req-body-realm body)
		      :cname (kdc-req-body-cname body)
		      :ticket (make-ticket :realm realm
					   :sname (krbtgt-principal realm)
					   :enc-part (encrypt-data (make-enc-ticket-part)))
		      :enc-part (encrypt-data (make-enc-kdc-rep-part)))))))

;; this is to request a ticket for any principal
(defun generate-tgs-rep (req)
  "Receive and authenticate a TGT-REQ. Returns either a TGS-REP or a KRB-ERROR."
  (let ((preauth (kdc-req-data req))
	(body (kdc-req-req-body req)))
    ;; try and find the principal
    (let ((srv (find-spn (principal-string (kdc-req-body-sname body) (kdc-req-body-realm body))))
	  (clt (find-spn (principal-string (kdc-req-body-cname body) (kdc-req-body-realm body)))))
      (unless srv (error 'krb-error-t :err (make-krb-error)))
      (unless clt (error 'krb-error-t :err (make-krb-error)))
      ;; one of the preauth MUST be a :TGS-REQ
      nil)))

(defun process-request (buffer count)
  (flexi-streams:with-output-to-sequence (out)
    (flexi-streams:with-input-from-sequence (in buffer :end count)
      (let ((res 
	     (handler-case 
		 (let ((req (decode-kdc-req in)))
		   (ecase (kdc-req-type req)
		     (10 ;; TGS-REQ
		      (generate-tgs-rep req))
		     (12 ;; AS-REQ 
		      (generate-as-rep req))))
	       (krb-error-t (e)
		 (kdc-log :error "KRB error: ~A" e)
		 (krb-error-err e))
	       (error (e) 
		 (kdc-log :error "Failed to process: ~A" e)
		 (generate-error :generic *default-realm*)))))
	(etypecase res
	  (kdc-rep (encode-kdc-rep out res))
	  (krb-error (encode-krb-error out res)))))))








;; -----------------------------------------------------------------

(defconstant +kdc-port+ 88)

(defstruct kdc-server 
  exiting
  timeout
  thread)

(defun purge-connections (conns now)
  (mapcan (lambda (conn)
	    (cond
	      ((< (cadr conn) now)
	       ;; expired, close it
	       (usocket:socket-close (car conn))
	       nil)
	      (t
	       ;; still active, keep it
	       (list conn))))
	  conns))

(defun run-kdc-server (server)
  (let ((tcp (usocket:socket-listen nil +kdc-port+
				    :reuse-address t
				    :element-type '(unsigned-byte 8)))
	(udp (usocket:socket-connect nil 0
				     :protocol :datagram
				     :element-type '(unsigned-byte 8)
				     :local-port +kdc-port+))
	(conns nil))
    (unwind-protect 
	 (do ((udp-buffer (nibbles:make-octet-vector 32768))
	      (now (get-universal-time) (get-universal-time)))
	     ((kdc-server-exiting server))
	   ;; iterate over the conns and clear them out if expired
	   (setf conns (purge-connections conns now))
	   ;; wait for input from the sockets/connections
	   (let ((socks (usocket:wait-for-input (append (list tcp udp) conns)
						:timeout 1
						:ready-only t)))
	     (dolist (sock socks)
	       (etypecase sock
		 (usocket:stream-server-usocket
		  (let ((conn (usocket:socket-accept sock)))
		    ;; log the connection
		    (kdc-log :info "TCP ~A:~A" (usocket:get-peer-address conn) (usocket:get-peer-port conn))
		    (push (list conn (+ now (kdc-server-timeout server))) conns)))
		 ;; accept the connection
		 (usocket:datagram-usocket
		  ;; read from the datagram
		  (multiple-value-bind (%buffer count remote-host remote-port) (usocket:socket-receive sock udp-buffer (length udp-buffer))
		    (declare (ignore %buffer))
		    ;; log the connections 
		    (kdc-log :info "UDP ~A:~A" remote-host remote-port)
		    (let ((resp-buffer (process-request udp-buffer count)))
		      (usocket:socket-send sock resp-buffer (length resp-buffer)
					   :host remote-host
					   :port remote-port))))
		 (usocket:stream-usocket
		  ;; read from tcp
		  (let ((len (nibbles:read-ub32/be (usocket:socket-stream sock))))
		    (read-sequence udp-buffer (usocket:socket-stream sock) :end len)
		    (let ((resp-buffer (process-request udp-buffer len)))
		      (nibbles:write-ub32/be (length resp-buffer) (usocket:socket-stream sock))
		      (write-sequence resp-buffer (usocket:socket-stream sock))
		      (force-output (usocket:socket-stream sock)))))))))
      (dolist (conn conns)
	(usocket:socket-close (car conn)))
      (usocket:socket-close tcp)
      (usocket:socket-close udp))))
  

(defvar *server* nil)

(defun start-kdc-server (&key timeout)
  (when *server* (error "KDC already running"))
  (setf *server* (make-kdc-server :timeout (or timeout 60)))
  (setf (kdc-server-thread *server*)
	(bt:make-thread (lambda ()
			  (run-kdc-server *server*))
			:name "kdc-server-thread"))
  *server*)
	
(defun stop-kdc-server ()
  (unless *server* (error "No KDC server running"))
  (setf (kdc-server-exiting *server*) t)
  (bt:join-thread (kdc-server-thread *server*))
  (setf *server* nil))


