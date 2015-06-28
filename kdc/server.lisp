;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:cerberus-kdc)


;; We have two jobs to do here:
;; 1. Provide the initial authentication, i.e. run as the Authentication Server (AS). 
;; We validate requests by checking the encrypted timestamp (pa-timestamp). Almost
;; always we will be providing tickets for the TGS i.e. ticket-granting tickets.
;; But it is permissable to provide tickets for any principal.
;;
;; 2. Generate tickets for any principal. We must be provided with a TGT, i.e. a ticket
;; for ourselves. We then generate a ticket for the requested principal.
;;


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

(defun select-etype (client-etypes server-etypes)
  (car (intersection client-etypes server-etypes)))

(defun select-key (client-keys supported-key-types)
  (find (select-etype (mapcar #'encryption-key-type client-keys)
		      supported-key-types)
	client-keys
	:key #'encryption-key-type))

(defun generate-session-key (etype)
  (make-encryption-key 
   :type etype
   :value (random-to-key etype 
			 ;; this doesn't work because some types return 1 here instead of their realm seed length 
			 (usb8 (loop :for i :below (profile-key-seed-length etype) 
				  :collect (random 256))))))

(defun generate-ticket (client server realm etypes &key start-time end-time flags)
  (declare (type principal-name client server)
	   (type string realm))
  (let ((sentry (find-spn (principal-string client realm))))
    (unless sentry 
      (error 'krb-error-t :err (generate-error :s-principal-unknown realm)))
    (let ((key (select-key (getf sentry :keys) etypes)))
      (make-ticket :realm realm
		   :sname server
		   :enc-part 
		   (encrypt-data (encryption-key-type key)
				 (pack #'encode-enc-ticket-part 
				       (make-enc-ticket-part :flags flags
							     :key (generate-session-key (encryption-key-type key))
							     :crealm realm
							     :cname client
							     :transited (make-transited-encoding :type 1)
							     :authtime (get-universal-time)
							     :starttime start-time
							     :endtime (or end-time (time-from-now :weeks 6))))	
				 (encryption-key-value key)
				 :usage :ticket)))))

;; allow a 5 minute maximum clock skew 
(defconstant +maximum-skew+ (* 5 60)) 

(defun authenticate-pa-timestamp (data key-list realm)
  ;; first find the key matching the encryption type of the auth data
  (let ((key (find-if (lambda (k)
			(eq (encryption-key-type k) (encrypted-data-type data)))
		      key-list)))
    (unless key 
      (error 'krb-error-t :err (generate-error :preauth-failed realm)))
    (let ((timestamp (unpack #'decode-pa-enc-ts-enc 
			     (decrypt-data data (encryption-key-value key)
					   :usage :pa-enc-timestamp))))
      (unless (< (abs (- (pa-enc-ts-enc-patimestamp timestamp) (get-universal-time)))
		 +maximum-skew+)
	(error 'krb-error-t :err (generate-error :preauth-failed realm)))))
  t)


(defun generate-as-response (req)
  (declare (type kdc-req req))
  (let* ((preauth (kdc-req-data req))
	 (body (kdc-req-req-body req))
	 (realm (kdc-req-body-realm body)))
	 
    ;; start by finding the keys for the client and server 
    (let ((ckeys (or (find-spn-keys (principal-string (kdc-req-body-cname body) realm))
		     (error 'krb-error-t :err (generate-error :c-principal-unknown realm)))))
      ;; preauthenticate 
      (let ((patimestamp (find-if (lambda (pa)
				    (eq (pa-data-type pa) :enc-timestamp))
				  preauth)))
	(unless patimestamp 
	  (error 'krb-error-t :err (generate-error :padata-type-nosupp realm)))
	(authenticate-pa-timestamp (pa-data-value patimestamp) ckeys realm)

	;; preauthentication has succeeded, grant the ticket 
	(let* ((end-time (time-from-now :weeks 6))
	       (flags nil)
	       (ticket 
		(generate-ticket (kdc-req-body-cname body)
				 (kdc-req-body-sname body)
				 realm
				 (mapcar #'encryption-key-type ckeys)
				 :end-time end-time
				 :flags flags)))
	  (let ((ckey (select-key ckeys (kdc-req-body-etype body))))
	    (unless ckey 
	      (error 'krb-error-t :err (generate-error :etype-nosupp realm)))
	    (make-kdc-rep :type :as
			  :crealm realm
			  :cname (kdc-req-body-cname body)
			  :ticket ticket 
			  :enc-part (encrypt-data (encryption-key-type ckey)
						  (pack #'encode-enc-as-rep-part 
							(make-enc-kdc-rep-part :key (generate-session-key (encryption-key-type ckey))
									       :nonce (kdc-req-body-nonce body)
									       :flags flags
									       :authtime (get-universal-time)
									       :endtime end-time
									       :srealm realm
									       :sname (kdc-req-body-sname body)))
						  (encryption-key-value ckey)
						  :usage :as-rep))))))))


;; ----------------------------------------------------

;; this should be bound to the keylist for the krbtgt/REALM principal.
(defvar *krbtgt-keylist* nil)

(defun authenticate-pa-tgs (data)
  (let ((ap-req (unpack #'decode-ap-req data)))
    ;; check the ticket 
    (valid-ticket-p *krbtgt-keylist* ap-req)))


;; this should authenticate and then generate a ticket for the principal 
(defun generate-tgs-response (req)
  (declare (type kdc-req req))
  (let* ((patgs (find-if (lambda (pa)
			   (eq (pa-data-type pa) :tgs-req))
			 (kdc-req-data req)))
	 (body (kdc-req-req-body req))
	 (realm (kdc-req-body-realm body)))
    (unless patgs 
      (error 'krb-error-t :err (generate-error :preauth-failed realm)))

    (let* ((keys (find-spn-keys (principal-string 
				 (kdc-req-body-cname body) realm)))
	   (ticket (generate-ticket (kdc-req-body-cname body)
				    (kdc-req-body-sname body)
				    realm
				    (mapcar #'encryption-key-type keys))))
      (make-kdc-rep :type :tgs
		    :crealm realm
		    :cname (kdc-req-body-cname body)
		    :ticket ticket 
		    :enc-part 
		    (encrypt-data (encryption-key-type (car keys))
				  (pack #'encode-enc-tgs-rep-part 
					(make-enc-kdc-rep-part))
				  (encryption-key-value (car keys))
				  :usage :tgs-rep)))))
    


;; -----------------------------------------------------


(defun process-request (buffer count)
  (kdc-log :info "~X" (subseq buffer 0 count))
  (let ((id (unpack #'decode-identifier buffer)))
    (flexi-streams:with-output-to-sequence (out)
      (flexi-streams:with-input-from-sequence (in buffer :end count)
	(let ((res 
	       (handler-case
		   (let ((req (ecase id 
				(10 (decode-as-req in))
				(12 (decode-tgs-req in)))))
		     (ecase (kdc-req-type req)
		       (:tgs ;; TGS-REQ		      
			(kdc-log :info "TGS-REQ")
			(generate-tgs-response req))
		       (:as ;; AS-REQ 
			(kdc-log :info "AS-REQ")
			(generate-as-response req))))
		 (krb-error-t (e)
		   (kdc-log :error "KRB error: ~A" e)
		   (krb-error-err e))
		 (error (e) 
		   (kdc-log :error "Failed to process: ~A" e)
		   (generate-error :generic *default-realm*)))))
	  (etypecase res
	    (kdc-rep (ecase id 
		       (10 (encode-as-rep out res))
		       (12 (encode-tgs-rep out res))))
	    (krb-error-t (encode-krb-error out res))))))))








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
	       (ignore-errors (usocket:socket-close (car conn)))
	       nil)
	      (t
	       ;; still active, keep it
	       (list conn))))
	  conns))

(defun run-kdc-server (server)
  (let ((tcp (usocket:socket-listen usocket:*wildcard-host* +kdc-port+
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
	   (let ((socks (usocket:wait-for-input (append (list tcp udp) 
							(mapcar #'car conns))
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
		  (kdc-log :info "Reading TCP req")
		  (handler-case 
		      (let ((len (nibbles:read-ub32/be (usocket:socket-stream sock))))
			(read-sequence udp-buffer (usocket:socket-stream sock) :end len)
			(let ((resp-buffer (process-request udp-buffer len)))
			  (nibbles:write-ub32/be (length resp-buffer) (usocket:socket-stream sock))
			  (write-sequence resp-buffer (usocket:socket-stream sock))
			  (force-output (usocket:socket-stream sock))))
		    (error (e)
		      (kdc-log :info "Error processing ~A" e)
		      (ignore-errors (usocket:socket-close sock))
		      (setf conns (remove sock conns :key #'car :test #'eql)))))))))
      (dolist (conn conns)
	(ignore-errors (usocket:socket-close (car conn))))
      (usocket:socket-close tcp)
      (usocket:socket-close udp))))
  

(defvar *kdc-server* nil)

(defun start-kdc-server (&key (realm *default-realm*) timeout)
  (when *kdc-server* (error "KDC already running"))
  (setf *krbtgt-keylist* (or (find-spn-keys (format nil "krbtgt/~A@~A" realm realm))
			     (error "No SPN for krbtgt"))
	*kdc-server* (make-kdc-server :timeout (or timeout 60)))
  (setf (kdc-server-thread *kdc-server*)
	(bt:make-thread (lambda ()
			  (run-kdc-server *kdc-server*))
			:name "kdc-server-thread"))
  *kdc-server*)
	
(defun stop-kdc-server ()
  (unless *kdc-server* (error "No KDC server running"))
  (setf (kdc-server-exiting *kdc-server*) t)
  (bt:join-thread (kdc-server-thread *kdc-server*))
  (setf *kdc-server* nil))


