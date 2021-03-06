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

(defun preferred-etype (etypes)
  (let ((all-types (cerberus::list-all-profiles)))
    (dolist (etype all-types)
      (when (member etype etypes)
        (return-from preferred-etype etype))))
  nil)

(defun select-etype (client-etypes server-etypes)
  (preferred-etype (intersection client-etypes server-etypes)))

(defun select-key (client-keys supported-key-types)
  (find (select-etype (mapcar #'encryption-key-type client-keys)
		      supported-key-types)
	client-keys
	:key #'encryption-key-type))

(defun generate-session-key (etype)
  (make-encryption-key 
   :type etype
   :value (random-to-key etype 
			 ;; this doesn't work because some types return 1 here instead of their real seed length 
			 (usb8 (loop :for i :below (profile-key-seed-length etype)
				  :collect (random 256))))))

(defun generate-ticket (client server realm etypes &key start-time end-time flags)
  (declare (type principal-name client server)
           (type string realm))
  (let ((sentry (find-spn (principal-string server realm))))
    (unless sentry 
      (error 'krb-error-t :err (generate-error :s-principal-unknown realm)))
    (let* ((key (select-key (getf sentry :keys) etypes))
           (session-key (generate-session-key (encryption-key-type key))))
      (kdc-log :trace "Generating ticket for ~A" (principal-string server realm))
      (kdc-log :trace "Encrypting ticket with ~A ~A" (encryption-key-type key) (encryption-key-value key))
      (values 
       (make-ticket :realm realm
                    :sname server
                    :enc-part 
                    (encrypt-data (encryption-key-type key)
                                  (pack #'encode-enc-ticket-part 
                                        (make-enc-ticket-part :flags flags
                                                              :key session-key 
                                                              :crealm realm
                                                              :cname client
                                                              :transited (make-transited-encoding :type 1)
                                                              :authtime (get-universal-time)
                                                              :starttime start-time
                                                              :endtime (or end-time (time-from-now :weeks 6))))	
                                  (encryption-key-value key)
                                  :usage :ticket))
       session-key))))

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
               (flags nil))
          (multiple-value-bind (ticket session-key)
              (generate-ticket (kdc-req-body-cname body)
                               (kdc-req-body-sname body)
                               realm
                               (mapcar #'encryption-key-type ckeys)
                               :end-time end-time
                               :flags flags)
            (let ((ckey (select-key ckeys (kdc-req-body-etype body))))
              (unless ckey 
                (error 'krb-error-t :err (generate-error :etype-nosupp realm)))
              (make-kdc-rep :type :as
                            :crealm realm
                            :cname (kdc-req-body-cname body)
                            :ticket ticket 
                            :enc-part (encrypt-data (encryption-key-type ckey)
                                                    (pack #'encode-enc-as-rep-part 
                                                          (make-enc-kdc-rep-part :key session-key
                                                                                 :nonce (kdc-req-body-nonce body)
                                                                                 :flags flags
                                                                                 :authtime (get-universal-time)
                                                                                 :endtime end-time
                                                                                 :srealm realm
                                                                                 :sname (kdc-req-body-sname body)))
                                                    (encryption-key-value ckey)
                                                    :usage :as-rep)))))))))


;; ----------------------------------------------------

;; this should be bound to the keylist for the krbtgt/REALM principal.
(defvar *krbtgt-keylist* nil)

;; the ticket is encrypted with the krbtgt's key. decrypt this first.
;; inside the ticket is the session key. Use this to decrypt the authenticator to validate.
;; is really that simple, essentially the same as normal. Only difference is we need to use a different 
;; usage value for decrpyting the authenticator.

(defun decrypt-krbtgt-ticket-enc-part (ticket)
  "Decrypt the enc-part of the ticket."
  (let ((enc (ticket-enc-part ticket)))
    (let ((key (find-if (lambda (k)
                          (eq (encryption-key-type k) (encrypted-data-type enc)))
                        *krbtgt-keylist*)))
      (unless key 
        (error "No key for encryption type ~S" (encrypted-data-type enc)))
                  
      (kdc-log :info "Decrypting ticket with ~A ~A" 
               (encryption-key-type key) (encryption-key-value key))

      (unpack #'decode-enc-ticket-part 
              (decrypt-data enc 
                            (encryption-key-value key)
                            :usage :ticket)))))


(defun authenticate-pa-tgs (pa)
  ;; check the ticket 
  (let* ((ap-req (pa-data-value pa))
         (ticket (ap-req-ticket ap-req))
         (enc-auth (ap-req-authenticator ap-req)))
    ;; start by decrypting the ticket to get the session key 
    (let ((enc (decrypt-krbtgt-ticket-enc-part ticket)))
      (setf (ticket-enc-part ticket) enc)
      
      (let ((key (enc-ticket-part-key enc)))
        ;; now decrypt the authenticator using the session key we got from the ticket
        (let ((a (unpack #'decode-authenticator 
                         (decrypt-data enc-auth (encryption-key-value key)
                                       :usage :pa-tgs-req))))

          ;; check the contents of the authenticator against the ticket....
          ;; check the crealm and cname match
          (unless (string= (enc-ticket-part-crealm enc) (authenticator-crealm a))
            (error 'kerberos-error 
                   :stat :badmatch
                   :desc "Client realm mismatch"))

          ;; check the ctime and cusec match
          (unless (every #'string= 
                         (principal-name-name (enc-ticket-part-cname enc))
                         (principal-name-name (authenticator-cname a)))
            (error 'kerberos-error 
                   :stat :badmatch
                   :desc "Principal name mismatch"))

          ;; check the client time is within acceptable skew of currnet time
          (unless (< (abs (- (get-universal-time) (authenticator-ctime a)))
                     +acceptable-skew+)
            (error 'kerberos-error :stat :skew))

          ;; check the endtime is less than the current time
          (unless (< (get-universal-time) (enc-ticket-part-endtime enc))
            (error 'kerberos-error :stat :tkt-expired))

          ;; fixup the ap-req and return that
          (setf (ap-req-ticket ap-req) ticket
                (ap-req-authenticator ap-req) a)

          ap-req)))))


;; this should authenticate and then generate a ticket for the principal 
(defun generate-tgs-response (req)
  (declare (type kdc-req req))
  (let* ((body (kdc-req-req-body req))
         (realm (kdc-req-body-realm body))
         (patgs (or (find-if (lambda (pa)
                               (eq (pa-data-type pa) :tgs-req))
                             (kdc-req-data req))
                    (error 'krb-error-t :err (generate-error :preauth-failed realm))))
         (ap-req (handler-case (let ((*break-on-signals* 'error)) (authenticate-pa-tgs patgs))
                   (error (e)
                     (kdc-log :error "PA failed: ~A" e)
                     (error 'krb-error-t :err (generate-error :preauth-failed realm))))))

    (let* ((keys (find-spn-keys (principal-string 
                                 (kdc-req-body-cname body) realm)))
           (key (ap-req-session-key ap-req))
           (end-time (time-from-now :weeks 6)))
      (multiple-value-bind (ticket session-key)
          (generate-ticket (kdc-req-body-cname body)
                           (kdc-req-body-sname body)
                           realm
                           (mapcar #'encryption-key-type keys)
                           :end-time end-time)
        (make-kdc-rep :type :tgs
                      :crealm realm
                      :cname (kdc-req-body-cname body)
                      :ticket ticket 
                      :enc-part 
                      (encrypt-data (encryption-key-type key)
                                    (pack #'encode-enc-tgs-rep-part 
                                          (make-enc-kdc-rep-part :key session-key
                                                                 :nonce (kdc-req-body-nonce body)
                                                                 :authtime (get-universal-time)
                                                                 :endtime end-time
                                                                 :srealm realm
                                                                 :sname (kdc-req-body-sname body)))
                                    (encryption-key-value key)
                                    :usage :tgs-rep))))))



;; -----------------------------------------------------


(defun process-request (buffer count)
;;  (kdc-log :info "PROCESS-REQUEST: ~X" (subseq buffer 0 count))
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
            (krb-error (encode-krb-error out res))))))))

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
  (kdc-log :info "Starting KDC server")
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
		  (kdc-log :trace "Reading TCP req")
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
      (usocket:socket-close udp)
      (kdc-log :info "Stopping KDC server"))))
  

(defvar *kdc-server* nil)
(defvar *rpc-server* nil)

(defun start-kdc-server (realm &key timeout (rpc-server t))
  (when *kdc-server* (error "KDC already running"))
  (let ((name (format nil "krbtgt/~A@~A" realm realm)))
    (setf *krbtgt-keylist* (or (find-spn-keys name)
                               (error "No SPN for krbtgt"))
          *kdc-server* (make-kdc-server :timeout (or timeout 60)))
    (setf (kdc-server-thread *kdc-server*)
          (bt:make-thread (lambda ()
                            (run-kdc-server *kdc-server*))
                          :name "kdc-server-thread"))

    (when rpc-server 
      (setf *rpc-server* (frpc:make-rpc-server)) ;; :programs '(kdc-prog)))
      (let ((cerberus:*current-user* (cerberus:logon-service name *krbtgt-keylist* :mode :network)))
        (frpc:gss-init))
      (frpc:start-rpc-server *rpc-server*))
    
    nil))
	
(defun stop-kdc-server ()
  (unless *kdc-server* (error "No KDC server running"))
  (setf (kdc-server-exiting *kdc-server*) t)
  (bt:join-thread (kdc-server-thread *kdc-server*))
  (setf *kdc-server* nil)

  (when *rpc-server* 
    (frpc:stop-rpc-server *rpc-server*)
    (setf *rpc-server* nil))
  
  nil)




