;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; This file contains the codes necessary to wrap the underlying 
;;; kerberos calls in a gss-like API
;;; 

(in-package #:cerberus)

;; ----------- for the client ---------------

(defgeneric acquire-credential (mech-type principal &key)
  (:documentation "Acquire credentials for the principal named. Returns a CREDENTIALS, for input into INITIALIZE-SECURITY-CONTEXT. 

c.f. GSS_Acquire_cred.
"))

(defgeneric initialize-security-context (credentials &key)
  (:documentation "Returns a security context to be sent to the application server.

c.f. GSS_Init_sec_context
"))

;; ---------- for the application server -----------

(defgeneric accept-security-context (credentials context &key)
  (:documentation "CREDENTIALS are credentials for the server principal. CONTEXT is the packed 
buffer sent from the client. It should be as returned from INITIALIZE-SECURITY-CONTEXT.

c.f. GSS_Accept_sec_context
"))

(defgeneric process-context-token (context &key)
  (:documentation "CONTEXT is returned from ACCEPT-SECURITY-CONTEXT.

c.f. GSS_Process_context_token
"))

;; ------------------ per-message calls --------------------------

;; Get_MIC()
(defgeneric get-mic (context-handle message &key qop))

;; GSS_VerifyMIC()
(defgeneric verify-mic (context-handle message message-token))

;; GSS_Wrap()
(defgeneric wrap (context-handle message &key conf-req-flag qop))

;; GSS_Unwrap()
(defgeneric unwrap (context-handle message))


