;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(asdf:defsystem :cerberus
  :name "cerberus"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "A Kerberos implementation"
  :license "MIT"
  :version "1.0.1"
  :components
  ((:file "package")
   (:file "asn1" :depends-on ("package"))
   (:file "messages" :depends-on ("asn1"))
   (:file "encryption" :depends-on ("messages" "errors"))
   (:file "checksums" :depends-on ("encryption"))
   (:file "ciphers" :depends-on ("errors" "checksums"))
   (:file "errors" :depends-on ("package" "asn1"))
   (:file "preauth" :depends-on ("asn1" "ciphers"))
   (:file "client" :depends-on ("package" "preauth"))
   (:file "keytab" :depends-on ("package" "asn1"))
   (:file "gss" :depends-on ("client")))
  :depends-on (:alexandria :nibbles :flexi-streams :babel 
	       :ironclad :usocket :glass))


