;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(asdf:defsystem :cerberus
  :name "cerberus"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "A Kerberos implementation"
  :license "MIT"
  :components
  ((:file "package")
   (:file "asn1" :depends-on ("package"))
   (:file "messages" :depends-on ("asn1"))
   (:file "encryption" :depends-on ("messages" "errors"))
   (:file "checksums" :depends-on ("encryption"))
   (:file "ciphers" :depends-on ("checksums" "errors"))
   (:file "errors" :depends-on ("package"))
   (:file "preauth" :depends-on ("asn1" "ciphers"))
   (:file "client" :depends-on ("package" "preauth")))
  :depends-on (:alexandria :nibbles :flexi-streams :babel 
	       :ironclad :usocket))


