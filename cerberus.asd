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
   (:file "encryption" :depends-on ("messages")))
  :depends-on (:alexandria :nibbles :flexi-streams :babel :ironclad))


