;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defsystem :cerberus-kdc
  :name "cerberus-kdc"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "Kerberos KDC server for cerberus."
  :license "MIT"
  :components
  ((:module :kdc
            :pathname "kdc"
            :components 
            ((:file "package")
             (:file "log" :depends-on ("package"))
             (:file "database" :depends-on ("package"))
             (:file "server" :depends-on ("log" "database"))
             (:file "kdc" :depends-on ("server")))))
  :depends-on (:cerberus :pounds :frpc))
