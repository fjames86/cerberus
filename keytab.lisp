;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:cerberus)

;; http://www.gnu.org/software/shishi/manual/html_node/The-Keytab-Binary-File-Format.html
;; keytab {
;;       uint16_t file_format_version;                    /* 0x502 */
;;       keytab_entry entries[*];
;;   };

;;   keytab_entry {
;;       int32_t size;
;;       uint16_t num_components;    /* sub 1 if version 0x501 */
;;       counted_octet_string realm;
;;       counted_octet_string components[num_components];
;;       uint32_t name_type;   /* not present if version 0x501 */
;;       uint32_t timestamp;
;;       uint8_t vno8;
;;       keyblock key;
;;       uint32_t vno; /* only present if >= 4 bytes left in entry */
;;   };

;;   counted_octet_string {
;;       uint16_t length;
;;       uint8_t data[length];
;;   };

;;   keyblock {
;;       uint16_t type;
;;       counted_octet_string;
;;   };

(defun read-counted-string (stream)
  (let ((len (nibbles:read-sb16/be stream)))
    (let ((v (nibbles:make-octet-vector len)))
      (read-sequence v stream)
      v)))

(defun read-etype-enum (stream)
  (let ((n (nibbles:read-sb16/be stream)))
    (case n
      (1 :des-cbc-crc)
      (2 :des-cbc-md4)
      (3 :des-cbc-md5)
      (5 :des3-cbc-md5)
      (7 :des3-cbc-sha1) ;; deprecated, should use the -kd version instead
      (16 :des3-cbc-sha1-kd)
      (17 :aes128-cts-hmac-sha1-96)
      (18 :aes256-cts-hmac-sha1-96)
      (23 :rc4-hmac)
      (24 :rc4-hmac-exp)
      (-135 :rc4-hmac-old-exp)
      (otherwise n))))

(defun read-principal-name-type (stream)
  (let ((n (nibbles:read-ub32/be stream)))
    (case n
      (0 :unknown)
      (1 :principal)
      (2 :srv-inst)
      (3 :srv-host)
      (4 :srv-xhost)
      (5 :uid)
      (6 :x500)
      (7 :smtp)
      (10 :enterprise)
      (otherwise n))))

(defstruct keytab-entry 
  etype
  key
  principal
  realm
  timestamp)


(defun read-keytab-entry (stream)
  ;; start by reading the size
  (let ((size (nibbles:read-sb32/be stream))
	(entry (make-keytab-entry))
	(pos (file-position stream)))
    ;; if the size is -ve then the entry is empty, read the bytes and advance to the next entry
    (when (< size 0)
      (dotimes (i (- size))
	(read-byte stream))
      (return-from read-keytab-entry nil))

    ;; read the object from the stream
    (let ((ncomponents (nibbles:read-ub16/be stream)))
      ;; read the realm
      (setf (keytab-entry-realm entry)
	    (babel:octets-to-string (read-counted-string stream))
	    ;; principal name
	    (keytab-entry-principal entry)
	    (make-principal-name :name (loop :for i :below ncomponents :collect 
					  (babel:octets-to-string (read-counted-string stream)))
				 :type (read-principal-name-type stream))
	    ;; timestamp
	    (keytab-entry-timestamp entry)
	    (+ (nibbles:read-ub32/be stream) (encode-universal-time 0 0 0 1 1 1970 0)))
      ;; ignore the vno8
      (read-byte stream)
      ;; the key 
      (setf (keytab-entry-etype entry)
	    (read-etype-enum stream)
	    (keytab-entry-key entry)
	    (read-counted-string stream))
      ;; advance the file position
      (file-position stream (+ pos size))
      entry)))

(defun load-keytab (pathspec)
  "Load the keytab file named by pathspec."
  (with-open-file (f pathspec :direction :input :element-type '(unsigned-byte 8))
    ;; read the version
    (nibbles:read-ub16/be f)
    ;; read the entries
    (let ((size (file-length f)))
      (do ((entries nil))
	  ((>= (file-position f) size) entries)
	(let ((entry (read-keytab-entry f)))
	  (when entry
	    (push entry entries)))))))
    
