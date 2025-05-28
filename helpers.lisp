(in-package :cleek)

(defgeneric contains? (container x)
  (:documentation "Returns a truthy value if CONTAINER contains the value X. Support multiple container types including: NETADDR:IP+, CL-DNS:DOMAIN-TRIE, HASH-TABLE, LIST, VECTOR, and STRING.")
  (:method ((container na::ip+) (x na::ip-like))
    (na:contains? container x))
  (:method ((container na::ip+) (x string))
    (na:contains? container (na:make-ip-address x)))
  (:method ((container cl-dns::domain-trie) (x string))
    (cl-dns:contains-domain? container x))
  (:method ((container hash-table) (x t))
    (gethash x container))
  (:method ((container cons) (x string))
    (member x container :test #'equal))
  (:method ((container cons) (x t))
    (member x container))
  (:method ((container vector) (x string))
    (find x container :test #'equal))
  (:method ((container vector) (x t))
    (find x container))
  (:method ((substring string) (x string))
    (str:contains? substring x)))
(serapeum:defalias c? #'contains? "Alias for CONTAINS?")

(serapeum:defalias s= #'string= "Alias for STRING=")
(serapeum:defalias s/= #'string/= "Alias for STRING/=")

(defun f (path &optional (type :str) (max-vector-size 7))
  "Read in a list of TYPE data from a file, one per line, to use as a container for CONTAINS? searches. TYPE must be one of (:STR :IP :DNS). :DNS builds a CL-DNS:TRIE to check for domain membership, :IP builds a NETADDR:IP-SET for IP/CIDR membership, and :STR builds an array (or HASH-TABLE if the file contains over MAX-VECTOR-SIZE items)."
  (let ((lines (uiop:read-file-lines path)))
    (ecase type
      (:str (let ((len (length lines)))
              (if (<= len max-vector-size)
                  (coerce lines 'simple-vector) ;; so #. trick works
                  (ax:alist-hash-table (mapcar #'cons lines (make-list len :initial-element t))
                                       :test #'equal :size len))))
      (:ip (na:make-ip-set (mapcar #'na::make-ip-like lines)))
      (:dns (apply #'cl-dns:make-trie lines)))))

;; basically what you want but you need to figure out the timezone bits.
(defgeneric ts (ts)
  (:documentation "Parse column values as a LOCAL-TIME:TIMESTAMP.")
  (:method ((timestring string))
    (local-time:parse-timestring timestring))
  (:method ((ts real))
    (double-to-timestamp ts)))

(serapeum:defalias ts< #'local-time:timestamp< "Alias for LOCAL-TIME:TIMESTAMP<")
(serapeum:defalias ts<= #'local-time:timestamp<= "Alias for LOCAL-TIME:TIMESTAMP<=")
(serapeum:defalias ts> #'local-time:timestamp> "Alias for LOCAL-TIME:TIMESTAMP>")
(serapeum:defalias ts>= #'local-time:timestamp>= "Alias for LOCAL-TIME:TIMESTAMP>=")
(serapeum:defalias ts= #'local-time:timestamp= "Alias for LOCAL-TIME:TIMESTAMP=")
(serapeum:defalias ts/= #'local-time:timestamp/= "Alias for LOCAL-TIME:TIMESTAMP/=")

(defmacro anno (field &rest containers-and-labels)
  "Given a column in FIELD and an even number of pair-wise containers/labels, return the label for which container contains FIELD. A default container can be specified with T. Use with SETF to create a new column based on this label, for example: (setf @orig_label (anno @o_h #.#I(\"192.168.0.0/16\") \"192.168\" \".127.52.\" \"string-contains\" \'(\"fe80::1462:3ff9:fd68:b0fc\") \"list-contains\" t \"unknown\")) creates the column ORIG_LABEL based on IP checks, a string check, a list membership check, and a default case."
  `(cond ,@(loop for (container label) on containers-and-labels by #'cddr
                 if (eq container t)
                   collect `(t ,label)
                 else
                   collect `((contains? ,container ,field) ,label))))

;; TODO: Should these return 'CL:NULL if they fail instead of NIL?
(defun e2ld (domain)
  "Return the effective second-level domain for a DOMAIN, e.g., (e2ld \"foo.bar.google.com\") => \"google.com\"."
  (ignore-errors (cl-tld:get-domain-suffix domain)))

(defun tld (domain)
  "Return the effective top-level domain for a DOMAIN, e.g., (e2ld \"foo.bar.google.com\") => \"com\"."
  (ignore-errors (cl-tld:get-tld domain)))

(defun sha256-string (string)
  (let* ((key (ironclad:ascii-string-to-byte-array "valkyrie"))
         (hmac (ironclad:make-hmac key :sha256)))
    (ironclad:update-hmac hmac (ironclad:ascii-string-to-byte-array string))
    (ironclad:byte-array-to-hex-string (ironclad:hmac-digest hmac))))

(defgeneric hash (field)
  (:documentation "Hashes a field using a SHA-256 keyed hash. Used for anonymizing logs.")
  (:method ((field string))
    (sha256-string field))
  (:method ((field na::ip-like))
    (sha256-string (na:str field)))
  (:method ((field t))
    (sha256-string (format nil "~a" field))))

(let* ((v6-permutors (loop repeat 16 collect (ax:shuffle (coerce (loop for x upto 255 collect x) 'vector))))
       (v4-permutors (nthcdr 12 v6-permutors))
       (v4-string-permutors (loop for p in v4-permutors collect (map 'vector #'write-to-string p))))
  (defgeneric anonip (ip)
    (:documentation "Anonymize an IP address by permuting each byte with a fixed set of permutations for each byte.")
    (:method ((ip string))
      (if (na::ipv4-str? ip)
          (let ((quads (split-sequence #\. ip)))
            (setf (first quads) (aref (first v4-string-permutors) (parse-integer (first quads)))
                  (second quads) (aref (second v4-string-permutors) (parse-integer (second quads)))
                  (third quads) (aref (third v4-string-permutors) (parse-integer (third quads)))
                  (fourth quads) (aref (fourth v4-string-permutors) (parse-integer (fourth quads))))
            (str:join "." quads))
          (str:downcase (na:str (anonip (na:make-ip-address ip))))))
    (:method ((ip na::ip-address))
      (let ((version (na:version ip))
            (ip (na:make-ip-address (na:int ip))))
        (loop for offset from (if (= version 4) 24 120) downto 0 by 8
              for permutor in (if (= version 4) v4-permutors v6-permutors)
              do (setf (ldb (byte 8 offset) (slot-value ip 'netaddr::int))
                       (aref permutor (ldb (byte 8 offset) (slot-value ip 'netaddr::int)))))
        (setf (slot-value ip 'netaddr:str) (na::ip-int-to-str (na:int ip) version))
        ip)))

  (defgeneric anoncidr (cidr)
    (:documentation "Anonymize a CIDR (or subnet in Zeek parlance) by using ANONIP on its first address and reapplying the netmask.")
    (:method ((cidr string))
      (str:downcase (na:str (anoncidr (na:make-ip-network cidr)))))
    (:method ((cidr na::ip-network))
      (with-slots (na:first-ip na::mask) cidr
        (let ((first-ip-anon (anonip na:first-ip)))
          (na:make-ip-network (format nil "~a/~a" (na:str first-ip-anon) na::mask)))))))

(serapeum:defalias public? #'na:public? "Alias for NETADDR:PUBLIC? which returns T if the IP address is publicly routable. Requires a NETADDR::IP-LIKE (so fully parse with @@).")
(serapeum:defalias private? #'na:private? "Alias for NETADDR:PRIVATE? which returns T if the IP address is privately routable. Requires a NETADDR::IP-LIKE (so fully parse with @@).")
(serapeum:defalias reserved? #'na:reserved? "Alias for NETADDR:RESERVED? which returns T if the IP address is reserved. Requires a NETADDR::IP-LIKE (so fully parse with @@).")

;; is there a reasonable way to anonymize domains?

(defmacro ~ (regex field)
  "Short-hand for CL-PPCRE:SCAN. Implemented as a macro so constant REGEXes only get compiled once."
  `(cl-ppcre:scan ,regex ,field))
