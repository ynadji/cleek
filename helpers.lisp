(in-package :cleek)

(defgeneric contains? (container x)
  (:documentation "Does CONTAINER contain X?")
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
(serapeum:defalias c? #'contains?)

;; starts-with?, starts?
;;; only makes sense for strings, no?
;; ends-with?, ends?
;;; only makes sense for strings, no?

(serapeum:defalias s= #'string=)
(serapeum:defalias s/= #'string/=)
;;; you could shadow = from CL-USER and do the same kind of dispatch.

(defun f (path &optional (type :str) (max-vector-size 7))
  (let ((lines (uiop:read-file-lines path)))
    (ecase type
      (:str (let ((len (length lines)))
              (if (<= len max-vector-size)
                  (coerce lines 'simple-vector) ;; so #. trick works
                  (ax:alist-hash-table (mapcar #'cons lines (make-list len :initial-element t))
                                       :test #'equal :size len))))
      (:ip (na:make-ip-set (mapcar #'na::make-ip-like lines)))
      (:dns (apply #'cl-dns:make-trie lines)))))

(defmacro anno (field &rest containers-and-labels)
  `(cond ,@(loop for (container label) on containers-and-labels by #'cddr
                 if (eq container t)
                   collect `(t ,label)
                 else
                   collect `((contains? ,container ,field) ,label))))

;; TODO: Should these return 'CL:NULL if they fail instead of NIL?
(defun e2ld (domain)
  (ignore-errors (cl-tld:get-domain-suffix domain)))

(defun tld (domain)
  (ignore-errors (cl-tld:get-tld domain)))

(defun sha256-string (string)
  (let* ((key (ironclad:ascii-string-to-byte-array "valkyrie"))
         (hmac (ironclad:make-hmac key :sha256)))
    (ironclad:update-hmac hmac (ironclad:ascii-string-to-byte-array string))
    (ironclad:byte-array-to-hex-string (ironclad:hmac-digest hmac))))

(defgeneric hash (field)
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
    (:method ((cidr string))
      (str:downcase (na:str (anoncidr (na:make-ip-network cidr)))))
    (:method ((cidr na::ip-network))
      (with-slots (na:first-ip na::mask) cidr
        (let ((first-ip-anon (anonip na:first-ip)))
          (na:make-ip-network (format nil "~a/~a" (na:str first-ip-anon) na::mask)))))))

;; is there a reasonable way to anonymize domains?

;; probably need to replace the symbol with a call to (PRODUCTIVE? LOG) in main.
(defun productive? (zeek-log)
  (declare (ignore zeek-log)))

;; this might be faster as a macro, since you (might?) get the benefits of the
;; scanner caching for free.
(defmacro ~ (field regex)
  `(cl-ppcre:scan ,regex ,field))
