(in-package :cleek)

;; from fleek to support:
;;
;; * annotations (IP-LIKEs, default columns, default new column namer, modify at runtime)
;; * DNS additions
;; * timestamp filter
;; * productive (these can be handled in general by filters)

(defgeneric contains? (container x)
  (:documentation "Does CONTAINER contain X?")
  (:method ((container na::ip+) (x na::ip-like))
    (na:contains? container x))
  (:method ((container na::ip+) (x string))
    (na:contains? container (na:make-ip-address x)))
  (:method ((container hash-table) (x t))
    (gethash x container))
  (:method ((container cons) (x string))
    (member x container :test #'equal))
  (:method ((container cons) (x t))
    (member x container))
  (:method ((container simple-vector) (x string))
    (find x container :test #'equal))
  (:method ((container simple-vector) (x t))
    (find x container))
  (:method ((substring string) (x string))
    (str:contains? substring x)))
(serapeum:defalias c? #'contains?)

;; starts-with?, starts?
;;; only makes sense for strings, no?
;; ends-with?, ends?
;;; only makes sense for strings, no?

(serapeum:defalias s= #'string=)
;;; you could shadow = from CL-USER and do the same kind of dispatch.
;; matches from a file
;;; maybe something like:
;;; (na:contains? (f "filename" :str/:ip/:domain) #I(:o_h))
;;; would load the ips/nets in "filename" and check against contains? you'd want to #. on it so it gets evaluated
;;; immediately and stored as the #<IP-SET> object (or LIST or w/e it is).

(defun e2ld (domain)
  (ignore-errors (cl-tld:get-domain-suffix domain)))

(defun tld (domain)
  (ignore-errors (cl-tld:get-tld domain)))

(defun hash! (field)
  (declare (ignore field)))

(let* ((v6-permutors (loop repeat 16 collect (ax:shuffle (coerce (loop for x upto 255 collect x) 'vector))))
       (v4-permutors (nthcdr 12 v6-permutors))
       (v4-string-permutors (loop for p in v4-permutors collect (map 'vector #'write-to-string p))))
  ;; TODO: IP-ADDRESS operation is destructive but STRING one is not. Hmm.
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
          (na:str (anonip (na:make-ip-address ip)))))
    (:method ((ip na::ip-address))
      (let ((version (na:version ip)))
        (loop for offset from (if (= version 4) 24 120) downto 0 by 8
              for permutor in (if (= version 4) v4-permutors v6-permutors)
              do (setf (ldb (byte 8 offset) (slot-value ip 'netaddr::int))
                       (aref permutor (ldb (byte 8 offset) (slot-value ip 'netaddr::int)))))
        (setf (slot-value ip 'netaddr:str) (na::ip-int-to-str (na:int ip) version))
        ip)))

  ;; TODO: lazy way: anonymize the whole IP, but still apply the mask which will just 0 out the bytes that don't matter
  ;; smarter way: only anonymize the bytes that aren't masked.
  (defgeneric anoncidr (cidr)
    (:method ((cidr string))
      (error "not implemented!"))
    (:method ((cidr na::ip-network))
      (error "not implemented!"))))

;; is there a reasonable way to anonymize domains?

;; probably need to replace the symbol with a call to (PRODUCTIVE? LOG) in main.
(defun productive? (zeek-log)
  (declare (ignore zeek-log)))

;; this might be faster as a macro, since you (might?) get the benefits of the
;; scanner caching for free.
(defmacro ~ (field regex)
  `(cl-ppcre:scan ,regex ,field))
