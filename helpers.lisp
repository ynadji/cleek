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

;; copy permutation algo from python code
(defun anonip! (ip)
  (declare (ignore ip)))

;; probably need to replace the symbol with a call to (PRODUCTIVE? LOG) in main.
(defun productive? (zeek-log)
  (declare (ignore zeek-log)))

;; this might be faster as a macro, since you (might?) get the benefits of the
;; scanner caching for free.
(defmacro ~ (field regex)
  `(cl-ppcre:scan ,regex ,field))
