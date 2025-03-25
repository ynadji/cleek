(in-package :cleek)

;; from fleek to support:
;;
;; * annotations (IP-LIKEs, default columns, default new column namer, modify at runtime)
;; * DNS additions
;; * modify column (turn /32 to /24 or w/e)
;; * timestamp filter
;; * productive (these can be handled in general by filters)

;; contains?, c?
;;; you could dispatch this so it works with: vectors and subnets.
;;; you will need to know the TYPE of the field as well.
;; starts-with?, starts?
;;; only makes sense for strings, no?
;; ends-with?, ends?
;;; only makes sense for strings, no?
;; string=, s=
;;; you could shadow = from CL-USER and do the same kind of dispatch.
;; matches from a file
;;; maybe something like:
;;; (na:contains? (f "filename" :str/:ip/:domain) #I(:o_h))
;;; would load the ips/nets in "filename" and check against contains? you'd want to #. on it so it gets evaluated
;;; immediately and stored as the #<IP-SET> object (or LIST or w/e it is).

;; this might be faster as a macro, since you (might?) get the benefits of the
;; scanner caching for free.
(defmacro ~ (field regex)
  `(cl-ppcre:scan ,regex ,field))
