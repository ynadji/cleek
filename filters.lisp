(in-package :cleek)

;; contains?, c?
;;; you could dispatch this so it works with: vectors and subnets.
;;; you will need to know the TYPE of the field as well.
;; starts-with?, starts?
;;; only makes sense for strings, no?
;; ends-with?, ends?
;;; only makes sense for strings, no?
;; string=, s=
;;; you could shadow = from CL-USER and do the same kind of dispatch.

;; this might be faster as a macro, since you (might?) get the benefits of the
;; scanner caching for free.
(defmacro ~ (field regex)
  `(cl-ppcre:scan ,regex ,field))
