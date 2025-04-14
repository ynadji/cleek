(in-package :cleek)

(defparameter *common-filters-and-mutators*
  `((productive? . (and (plusp @@orig_bytes)
                        (plusp @@resp_bytes)))
    (domain-parts . (setf @query_e2ld (e2ld @query)
                          @query_tld (tld @query)))))
