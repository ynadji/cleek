(in-package :cleek)

(defparameter *common-filters-and-mutators*
  `((productive? . (and (and (string/= @orig_bytes "-") (plusp (parse-integer @orig_bytes)))
                        (and (string/= @resp_bytes "-") (plusp (parse-integer @resp_bytes)))))
    (domain-parts . (setf @query_e2ld (e2ld @query)
                          @query_tld (tld @query)))))
