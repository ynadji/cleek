(in-package :cleek)

(cl-interpol:enable-interpol-syntax)

(defparameter *weak-ciphers* '("rc4-hmac" "rc4-hmac-exp" "des-cbc-crc" "des-cbc-md4" "des-cbc-md5" "des3-cbc-md5" "des3-cbc-sha1"))

(defparameter *common-filters-and-mutators*
  `((productive? . (and (plusp @@orig_bytes)
                        (plusp @@resp_bytes)))
    (domain-parts . (setf @query_e2ld (e2ld @query)
                          @query_tld (tld @query)))
    (requested-weak-ciphers? . (intersection (coerce @@cipher_req 'list) *weak-ciphers* :test #'string=))
    (requested-only-weak-ciphers? . (null (set-difference (coerce @@cipher_req 'list) *weak-ciphers* :test #'string=)))
    (responded-weak-cipher? . (member @cipher_rep *weak-ciphers* :test #'string=))
    (more-closed-than-opened? . (loop for c across (subseq @filter 0 (1- (length @filter)))
                                      with closed = 0 with open = 0
                                      when (char= c #\()
                                        do (incf open)
                                      when (char= c #\))
                                        do (incf closed)
                                        thereis (> closed open)))
    (ok-local-subnets? . (and productive? (~ #?/^Sh/ @history)
                              (public? @@o_h) (public? @@r_h)))
    (ok-local-subnets-orig? . (and productive? (s= "tcp" @proto)
                                   (s= "SF" @conn_state) (~ #?/^Sh/ @history)
                                   (public? @@o_h) (public? @@r_h)))
    (route-status . (setf @resp_route (routes @@r_h)
                          @orig_route (routes @@o_h)))))
