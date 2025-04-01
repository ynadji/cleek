(defpackage :cleek
  (:use :cl)
  (:local-nicknames (:ax :alexandria)
                    (:na :netaddr)
                    (:dns :cl-dns)
                    (:tld :cl-tld)
                    (:jzon :com.inuoe.jzon))
  (:import-from :split-sequence #:split-sequence)
  (:export :main))
