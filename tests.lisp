(defpackage cleek/tests
  (:use #:cl #:cleek)
  (:import-from #:fiveam
                #:def-suite
                #:in-suite
                #:test
                #:is)
  (:export #:tests))

(in-package :cleek/tests)

(def-suite tests)
(in-suite tests)
