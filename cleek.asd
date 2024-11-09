(asdf:defsystem cleek
  :serial t
  :description "DNS manipulation library"
  :author "Yacin Nadji <yacin@defmacro.cc>"
  :license "MIT"
  :depends-on ("str" "uiop" "alexandria" "cl-ppcre" "cl-tld" "netaddr" "cl-dns" "com.inuoe.jzon" "zstd" "chipz" "salza2" "babel" "local-time" "transducers")
  :components ((:file "packages")
               (:file "types")
               (:file "io")
               (:file "main"))
  :in-order-to ((test-op (test-op :cleek/tests))))

(asdf:defsystem :cleek/tests
  :author "Yacin Nadji <yacin@defmacro.cc>"
  :license "MIT"
  :depends-on ("cleek" "fiveam")
  :components ((:file "tests"))
  :perform (test-op (o c) (symbol-call :fiveam '#:run!
                                       (uiop:find-symbol* '#:tests
                                                          '#:cleek/tests))))
