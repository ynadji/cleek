(asdf:defsystem cleek
  :serial t
  :description "DNS manipulation library"
  :author "Yacin Nadji <yacin@defmacro.cc>"
  :license "MIT"
  :depends-on ("str" "uiop" "alexandria" "cl-ppcre" "cl-tld" "netaddr" "cl-dns" "com.inuoe.jzon" "zstd" "chipz" "salza2" "babel" "local-time" "transducers" "clingon")
  :components ((:file "packages")
               (:file "types")
               (:file "io")
               (:file "main"))
  :defsystem-depends-on (:deploy)
  :build-operation "deploy-op"
  :build-pathname "cleek"
  :entry-point "cleek:main"
  :in-order-to ((test-op (test-op :cleek/tests))))

(asdf:defsystem :cleek/tests
  :author "Yacin Nadji <yacin@defmacro.cc>"
  :license "MIT"
  :depends-on ("cleek" "fiveam" "str")
  :components ((:file "tests"))
  :perform (test-op (o c) (progn (symbol-call :fiveam '#:run!
                                              (uiop:find-symbol* '#:tests
                                                                 '#:cleek/tests))
                                 (symbol-call :fiveam '#:run!
                                              (uiop:find-symbol* '#:types
                                                                 '#:cleek/tests))
                                 (symbol-call :fiveam '#:run!
                                              (uiop:find-symbol* '#:end-to-end
                                                                 '#:cleek/tests)))))
