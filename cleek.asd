#+sb-core-compression
(defmethod asdf:perform ((o asdf:image-op) (c asdf:system))
  (uiop:dump-image (asdf:output-file o c)
                   :executable t
                   :compression t))

(asdf:defsystem cleek
  :serial t
  :description "DNS manipulation library"
  :author "Yacin Nadji <yacin@defmacro.cc>"
  :license "MIT"
  :depends-on ("str" "uiop" "alexandria" "cl-ppcre" "cl-tld" "netaddr" "cl-dns" "com.inuoe.jzon" "local-time" "clingon" "serapeum" "split-sequence" "cl-interpol")
  :components ((:file "packages")
               (:file "types")
               (:file "io")
               (:file "filters")
               (:file "main"))
  :build-operation "program-op"
  :build-pathname "bin/cleek"
  :entry-point "cleek:main"
  :in-order-to ((test-op (test-op :cleek/tests))))

(asdf:defsystem :cleek/tests
  :author "Yacin Nadji <yacin@defmacro.cc>"
  :license "MIT"
  :depends-on ("cleek" "fiveam" "str")
  :components ((:file "tests"))
  :perform (test-op (o c) (loop for suite in '(#:tests #:types #:end-to-end)
                                do (symbol-call :fiveam '#:run!
                                                (uiop:find-symbol* suite '#:cleek/tests)))))
