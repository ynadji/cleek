#+sb-core-compression
(defmethod asdf:perform ((o asdf:image-op) (c asdf:system))
  (uiop:dump-image (asdf:output-file o c)
                   :executable t
                   :compression t))

(asdf:defsystem cleek
  :serial t
  :description "A Zeek log manipulation CLI tool."
  :author "Yacin Nadji <yacin@defmacro.cc>"
  :license "MIT"
  :depends-on ("str" "uiop" "alexandria" "cl-ppcre" "cl-tld" "netaddr" "cl-dns" "com.inuoe.jzon" "local-time" "clingon" "split-sequence" "cl-interpol" "ironclad")
  :components ((:file "packages")
               (:file "types")
               (:file "io")
               (:file "bio")
               (:file "helpers")
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
  ;; FIVEAM:RUN! returns NIL when a suite had failures, and prints them. Ignoring
  ;; that return value made `make test` exit 0 on a red suite, so collect the
  ;; failures and signal: callers (and ci.lisp) can then see a test run fail.
  :perform (test-op (o c)
                    (let ((failed (loop for suite in '(#:tests #:types #:end-to-end)
                                        unless (symbol-call :fiveam '#:run!
                                                            (uiop:find-symbol* suite '#:cleek/tests))
                                          collect suite)))
                      (when failed
                        (error "fiveam suite~p failed: ~{~(~a~)~^, ~}" (length failed) failed)))))
