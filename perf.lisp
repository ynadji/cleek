(asdf:load-system :cleek)

(in-package :cleek)

(defun %format-decimal (stream number power)
  (declare (stream stream)
           (integer number power))
  (when (minusp number)
    (write-char #\- stream)
    (setf number (- number)))
  (let ((scale (expt 10 power)))
    (labels ((%fraction (fraction)
               (if (zerop fraction)
                   (%zeroes)
                   (let ((scaled (* 10 fraction)))
                     (loop while (< scaled scale)
                           do (write-char #\0 stream)
                              (setf scaled (* scaled 10)))))
               (format stream "~D" fraction))
             (%zeroes ()
               (let ((scaled (/ scale 10)))
                 (write-char #\0 stream)
                 (loop while (> scaled 1)
                       do (write-char #\0 stream)
                          (setf scaled (/ scaled 10))))))
      (cond ((zerop number)
             (write-string "0." stream)
             (%zeroes))
            ((< number scale)
             (write-string "0." stream)
             (%fraction number))
            ((= number scale)
             (write-string "1." stream)
             (%zeroes))
            ((> number scale)
             (multiple-value-bind (whole fraction) (floor number scale)
               (format stream "~D." whole)
               (%fraction fraction))))))
  nil)

(defun format-microseconds (stream usec &optional colonp atp)
  (declare (ignore colonp atp))
  (%format-decimal stream usec 6))

(defun format-milliseconds (stream usec &optional colonp atp)
  (declare (ignore colonp atp))
  (%format-decimal stream usec 3))

(defun write-time (stream &key real-time-ms user-run-time-us system-run-time-us
                            gc-run-time-ms gc-real-time-ms processor-cycles eval-calls
                            lambdas-converted page-faults bytes-consed
                            aborted)
  (declare (ignore aborted gc-run-time-ms processor-cycles eval-calls lambdas-converted page-faults))
  (let ((*print-length* nil))
    (format stream
            "~/cleek::format-milliseconds/,~
             ~/cleek::format-milliseconds/,~
             ~/cleek::format-milliseconds/,~
             ~/cleek::format-milliseconds/,~
             ~/cleek::format-milliseconds/,~
             ~:a~%"
            real-time-ms
            user-run-time-us
            system-run-time-us
            gc-real-time-ms
            (- real-time-ms gc-real-time-ms)
            bytes-consed)))

(defmacro my-time (stream form)
  `(sb-impl::call-with-timing (lambda (&rest keys &key &allow-other-keys)
                                (apply #'write-time ,stream keys))
                              (lambda () ,form)))

(require :sb-sprof)

(defparameter *big-conn* (asdf:system-relative-pathname "cleek" "data/test-input/homenet-uncompressed.zeek.log"))
(defparameter *big-conn-json* (asdf:system-relative-pathname "cleek" "data/test-input/homenet-uncompressed.json.log"))

(let ((*common-filters-and-mutators-path* (asdf:system-relative-pathname "cleek" "common-filters-and-mutators.lisp")))
  (init-common-filters-and-mutators))

(defparameter *filters*
  `(("nil" nil nil)
    ("one-match-str-contains" nil "(c? \"CnekyC2HjFQJ61lUM\" LINE)")
    ("one-match-regex" nil "(~ \"CnekyC2HjFQJ61lUM\" LINE)")
    ("many-matches-str-contains" nil "(c? \"tcp\" LINE)")
    ("many-matches-regex" nil "(~ \"tcp\" LINE)")

    ("one-field-s=" nil "(s= @o_h \"8.8.8.8\")")
    ("productive-tcp" nil "(and (s= @proto \"tcp\") productive?)")
    ("productive-tcp-bignatius-orig" nil "(and (s= @proto \"tcp\")
                                               productive?
                                               (c? @@id.orig_h_name.vals \"bignatius.nadji.us\"))")
    ("productive-tcp-big-orig-more" nil "(and (s= @proto \"tcp\")
                                               productive?
                                               (c? @@id.orig_h_name.vals \"bignatius.nadji.us\")
                                               (not @@local_orig)
                                               (= 1 (length @@id.resp_h_name.vals))
                                               (not (c? @@id.resp_h_name.vals \"-\")))")

    ("set-lengths-prod-tcp-filter" "(setf @resp_names_length (length @@id.resp_h_name.vals)
                                          @orig_names_length (length @@id.orig_h_name.vals))"
                                   "(and (s= @proto \"tcp\")
                                         productive?
                                         (c? @@id.orig_h_name.vals \"bignatius.nadji.us\")
                                         (not @@local_orig)
                                         (not (minusp @orig_names_length))
                                         (= 1 @resp_names_length)
                                         (not (c? @@id.resp_h_name.vals \"-\")))")))


(defun run-perf-test (input-log output-format name mutator-expr filter-expr csv-stream &optional profile? (n 3))
  (format t "# Running test ~a (profiling ~a)~%" name profile?)
  (if profile?
      (sb-sprof:with-profiling (:report :graph :sample-interval 0.001)
        (cat-logs-string #P"perf.log" output-format mutator-expr filter-expr input-log))
      ;; i really need to output this to a CSV so i can easily compare before and afters.
      (progn (format csv-stream "~a," name)
             (my-time csv-stream
                      (dotimes (n n)
                        (cat-logs-string #P"perf.log" output-format mutator-expr filter-expr input-log))))))

(defun run-all-perf-tests (output-path)
  (with-open-file (stream output-path :direction :output :if-exists :supersede)
    (format stream "test-name,real-time,user-time,system-time,gc-real-time,non-gc-real-time,bytes-consed~%")
    (loop for (name mutator-expr filter-expr) in *filters*
          do (loop for input-log in (list *big-conn* *big-conn-json*) for type in (list :zeek :json)
                   do (run-perf-test input-log type (format nil "~a-~(~a~)" name type) mutator-expr filter-expr stream)
                      (sb-ext:gc :full t)
                      (run-perf-test input-log type (format nil "~a-~(~a~)" name type) mutator-expr filter-expr stream t)
                      (sb-ext:gc :full t)))))
