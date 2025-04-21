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

(defparameter *filters*
  `(("nil" nil nil)
    ("one-match-str-contains" nil "(c? \"CnekyC2HjFQJ61lUM\" LINE)")
    ("one-match-regex" nil "(~ \"CnekyC2HjFQJ61lUM\" LINE)")
    ("many-matches-str-contains" nil "(c? \"tcp\" LINE)")
    ("many-matches-regex" nil "(~ \"tcp\" LINE)")

    ("one-field-s=" nil "(s= @o_h \"8.8.8.8\")")))


(defun run-perf-test (name mutator-expr filter-expr csv-stream &optional profile? (n 3))
  (format t "# Running test ~a (profiling ~a)~%" name profile?)
  (if profile?
      (sb-sprof:with-profiling (:report :graph :sample-interval 0.001)
        (cat-logs-string #P"perf.log" :zeek mutator-expr filter-expr *big-conn*))
      ;; i really need to output this to a CSV so i can easily compare before and afters.
      (progn (format csv-stream "~a," name)
             (my-time csv-stream
                      (dotimes (n n)
                        (cat-logs-string #P"perf.log" :zeek mutator-expr filter-expr *big-conn*))))))

(defun run-all-perf-tests (output-path)
  (with-open-file (stream output-path :direction :output :if-exists :supersede)
    (format stream "test-name,real-time,user-time,system-time,gc-real-time,non-gc-real-time,bytes-consed~%")
    (loop for (name mutator-expr filter-expr) in *filters*
          do (run-perf-test name mutator-expr filter-expr stream)
             (sb-ext:gc :full t)
             (run-perf-test name mutator-expr filter-expr stream t)
             (sb-ext:gc :full t))))
