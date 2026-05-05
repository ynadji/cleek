(asdf:load-system :cleek)

(in-package :cleek)

(require :sb-sprof)

(defparameter *bench-zeek-input*
  (asdf:system-relative-pathname "cleek" "data/test-input/homenet-uncompressed.zeek.log"))

(defparameter *bench-json-input*
  (asdf:system-relative-pathname "cleek" "data/test-input/homenet-uncompressed.json.log"))

;;; --- Timing infrastructure (mirrors perf.lisp:my-time) ---

(defmacro bench-time (&body body)
  "Execute BODY and return (values result seconds bytes-consed)."
  `(let ((start-bytes (sb-ext:get-bytes-consed))
         (start-time (get-internal-real-time)))
     (let ((result (progn ,@body)))
       (let ((elapsed-seconds (/ (- (get-internal-real-time) start-time)
                                 (float internal-time-units-per-second 1.0d0)))
             (bytes (- (sb-ext:get-bytes-consed) start-bytes)))
         (values result elapsed-seconds bytes)))))

(defun run-bench (name n thunk)
  "Run THUNK N times, report timing as CSV row to *standard-output*."
  (sb-ext:gc :full t)
  (multiple-value-bind (_result elapsed bytes)
      (bench-time (dotimes (_ n) (funcall thunk)))
    (declare (ignore _result))
    (format t "~a,~a,~,6f,~d,~,6f~%"
            name n elapsed bytes (/ elapsed n))))

;;; --- Function-level benchmarks ---

(defun bench-ensure-row-strings (&optional (n 3))
  (with-zeek-log (log *bench-zeek-input* '(:proto))
    (run-bench "ensure-row-strings" n
               (lambda ()
                 (loop while (zeek-line log)
                       do (setf (zeek-status log) :unparsed)
                          (ensure-row-strings log)
                          (next-record log))))))

(defun bench-parse-zeek-type (&optional (n 100000))
  (run-bench "parse-zeek-type" n
             (lambda ()
               (parse-zeek-type "1623187704.078114" :time)
               (parse-zeek-type "48610" :port)
               (parse-zeek-type "140.249.20.119" :addr)
               (parse-zeek-type "tcp" :enum)
               (parse-zeek-type "12345" :count))))

(defun bench-ensure-map-zeek (&optional (n 3))
  (with-zeek-log (log *bench-zeek-input* '(:proto))
    (run-bench "ensure-map-zeek" n
               (lambda ()
                 (loop while (zeek-line log)
                       do (setf (zeek-status log) :unparsed)
                          (clrhash (zeek-map log))
                          (ensure-map log)
                          (next-record log))))))

(defun bench-ensure-map-json (&optional (n 3))
  (with-zeek-log (log *bench-json-input* '(:proto))
    (run-bench "ensure-map-json" n
               (lambda ()
                 (loop while (zeek-line log)
                       do (setf (zeek-status log) :unparsed)
                          (clrhash (zeek-map log))
                          (ensure-map log)
                          (next-record log))))))

(defun bench-write-zeek-log-line (&optional (n 3))
  (with-zeek-log (log *bench-zeek-input* '(:proto))
    (with-open-file (out "/dev/null" :direction :output :if-exists :supersede)
      (run-bench "write-zeek-log-line" n
                 (lambda ()
                   (loop while (zeek-line log)
                         do (write-zeek-log-line log out :zeek)
                            (next-record log)))))))

(defun bench-next-record (&optional (n 3))
  (with-zeek-log (log *bench-zeek-input*)
    (run-bench "next-record" n
               (lambda ()
                 (loop while (zeek-line log) do (next-record log))))))

(defun run-all-function-benchmarks (&optional (output-path "bench-results.csv"))
  "Run all function-level benchmarks and write CSV to OUTPUT-PATH."
  (with-open-file (*standard-output* output-path :direction :output :if-exists :supersede)
    (format t "benchmark,iterations,total_seconds,bytes_consed,seconds_per_iteration~%")
    (bench-ensure-row-strings)
    (bench-parse-zeek-type)
    (bench-ensure-map-zeek)
    (bench-ensure-map-json)
    (bench-write-zeek-log-line)
    (bench-next-record))
  (format *error-output* "Function benchmarks written to ~a~%" output-path))

;;; --- sb-sprof profiling ---

(defun profile-function (name thunk)
  "Profile THUNK with sb-sprof. NAME is for display only."
  (format t "~%=== Profiling: ~a ===~%" name)
  (sb-sprof:with-profiling (:report :graph :sample-interval 0.001)
    (funcall thunk)))

(defun profile-passthrough-zeek ()
  (profile-function "passthrough-zeek"
    (lambda () (cat-logs-string #P"/dev/null" :zeek nil nil *bench-zeek-input*))))

(defun profile-passthrough-json ()
  (profile-function "passthrough-json"
    (lambda () (cat-logs-string #P"/dev/null" :json nil nil *bench-json-input*))))

(defun profile-filter-zeek ()
  (profile-function "filter-@@-zeek"
    (lambda () (cat-logs-string #P"/dev/null" :zeek nil
                                "(and (plusp @@orig_bytes) (plusp @@resp_bytes))"
                                *bench-zeek-input*))))

(defun profile-filter-json ()
  (profile-function "filter-@@-json"
    (lambda () (cat-logs-string #P"/dev/null" :json nil
                                "(and (plusp @@orig_bytes) (plusp @@resp_bytes))"
                                *bench-json-input*))))

(defun profile-mutator-zeek ()
  (profile-function "mutator-zeek"
    (lambda () (cat-logs-string #P"/dev/null" :zeek
                                "(anonip! @id.orig_h @id.resp_h)" nil
                                *bench-zeek-input*))))

(defun profile-format-conversion ()
  (profile-function "zeek->json"
    (lambda () (cat-logs-string #P"/dev/null" :json nil nil *bench-zeek-input*))))

(defun run-all-profiles ()
  "Run sb-sprof profiling on key scenarios."
  (profile-passthrough-zeek)
  (sb-ext:gc :full t)
  (profile-passthrough-json)
  (sb-ext:gc :full t)
  (profile-filter-zeek)
  (sb-ext:gc :full t)
  (profile-mutator-zeek)
  (sb-ext:gc :full t)
  (profile-format-conversion))
