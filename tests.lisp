(defpackage cleek/tests
  (:use #:cl #:cleek #:netaddr)
  (:import-from #:fiveam
                #:def-suite
                #:in-suite
                #:test
                #:is)
  (:import-from #:local-time
                #:timestamp=
                #:make-timestamp)
  (:import-from #:cleek
                #:parse-zeek-type
                #:unparse-zeek-type
                #:cat-logs-string
                #:string->keyword)
  (:import-from #:cl-interpol
                #:enable-interpol-syntax)
  (:export #:tests))

(in-package :cleek/tests)

(enable-ip-syntax)
(enable-interpol-syntax)

(def-suite tests)
(def-suite types)
(def-suite end-to-end)

(in-suite tests)

;; just a reminder how to have multiple suites :)
(test basic
  (is (= 1 1)))

(in-suite types)

(test parse-zeek-type
  (is (parse-zeek-type "T" :bool))
  (is (not (parse-zeek-type "F" :bool)))

  (is (eq 'cl::null (parse-zeek-type "-" :bool)))
  (is (eq 'cl::null (parse-zeek-type "-" :string)))
  (is (eq 'cl::null (parse-zeek-type "-" :count)))

  (is (= 1 (parse-zeek-type "1" :count)))

  (is (= 1 (parse-zeek-type "1" :int)))

  (is (= 0.41 (parse-zeek-type "0.41" :double)))

  (is (timestamp= (make-timestamp :day 7769 :sec 77304 :nsec 78114)
                  (parse-zeek-type "1623187704.078114" :time)))

  (is (ip= #I("10.20.30.40") (parse-zeek-type "10.20.30.40" :addr)))
  (is (ip= #I("cafe:babe::") (parse-zeek-type "cafe:babe::" :addr)))

  (is (ip= #I("10.20.30.0/24") (parse-zeek-type "10.20.30.0/24" :subnet)))
  (is (ip= #I("cafe:babe::/94") (parse-zeek-type "cafe:babe::/94" :subnet)))

  (is (every #'ip= #I("1.1.1.1" "255.255.255.255" "::") (parse-zeek-type "1.1.1.1,255.255.255.255,::" :vector[addr])))
  (is (every #'ip= #I("1.1.1.1" "255.255.255.255" "::") (parse-zeek-type "1.1.1.1,255.255.255.255,::" :set[addr])))

  (is (every #'ip= #I("1.1.1.1/24" "255.255.255.255/10" "::/96") (parse-zeek-type "1.1.1.1/24,255.255.255.255/10,::/96" :vector[subnet])))
  (is (every #'ip= #I("1.1.1.1/24" "255.255.255.255/10" "::/96") (parse-zeek-type "1.1.1.1/24,255.255.255.255/10,::/96" :set[subnet])))

  (is (every #'= #(1 217 41) (parse-zeek-type "1,217,41" :vector[count])))
  (is (every #'string= #("google.com" "foo.bar" "bing.bong") (parse-zeek-type "google.com,foo.bar,bing.bong" :set[string]))))

(test unparse-zeek-type
  (is (string= "T" (unparse-zeek-type (parse-zeek-type "T" :bool) :bool)))
  (is (string= "F" (unparse-zeek-type (parse-zeek-type "F" :bool) :bool)))

  (is (string= "-" (unparse-zeek-type (parse-zeek-type "-" :bool) :bool)))
  (is (string= "-" (unparse-zeek-type (parse-zeek-type "-" :count) :count)))
  (is (string= "-" (unparse-zeek-type (parse-zeek-type "-" :addr) :addr)))

  (is (string= "1" (unparse-zeek-type (parse-zeek-type "1" :count) :count)))

  (is (string= "1" (unparse-zeek-type (parse-zeek-type "1" :int) :int)))

  (is (string= "0.410000" (unparse-zeek-type (parse-zeek-type "0.41" :double) :double)))

  (is (string= "1623187704.078114"
               (unparse-zeek-type (parse-zeek-type "1623187704.078114" :time) :time)))

  (is (string= "10.20.30.40" (unparse-zeek-type (parse-zeek-type "10.20.30.40" :addr) :addr)))
  (is (string= "cafe:babe::" (unparse-zeek-type (parse-zeek-type "cafe:babe::" :addr) :addr)))

  (is (string= "10.20.30.0/24" (unparse-zeek-type (parse-zeek-type "10.20.30.0/24" :subnet) :addr)))
  (is (string= "cafe:babe::/94" (unparse-zeek-type (parse-zeek-type "cafe:babe::/94" :subnet) :addr)))

  (is (string= "1.1.1.1,255.255.255.255,::"
               (unparse-zeek-type (parse-zeek-type "1.1.1.1,255.255.255.255,::" :vector[addr])
                                  :vector[addr])))
  (is (string= "1.1.1.1,255.255.255.255,::"
               (unparse-zeek-type (parse-zeek-type "1.1.1.1,255.255.255.255,::" :set[addr])
                                  :set[addr])))

  (is (string= "1.1.1.0/24,255.192.0.0/10,::/96"
               (unparse-zeek-type (parse-zeek-type "1.1.1.1/24,255.255.255.255/10,::/96" :vector[subnet])
                                  :vector[subnet])))
  (is (string= "1.1.1.0/24,255.192.0.0/10,::/96"
               (unparse-zeek-type (parse-zeek-type "1.1.1.1/24,255.255.255.255/10,::/96" :set[subnet])
                                  :set[subnet])))

  (is (string= "1,217,41"
               (unparse-zeek-type (parse-zeek-type "1,217,41" :vector[count])
                                  :vector[count])))
  (is (string= "google.com,foo.bar,bing.bong"
               (unparse-zeek-type (parse-zeek-type "google.com,foo.bar,bing.bong" :set[string])
                                  :set[string]))))

(in-suite end-to-end)

(defvar *test-inputs-dir* (asdf:system-relative-pathname "cleek" "data/test-input/"))
(defvar *baselines-dir* (asdf:system-relative-pathname "cleek" "data/baselines/"))
(defvar *diff-script* (asdf:system-relative-pathname "cleek" "scripts/diff.sh"))

(test cat
  ;; TODO: make sure you're testing against the output format's input file.
  ;; UIDs are different too. as are the paths, timestamps, open/close times.
  (loop for input-format in '("zeek" "json")
        for tmp-dir = (uiop:temporary-directory) do
          (loop for output-format in (list input-format) do ;in '("zeek" "json") do
            (loop for input-path in (uiop:directory-files (merge-pathnames #?"${input-format}/" *test-inputs-dir*))
                  for basename = (pathname-name input-path)
                  for output-path = (merge-pathnames basename tmp-dir)
                  do ;;(format t "(cat-logs-string ~a ~a ~a ~a)~%" output-path (string->keyword output-format) "t" input-path)
                     (cat-logs-string output-path (string->keyword output-format) nil "t" input-path)
                     (multiple-value-bind (stdout stderr exit-code)
                         (uiop:run-program (format nil "~a ~a ~a"
                                                   *diff-script* input-path output-path)
                                           :ignore-error-status t)
                       (declare (ignorable stdout stderr))
                       (is (zerop exit-code)
                           "~%Input: ~a~&Input Format: ~a~&Output Format: ~a~&Exit code: ~a~%~%Diff: ~a"
                           input-path input-format output-format exit-code stdout))))))

(defun count-rows (log-path)
  (with-open-file (in log-path)
    (loop for line = (read-line in nil)
          while line
          count (char/= #\# (char line 0)))))

(defgeneric field= (x y)
  (:method ((x local-time:timestamp) (y local-time:timestamp))
    (< (abs (local-time:timestamp-difference x y)) 1))
  (:method ((x netaddr::ip+) (y netaddr::ip+))
    (ip= x y))
  (:method ((x double-float) (y double-float))
    (<= (abs (- x y)) 0.001))
  ;; This doesn't take into account that Zeek does not mandate an order for set[*] types, except for conn.log as of
  ;; 7.2.0-dev.194.
  (:method ((x simple-vector) (y simple-vector))
    (every #'field= x y))
  (:method ((x t) (y t))
    (equal x y)))

;; client_scid in zeek log is "(empty)" but "" in json log
(defun zeek-log= (path1 path2 &optional ignore-columns)
  (labels ((fields-equal (zl1 zl2 &optional ignore-columns)
             (loop for field in (cleek::zeek-fields zl1)
                   for type in (cleek::zeek-types zl1)
                   ;;do (format t "~a = ~a ? " (gethash field (cleek::zeek-map zl1) 'cl::null) (gethash field (cleek::zeek-map zl2) 'cl::null))
                   always (or (member field ignore-columns)
                              (let ((foo (field= (gethash field (cleek::zeek-map zl1) 'cl::null)
                                                 (gethash field (cleek::zeek-map zl2) 'cl::null))))
                                (unless foo (format t "~a vs. ~a~%~a = ~a ? FALSE~%" path1 path2 (gethash field (cleek::zeek-map zl1) 'cl::null) (gethash field (cleek::zeek-map zl2) 'cl::null)))
                                foo))
                   ;;do (terpri)
                   )))
    (cleek::with-zeek-log (zl1 path1)
      (cleek::with-zeek-log (zl2 path2)
        (and (= (count-rows path1) (count-rows path2))
             (equal (cleek::zeek-fields zl1) (cleek::zeek-fields zl2))
             (loop while (and (cleek::zeek-line zl1) (cleek::zeek-line zl2))
                   do (cleek::ensure-zeek-map zl1) (cleek::ensure-zeek-map zl2)
                   always (fields-equal zl1 zl2 ignore-columns)
                   do (cleek::next-record zl1) (cleek::next-record zl2)))))))

(test zeek-log=
  (loop for zeek in (uiop:directory-files (merge-pathnames "zeek/" *test-inputs-dir*))
        for json in (uiop:directory-files (merge-pathnames "json/" *test-inputs-dir*))
        do (is (zeek-log= zeek zeek))
           (is (zeek-log= json json))
           (is (zeek-log= zeek json))))

(test filters
  (enable-ip-syntax)           ; needed to add this or the #I()s were failing...
  (let ((test-output (merge-pathnames "test.log" (uiop:temporary-directory)))
        (ssh-log (merge-pathnames "zeek/ssh.log" *test-inputs-dir*))
        (ssh-log-json (merge-pathnames "json/ssh.log" *test-inputs-dir*))
        (conn-log (merge-pathnames "zeek/conn.log" *test-inputs-dir*))
        (conn-log-json (merge-pathnames "json/conn.log" *test-inputs-dir*)))

    (is (= 2 (count-rows ssh-log) (count-rows ssh-log-json)))
    (is (= 481 (count-rows conn-log) (count-rows conn-log-json)))

    (cat-logs-string test-output :zeek nil "(string= @direction \"INBOUND\")" ssh-log)
    (is (= 1 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)
    (cat-logs-string test-output :json nil "(string= @direction \"INBOUND\")" ssh-log-json)
    (is (= 1 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :zeek nil "(contains? #.#I(\"71.127.52.0/24\") #I(@r_h))" ssh-log)
    (is (= 1 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)
    (cat-logs-string test-output :json nil "(contains? #.#I(\"71.127.52.0/24\") #I(@r_h))" ssh-log-json)
    (is (= 1 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :zeek nil "(and (member @conn_state '(\"SF\" \"SHR\") :test 'equal) 
                                             (string= @proto \"tcp\") 
                                             (or (plusp (parse-integer @orig_bytes)) 
                                                 (plusp (parse-integer @resp_bytes))))" conn-log)
    (is (= 7 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)
    ;; NB: because of how JSON is parsed, the bytes fields are already integers.
    (cat-logs-string test-output :json nil "(and (member @conn_state '(\"SF\" \"SHR\") :test 'equal) 
                                             (string= @proto \"tcp\") 
                                             (or (plusp @orig_bytes) 
                                                 (plusp @resp_bytes)))" conn-log-json)
    (is (= 7 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)))
