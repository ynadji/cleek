(defpackage cleek/tests
  (:use #:cl #:cleek)
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

(netaddr:enable-ip-syntax)
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

  (is (netaddr:ip= #I("10.20.30.40") (parse-zeek-type "10.20.30.40" :addr)))
  (is (netaddr:ip= #I("cafe:babe::") (parse-zeek-type "cafe:babe::" :addr)))

  (is (netaddr:ip= #I("10.20.30.0/24") (parse-zeek-type "10.20.30.0/24" :subnet)))
  (is (netaddr:ip= #I("cafe:babe::/94") (parse-zeek-type "cafe:babe::/94" :subnet)))

  (is (every #'netaddr:ip= #I("1.1.1.1" "255.255.255.255" "::") (parse-zeek-type "1.1.1.1,255.255.255.255,::" :vector[addr])))
  (is (every #'netaddr:ip= #I("1.1.1.1" "255.255.255.255" "::") (parse-zeek-type "1.1.1.1,255.255.255.255,::" :set[addr])))

  (is (every #'netaddr:ip= #I("1.1.1.1/24" "255.255.255.255/10" "::/96") (parse-zeek-type "1.1.1.1/24,255.255.255.255/10,::/96" :vector[subnet])))
  (is (every #'netaddr:ip= #I("1.1.1.1/24" "255.255.255.255/10" "::/96") (parse-zeek-type "1.1.1.1/24,255.255.255.255/10,::/96" :set[subnet])))

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

(defgeneric field= (x y)
  (:method ((x local-time:timestamp) (y local-time:timestamp))
    (< (abs (local-time:timestamp-difference x y)) 1))
  (:method ((x netaddr::ip+) (y netaddr::ip+))
    (netaddr:ip= x y))
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
                   always (or (member field ignore-columns)
                              (field= (gethash field (cleek::zeek-map zl1) 'cl::null)
                                      (gethash field (cleek::zeek-map zl2) 'cl::null))))))
    (cleek::with-zeek-log (zl1 path1)
      (cleek::with-zeek-log (zl2 path2)
        (and (= (count-rows path1) (count-rows path2))
             (equal (cleek::zeek-fields zl1) (cleek::zeek-fields zl2))
             (loop while (and (cleek::zeek-line zl1) (cleek::zeek-line zl2))
                   do (cleek::ensure-zeek-map zl1) (cleek::ensure-zeek-map zl2)
                   always (fields-equal zl1 zl2 ignore-columns)
                   do (cleek::next-record zl1) (cleek::next-record zl2)))))))

(test cat-and-format-conversion
  (loop for input-format in '("zeek" "json")
        for tmp-dir = (uiop:temporary-directory) do
          (loop for output-format in '("zeek" "json") do
            (loop for input-path in (uiop:directory-files (merge-pathnames #?"${input-format}/" *test-inputs-dir*))
                  for basename = (pathname-name input-path)
                  for output-path = (merge-pathnames basename tmp-dir)
                  do (cat-logs-string output-path (string->keyword output-format) nil nil input-path)
                     (is (zeek-log= input-path output-path))))))

(defun count-rows (log-path)
  (with-open-file (in log-path)
    (loop for line = (read-line in nil)
          while line
          count (char/= #\# (char line 0)))))

(test zeek-log=
  (loop for zeek in (uiop:directory-files (merge-pathnames "zeek/" *test-inputs-dir*))
        for json in (uiop:directory-files (merge-pathnames "json/" *test-inputs-dir*))
        do (is (zeek-log= zeek zeek))
           (is (zeek-log= json json))
           (is (zeek-log= zeek json))))

(test filters
  (netaddr:enable-ip-syntax)
  (enable-interpol-syntax)
  (let ((test-output (merge-pathnames "test.log" (uiop:temporary-directory)))
        (dns-log (merge-pathnames "zeek/dns.log" *test-inputs-dir*))
        (dns-log-json (merge-pathnames "json/dns.log" *test-inputs-dir*))
        (ssh-log (merge-pathnames "zeek/ssh.log" *test-inputs-dir*))
        (ssh-log-json (merge-pathnames "json/ssh.log" *test-inputs-dir*))
        (conn-log (merge-pathnames "zeek/conn.log" *test-inputs-dir*))
        (conn-log-json (merge-pathnames "json/conn.log" *test-inputs-dir*)))

    (is (= 2 (count-rows ssh-log) (count-rows ssh-log-json)))
    (is (= 481 (count-rows conn-log) (count-rows conn-log-json)))

    ;; Regex match against the LINE on anything.
    (cat-logs-string test-output :zeek nil "(~ #?/.*/ LINE)" conn-log)
    (is (= 481 (count-rows test-output)))
    (is (zeek-log= test-output conn-log))
    (uiop:delete-file-if-exists test-output)
    (cat-logs-string test-output :json nil "(~ #?/.*/ LINE)" conn-log-json)
    (is (= 481 (count-rows test-output)))
    (is (zeek-log= test-output conn-log-json))
    (uiop:delete-file-if-exists test-output)

    ;; In the CLI, you could use the CL-INTERPOL syntax for this regex that would look like: #?/tcp.*?SF\s\w/
    ;; but passing a string will interfere with the escaping so we use the double escapes from now one.
    (cat-logs-string test-output :zeek nil "(~ \"tcp.*?SF\\\\s\\\\w\" LINE)" conn-log)
    (is (= 15 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)
    ;; Note that LINE in :json is still a JSON blob and not the same as a :zeek line. This filter is largely equivalent
    ;; to the one for :zeek. Same regex in sane form is #?/tcp.*?SF",/
    (cat-logs-string test-output :json nil "(~ \"tcp.*?SF\\\",\" LINE)" conn-log-json)
    (is (= 15 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

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

    (cat-logs-string test-output :zeek nil "(and (c? '(\"SF\" \"SHR\") @conn_state)
                                             (string= @proto \"tcp\")
                                             (or (plusp @@orig_bytes)
                                                 (plusp @@resp_bytes)))" conn-log)
    (is (= 7 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)
    ;; NB: because of how JSON is parsed, the bytes fields are already integers.
    (cat-logs-string test-output :json nil "(and (c? '(\"SF\" \"SHR\") @conn_state)
                                             (string= @proto \"tcp\")
                                             (or (plusp @orig_bytes)
                                                 (plusp @resp_bytes)))" conn-log-json)
    (is (= 7 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    ;; Using the fully parsed @@ syntax also works for JSON, however.
    (cat-logs-string test-output :json nil "(and (c? '(\"SF\" \"SHR\") @conn_state)
                                             (string= @proto \"tcp\")
                                             (or (plusp @@orig_bytes)
                                                 (plusp @@resp_bytes)))" conn-log-json)
    (is (= 7 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :zeek nil "(c? @@answers \"54.204.130.107\")" dns-log)
    (is (= 2 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :json nil "(c? @@answers \"54.204.130.107\")" dns-log-json)
    (is (= 2 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :zeek nil "@@ra" dns-log)
    (is (= 11 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :json nil "@@ra" dns-log-json)
    (is (= 11 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    ;; Can specify timestamps with unix epoch ts, epoch w/ nsec, or ISO 8601 format (default from zeek-cut -d.
    (cat-logs-string test-output :zeek nil "(ts<= (ts 1623187713) @@ts (ts 1623187714))" conn-log)
    (is (= 6 (count-rows test-output)))
    (cat-logs-string test-output :zeek nil "(ts<= (ts 1623187713.511287) @@ts (ts 1623187714.507970))" conn-log)
    (is (= 6 (count-rows test-output)))
    (cat-logs-string test-output :zeek nil "(ts< (ts \"2021-06-08T17:28:33-0400\") @@ts (ts \"2021-06-08T17:28:35-0400\"))" conn-log)
    (is (= 13 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (let ((cleek::*common-filters-and-mutators-path* (asdf:system-relative-pathname "cleek" "common-filters-and-mutators.lisp")))
      (cleek::init-common-filters-and-mutators)
      ;; We need to specify CLEEK:: only because we are calling from a different package.
      (cat-logs-string test-output :zeek nil "(and (string= @proto \"tcp\") cleek::productive?)" conn-log)
      (is (= 150 (count-rows test-output)))
      (uiop:delete-file-if-exists test-output)

      (cat-logs-string test-output :json nil "(and (string= @proto \"tcp\") cleek::productive?)" conn-log-json)
      (is (= 150 (count-rows test-output)))
      (uiop:delete-file-if-exists test-output)

      (cat-logs-string test-output :zeek nil "(and (<= @@r_p 1024)
                                                   (s/= @proto \"icmp\")
                                                   cleek::productive?
                                                   (public? @@o_h)
                                                   (private? @@r_h))" conn-log)
      (is (= 1 (count-rows test-output)))
      (uiop:delete-file-if-exists test-output)

      (cat-logs-string test-output :json nil "(and (<= @@r_p 1024)
                                                   (s/= @proto \"icmp\")
                                                   cleek::productive?
                                                   (public? @@o_h)
                                                   (private? @@r_h))" conn-log-json)
      (is (= 1 (count-rows test-output)))
      (uiop:delete-file-if-exists test-output)
      )))

(defmacro with-tmp-file ((var string) &body body)
  `(uiop:with-temporary-file (:pathname ,var)
     (str:to-file ,var ,string)
     ,@body))

(test mutators
  (netaddr:enable-ip-syntax)
  (let ((test-output (merge-pathnames "test.log" (uiop:temporary-directory)))
        (dns-log (merge-pathnames "zeek/dns.log" *test-inputs-dir*))
        (dns-log-json (merge-pathnames "json/dns.log" *test-inputs-dir*))
        (conn-log (merge-pathnames "zeek/conn.log" *test-inputs-dir*))
        (conn-log-json (merge-pathnames "json/conn.log" *test-inputs-dir*)))

    (is (= 25 (count-rows dns-log) (count-rows dns-log-json)))
    (is (= 481 (count-rows conn-log) (count-rows conn-log-json)))

    (cat-logs-string test-output :json "(anonip! @o_h) (hash! @uid)" nil dns-log-json)
    (is (= 25 (count-rows test-output)))
    (is (not (zeek-log= dns-log-json test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :json "(anonip! @o_h @r_h) (hash! @uid @proto)" nil dns-log-json)
    (is (= 25 (count-rows test-output)))
    (is (not (zeek-log= dns-log-json test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :zeek "(anonip! @o_h @r_h) (hash! @uid @proto)" nil dns-log-json)
    (is (= 25 (count-rows test-output)))
    (is (not (zeek-log= dns-log test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :json "(setf @e2ld (e2ld @query)
                                              @tld (tld @query))" "(string= @tld \"com\")" dns-log-json)
    (is (= 15 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)
    (cat-logs-string test-output :json "(setf @e2ld (e2ld @query)
                                              @tld (tld @query))" "(string= @tld \"local\")" dns-log-json)
    (is (= 6 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :json "(setf @total_bytes (+ @@orig_bytes @@resp_bytes))"
                     "(and (= 1 @total_bytes) (string= @proto \"tcp\"))" conn-log-json)
    (is (= 46 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :json "(setf @total_bytes (+ (or @orig_bytes 0) (or @resp_bytes 0)))"
                     "(and (= 1 @total_bytes) (string= @proto \"tcp\"))" conn-log-json)
    (is (= 46 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :json "(setf @total_bytes (+ @@orig_bytes @@resp_bytes))"
                     "(and (plusp @total_bytes) (string= @proto \"tcp\"))" conn-log-json)
    (is (= 224 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :json "(setf @total_bytes (+ (or @orig_bytes 0) (or @resp_bytes 0)))"
                     "(and (plusp @total_bytes) (string= @proto \"tcp\"))" conn-log-json)
    (is (= 224 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :zeek "(anonip! @o_h) (hash! @uid)" nil dns-log)
    (is (= 25 (count-rows test-output)))
    (is (not (zeek-log= dns-log test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :zeek "(anonip! @o_h @r_h) (hash! @uid @proto)" nil dns-log)
    (is (= 25 (count-rows test-output)))
    (is (not (zeek-log= dns-log test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :json "(anonip! @o_h @r_h) (hash! @uid @proto)" nil dns-log)
    (is (= 25 (count-rows test-output)))
    (is (not (zeek-log= dns-log-json test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :zeek "(setf @e2ld (e2ld @query)
                                              @tld (tld @query))" "(string= @tld \"com\")" dns-log)
    (is (= 15 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)
    (cat-logs-string test-output :zeek "(setf @e2ld (e2ld @query)
                                              @tld (tld @query))" "(string= @tld \"local\")" dns-log)
    (is (= 6 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :zeek "(setf @total_bytes (+ @@orig_bytes @@resp_bytes))"
                     "(and (= 1 @total_bytes) (string= @proto \"tcp\"))" conn-log)
    (is (= 46 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :zeek "(setf @total_bytes (+ @@orig_bytes @@resp_bytes))"
                     "(and (plusp @total_bytes) (string= @proto \"tcp\"))" conn-log)
    (is (= 224 (count-rows test-output)))
    (uiop:delete-file-if-exists test-output)

    (cat-logs-string test-output :zeek "(setf @orig_label (anno @o_h #.#I(\"192.168.0.0/16\") \"192.168\" \".127.52.\" \"string-contains\" \'(\"fe80::1462:3ff9:fd68:b0fc\") \"list-contains\" t \"unknown\"))" nil dns-log)

    (let ((lines (uiop:read-file-lines test-output)))
      (dolist (line lines)
        (when (str:starts-with? "#fields" line)
          (is (str:ends-with? "orig_label" line)))
        (unless (str:starts-with? "#" line)
          (let* ((fields (str:split #\Tab line))
                 (o-h (third fields))
                 (label (car (last fields))))
            (cond ((str:starts-with? "192.168" o-h)
                   (is (string= label "192.168")))
                  ((str:contains? ".127.52." o-h)
                   (is (string= label "string-contains")))
                  ((string= "fe80::1462:3ff9:fd68:b0fc" o-h)
                   (is (string= label "list-contains")))
                  (t (is (string= label "unknown"))))))))
    (uiop:delete-file-if-exists test-output)

    (let ((cleek::*common-filters-and-mutators-path* (asdf:system-relative-pathname "cleek" "common-filters-and-mutators.lisp")))
      (cleek::init-common-filters-and-mutators)
      ;; We need to specify CLEEK:: only because we are calling from a different package.
      (cat-logs-string test-output :zeek "cleek::domain-parts" "(or (string= @query_tld \"akamaiedge.net\") (string= @query_e2ld \"slack.com\"))" dns-log)
      (is (= 6 (count-rows test-output)))
      (uiop:delete-file-if-exists test-output))))

(test filters-from-file
  (let ((test-output (merge-pathnames "test.log" (uiop:temporary-directory)))
        (dns-log (merge-pathnames "zeek/dns.log" *test-inputs-dir*))
        (dns-log-json (merge-pathnames "json/dns.log" *test-inputs-dir*)))
    (with-tmp-file (queries "unchartedsoftware.slack.com
www.dropbox.com
+.local
")
      (cat-logs-string test-output :zeek nil #?"(c? (f \"${queries}\" :dns) @query)" dns-log)
      (is (= 10 (count-rows test-output)))
      (uiop:delete-file-if-exists test-output)

      (cat-logs-string test-output :json nil #?"(c? (f \"${queries}\" :dns) @query)" dns-log-json)
      (is (= 10 (count-rows test-output)))
      (uiop:delete-file-if-exists test-output)

      (cat-logs-string test-output :json nil #?"(c? (f \"${queries}\" :dns) @query)" dns-log)
      (is (= 10 (count-rows test-output)))
      (uiop:delete-file-if-exists test-output)

      (cat-logs-string test-output :zeek nil #?"(c? (f \"${queries}\" :dns) @query)" dns-log-json)
      (is (= 10 (count-rows test-output)))
      (uiop:delete-file-if-exists test-output))

    (with-tmp-file (foo "one
two
three
four
five
six
seven")
      (is (typep (f #?"${foo}") 'vector)))

    (with-tmp-file (foo "one
two
three
four
five
six
seven
eight")
      (is (typep (f #?"${foo}") 'hash-table)))))

(test error-handling
  (let ((test-output (merge-pathnames "test.log" (uiop:temporary-directory)))
        (bad-ssh (merge-pathnames "aux/bad-ssh.log" *test-inputs-dir*))
        (bad-ssh-json (merge-pathnames "aux/bad-ssh-json.log" *test-inputs-dir*)))
    (handler-bind ((error (lambda (c)
                            (declare (ignore c))
                            (invoke-restart 'cleek::drop-line))))
      (cat-logs-string test-output :zeek nil "(= @@r_p 22)" bad-ssh)
      (is (= 3 (count-rows test-output))))

    (handler-bind ((error (lambda (c)
                            (declare (ignore c))
                            (invoke-restart 'cleek::drop-line))))
      (cat-logs-string test-output :json nil "(= @@r_p 22)" bad-ssh-json)
      (is (= 3 (count-rows test-output))))))
