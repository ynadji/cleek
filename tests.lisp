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
                #:unparse-zeek-type)
  (:export #:tests))

(in-package :cleek/tests)

(enable-ip-syntax)

(def-suite tests)
(def-suite types)

(in-suite tests)

;; just a reminder how to have multiple suites :)
(test basic
  (is (= 1 1)))

(in-suite types)

(test parse-zeek-type
  (is (parse-zeek-type "T" :bool))
  (is (not (parse-zeek-type "F" :bool)))
  (is (string= "-" (parse-zeek-type "-" :bool)))

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

  (is (equalp '(1 217 41) (parse-zeek-type "1,217,41" :vector[count])))
  (is (equalp '("google.com" "foo.bar" "bing.bong") (parse-zeek-type "google.com,foo.bar,bing.bong" :set[string]))))

(test unparse-zeek-type
  (is (string= "T" (unparse-zeek-type (parse-zeek-type "T" :bool) :bool)))
  (is (string= "F" (unparse-zeek-type (parse-zeek-type "F" :bool) :bool)))
  (is (string= "-" (unparse-zeek-type (parse-zeek-type "-" :bool) :bool)))

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
