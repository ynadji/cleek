(in-package :cleek)

;; from fleek to support:
;;
;; * annotations (IP-LIKEs, default columns, default new column namer, modify at runtime)
;; * DNS additions
;; * modify column (turn /32 to /24 or w/e)
;; * timestamp filter
;; * productive (these can be handled in general by filters)

;; TODO: WITH-WRITER to handle the header/footer mumbo jumbo. hmm, that won't
;; work in the case where we have multiple readers and one writer... probably
;; doesn't need to be abstracted that much.
(defun read-transform-write (in-path out-path &key (output-format :zeek))
  (let (*field-names* *types* *header-already-printed?*)
    (with-open-log (in in-path)
      (with-open-log (out out-path :direction :output :if-exists :supersede)
        (let ((reader (make-reader in)))
          (multiple-value-bind (writer write-header write-footer) (make-writer out *field-names* output-format *types*)
            (when write-header
              (funcall write-header))
            (loop for record = (funcall reader)
                  while record
                  do (funcall writer record))
            (when write-footer
              (funcall write-footer))))))))

;; how can i know if i need to parse the value from the hash-table or not? i
;; think i'm going to need to have this map of field-names to types at runtime.

(defun compile-runtime-filters (s)
  (let ((filters (subst-if '(gethash :original-key record)
                           #'keywordp
                           (with-input-from-string (in s)
                             (read in nil)))))
    (values (compile nil `(lambda (record) ,filters))
            filters)))

;; TODO: how easy is it to build up transducers? you probably need a macro that
;; takes a bunch of existing functions (or forms) that get T:COMPd together in
;; the correct order (and wrapped by a lambda for forms) and used here. you
;; always need the T:TAKE-WHILE #'IDENTITY so when the READER returns NIL it
;; knows to stop. it will probably be interesting to see how the LOOP vs.
;; T:TRANSDUCE implementations are different (perf- and code-wise).
(defun read-transform-write-transducer (in-path out-path &key (output-format :zeek))
  (let (*field-names* *types* *header-already-printed?*)
    (with-open-log (in in-path)
      (with-open-log (out out-path :direction :output :if-exists :supersede)
        (let ((reader (make-reader in)))
          (multiple-value-bind (writer write-header write-footer) (make-writer out *field-names* output-format *types*)
            (when write-header
              (funcall write-header))
            (t:transduce (t:take-while #'identity)
                         (lambda (&optional acc record)
                           (declare (ignore acc))
                           (when record (funcall writer record)))
                         (t::make-generator :func reader))
            (when write-footer
              (funcall write-footer))))))))

(defun cat/options ()
  (list (clingon:make-option :string
                             :description "Output file"
                             :short-name #\o
                             :long-name "output-file"
                             :initial-value "/dev/stdout"
                             :key :output)
        (clingon:make-option :choice
                             :description "Output format"
                             :short-name #\f
                             :long-name "output-format"
                             :items '("zeek" "json")
                             :initial-value "zeek"
                             :key :format)
        (clingon:make-option :choice
                             :description "Output compression"
                             :short-name #\c
                             :long-name "output-compression"
                             :items '("none" "gzip" "zstd")
                             :initial-value "none"
                             :key :compression)))

(defun cat-logs (output-file output-format &rest input-files)
  (when input-files
   (let (*field-names* *types* write-footer *header-already-printed?*)
     (with-open-log (in (first input-files))
       (funcall (make-reader in))) ; read a record so we can get the field-names/types.
     (with-open-log (out output-file :direction :output :if-exists :supersede)
       (loop for in-path in input-files do
         (with-open-log (in in-path)
           (let ((reader (make-reader in)))
             (multiple-value-bind (writer write-header w-f)
                 (make-writer out output-format)
               (setf write-footer w-f)
               (when write-header
                 (funcall write-header))
               (t:transduce (t:take-while #'identity)
                            (lambda (&optional acc record)
                              (declare (ignore acc))
                              (when record (funcall writer record)))
                            (t::make-generator :func reader))))))
       (when write-footer
         (funcall write-footer))))))

(defun cat-logs-string (output-file output-format &rest input-files)
  (with-open-file (out output-file :direction :output :if-exists :supersede)
    (if (zerop (length input-files))
        (with-open-file (in "/dev/stdin")
          (let ((zeek-log (open-zeek-log :stream in)))
            (format out "~{~a~^~%~}~%" (zeek-raw-header zeek-log))
            (loop while (zeek-line zeek-log)
                  do (write-zeek-log-line zeek-log out output-format)
                     (next-record zeek-log))))
        (loop for in-path in input-files do
          (with-zeek-log (zeek-log in-path)
            (format out "~{~a~^~%~}~%" (zeek-raw-header zeek-log))
            (loop while (zeek-line zeek-log)
                  do (write-zeek-log-line zeek-log out output-format)
                     (next-record zeek-log)))))
    (format out (format nil "#close~a~~a~%" *zeek-field-separator*)
            (timestamp-to-zeek-open-close-string (local-time:now)))))

(defun cat-logs-string-multi (output-file &rest input-files)
  (with-open-file (out output-file :direction :output :if-exists :supersede)
    (with-zeek-logs (zeek-log input-files)
      (format out "~{~a~^~%~}~%" (zeek-raw-header zeek-log))
      (loop while (zeek-line zeek-log)
            do (write-line (zeek-line zeek-log) out)
               (next-record zeek-log)))
    (format out (format nil "#close~a~~a~%" *zeek-field-separator*)
            (timestamp-to-zeek-open-close-string (local-time:now)))))

(defun perf-test (&optional (path #P"~/tmp/test2.log"))
  (cat-logs-string path :zeek #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_00:00:00-01:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_01:00:00-02:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_02:00:00-03:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_03:00:00-04:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_04:00:00-05:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_05:00:00-06:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_06:00:00-07:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_07:00:00-08:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_08:00:00-09:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_09:00:00-10:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_10:00:00-11:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_11:00:00-12:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_12:00:00-13:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_13:00:00-14:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_14:00:00-15:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_15:00:00-16:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_16:00:00-17:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_17:00:00-18:00:00-0500.log" #P"/Users/yacin/code/cleek/data/homenet-uncompressed/conn_20241106_18:00:00-19:00:00-0500.log"))

(defun cat/handler (cmd)
  (let ((args (clingon:command-arguments cmd))
        (output-file (clingon:getopt cmd :output))
        (format (string->keyword (clingon:getopt cmd :format)))
        (compression (string->keyword (clingon:getopt cmd :compression))))
    (declare (ignore compression))
    (apply #'cat-logs-string output-file format args)))

(defun wip-compile-filter-expression ()
  (let ((func (compile-runtime-filters "(or (string= \"foo\" :bar) (string= \"baz\" :bar))")))
    (print (funcall func (serapeum:dict :original-key "baz")))
    (print (funcall func (serapeum:dict :original-key "bong")))))

;; TODO: also read from *stdin*? less important since i can directly read
;; compressed files.
(defun cat/command ()
  "Concatenate Zeek logs"
  (clingon:make-command
   :name "cleek"
   :version "0.1.0"
   :usage "[ZEEK-LOG]..."
   :description "Concatenate Zeek logs"
   :handler #'cat/handler
   :options (cat/options)))

(defun main ()
  (let ((app (cat/command)))
    (clingon:run app)))
