(in-package :cleek)

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
                             :items '("zeek" "json" "input-format")
                             :initial-value "input-format"
                             :key :format)
        (clingon:make-option :choice
                             :description "Output compression"
                             :short-name #\c
                             :long-name "output-compression"
                             :items '("none" "gzip" "zstd")
                             :initial-value "none"
                             :key :compression)
        (clingon:make-option :string
                             :description "Filter expression"
                             :short-name #\x
                             :long-name "filter"
                             :initial-value "t"
                             :key :filter-expr)
        (clingon:make-option :string
                             :description "Mutator expression"
                             :short-name #\m
                             :long-name "mutator"
                             :initial-value nil
                             :key :mutator-expr)))

(defun cat-logs-string (output-file output-format mutator-expr filter-expr &rest input-files)
  (multiple-value-bind (mutator-func mutator-columns) (compile-runtime-mutators mutator-expr)
    (multiple-value-bind (filter-func filter-columns) (compile-runtime-filters filter-expr)
      (let ((columns (union mutator-columns filter-columns)))
        (with-open-file (out output-file :direction :output :if-exists :supersede)
          (when (zerop (length input-files))
            (push "/dev/stdin" input-files))
          (loop for in-path in input-files do
            (with-zeek-log (zeek-log in-path)
              (when (eq output-format :input-format)
                (setf output-format (zeek-format zeek-log)))
              (write-zeek-header zeek-log out output-format)
              (when columns
                (ecase (zeek-format zeek-log)
                  (:zeek (ensure-fields->idx zeek-log) (ensure-row-strings zeek-log))
                  (:json (ensure-map zeek-log))))
              (loop while (zeek-line zeek-log)
                    do (when columns
                         (ecase (zeek-format zeek-log)
                           (:zeek (ensure-row-strings zeek-log))
                           (:json (ensure-map zeek-log))))
                       (when mutator-func
                         (funcall mutator-func zeek-log))
                       (when (funcall filter-func zeek-log)
                         (write-zeek-log-line zeek-log out output-format))
                       (next-record zeek-log))))
          (when (eq output-format :zeek)
            (format out (format nil "#close~a~~a~%" *zeek-field-separator*)
                    (timestamp-to-zeek-open-close-string (local-time:now)))))))))

(defun cat-logs-string-multi (output-file &rest input-files)
  (with-open-file (out output-file :direction :output :if-exists :supersede)
    (with-zeek-logs (zeek-log input-files)
      (format out "~{~a~^~%~}~%" (zeek-raw-header zeek-log))
      (loop while (zeek-line zeek-log)
            do (write-line (zeek-line zeek-log) out)
               (next-record zeek-log)))
    (format out (format nil "#close~a~~a~%" *zeek-field-separator*)
            (timestamp-to-zeek-open-close-string (local-time:now)))))

(defun perf-test (&optional (output-format :zeek) (filter-expr "t") (path #P"~/tmp/test2.log"))
  (cat-logs-string path output-format filter-expr #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_00:00:00-01:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_01:00:00-02:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_02:00:00-03:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_03:00:00-04:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_04:00:00-05:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_05:00:00-06:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_06:00:00-07:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_07:00:00-08:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_08:00:00-09:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_09:00:00-10:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_10:00:00-11:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_11:00:00-12:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_12:00:00-13:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_13:00:00-14:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_14:00:00-15:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_15:00:00-16:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_16:00:00-17:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_17:00:00-18:00:00-0500.log" #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_18:00:00-19:00:00-0500.log"))
    ;;(cat-logs-string path output-format filter-func columns #P"~/code/cleek/data/homenet-uncompressed/conn_20241106_18:00:00-19:00:00-0500.log")))

;; TODO: performance isn't _too_ bad. if we are only filtering, and r/w JSON, we're already ~3x faster than the
;; equivalent `cat log | jq 'select(.field) == "val"` if we just filter and ~2x faster if we have to reconstruct the
;; line from the map. that said, it is still quite a bit slower than parsing from the zeek logs (~7x slower). maybe try
;; JSOWN and JSOON to see what kind of boost you get there? beyond that, getting the typed output correct when
;; converting is the higher priority for now. JSOON prob only improves things on x86. but see if JSOWN is generating
;; SIMD instructions because if so, you could copy what's there to JZON maybe?
(defun perf-test-json (&optional (output-format :json) (filter-expr "t") (path #P"~/tmp/test2.log"))
  (cat-logs-string path output-format filter-expr #P"~/code/cleek/data/json/homenet-uncompressed.log"))

(defun cat/handler (cmd)
  (in-package :cleek)
  (na:enable-ip-syntax)
  (cl-interpol:enable-interpol-syntax)
  (let ((args (clingon:command-arguments cmd))
        (output-file (clingon:getopt cmd :output))
        (format (string->keyword (clingon:getopt cmd :format)))
        (compression (string->keyword (clingon:getopt cmd :compression)))
        (filter-expr (clingon:getopt cmd :filter-expr))
        (mutator-expr (clingon:getopt cmd :mutator-expr)))
    (declare (ignore compression))
    (handler-bind ((error (lambda (condition) (invoke-debugger condition))))
      (apply #'cat-logs-string output-file format mutator-expr filter-expr args))))

(defparameter *nicknames*
  '((:o_h . :id.orig_h)
    (:r_h . :id.resp_h)
    (:o_p . :id.orig_p)
    (:r_p . :id.resp_p)
    (:q . :query)))

(defun or-nickname (column)
  (or (ax:assoc-value *nicknames* column) column))

(defun column? (symbol)
  (and (symbolp symbol) (char= #\@ (char (symbol-name symbol) 0))))

(defun column->keyword (symbol)
  (when (column? symbol)
    (intern (subseq (symbol-name symbol) 1) :keyword)))

;; TODO: terse regex func? e.g., (~ :o_h "^[0-4]\.") or something?
;; if you _just_ do this for string stuff, you'll know anything that uses it
;; needs to have strings. otherwise fully parse. but uhh what about mixed?
;; or (or (~ :o_p "443") (> :o_p 443))? do i need two arrays with strings
;; and fully parsed versions? i guess you could just define a list of funcs
;; and stick with those? what if you want to use something else?
;; TODO: save common filters to a file, show in --help output or something?
;;
;; so using keywords prevents me from using functions with keyword arguments :|. what if i do:
;;
;; @field to get the string, and
;; p@field to get the fully parsed field?
;;
;; still need to think about the JSON stuff cuz that's messy.
(defun update-columns (form)
  ;; (eq form 'line) didn't work and i don't know why...
  (cond ((and (symbolp form)
              (string= "LINE" (symbol-name form))) '(zeek-line log))
        ((column? form) (let ((form (column->keyword form)))
                          `(get-value log ,(or-nickname form))))
        ((atom form) form)
        (t (cons (update-columns (car form))
                 (update-columns (cdr form))))))

(defun compile-runtime-filters (s)
  (let* ((raw-filters (with-input-from-string (in s)
                        (macroexpand-1 (read in nil))))
         (filters (update-columns raw-filters))
         (columns (mapcar #'or-nickname (mapcar #'column->keyword (remove-if-not #'column? (ax:flatten raw-filters))))))
    (values (compile nil `(lambda (log) (declare (ignorable log))
                            (restart-case ,filters
                              (drop-line () :report (lambda (stream)
                                                      (format stream "DROP-LINE: \"~a\"" (zeek-line log))) nil)
                              (keep-line () t))))
            columns
            filters)))

;; SETF is a macro that needs to be expanded _after_ we update the columns, otherwise it won't use the SETF function for
;; GET-VALUE.
;; TODO: allow suffixing normal functions with ! to automatically expand to a SETF form, i.e.,
;; (anonip! @o_h) -> (setf @o_h (anonip @o_h)) -> (setf (get-value log @id.orig_h) (anonip (get-value log @id.orig_h)))
;; probably need to use MACROEXPAND instead of MACROEXPAND-1?
(defun compile-runtime-mutators (s)
  (when s
    (let* ((raw-mutators (with-input-from-string (in s)
                           (read in nil)))
           (mutators (update-columns raw-mutators))
           (columns (mapcar #'or-nickname (mapcar #'column->keyword (remove-if-not #'column? (ax:flatten raw-mutators))))))
      (values (compile nil `(lambda (log) (declare (ignorable log)) ,(macroexpand-1 mutators)))
              columns
              mutators))))

(defun cat/command ()
  (clingon:make-command
   :name "cleek"
   :version "0.5.0"
   :usage "[ZEEK-LOG]..."
   :description "Concatenate, filter, and convert Zeek logs"
   :handler #'cat/handler
   :options (cat/options)))

(defun main ()
  (let ((app (cat/command)))
    (clingon:run app)))
