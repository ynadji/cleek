(in-package :cleek)

;; TODOs:
;; * timestamp filtering maybe t< t> t<= t>=? handle the conversion with generic functions?
;; * shorthand for fully parse. maybe @@? how do i know to fully deparse then?
;; * suite for performance testing so you can optimize things more easily.

(defvar *common-filters-and-mutators-path* #P"~/.config/cleek/common-filters-and-mutators.lisp")
(defparameter *common-filters-and-mutators* nil)
(defun init-common-filters-and-mutators ()
  (when (probe-file *common-filters-and-mutators-path*)
    (load *common-filters-and-mutators-path*)))

(defun cat-logs-string (output-file output-format mutator-expr filter-expr &rest input-files)
  (multiple-value-bind (mutator-func mutator-columns) (compile-runtime-mutators mutator-expr)
    (multiple-value-bind (filter-func filter-columns) (compile-runtime-filters filter-expr)
      (let ((columns (union mutator-columns filter-columns)))
        (with-open-file (out output-file :direction :output :if-exists :supersede)
          (when (zerop (length input-files))
            (push "/dev/stdin" input-files))
          (loop for in-path in input-files do
            (with-zeek-log (zeek-log in-path columns)
              (when (eq output-format :input-format)
                (setf output-format (zeek-format zeek-log)))
              (write-zeek-header zeek-log out output-format)
              (loop while (zeek-line zeek-log)
                    do (when mutator-func
                         (funcall mutator-func zeek-log))
                       (when (or (null filter-func)
                                 (funcall filter-func zeek-log))
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

(defun update-columns (form)
  ;; (eq form 'line) didn't work and i don't know why...
  (cond ((and (symbolp form)
              (string= "LINE" (symbol-name form))) '(zeek-line log))
        ((column? form) (let ((form (column->keyword form)))
                          `(get-value log ,(or-nickname form))))
        ((atom form) (or (ax:assoc-value *common-filters-and-mutators* form)
                         form))
        (t (cons (update-columns (car form))
                 (update-columns (cdr form))))))

(defun expand-columns (filters &optional columns)
  (flet ((extract-columns (form)
           (remove-duplicates (mapcar #'or-nickname (mapcar #'column->keyword (remove-if-not #'column?
                                                                                             (ax:flatten form)))))))
    (let ((new-filters (update-columns filters))
          (new-columns (extract-columns filters)))
      (if (or (eq filters t)
              (and columns
                   (null (set-exclusive-or columns (union columns new-columns)))))
          (values new-filters columns)
          (expand-columns new-filters new-columns)))))

;; From https://lispcookbook.github.io/cl-cookbook/error_handling.html#defining-restarts-restart-case
(defun prompt-new-value (prompt)
  (format *query-io* prompt)
  (force-output *query-io*)
  (list (read *query-io*)))

;; TODO: guard against filters without any @columns?
(defun compile-runtime-filters (s)
  (when s
    (restart-case
        (let ((raw-filters (with-input-from-string (in s)
                             (read in nil))))
          (multiple-value-bind (filters columns) (expand-columns raw-filters)
            (values (compile nil `(lambda (log) (declare (ignorable log))
                                    (restart-case ,(macroexpand-1 filters)
                                      (drop-line () :report (lambda (stream)
                                                              (format stream "DROP-LINE: \"~a\"" (zeek-line log))) nil)
                                      (keep-line () t))))
                    columns
                    filters)))
      (set-new-filter (filter)
        :report "Enter a new filter"
        :interactive (lambda () (prompt-new-value "Please enter a new filter: "))
        (compile-runtime-filters filter))
      (remove-filter ()
        :report "Remove filter"
        nil))))

(defun update-setters (form)
  (flet ((setter? (fun)
           (and (symbolp fun) (str:ends-with? "!" (symbol-name fun))))
         (fun-name-from-setter (setter)
           (let ((s (symbol-name setter)))
             (intern (str:substring 0 (1- (length s)) s)))))
    (cond ((and (consp form) (setter? (car form)))
           `(setf ,(cadr form) (,(fun-name-from-setter (car form)) ,@(rest form))))
          ((atom form) form)
          (t (cons (update-setters (car form))
                   (update-setters (cdr form)))))))

;; SETF is a macro that needs to be expanded _after_ we update the columns, otherwise it won't use the SETF function for
;; GET-VALUE.
(defun compile-runtime-mutators (s)
  (when s
    (restart-case
        ;; Read all forms in mutator string and wrap in PROGN.
        (flet ((read-all-progn (stream)
                 (let ((forms (loop for form = (read stream nil)
                                    while form collect form)))
                   (push 'progn forms))))
          (let* ((raw-mutators (with-input-from-string (in s)
                                 (read-all-progn in))))
            (multiple-value-bind (mutators columns) (expand-columns (update-setters raw-mutators))
              (values (compile nil `(lambda (log) (declare (ignorable log)) ,(macroexpand-1 mutators)))
                      columns
                      mutators))))
      (set-new-mutator (mutator)
        :report "Enter a new mutator"
        :interactive (lambda () (prompt-new-value "Please enter a new mutator: "))
        (compile-runtime-mutators mutator))
      (remove-mutator ()
        :report "Remove mutator"
        nil))))

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
        (clingon:make-option :string
                             :description "Filter expression"
                             :short-name #\x
                             :long-name "filter"
                             :initial-value nil
                             :key :filter-expr)
        (clingon:make-option :string
                             :description "Mutator expression"
                             :short-name #\m
                             :long-name "mutator"
                             :initial-value nil
                             :key :mutator-expr)))

(defun cat/handler (cmd)
  (in-package :cleek)
  (na:enable-ip-syntax)
  (cl-interpol:enable-interpol-syntax)
  (let ((args (clingon:command-arguments cmd))
        (output-file (clingon:getopt cmd :output))
        (format (string->keyword (clingon:getopt cmd :format)))
        (filter-expr (clingon:getopt cmd :filter-expr))
        (mutator-expr (clingon:getopt cmd :mutator-expr)))
    (init-common-filters-and-mutators)
    (handler-bind ((error (lambda (condition) (invoke-debugger condition))))
      (handler-case
          (apply #'cat-logs-string output-file format mutator-expr filter-expr args)
        ;; Still doesn't build on ECL due to not being able to find ASDF/SYSTEM::FIND-SYSTEM even if i add "asdf" to the
        ;; :depends-on bit of my DEFSYSTEM call. Seem similar to
        ;; https://www.reddit.com/r/Common_Lisp/comments/hicmyt/error_with_uiop_running_ecl_application_built_by/ in
        ;; that weird things happen based on the order. If I put "asdf" before "str" it complains about not being able
        ;; to find "str" component. /shrugs
        ;;((or end-of-file #+sbcl sb-int:broken-pipe) nil)
        ;;
        ;; if you handle END-OF-FILE here, it prevents the RESTART-CASE in the COMPILE-RUNTIME-* functions from being
        ;; able to handle the restarts. unsure why.
        (sb-int:broken-pipe nil)
        ;; If there's a debugger error, after aborting SIMPLE-FILE-ERROR is raised again. This let's a user immediately
        ;; exit after running into an error.
        (sb-int:simple-file-error nil)))))

(defun cat/command ()
  (clingon:make-command
   :name "cleek"
   :version "0.10.2"
   :usage "[ZEEK-LOG]..."
   :description "Concatenate, filter, and convert Zeek logs"
   :handler #'cat/handler
   :options (cat/options)))

(defun main ()
  (let ((app (cat/command)))
    (clingon:run app)))
