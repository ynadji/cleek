(in-package :cleek)

(defun read-transform-write (in-path out-path &key (output-format :zeek))
  (let (*field-names* *types*)
    (with-open-log (in in-path)
      (with-open-log (out out-path :direction :output :if-exists :supersede)
        (let ((reader (make-reader in)))
          (multiple-value-bind (writer footer?) (make-writer out *field-names* output-format *types*)
            (loop for record = (funcall reader)
                  while record
                  do (funcall writer record))
            (when footer?
              (funcall footer?))))))))

;; TODO: how easy is it to build up transducers? you probably need a macro that
;; takes a bunch of existing functions (or forms) that get T:COMPd together in
;; the correct order (and wrapped by a lambda for forms) and used here. you
;; always need the T:TAKE-WHILE #'IDENTITY so when the READER returns NIL it
;; knows to stop. it will probably be interesting to see how the LOOP vs.
;; T:TRANSDUCE implementations are different (perf- and code-wise).
(defun read-transform-write-transducer (in-path out-path &key (output-format :zeek))
  (let (*field-names* *types*)
    (with-open-log (in in-path)
      (with-open-log (out out-path :direction :output :if-exists :supersede)
        (let ((reader (make-reader in)))
          (multiple-value-bind (writer footer?) (make-writer out *field-names* output-format *types*)
            (t:transduce (t:take-while #'identity)
                         (lambda (&optional acc record)
                           (declare (ignore acc))
                           (when record (funcall writer record)))
                         (t::make-generator :func reader))
            (when footer?
              (funcall footer?))))))))

(defun cat/options ()
  (list (clingon:make-option :string
                             :description "Output file"
                             :short-name #\o
                             :long-name "output-file"
                             :initial-value "/dev/tty"
                             :key :output)))

;; also need a good way to handle not dumping the header and footer all the
;; time.
(defun cat/handler (cmd)
  (let ((args (clingon:command-arguments cmd))
        (output-file (clingon:getopt cmd :output)))
    (let (*field-names* *types* footer?)
      (with-open-log (out output-file :direction :output :if-exists :supersede)
        (loop for in-path in args do
          (with-open-log (in in-path)
            (let ((reader (make-reader in)))
              (multiple-value-bind (writer f?) (make-writer out *field-names* :zeek *types*)
                (setf footer? f?)
                (t:transduce (t:take-while #'identity)
                             (lambda (&optional acc record)
                               (declare (ignore acc))
                               (when record (funcall writer record)))
                             (t::make-generator :func reader))))))
        (when footer?
          (funcall footer?))))))

(defun cat/command ()
  "Concatenate Zeek logs"
  (clingon:make-command
   :name "cat"
   :usage "[log1 ... logN]"
   :description "Concatenate Zeek logs"
   :handler #'cat/handler
   :options (cat/options)))

(defun main ()
  (let ((app (cat/command)))
    (clingon:run app)))
