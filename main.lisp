(in-package :cleek)

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
                             :key :output)))

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

(defun cat/handler (cmd)
  (let ((args (clingon:command-arguments cmd))
        (output-file (clingon:getopt cmd :output)))
    (let (*field-names* *types* write-footer *header-already-printed?*)
      (with-open-log (out output-file :direction :output :if-exists :supersede)
        (loop for in-path in args do
          (with-open-log (in in-path)
            (let ((reader (make-reader in)))
              (multiple-value-bind (writer write-header w-f) (make-writer out *field-names* :zeek *types*)
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
