(in-package :cleek)

(defvar *zeek-field-separator* #\Tab)

(defstruct zeek
  filepath
  path
  stream
  raw-header
  (compression :none :type keyword)     ; :none :gzip :zstd
  line
  types
  fields
  row-strings
  row
  (field->idx (make-hash-table) :type hash-table)
  (status :unparsed :type keyword) ; :unparsed :bytes :? :string-map :parsed-map
  modified?
  (buffer (make-array 32                ; Grow this if actually used.
                      :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8)))
  (map (make-hash-table) :type hash-table)
  (format :zeek :type keyword)          ; :zeek :json
  )

(defun infer-format (stream)
  (ecase (peek-char nil stream)
    (#\{ :json)
    (#\# :zeek)))

(defun parse-zeek-header (zeek-log)
  (flet ((parse-header-values (line)
           (mapcar #'string->keyword (rest (split-sequence *zeek-field-separator* line)))))
    (let ((more-header? t))
      (loop for line = (read-line (zeek-stream zeek-log) nil)
            while (and more-header? line)
            do (push line (zeek-raw-header zeek-log))
            when (str:starts-with? "#path" line)
              do (setf (zeek-path zeek-log)
                       (first (parse-header-values line)))
            when (str:starts-with? "#fields" line)
              do (setf (zeek-fields zeek-log)
                       (parse-header-values line))
            when (str:starts-with? "#types" line)
              do (setf (zeek-types zeek-log)
                       (parse-header-values line)
                       more-header? nil)
            finally (setf (zeek-line zeek-log) line
                          (zeek-status zeek-log) :unparsed
                          (zeek-modified? zeek-log) nil)) ; TODO: remove duplicate in NEXT-RECORD :\
      (ax:reversef (zeek-raw-header zeek-log))
      zeek-log)))

(defun get-value (zeek-log field)
  (ecase (zeek-format zeek-log)
    ;; TODO: these are always strings. what about when we want not strings?
    (:zeek (aref (zeek-row-strings zeek-log) (field->idx zeek-log field)))
    ;; TODO: these are always "parsed" from jzon
    (:json (gethash field (zeek-map zeek-log)))))

;; TODO: Make this work with the condition system
(defun open-zeek-log (&key filepath stream)
  (when (or (and filepath stream) (and (null stream) (null filepath)))
    (error "Specify exactly one of FILEPATH or STREAM"))
  (let ((zeek-log (make-zeek :filepath (or filepath "N/A")
                             :stream (or stream (open filepath)))))
    (setf (zeek-format zeek-log) (infer-format (zeek-stream zeek-log)))
    (ecase (zeek-format zeek-log)
      (:zeek (parse-zeek-header zeek-log))
      (:json (next-record zeek-log) (infer-log-path-fields-types zeek-log)))
    zeek-log))

(defun next-record (zeek-log)
  ;; TODO: Add condition handling for when the header differs.
  (progn (setf (zeek-line zeek-log) (read-line (zeek-stream zeek-log) nil)
               (zeek-status zeek-log) :unparsed
               (zeek-modified? zeek-log) nil)
         (cond ((str:starts-with? "#close" (zeek-line zeek-log))
                (next-record zeek-log))
               ;; new header
               ((str:starts-with? "#" (zeek-line zeek-log))
                (let ((prev-fields (zeek-fields zeek-log)))
                  (parse-zeek-header zeek-log)
                  (let ((fields-diff (set-exclusive-or prev-fields (zeek-fields zeek-log))))
                    (when (and prev-fields fields-diff)
                      (error "Fields differ in zeek logs!~%	Old: ~a~%	New: ~a~%	Diff: ~a~%" prev-fields (zeek-fields zeek-log) fields-diff)))
                  ;; skip empty files that go directly from header to #close.
                  (when (str:starts-with? "#close" (zeek-line zeek-log))
                    (next-record zeek-log)))
                zeek-log)
               (t zeek-log))))

(defmacro with-zeek-log ((log filepath) &body body)
  (ax:with-gensyms (abort?)
    `(let ((,log (open-zeek-log :filepath ,filepath))
           (,abort? t))
       (unwind-protect
            (multiple-value-prog1
                (progn ,@body)
              (setq ,abort? nil))
         (when (and ,log (zeek-stream ,log))
           (close (zeek-stream ,log) :abort ,abort?))))))

;; concatenated streams are _way_ slower than just looping over each log and
;; doing a WITH-ZEEK-LOG serially. no idea why. not a super common use case for
;; now.
(defmacro with-zeek-logs ((log filepaths) &body body)
  (ax:with-gensyms (abort? cstream streams)
    `(let* ((,streams (mapcar #'open ,filepaths))
            (,cstream (apply #'make-concatenated-stream ,streams))
            (,log (open-zeek-log :stream ,cstream))
            (,abort? t))
       (unwind-protect
            (multiple-value-prog1
                (progn ,@body)
              (setq ,abort? nil))
         (when (and ,log (zeek-stream ,log))
           (mapcar (lambda (s) (close s :abort ,abort?)) ,streams)
           (close (zeek-stream ,log) :abort ,abort?))))))

;; TODO: if FIELDS is non-NIL, only parse those fields.
;; just make ROW-STRINGS only as long as the number of fields you have
;; then ENSURE-ROW will just work.
;;
;; thinking about this more, you'd basically have to handroll something to look
;; for the delimiters and it would only be noticeably faster if there aren't a
;; lot of fields and they're early on in the line.
(defun ensure-row-strings (zeek-log &optional fields)
  (when (eq :unparsed (zeek-status zeek-log))
    (if fields
        (error "Parsing of individual fields not implemented.")
        (setf (zeek-row-strings zeek-log) (coerce (split-sequence #\Tab (zeek-line zeek-log)) 'vector)
              (zeek-status zeek-log) :row-strings))))

;; TODO: if FIELDS is non-NIL, only parse those fields.
;; TODO: you should do a quick check to see if only parsing the needed fields
;; is any faster than just parsing all of them and by how much.
(defun ensure-row (zeek-log &optional fields)
  (unless (eq :row (zeek-status zeek-log))
    (ensure-row-strings zeek-log fields)
    (if fields
        (error "Parsing of individual fields not implemented.")
        (setf (zeek-row zeek-log)
              (coerce (loop for type in (zeek-types zeek-log)
                            for field across (zeek-row-strings zeek-log)
                            collect (parse-zeek-type field type)) 'vector)
              (zeek-status zeek-log) :row))))

(defun ensure-fields->idx (zeek-log)
  (when (zerop (hash-table-count (zeek-field->idx zeek-log)))
    (ensure-fields zeek-log)
    (loop for idx from 0 for field in (zeek-fields zeek-log)
          do (setf (gethash field (zeek-field->idx zeek-log)) idx))))

(defun field->idx (zeek-log field)
  (gethash field (zeek-field->idx zeek-log)))

;; TODO: i probably don't need this anymore. just something that
;; writes out a json log.
(defun ensure-map (zeek-log)     ; TODO: add parse for :parsed-map
  (when (eq :unparsed (zeek-status zeek-log))
   (ecase (zeek-format zeek-log)
     (:zeek
      (clrhash (zeek-map zeek-log))
      (loop for field in (split-sequence *zeek-field-separator* (zeek-line zeek-log))
            for name in (zeek-fields zeek-log)
            do (setf (gethash name (zeek-map zeek-log)) field)))
     (:json
      (clrhash (zeek-map zeek-log))
      (setf (zeek-map zeek-log) (jzon:parse (zeek-line zeek-log) :key-fn #'string->keyword))))
   (setf (zeek-status zeek-log) :string-map)))

(defun ensure-fields (zeek-log)
  (unless (zeek-fields zeek-log)
    (when (zerop (hash-table-count (zeek-map zeek-log)))
      (error "FIELDS and MAP are both empty so FIELDS cannot be populated."))
    (setf (zeek-fields zeek-log) (ax:hash-table-keys (zeek-map zeek-log)))))

(defun generate-zeek-header (field-names types)
  (let ((field-names (mapcar #'str:downcase (mapcar #'string field-names))))
    (format nil "~a~%~a~%~a~%~a~%~a~%~a~%~a~%~a~%"
            (format nil "#separator \\x~2,'0x" (char-code *zeek-field-separator*))
            (format nil (format nil "#set_separator~a~~a" *zeek-field-separator*) *zeek-set-separator*)
            (format nil (format nil "#empty_field~a~~a" *zeek-field-separator*) *zeek-empty-field*)
            (format nil (format nil "#unset_field~a~~a" *zeek-field-separator*) "-")
            (format nil (format nil "#path~a~~a" *zeek-field-separator*) "cleek_path") ; TODO
            (format nil (format nil "#open~a~~a" *zeek-field-separator*)
                    (timestamp-to-zeek-open-close-string (local-time:now)))
            (format nil (format nil "#fields~a~~a" *zeek-field-separator*)
                    (str:join *zeek-field-separator* field-names))
            (format nil (format nil "#types~a~~a" *zeek-field-separator*)
                    (str:join *zeek-field-separator* (if types
                                                         (mapcar #'keyword->string types)
                                                         (make-list (length field-names)
                                                                    :initial-element "not implemented")))))))

(defun write-zeek-header (zeek-log stream format)
  (when (eq format :zeek)
    (ax:if-let ((header (zeek-raw-header zeek-log)))
      (format stream "~{~a~^~%~}~%" header)
      (progn (ensure-map zeek-log)
             (ensure-fields zeek-log)
             (format stream "~a" (generate-zeek-header (zeek-fields zeek-log) (zeek-types zeek-log)))))))

;; TODO: handle set/vector types appropriately.
(defun write-zeek-log-line (zeek-log stream format)
  (cond ((and (not (zeek-modified? zeek-log)) (eq format (zeek-format zeek-log)))
         (write-line (zeek-line zeek-log) stream))
        ((not (zeek-modified? zeek-log))
         (ensure-map zeek-log)
         (ensure-fields zeek-log)
         (ecase format
           (:json (jzon:stringify (zeek-map zeek-log) :stream stream) (terpri stream))
           (:zeek (format stream (format nil "~~{~~a~~^~C~~}~~%" *zeek-field-separator*)
                          (loop for field-name in (zeek-fields zeek-log)
                                collect (or (gethash field-name (zeek-map zeek-log) "-") "-"))))))
        (t (error "Modified log writing not supported."))))
