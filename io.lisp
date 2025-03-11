(in-package :cleek)

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
  (status :unparsed :type keyword)      ; :unparsed :bytes :? :string-map :parsed-map
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
           (mapcar #'string->keyword (rest (str:split *zeek-field-separator* line)))))
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
                      (error "Fields differ in zeek logs!~%	Old: ~a~%	New: ~a~%	Diff: ~a~%" prev-fields (zeek-fields zeek-log) fields-diff))))
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
      (loop for field in (str:split *zeek-field-separator* (zeek-line zeek-log))
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

(defvar *input-format* :zeek) ; or :json
(defvar *output-format* :zeek) ; or :json

(defvar *input-compression* :txt) ; or :zstd or :gzip
(defvar *output-compression* :txt) ; or :zstd or :gzip

(defvar *zeek-field-separator* #\Tab)

(defparameter *buffer-size* (expt 2 16)) ; i used 32MB! before for very long log lines hmm.
(defparameter *buffer* (make-array *buffer-size* :element-type '(unsigned-byte 8)))
(defvar *newline-byte* (char-code #\Newline))

(defun shift-unfinished-sequence (buf start)
  (let ((read-index (- (length buf) start)))
    (replace buf buf :start1 0 :start2 start)
    (fill buf 0 :start read-index)
    read-index))

(defun sequence-line-reader (stream)
  (let ((start 0)
        (eof? nil)
        (first-byte (setf (aref *buffer* 0)
                          (read-byte stream nil))))
    (read-sequence *buffer* stream :start 1) ; we already read the first byte above.
    (labels ((slr ()
               (when eof?
                 (return-from slr))
               (ax:if-let ((end (position *newline-byte* *buffer* :start start)))
                 (prog1 (babel:octets-to-string *buffer* :start start :end end)
                   (setf start (1+ end)))
                 (let ((read-index (shift-unfinished-sequence *buffer* start)))
                   ;; READ-SEQUENCE returns the first element of *BUFFER* that
                   ;; was unmodified. If it is equal to whatever the :START was,
                   ;; that means it read zero bytes and we hit EOF.
                   (setf eof? (= read-index
                                 (read-sequence *buffer* stream :start read-index)))
                   (setf start 0)
                   (slr)))))
      (values #'slr
              (ecase first-byte ; 123 is (char-code #\{), 35 is (char-code #\#)
                (123 :json)
                (35 :zeek))))))

(defvar *field-names* nil)
(defvar *types* nil)
(defvar *header-already-printed?* nil)

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
                                                                    :initial-element "not implemented"))))))) ; TODO

(defun read-zeek-header (line-reader)
  (let ((more-header? t))
    (loop while more-header?
          for line = (funcall line-reader)
          when (str:starts-with? "#fields" line)
            do (setf *field-names* (mapcar #'string->keyword (rest (str:split *zeek-field-separator* line))))
          when (str:starts-with? "#types" line)
            do (setf *types* (mapcar #'string->keyword (rest (str:split *zeek-field-separator* line)))
                     more-header? nil))
    (values *field-names* *types*)))

(defun zeek-reader (line-reader)
  (read-zeek-header line-reader)
  (let ((num-fields (length *field-names*)))
    (lambda ()
      (let ((line (funcall line-reader))
            (ht (make-hash-table :size num-fields)))
        (unless (or (not line)
                    (char= #\# (char line 0)))
          (loop for field in (str:split *zeek-field-separator* line)
                for name in *field-names*
                do (setf (gethash name ht) field)))
        (unless (zerop (hash-table-count ht))
          ht)))))

(defun json-reader (line-reader)
  (let ((num-fields 0))
    (lambda ()
      (ax:when-let* ((line (funcall line-reader))
                     (json (jzon:parse line :key-fn #'string->keyword)))
        (when (> (hash-table-count json) num-fields)
          (setf *field-names* (ax:hash-table-keys json))
          (setf num-fields (length *field-names*)))
        json))))

(defun make-reader (stream)
  (multiple-value-bind (line-reader format) (sequence-line-reader stream)
    (ecase format
      (:zeek (zeek-reader line-reader))
      (:json (json-reader line-reader)))))

(defun json-writer (stream &optional field-names)
  (lambda (record)
    (write-sequence (record->bytes record field-names :json) stream)))

;; TODO: FIELD-NAMES and TYPES should just default to the dynamic variables. it
;; doesn't matter now, but when you're adding fields (add e2ld or bin to /24)
;; you'll want to be able to handle that in the caller rather than here.
(defun zeek-writer (stream)
  (values (lambda (record)
            ;; can i buffer these so i write fewer times?
            (write-sequence (record->bytes record *field-names* :zeek) stream))
          (lambda ()
            (unless *header-already-printed?*
              (write-sequence (babel:string-to-octets (generate-zeek-header *field-names* *types*)) stream)
              (setf *header-already-printed?* t)))
          (lambda ()
            (write-sequence
             (babel:string-to-octets
              (format nil (format nil "#close~a~~a~%" *zeek-field-separator*)
                      (timestamp-to-zeek-open-close-string (local-time:now))))
             stream))))

(defun make-writer (stream format &optional (field-names *field-names*) (types *types*))
  (declare (ignorable field-names types))
  (ecase format
    (:zeek (zeek-writer stream))
    (:json (json-writer stream))))

;; TODO: Fix zst.
(defun get-de/compression-func (filename output?)
  (if output?
      (cond ((str:ends-with? ".log" filename :ignore-case t)
             nil)
            ((str:ends-with? ".zst" filename :ignore-case t)
             (lambda (stream) (zstd:make-compressing-stream stream)))
            ((str:ends-with? ".gz" filename :ignore-case t)
             (lambda (stream) (salza2:make-compressing-stream 'salza2:gzip-compressor stream)))
            (t nil))
      (cond ((str:ends-with? ".log" filename :ignore-case t)
             nil)
            ((str:ends-with? ".zst" filename :ignore-case t)
             (lambda (stream) (zstd:make-decompressing-stream stream)))
            ((str:ends-with? ".gz" filename :ignore-case t)
             (lambda (stream) (chipz:make-decompressing-stream 'chipz:gzip stream)))
            (t nil))))

(defmacro with-open-log ((stream filespec &rest options) &body body)
  (ax:with-gensyms (io de/compressor)
    `(let ((,de/compressor (get-de/compression-func (file-namestring ,filespec)
                                                    ,(find :output options))))
       (if ,de/compressor
           (with-open-file (,io ,filespec :element-type '(unsigned-byte 8) ,@options)
              (with-open-stream (,stream (funcall ,de/compressor ,io))
                ,@body))
           (with-open-file (,stream ,filespec :element-type '(unsigned-byte 8) ,@options)
              ,@body)))))

(defun record->bytes (record field-names output-format)
  (case output-format
    (:json (babel:string-to-octets
            (format nil "~a~%"
                    (jzon:stringify record
                                    :replacer (lambda (k v) (declare (ignore k)) (not (equal "-" v)))))))
    (:zeek ;; this is incomplete until you handle JSON arrays (when going from json->zeek).
     (babel:string-to-octets
      (format nil (format nil "~~{~~a~~^~C~~}~~%" *zeek-field-separator*)
              (loop for field-name in field-names
                    collect (gethash field-name record "-")))))))
