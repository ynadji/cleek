(in-package :cleek)

(defvar *zeek-field-separator* #\Tab)

(defvar *delimiter* nil
  "Field delimiter character for -D/--delimiter-mode, NIL when not in delimiter
mode. In delimiter mode input is plain text: every line is a record, fields are
split on this character, and columns are referenced positionally as @N (1-based).")

(defun parse-delimiter (s)
  "Turn the -D/--delimiter-mode argument S into a single delimiter character.
Accepts a literal character or the escapes \\t, \\r, \\s, and \\0 (shells that
can produce the real character, e.g. -D $'\\t', work too)."
  (cond ((null s) nil)
        ((= 1 (length s)) (char s 0))
        ((string= s "\\t") #\Tab)
        ((string= s "\\r") #\Return)
        ((string= s "\\s") #\Space)
        ((string= s "\\0") (code-char 0))
        (t (error "-D/--delimiter-mode takes a single character (or one of \\t, \\r, \\s, \\0); got ~s" s))))

(defun delim-column-index (field)
  "0-based row index for the delimiter-mode column keyword FIELD (:|3| => 2), or
NIL if FIELD does not name a positive integer."
  (let ((idx (ignore-errors (parse-integer (symbol-name field)))))
    (when (and idx (plusp idx))
      (1- idx))))

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
      ;; Check for newly created fields from mutators.
      (ax:when-let ((created-fields (set-difference (zeek-accessed-columns zeek-log) (zeek-fields zeek-log))))
        (setf (zeek-created-fields zeek-log) created-fields
              ;; TODO: How can I infer the type?
              (zeek-created-types zeek-log) (make-list (length created-fields) :initial-element :string)))
      zeek-log)))

(defun has-field? (zeek-log field)
  (ecase (zeek-format zeek-log)
    (:zeek (field->idx zeek-log field))
    (:json (gethash field (zeek-map zeek-log)))
    (:delim (ax:when-let ((idx (field->idx zeek-log field)))
              (< idx (length (zeek-row-strings zeek-log)))))))

(defun get-value (zeek-log field &optional fully-parsed?)
  (declare (optimize (speed 3) (debug 0) (space 0) (compilation-speed 0))
           (type zeek zeek-log)
           (type keyword field))
  (ecase (zeek-format zeek-log)
    (:zeek (if (and (zeek-created-fields zeek-log) (not (has-field? zeek-log field)))
                 ;; Created fields: read from zeek-map (unchanged)
                 (let ((val (gethash field (zeek-map zeek-log))))
                   (if fully-parsed?
                       (parse-zeek-type val (field->type zeek-log field) t)
                       val))
                  ;; Regular fields: lazy materialization from offsets
                  (let* ((idx (the fixnum (field->idx zeek-log field)))
                         (cached (svref (zeek-row-strings zeek-log) idx)))
                    (if cached
                        (if fully-parsed?
                            (parse-zeek-type cached (field->type zeek-log field) t)
                            cached)
                        (let* ((offsets (zeek-offsets zeek-log))
                               (bline (zeek-bline zeek-log))
                               (start (if (zerop idx)
                                          (aref offsets idx)
                                          (1+ (aref offsets idx))))
                               (end (aref offsets (1+ idx)))
                               (type (field->type zeek-log field)))
                          (declare (type (simple-array fixnum (*)) offsets)
                                   (type fixnum start end))
                          ;; For numeric types with fully-parsed?, parse directly
                          ;; with :start/:end — avoids subseq allocation.
                          (if (and fully-parsed?
                                   ;; Not unset ("-") or empty "(empty)"
                                   (/= (- end start) 1)
                                   (member type '(:double :interval :count :int :port) :test #'eq))
                              (if bline
                                  (case type
                                    ((:double :interval)
                                     (%fast-parse-double-u8 bline start end))
                                    ((:count :int :port)
                                     (%parse-integer-u8 bline start end)))
                                  (let ((line (zeek-line zeek-log)))
                                    (declare (type simple-string line))
                                    (case type
                                      ((:double :interval)
                                       (fast-parse-double line :start start :end end))
                                      ((:count :int :port)
                                       (parse-integer line :start start :end end)))))
                              ;; Non-numeric or needs subseq: materialize and cache
                              (let ((val (if bline
                                             (%bytes->string bline start end)
                                             (subseq (the simple-string (zeek-line zeek-log))
                                                     start end))))
                                (setf (svref (zeek-row-strings zeek-log) idx) val)
                                (if fully-parsed?
                                    (parse-zeek-type val type t)
                                    val))))))))
    (:json (if fully-parsed?
               (zeekify-json-type (gethash field (zeek-map zeek-log)) (field->type zeek-log field))
               (gethash field (zeek-map zeek-log))))
    ;; Delimiter mode has no #types, so FULLY-PARSED? is ignored: @@N is @N. A
    ;; row narrower than @N reads as "" rather than NIL, which is a string
    ;; designator and would make (string= @9 "GET") compare against "NIL".
    (:delim (let ((idx (field->idx zeek-log field))
                  (row (zeek-row-strings zeek-log)))
              (if (and idx (< (the fixnum idx) (length (the simple-vector row))))
                  (svref row (the fixnum idx))
                  "")))))

(defun %set-delim-value (new-value zeek-log field)
  "Write NEW-VALUE to delimiter-mode column FIELD (@N). Setting a column past the
row's width appends it, padding any gap with empty fields, so a mutator can add
columns to a plain text row."
  (let ((idx (or (delim-column-index field)
                 (error "delimiter mode (-D) only supports numeric column references like @1; got @~a"
                        (keyword->string field))))
        (row (zeek-row-strings zeek-log)))
    (when (>= idx (length row))
      (let ((grown (make-array (1+ idx) :initial-element "")))
        (replace grown row)
        (setf row grown
              (zeek-row-strings zeek-log) grown)))
    (setf (zeek-modified? zeek-log) t
          (svref row idx) new-value)))

(defun (setf get-value) (new-value zeek-log field &optional fully-parsed?)
  (declare (optimize (speed 3) (debug 0) (space 0) (compilation-speed 0))
           (ignore fully-parsed?)
           (type zeek zeek-log)
           (type keyword field))
  (cond ((eq :delim (zeek-format zeek-log))
         (%set-delim-value new-value zeek-log field))
        ((has-field? zeek-log field)
         (prog1 (ecase (zeek-format zeek-log)
                  (:zeek (setf (aref (the simple-vector (zeek-row-strings zeek-log))
                                     (the fixnum (field->idx zeek-log field)))
                               new-value))
                  (:json (setf (gethash field (zeek-map zeek-log)) new-value)))
           (setf (zeek-modified? zeek-log) t)))
        (t
         (prog1 (ecase (zeek-format zeek-log)
                  (:zeek (setf (gethash field (zeek-map zeek-log)) new-value))
                  (:json (setf (gethash field (zeek-map zeek-log)) new-value)))
           (setf (zeek-modified? zeek-log) t)))))

;; TODO: Make this work with the condition system
(defun open-zeek-log (&key filepath stream columns)
  (when (or (and filepath stream) (and (null stream) (null filepath)))
    (error "Specify exactly one of FILEPATH or STREAM"))
  (let ((zeek-log (make-zeek :filepath (or filepath "N/A")
                             :stream (or stream (open filepath)))))
    ;; In delimiter mode we must not INFER-FORMAT: a plain text line may well
    ;; start with # or {, and the peek would consume nothing but mislead.
    (setf (zeek-format zeek-log) (if *delimiter* :delim (infer-format (zeek-stream zeek-log)))
          (zeek-accessed-columns zeek-log) columns)
    (ecase (zeek-format zeek-log)
      (:zeek (parse-zeek-header zeek-log))
      (:json (next-record zeek-log) (infer-log-path-fields-types zeek-log))
      (:delim (init-delim-log zeek-log)))
    ;; Pre-allocate offsets and row-strings vectors now that field count is known.
    (when (zeek-fields zeek-log)
      (setf (zeek-offsets zeek-log)
            (make-array (1+ (length (zeek-fields zeek-log))) :element-type 'fixnum)
            (zeek-row-strings zeek-log)
            (make-array (length (zeek-fields zeek-log)) :initial-element nil)))
    ;; INIT-DELIM-LOG has already done the equivalent work; ENSURE-FIELDS->IDX
    ;; would error here since delimiter mode has neither FIELDS nor a MAP.
    (when (and (zeek-accessed-columns zeek-log)
               (not (eq :delim (zeek-format zeek-log))))
      (ensure-fields->idx zeek-log)
      (ecase (zeek-format zeek-log)
        (:zeek (ensure-row-strings zeek-log))
        (:json (ensure-map zeek-log))))
    zeek-log))

(defun init-delim-log (zeek-log)
  "Prepare ZEEK-LOG for delimiter mode and read its first record. There is no
header to parse, so instead of deriving FIELD->IDX from #fields we map each
accessed @N column straight to index N-1 (type :STRING), keeping per-access
lookup the same O(1) GETHASH the zeek path gets from ENSURE-FIELDS->IDX."
  (loop for column in (zeek-accessed-columns zeek-log)
        for idx = (or (delim-column-index column)
                      (error "delimiter mode (-D) only supports numeric column references like @1; got @~a"
                             (keyword->string column)))
        do (setf (gethash column (zeek-field->idx zeek-log)) idx
                 (gethash column (zeek-field->type zeek-log)) :string))
  (setf (zeek-row-strings zeek-log) (make-array 0))
  (next-delim-record zeek-log))

(defun ensure-delim-fields (zeek-log)
  "Split the current delimiter-mode record into ROW-STRINGS. Unlike the zeek TSV
path this materializes every field up front rather than lazily slicing out of
OFFSETS: plain text declares its width nowhere, so rows are allowed to be ragged
and COMPUTE-OFFSETS' fixed field count would fold a too-wide row's tail into the
last column."
  (when (eq :unparsed (zeek-status zeek-log))
    (setf (zeek-row-strings zeek-log)
          (coerce (split-sequence *delimiter* (zeek-line zeek-log)) 'simple-vector)
          (zeek-status zeek-log) :delim-fields)))

(defun next-delim-record (zeek-log)
  "Advance ZEEK-LOG by one delimiter-mode record. Every line is a record: there
are no headers, no #close footer, and a leading # is data, not a header."
  (setf (zeek-line zeek-log) (read-line (zeek-stream zeek-log) nil)
        (zeek-status zeek-log) :unparsed
        (zeek-modified? zeek-log) nil)
  (when (and (zeek-line zeek-log) (zeek-accessed-columns zeek-log))
    (ensure-delim-fields zeek-log))
  zeek-log)

(defun next-record (zeek-log)
  ;; TODO: Add condition handling for when the header differs.
  (declare (optimize (speed 3) (debug 0) (space 0) (compilation-speed 0))
           (type zeek zeek-log))
  (when (eq :delim (zeek-format zeek-log))
    (return-from next-record (next-delim-record zeek-log)))
  (let ((line (setf (zeek-line zeek-log) (read-line (zeek-stream zeek-log) nil))))
    (setf (zeek-status zeek-log) :unparsed
          (zeek-modified? zeek-log) nil)
    (unless (zerop (hash-table-count (zeek-map zeek-log)))
      (clrhash (zeek-map zeek-log)))
    (cond ;; Normal record (or EOF) — the common case, checked with a single
          ;; char compare instead of two str:starts-with? calls per line.
          ((or (null line) (zerop (length line)) (char/= #\# (char line 0)))
           (when (and line (zeek-accessed-columns zeek-log))
             (ecase (zeek-format zeek-log)
               (:zeek (ensure-row-strings zeek-log))
               (:json (ensure-map zeek-log))))
           zeek-log)
          ((str:starts-with? "#close" line)
           (next-record zeek-log))
          ;; new header
          (t
           (let ((prev-fields (zeek-fields zeek-log)))
             (parse-zeek-header zeek-log)
             (let ((fields-diff (set-exclusive-or prev-fields (zeek-fields zeek-log))))
               (when (and prev-fields fields-diff)
                 (error "Fields differ in zeek logs!~%	Old: ~a~%	New: ~a~%	Diff: ~a~%" prev-fields (zeek-fields zeek-log) fields-diff)))
             ;; skip empty files that go directly from header to #close.
             (when (str:starts-with? "#close" (zeek-line zeek-log))
               (next-record zeek-log)))
           (when (and (zeek-line zeek-log) (zeek-accessed-columns zeek-log))
             (ecase (zeek-format zeek-log)
               (:zeek (ensure-row-strings zeek-log))
               (:json (ensure-map zeek-log))))
           zeek-log))))

(defmacro with-zeek-log ((log filepath &optional columns) &body body)
  (ax:with-gensyms (abort?)
    `(let ((,log (open-zeek-log :filepath ,filepath :columns ,columns))
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

(defun compute-offsets (line offsets)
  "Scan LINE for tabs, store field boundaries in OFFSETS (pre-allocated).
   OFFSETS[0] = 0 (start of field 0).
   OFFSETS[i] for i=1..nfields-1 = tab position (exclusive end of field i-1).
   OFFSETS[nfields] = (length line) (exclusive end of last field).
   Field 0: (subseq line 0 (aref offsets 1)).
   Field i>0: (subseq line (1+ (aref offsets i)) (aref offsets (1+ i)))."
  (declare (optimize (speed 3) (safety 1))
           (type simple-string line)
           (type (simple-array fixnum (*)) offsets))
  (let ((nfields (1- (length offsets))))
    (declare (type fixnum nfields))
    (setf (aref offsets 0) 0)
    (loop with start fixnum = 0
          for i fixnum from 1 below nfields
          for tab-pos = (position #\Tab line :start start)
          while tab-pos
          do (setf (aref offsets i) (the fixnum tab-pos)
                   start (the fixnum (1+ tab-pos)))
          finally (loop for j fixnum from i to nfields
                        do (setf (aref offsets j) (length line))))
    (setf (aref offsets nfields) (length line))))

;; TODO: if FIELDS is non-NIL, only parse those fields.
;; just make ROW-STRINGS only as long as the number of fields you have
;; then ENSURE-ROW will just work.
;;
;; thinking about this more, you'd basically have to handroll something to look
;; for the delimiters and it would only be noticeably faster if there aren't a
;; lot of fields and they're early on in the line.
(defun ensure-row-strings (zeek-log &optional fields)
  (declare (optimize (speed 3) (debug 0) (space 0) (compilation-speed 0))
           (type zeek zeek-log))
  (when (eq :unparsed (zeek-status zeek-log))
    (if fields
        (error "Parsing of individual fields not implemented.")
        (let ((line (zeek-line zeek-log)))
          (declare (type simple-string line))
          (compute-offsets line (zeek-offsets zeek-log))
          (fill (zeek-row-strings zeek-log) nil)
          (setf (zeek-status zeek-log) :row-strings)))))

(defun ensure-fields->idx (zeek-log)
  (when (zerop (hash-table-count (zeek-field->idx zeek-log)))
    (ensure-fields zeek-log)
    (loop for idx from 0 for field in (zeek-fields zeek-log)
          for type in (zeek-types zeek-log)
          do (setf (gethash field (zeek-field->idx zeek-log)) idx
                   (gethash field (zeek-field->type zeek-log)) type))))

(defun field->idx (zeek-log field)
  (declare (optimize (speed 3) (debug 0) (space 0) (compilation-speed 0))
           (type zeek zeek-log)
           (type keyword field))
  (the (or null fixnum) (gethash field (zeek-field->idx zeek-log))))

(defun field->type (zeek-log field)
  (declare (optimize (speed 3) (debug 0) (space 0) (compilation-speed 0))
           (type zeek zeek-log)
           (type keyword field))
  (gethash field (zeek-field->type zeek-log)))

;; TODO: i probably don't need this anymore. just something that
;; writes out a json log.
(defun ensure-map (zeek-log)            ; TODO: add parse for :parsed-map
  (when (member (zeek-status zeek-log) '(:unparsed :row-strings))
    (ecase (zeek-format zeek-log)
      (:zeek
       ;; Compute offsets if still :unparsed, then read cached values (which
       ;; may include mutations) from row-strings, falling back to offsets.
       (ensure-row-strings zeek-log)
       (let ((offsets (zeek-offsets zeek-log))
             (line (zeek-line zeek-log))
             (row-strings (zeek-row-strings zeek-log)))
         (loop for name in (zeek-fields zeek-log)
               for type in (zeek-types zeek-log)
               for idx from 0
               for field = (or (svref row-strings idx)
                               (subseq line
                                       (if (zerop idx) (aref offsets idx) (1+ (aref offsets idx)))
                                       (aref offsets (1+ idx))))
               do (setf (gethash name (zeek-map zeek-log)) (parse-zeek-type field type)))
         (setf (zeek-status zeek-log) :zeek-map)))
      (:json
       (restart-case (setf (zeek-map zeek-log) (jzon:parse (zeek-line zeek-log) :key-fn #'string->keyword)
                           (zeek-status zeek-log) :jzon-map)
         (drop-line () :report (lambda (stream)
                                 (format stream "DROP-LINE: \"~a\"" (zeek-line zeek-log))) nil)
         (keep-line () t))))))

(defun ensure-zeek-map (zeek-log)
  (when (member (zeek-status zeek-log) '(:unparsed :row-strings))
    (ensure-map zeek-log))
  (when (and (eq (zeek-format zeek-log) :json)
             (eq (zeek-status zeek-log) :jzon-map))
    (prog1 (zeekify-json-map (zeek-map zeek-log))
      (setf (zeek-status zeek-log) :zeek-map))))

(defun ensure-fields (zeek-log)
  (unless (zeek-fields zeek-log)
    (when (zerop (hash-table-count (zeek-map zeek-log)))
      (error "FIELDS and MAP are both empty so FIELDS cannot be populated."))
    (setf (zeek-fields zeek-log) (ax:hash-table-keys (zeek-map zeek-log)))))

(defun generate-zeek-header (zeek-log)
  (let ((path (or (str:downcase (string (zeek-path zeek-log))) "cleek_path"))
        (types (append (zeek-types zeek-log) (zeek-created-types zeek-log)))
        (field-names (mapcar #'str:downcase (mapcar #'string (append (zeek-fields zeek-log) (zeek-created-fields zeek-log))))))
    (format nil "~a~%~a~%~a~%~a~%~a~%~a~%~a~%~a~%"
            (format nil "#separator \\x~2,'0x" (char-code *zeek-field-separator*))
            (format nil (format nil "#set_separator~a~~a" *zeek-field-separator*) *zeek-set-separator*)
            (format nil (format nil "#empty_field~a~~a" *zeek-field-separator*) *zeek-empty-field*)
            (format nil (format nil "#unset_field~a~~a" *zeek-field-separator*) "-")
            (format nil (format nil "#path~a~~a" *zeek-field-separator*) path)
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
    (let ((header (zeek-raw-header zeek-log))
          (created-fields (zeek-created-fields zeek-log)))
      (if (and header (null created-fields))
          (format stream "~{~a~^~%~}~%" header)
          (progn (ensure-fields zeek-log)
                 (format stream "~a" (generate-zeek-header zeek-log)))))))

(defun %write-map-as-zeek-line (zeek-log stream)
  "Write ZEEK-LOG's map as a separated zeek line. Replaces a FORMAT call whose
control string was itself built with FORMAT per record, plus a collected list."
  (loop for field-name in (zeek-fields zeek-log)
        for type in (zeek-types zeek-log)
        for first = t then nil
        unless first do (write-char *zeek-field-separator* stream)
          do (write-string (or (stringify-json-type-to-zeek-string
                                (gethash field-name (zeek-map zeek-log) "-") type)
                               "-")
                           stream))
  (terpri stream))

(defun %write-delim-line (zeek-log stream)
  "Write the current delimiter-mode record. Unmodified rows go out verbatim; a
modified row is re-joined with *DELIMITER*, PRINCing whatever non-string value a
mutator may have stored (e.g. (setf @9 (length @3)))."
  (if (zeek-modified? zeek-log)
      (let ((row (zeek-row-strings zeek-log)))
        (loop for i from 0 below (length row)
              unless (zerop i) do (write-char *delimiter* stream)
                do (let ((val (svref row i)))
                     (if (stringp val)
                         (write-string val stream)
                         (princ val stream))))
        (terpri stream))
      (write-line (zeek-line zeek-log) stream)))

(defun write-zeek-log-line (zeek-log stream format)
  (declare (optimize (speed 3) (debug 0) (space 0) (compilation-speed 0))
           (type zeek zeek-log)
           (type keyword format))
  (when (eq :delim format)
    (return-from write-zeek-log-line (%write-delim-line zeek-log stream)))
  (let ((same-format? (eq format (zeek-format zeek-log))))
    (cond ((and (not (zeek-modified? zeek-log)) same-format?)
           (write-line (zeek-line zeek-log) stream))
          ((not (zeek-modified? zeek-log))
           (ensure-map zeek-log)
           (ensure-fields zeek-log)
           (ecase format
             (:json (jzon:stringify (if (eq (zeek-status zeek-log) :zeek-map)
                                        (jsonify-zeek-map (zeek-map zeek-log))
                                        (zeek-map zeek-log)) :stream stream) (terpri stream))
             (:zeek (%write-map-as-zeek-line zeek-log stream))))
          ((and same-format? (zeek-modified? zeek-log))
           (ecase format
             (:json (jzon:stringify (if (eq (zeek-status zeek-log) :zeek-map)
                                        (jsonify-zeek-map (zeek-map zeek-log))
                                        (zeek-map zeek-log)) :stream stream) (terpri stream))
              (:zeek (ecase (zeek-status zeek-log)
                       (:row-strings
                        (let ((row (zeek-row-strings zeek-log))
                              (offsets (zeek-offsets zeek-log))
                              (line (zeek-line zeek-log))
                              (nfields (length (zeek-row-strings zeek-log))))
                          (loop for i from 0 below nfields
                                when (plusp i) do (write-char *zeek-field-separator* stream)
                                do (let ((val (svref row i)))
                                     (if val
                                         (write-string val stream)
                                         (write-string line stream
                                                       :start (if (zerop i)
                                                                   (aref offsets i)
                                                                   (1+ (aref offsets i)))
                                                       :end (aref offsets (1+ i)))))))
                       (when (zeek-created-fields zeek-log)
                         (princ *zeek-field-separator* stream)
                         (loop for i from 1 for created-field in (zeek-created-fields zeek-log)
                               for field = (gethash created-field (zeek-map zeek-log))
                               do (princ field stream)
                               when (< i (length (zeek-created-fields zeek-log)))
                                 do (princ *zeek-field-separator* stream)))
                       (terpri stream))))))
          (t (ensure-map zeek-log)
             (ensure-fields zeek-log)
             (ecase format
               (:json (jzon:stringify (if (eq (zeek-status zeek-log) :zeek-map)
                                          (jsonify-zeek-map (zeek-map zeek-log))
                                          (zeek-map zeek-log)) :stream stream) (terpri stream))
               (:zeek (if (zeek-types zeek-log)
                          (%write-map-as-zeek-line zeek-log stream)
                          (error "Couldn't infer zeek log format. Cannot properly build Zeek log header."))))))))
