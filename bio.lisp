(in-package :cleek)

;;;; Byte-mode engine (prototype, enabled with -B/--byte-mode).
;;;;
;;;; Reads zeek TSV logs as raw (unsigned-byte 8) blocks instead of
;;;; read-line'd character strings: no per-line utf-8 decode, 1 byte/char
;;;; instead of 4, and newline/tab scanning hits SBCL's simd-position8
;;;; (~4x the throughput of the character-string routines). Fields are byte
;;;; spans; numeric @@ columns parse straight from the bytes; other fields
;;;; materialize (and cache) as strings only when a filter/mutator touches
;;;; them. Unmodified lines are written back verbatim with write-sequence.
;;;;
;;;; Scope: zeek TSV in, zeek TSV out. CAT-LOGS-BYTES declines (returns NIL,
;;;; caller falls back to the normal engine) for JSON input, non-zeek output,
;;;; or filters/mutators that reference LINE (which needs a character string).

(defvar *byte-mode* nil)

;;; ---------------- block reader ----------------

(defstruct (breader (:constructor %make-breader))
  stream
  (buf (make-array (* 1024 1024) :element-type '(unsigned-byte 8))
       :type (simple-array (unsigned-byte 8) (*)))
  (pos 0 :type fixnum)
  (end 0 :type fixnum)
  (eof nil))

(defun breader-next-line (r)
  "Next line as a fresh ub8 vector (newline excluded), or NIL at EOF."
  (declare (optimize (speed 3) (safety 1)))
  (loop
    (let* ((buf (breader-buf r))
           (nl (position 10 buf :start (breader-pos r) :end (breader-end r))))
      (cond (nl
             (let ((line (subseq buf (breader-pos r) nl)))
               (setf (breader-pos r) (1+ nl))
               (return line)))
            ((breader-eof r)
             (if (< (breader-pos r) (breader-end r))
                 (let ((line (subseq buf (breader-pos r) (breader-end r))))
                   (setf (breader-pos r) (breader-end r))
                   (return line))
                 (return nil)))
            (t ;; shift the partial line to the front and refill
             (let ((rem (- (breader-end r) (breader-pos r))))
               (replace buf buf :start2 (breader-pos r) :end2 (breader-end r))
               (setf (breader-pos r) 0
                     (breader-end r) rem)
               (when (= rem (length buf)) ; line longer than the buffer
                 (let ((nbuf (make-array (* 2 (length buf))
                                         :element-type '(unsigned-byte 8))))
                   (replace nbuf buf)
                   (setf (breader-buf r) nbuf)))
               (let ((n (read-sequence (breader-buf r) (breader-stream r)
                                       :start (breader-end r))))
                 (declare (fixnum n))
                 (when (= n (breader-end r))
                   (setf (breader-eof r) t))
                 (setf (breader-end r) n))))))))

;;; ---------------- byte-level parsing helpers ----------------

(defun compute-offsets-u8 (line offsets)
  "COMPUTE-OFFSETS for a ub8 line; POSITION here is sb-vm::simd-position8."
  (declare (optimize (speed 3) (safety 1))
           (type (simple-array (unsigned-byte 8) (*)) line)
           (type (simple-array fixnum (*)) offsets))
  (let ((nfields (1- (length offsets))))
    (declare (type fixnum nfields))
    (setf (aref offsets 0) 0)
    (loop with start fixnum = 0
          for i fixnum from 1 below nfields
          for tab-pos = (position 9 line :start start)
          while tab-pos
          do (setf (aref offsets i) (the fixnum tab-pos)
                   start (the fixnum (1+ tab-pos)))
          finally (loop for j fixnum from i to nfields
                        do (setf (aref offsets j) (length line))))
    (setf (aref offsets nfields) (length line))))

(defun %bytes->string (v start end)
  "Materialize a byte span as a string (one char per byte)."
  (declare (optimize (speed 3) (safety 1))
           (type (simple-array (unsigned-byte 8) (*)) v)
           (type fixnum start end))
  (let ((s (make-string (- end start))))
    (loop for i fixnum from start below end
          for j fixnum from 0
          do (setf (schar s j) (code-char (aref v i))))
    s))

(defun %parse-integer-u8 (v start end)
  (declare (optimize (speed 3) (safety 0))
           (type (simple-array (unsigned-byte 8) (*)) v)
           (type fixnum start end))
  (let ((pos start) (neg nil) (n 0))
    (declare (fixnum pos) (integer n))
    (when (and (< pos end) (= 45 (aref v pos))) ; #\-
      (setf neg t) (incf pos))
    (when (= pos end)
      (error "junk in integer field"))
    (loop while (< pos end)
          for b = (aref v pos)
          do (unless (<= 48 b 57)
               (error "junk in integer field: ~a" (%bytes->string v start end)))
             (setf n (+ (* n 10) (- b 48)))
             (incf pos))
    (if neg (- n) n)))

(defun %fast-parse-double-u8 (v start end)
  "FAST-PARSE-DOUBLE ported to byte spans."
  (declare (optimize (speed 3) (safety 0))
           (type (simple-array (unsigned-byte 8) (*)) v)
           (type fixnum start end))
  (let ((pos start) (neg nil) (significand 0) (n-frac 0) (exp-part 0) (exp-neg nil))
    (declare (fixnum pos n-frac exp-part))
    (when (and (< pos end) (= 45 (aref v pos)))
      (setf neg t) (incf pos))
    (loop while (and (< pos end) (<= 48 (aref v pos) 57))
          do (setf significand (+ (* significand 10) (- (aref v pos) 48)))
             (incf pos))
    (when (and (< pos end) (= 46 (aref v pos))) ; #\.
      (incf pos)
      (loop while (and (< pos end) (<= 48 (aref v pos) 57))
            do (setf significand (+ (* significand 10) (- (aref v pos) 48)))
               (incf n-frac) (incf pos)))
    (when (and (< pos end) (let ((b (aref v pos))) (or (= b 101) (= b 69)))) ; e/E
      (incf pos)
      (when (and (< pos end) (let ((b (aref v pos))) (or (= b 45) (= b 43))))
        (when (= 45 (aref v pos)) (setf exp-neg t))
        (incf pos))
      (loop while (and (< pos end) (<= 48 (aref v pos) 57))
            do (setf exp-part (+ (* exp-part 10) (- (aref v pos) 48)))
               (incf pos)))
    (let* ((effective-exp (- (if exp-neg (- exp-part) exp-part) n-frac))
           (rational-val (if (>= effective-exp 0)
                             (* significand (expt 10 effective-exp))
                             (/ significand (expt 10 (- effective-exp)))))
           (result (coerce rational-val 'double-float)))
      (if neg (- result) result))))

;;; ---------------- output ----------------

(defun %write-string-bytes (s out)
  (declare (optimize (speed 3) (safety 1))
           (type string s))
  (loop for c across s do (write-byte (char-code c) out)))

(defun %write-byte-log-line (zeek-log out)
  (declare (optimize (speed 3) (safety 1)))
  (if (not (zeek-modified? zeek-log))
      (write-sequence (zeek-bline zeek-log) out)
      ;; mutated: cached/mutated strings from row-strings, untouched fields
      ;; verbatim from the byte line, created fields from the map.
      (let ((row (zeek-row-strings zeek-log))
            (offsets (zeek-offsets zeek-log))
            (bline (zeek-bline zeek-log))
            (nfields (length (zeek-row-strings zeek-log))))
        (declare (type simple-vector row)
                 (type (simple-array fixnum (*)) offsets)
                 (type (simple-array (unsigned-byte 8) (*)) bline))
        (loop for i fixnum from 0 below nfields
              when (plusp i) do (write-byte 9 out)
                do (let ((val (svref row i)))
                     (if val
                         (%write-string-bytes val out)
                         (write-sequence bline out
                                         :start (if (zerop i) 0 (1+ (aref offsets i)))
                                         :end (aref offsets (1+ i))))))
        (when (zeek-created-fields zeek-log)
          (loop for created-field in (zeek-created-fields zeek-log)
                do (write-byte 9 out)
                   (%write-string-bytes
                    (princ-to-string (gethash created-field (zeek-map zeek-log)))
                    out)))))
  (write-byte 10 out))

;;; ---------------- engine ----------------

(defun %tree-member? (sym tree)
  (cond ((eq sym tree) t)
        ((consp tree) (or (%tree-member? sym (car tree))
                          (%tree-member? sym (cdr tree))))))

(defun %zeek-file? (path)
  (with-open-file (in path :element-type '(unsigned-byte 8) :if-does-not-exist nil)
    (and in (eql 35 (read-byte in nil))))) ; #\#

(defun %parse-byte-header (r zeek-log)
  "Read header lines from R into ZEEK-LOG (mirrors PARSE-ZEEK-HEADER)."
  (flet ((parse-header-values (line)
           (mapcar #'string->keyword (rest (split-sequence *zeek-field-separator* line)))))
    (loop for bline = (breader-next-line r)
          while bline
          for line = (%bytes->string bline 0 (length bline))
          do (push line (zeek-raw-header zeek-log))
             (cond ((str:starts-with? "#path" line)
                    (setf (zeek-path zeek-log) (first (parse-header-values line))))
                   ((str:starts-with? "#fields" line)
                    (setf (zeek-fields zeek-log) (parse-header-values line)))
                   ((str:starts-with? "#types" line)
                    (setf (zeek-types zeek-log) (parse-header-values line))
                    (loop-finish))))
    (ax:reversef (zeek-raw-header zeek-log))
    (ax:when-let ((created-fields (set-difference (zeek-accessed-columns zeek-log)
                                                  (zeek-fields zeek-log))))
      (setf (zeek-created-fields zeek-log) created-fields
            (zeek-created-types zeek-log)
            (make-list (length created-fields) :initial-element :string)))
    zeek-log))

(defun cat-logs-bytes (output-file output-format ensure-truthy-parse-func
                       mutator-func filter-func columns filters mutators input-files)
  "Byte-mode zeek→zeek engine. Returns T if handled, NIL to fall back."
  (when (or (not (member output-format '(:input-format :zeek)))
            (%tree-member? 'zeek-line filters)
            (%tree-member? 'zeek-line mutators)
            (notevery #'%zeek-file? input-files))
    (return-from cat-logs-bytes nil))
  (with-open-file (out output-file :direction :output :if-exists :supersede
                       :element-type '(unsigned-byte 8))
    (let ((first-file t))
      (dolist (file input-files)
        (with-open-file (in file :element-type '(unsigned-byte 8))
          (let ((r (%make-breader :stream in))
                (zeek-log (make-zeek :filepath file :format :zeek)))
            (setf (zeek-accessed-columns zeek-log) columns)
            (%parse-byte-header r zeek-log)
            (ensure-fields->idx zeek-log)
            (setf (zeek-offsets zeek-log)
                  (make-array (1+ (length (zeek-fields zeek-log))) :element-type 'fixnum)
                  (zeek-row-strings zeek-log)
                  (make-array (length (zeek-fields zeek-log)) :initial-element nil))
            (when first-file
              (if (zeek-created-fields zeek-log)
                  (%write-string-bytes (generate-zeek-header zeek-log) out)
                  (dolist (line (zeek-raw-header zeek-log))
                    (%write-string-bytes line out)
                    (write-byte 10 out)))
              (setf first-file nil))
            (loop for bline = (breader-next-line r)
                  while bline
                  unless (or (zerop (length bline))
                             ;; skip #close markers and repeated headers
                             ;; (TODO: verify repeated headers match)
                             (= 35 (aref bline 0)))
                    do (setf (zeek-bline zeek-log) bline
                             (zeek-status zeek-log) :unparsed
                             (zeek-modified? zeek-log) nil)
                       (unless (zerop (hash-table-count (zeek-map zeek-log)))
                         (clrhash (zeek-map zeek-log)))
                       (when columns
                         (compute-offsets-u8 bline (zeek-offsets zeek-log))
                         (fill (zeek-row-strings zeek-log) nil)
                         (setf (zeek-status zeek-log) :row-strings))
                       (when (or (null ensure-truthy-parse-func)
                                 (funcall ensure-truthy-parse-func zeek-log))
                         (when mutator-func
                           (funcall mutator-func zeek-log))
                         (when (or (null filter-func)
                                   (funcall filter-func zeek-log))
                           (%write-byte-log-line zeek-log out)))))))
      (%write-string-bytes
       (format nil "#close~a~a~%" *zeek-field-separator*
               (timestamp-to-zeek-open-close-string (local-time:now)))
       out)))
  t)
