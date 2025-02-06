(defpackage :ghidra-cl
  (:nicknames :gcl)
  (:use :cl)
  (:export #:set-current-program))

(defparameter *current-program* nil)

(defun set-current-program (new-cp)
  (setf *current-program* new-cp))