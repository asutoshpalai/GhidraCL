(defpackage :ghidra-cl
  (:nicknames :gcl)
  (:use :cl)
  (:export #:set-current-program))

(in-package :ghidra-cl)

(defparameter *current-program* nil)

(defun set-current-program (new-cp)
  (setf *current-program* new-cp))
