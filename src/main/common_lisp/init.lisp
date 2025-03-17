(defpackage :ghidra-cl
  (:nicknames :gcl)
  (:use :cl)
  (:export #:get-current-program
           #:get-current-location))

(in-package :ghidra-cl)

(defparameter *ghidra-cl-instance* nil)

(defun set-ghidra-cl-instance (inst)
  (setf *ghidra-cl-instance* inst))

(defun get-current-program ()
  (java:jcall "getCurrentProgram" gcl::*ghidra-cl-instance*))

(defun get-current-location ()
  (java:jcall "getProgramLocation" gcl::*ghidra-cl-instance*))
