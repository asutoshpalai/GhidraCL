# GhidraCL

An experiment about trying to use Common Lisp with
[Ghidra](https://ghidra-sre.org). Initial goal was to be able to do Ghidra
scripting from comfort of [Emacs/Sly](https://github.com/joaotavora/sly). Maybe
I will later develop it into a full framework of loading CL scripts onto Ghidra.

My notes on how I went about implementing this can be found in my [notes
repo](https://github.com/asutoshpalai/notes/blob/master/Ghidra.md#plugin-development).

## Install

- Clone the repo
```
    $ git clone https://github.com/asutoshpalai/GhidraCL.git

```

- Build the extension.
```
    $ gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra> distributeExtension
```

- Install the extension from Ghidra's menu `File`->`Install Extensions`. Restart
  Ghidra as suggested.

- Ensure that it's activated from the CodeBrowser window. Go to
  `File` -> `Configure` -> `Miscellenious`. Check that GhidraCL is checked.

## Usage

Note: This is at very rudimentary state. Basic functionalities are not exposed
yet.

- Install [SLY](https://github.com/joaotavora/sly) on Emacs.

- Open CodeBrowser in Ghidra.

- Start Slynk server from menu by going to `Common Lisp` -> `Start Slynk`. It
  will display the port to be used from SLY.

- Open Emacs. Execute `M-x sly-connect`. Choose `localhost` as `Host` and the
  port displayed in the previous step for `Port`.

- Run the following to test that it's working
```lisp
CL-USER> (let* ((adr (#"toString" (#"getAddress" (gcl::get-current-location))))
                (msg (format nil "current address is 0x~a" adr)))
            (jstatic "showInfo" "ghidra.util.Msg"
              (jclass "ghidracl.GhidraCLPlugin")
              (jcoerce nil "java.awt.Component")
              "GhidraCL" msg))
```

### Common Lisp examples

- Print the name of all the functions and their addresses
```lisp
CL-USER> (let* ((cp (gcl:get-current-program))
                (fm (#"getFunctionManager" cp))
                (functions-it (#"getFunctions" fm t)))
          (loop while (java:jcall "hasNext" functions-it)
                do (let ((function (java:jcall "next" functions-it)))
                      (format t "Function: ~a Addr: 0x~a ~%"
                        (#"getName" function)
                        (#"toString" (#"getEntryPoint" function))))))
```

- Get decompiled code for a given function
```
CL-USER> (let ((ifc (jss:new 'DecompInterface)))
            (jcall "openProgram" ifc (gcl:get-current-program))
            (let ((main-functions (jcall "getGlobalFunctions"
                                (jcall "getListing" (gcl:get-current-program))
                                "main")))
              (let ((res (jcall "decompileFunction"
                                ifc
                                (jcall "getFirst" main-functions)
                                0
                                (jss:new 'ConsoleTaskMonitor))))
                (format t "~a~%" (#"toString" (jcall "getCCodeMarkup" res))))))
```