=========================
Using Clangd with Libvirt
=========================

`clangd <https://clangd.llvm.org/>`__ is an implementation of the
`language server protocol
<https://en.wikipedia.org/wiki/Language_Server_Protocol>`__ for C
and C++.

When paired with an LSP-compatible editor or IDE (e.g. emacs,
vim, vscode), ``clangd`` can helpful when working with libvirt's
C sources e.g. navigating the code base.

Whilst other C LSPs are available, ``clangd`` should work
correctly with the libvirt because clang is a supported compiler
for libvirt, and ``clangd`` is part of the same code base as
clang.

If clang is the default compiler on your system, then ``clangd``
can be used as soon as ``meson setup`` has been run.

If gcc is your build environment's default compiler, then
additional steps are required to use ``clangd``:

``clangd`` looks for a ``compile_commands.json`` file in the top
level directory of the project and also in the ``build/``
subdirectory to discover which include paths, compiler flags etc.
should be used when it parses each source file.

Meson creates a ``compile_commands.json`` in the build directory.
Meson defaults to the system's default C compiler. When the
default compiler is gcc, its ``compile_commands.json`` output
cannot be used with ``clangd`` due to differences in compiler
invocation flags when building libvirt.

Create a separate build directory with a ``clangd`` compatible
``compile_commands.json`` as follows:

::

   CC=clang CXX=clang++ meson setup build-clang

There are a small number of source files that are generated as part of the
build process. In order to navigate this generated source code, you should also
execute a build in this directory:

::

    ninja -C build-clang

Point ``clangd`` (v12 or later) at the correct
``compile_commands.json`` by placing the following into a
``.clangd`` file in the root of the project:

::

   ---
   CompileFlags:
     CompilationDatabase: "build-clang"


Please note that if you are not using clang for your daily development, the
``build-clang`` directory can get out of sync with the current state of the
project over time. When you update your git checkout, new files may be added or
configuration options changed and ``clangd`` may start to behave unpredictably.
In this case, you will need to update your compilation database by doing a new
build in the ``build-clang`` directory. This should allow clangd to work
reliably again.
