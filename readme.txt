TurboPower LockBox


Table of contents

1.  Introduction
2.  Package names
3.  Installation
4.  Version history
4.1   Release 2.07

==============================================


1. Introduction


LockBox is a cross-platform toolkit for data encryption. It contains
routines & components for use with Borland Delphi, C++Builder, &
Kylix. It provides support for Blowfish, RSA, MD5, SHA-1, DES, triple-
DES, Rijndael, & digital signing of messages.

This is a source-only release of TurboPower LockBox. It includes
designtime and runtime packages for Delphi 3 through 7 and C++Builder
3 through 6.

==============================================

2. Package names


TurboPower LockBox package names have the following form:

  LNNNMKVV.*
   |  |||
   |  ||+------ VV  VCL version (30=Delphi 3, 40=Delphi 4, 70=Delphi 7)
   |  |+------- K   Kind of package (R=runtime, D=designtime)
   |  +-------- M   Product-specific modifier (typically underscore, V = VCL, C = CLX)
   +----------- NNN Product version number (e.g., 207=version 2.07)


For example, the LockBox CLX designtime package files for Delphi 7 have
the filename L207CD70.*.

==============================================

3. Installation


To install TurboPower LockBox into your IDE, take the following steps:

  1. Unzip the release files into a directory (e.g., d:\lockbox).

  2. Start Delphi or C++Builder.

  3. Add the source subdirectory (e.g., d:\lockbox\source) to the
     IDE's library path.

  4. Open & install the designtime package specific to the IDE being
     used. The IDE should notify you the components have been
     installed.

     a. For C++Builder 6 and Delphi 6 or higher, install the VCL
        design-time package (e.g., LxxxVDxx.*) when using LockBox
        classes with VCL applications.

     b. For C++Builder 6 and Delphi 6 or higher, install the CLX
        design-time package (e.g., LxxxCDxx.*) when using LockBox
        classes with CLX applications.

  5. Make sure the PATH environmental variable contains the directory
     in which the compiled packages (i.e., BPL or DPL files) were
     placed.

==============================================

4. Version history


4.1 Release 2.07

    Enhancements
    -------------------------------------------------------------
    Added support for Delphi 7

4.2 Release 2.08

    Enhancements
    -------------------------------------------------------------
    Added support for Delphi 2009 / Tiburon
