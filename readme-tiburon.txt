LockBox 2.08 Beta for Delphi 2009+

This version of LockBox has been updated so that it can be used with Tiburon. Creating a version of LockBox that is compatible with Tiburon is not very difficult. All that needed to be done was upgrading the strings and changing the buffer sizes. The real challenge is making a version that is not only backwards compatible, but also supports Unicode. If you have encrypted a string with LockBox for Delphi 7 you'll probably want to be able to decrypt it with LockBox for Delphi 200+. But you might also want to encrypt Unicode strings.

The only way to do both is to have an Ansi and a Wide function for encrypting or decrypting strings. And that is what I've done.

For example LockBox 2.07 has only one function BFEncryptStringEx. For Tiburon we need  BFEncryptStringExA and BFEncryptStringExW. BFEncryptStringEx is a generic function that is either Ansi or Unicode. The default is Ansi. This default setting can be changed using the LOCKBOXUNICODE conditional define. You can find this in the file Lockbox.inc.

Currently there is no Ansi/Unicode switch for assymetric encryption. This is still a todo.

Sebastian Zierer