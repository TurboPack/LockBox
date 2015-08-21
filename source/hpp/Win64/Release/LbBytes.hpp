// CodeGear C++Builder
// Copyright (c) 1995, 2015 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbBytes.pas' rev: 30.00 (Windows)

#ifndef LbbytesHPP
#define LbbytesHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member 
#pragma pack(push,8)
#include <System.hpp>
#include <SysInit.hpp>
#include <System.Classes.hpp>
#include <System.SysUtils.hpp>
#include <LbCipher.hpp>
#include <LbProc.hpp>

//-- user supplied -----------------------------------------------------------

namespace Lbbytes
{
//-- forward type declarations -----------------------------------------------
class DELPHICLASS TBlowfishBytes;
class DELPHICLASS TDESBytes;
class DELPHICLASS TRDLBytes;
struct TLbBase64;
//-- type declarations -------------------------------------------------------
class PASCALIMPLEMENTATION TBlowfishBytes : public Lbproc::TBlowfishEncrypt
{
	typedef Lbproc::TBlowfishEncrypt inherited;
	
public:
	static void __fastcall BFEncryptBytes(const System::TArray__1<System::Byte> InBytes, System::TArray__1<System::Byte> &OutBytes, const Lbcipher::TKey128 &Key, bool Encrypt);
	static void __fastcall BFEncryptBytesCBC(const System::TArray__1<System::Byte> InBytes, System::TArray__1<System::Byte> &OutBytes, const Lbcipher::TKey128 &Key, bool Encrypt);
	static System::TArray__1<System::Byte> __fastcall BFEncryptBytesCBCEx(const System::TArray__1<System::Byte> InBytes, const Lbcipher::TKey128 &Key, bool Encrypt);
	static System::TArray__1<System::Byte> __fastcall BFEncryptBytesEx(const System::TArray__1<System::Byte> InBytes, const Lbcipher::TKey128 &Key, bool Encrypt);
public:
	/* TObject.Create */ inline __fastcall TBlowfishBytes(void) : Lbproc::TBlowfishEncrypt() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TBlowfishBytes(void) { }
	
};


class PASCALIMPLEMENTATION TDESBytes : public Lbproc::TDESEncrypt
{
	typedef Lbproc::TDESEncrypt inherited;
	
public:
	static void __fastcall DESEncryptBytes(const System::TArray__1<System::Byte> InBytes, System::TArray__1<System::Byte> &OutBytes, const Lbcipher::TKey64 Key, bool Encrypt);
	static void __fastcall DESEncryptBytesCBC(const System::TArray__1<System::Byte> InBytes, System::TArray__1<System::Byte> &OutBytes, const Lbcipher::TKey64 Key, bool Encrypt);
	static System::TArray__1<System::Byte> __fastcall DESEncryptBytesCBCEx(const System::TArray__1<System::Byte> InBytes, const Lbcipher::TKey64 Key, bool Encrypt);
	static System::TArray__1<System::Byte> __fastcall DESEncryptBytesEx(const System::TArray__1<System::Byte> InBytes, const Lbcipher::TKey64 Key, bool Encrypt);
	static void __fastcall TripleDESEncryptBytes(const System::TArray__1<System::Byte> InBytes, System::TArray__1<System::Byte> &OutBytes, const Lbcipher::TKey128 &Key, bool Encrypt);
	static void __fastcall TripleDESEncryptBytesCBC(const System::TArray__1<System::Byte> InBytes, System::TArray__1<System::Byte> &OutBytes, const Lbcipher::TKey128 &Key, bool Encrypt);
	static System::TArray__1<System::Byte> __fastcall TripleDESEncryptBytesCBCEx(const System::TArray__1<System::Byte> InBytes, const Lbcipher::TKey128 &Key, bool Encrypt);
	static System::TArray__1<System::Byte> __fastcall TripleDESEncryptBytesEx(const System::TArray__1<System::Byte> InBytes, const Lbcipher::TKey128 &Key, bool Encrypt);
public:
	/* TObject.Create */ inline __fastcall TDESBytes(void) : Lbproc::TDESEncrypt() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TDESBytes(void) { }
	
};


class PASCALIMPLEMENTATION TRDLBytes : public Lbproc::TRDLEncrypt
{
	typedef Lbproc::TRDLEncrypt inherited;
	
public:
	static void __fastcall RDLEncryptBytes(const System::TArray__1<System::Byte> InBytes, System::TArray__1<System::Byte> &OutBytes, const void *Key, int KeySize, bool Encrypt);
	static void __fastcall RDLEncryptBytesCBC(const System::TArray__1<System::Byte> InBytes, System::TArray__1<System::Byte> &OutBytes, const void *Key, int KeySize, bool Encrypt);
	static System::TArray__1<System::Byte> __fastcall RDLEncryptBytesCBCEx(const System::TArray__1<System::Byte> InBytes, const void *Key, int KeySize, bool Encrypt);
	static System::TArray__1<System::Byte> __fastcall RDLEncryptBytesEx(const System::TArray__1<System::Byte> InBytes, const void *Key, int KeySize, bool Encrypt);
public:
	/* TObject.Create */ inline __fastcall TRDLBytes(void) : Lbproc::TRDLEncrypt() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TRDLBytes(void) { }
	
};


struct DECLSPEC_DRECORD TLbBase64
{
private:
	static System::StaticArray<System::Byte, 64> Lb64Table;
	static System::StaticArray<System::Byte, 80> LbD64Table;
	
public:
	static void __fastcall LbDecodeBase64(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
	static void __fastcall LbEncodeBase64(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
};


//-- var, const, procedure ---------------------------------------------------
}	/* namespace Lbbytes */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBBYTES)
using namespace Lbbytes;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// LbbytesHPP
