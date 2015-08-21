// CodeGear C++Builder
// Copyright (c) 1995, 2015 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbProc.pas' rev: 30.00 (iOS)

#ifndef LbprocHPP
#define LbprocHPP

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

//-- user supplied -----------------------------------------------------------

namespace Lbproc
{
//-- forward type declarations -----------------------------------------------
class DELPHICLASS ECipherException;
struct TLbProgress;
class DELPHICLASS TBlowfishEncrypt;
class DELPHICLASS TDESEncrypt;
class DELPHICLASS TLBCEncrypt;
class DELPHICLASS TLSCEncrypt;
class DELPHICLASS TRNGEncrypt;
class DELPHICLASS TRDLEncrypt;
class DELPHICLASS TMD5Encrypt;
class DELPHICLASS TSHA1Encrypt;
//-- type declarations -------------------------------------------------------
#pragma pack(push,4)
class PASCALIMPLEMENTATION ECipherException : public System::Sysutils::Exception
{
	typedef System::Sysutils::Exception inherited;
	
public:
	/* Exception.Create */ inline __fastcall ECipherException(const System::UnicodeString Msg) : System::Sysutils::Exception(Msg) { }
	/* Exception.CreateFmt */ inline __fastcall ECipherException(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_High) : System::Sysutils::Exception(Msg, Args, Args_High) { }
	/* Exception.CreateRes */ inline __fastcall ECipherException(System::PResStringRec ResStringRec) : System::Sysutils::Exception(ResStringRec) { }
	/* Exception.CreateResFmt */ inline __fastcall ECipherException(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_High) : System::Sysutils::Exception(ResStringRec, Args, Args_High) { }
	/* Exception.CreateHelp */ inline __fastcall ECipherException(const System::UnicodeString Msg, int AHelpContext) : System::Sysutils::Exception(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall ECipherException(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_High, int AHelpContext) : System::Sysutils::Exception(Msg, Args, Args_High, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall ECipherException(System::PResStringRec ResStringRec, int AHelpContext) : System::Sysutils::Exception(ResStringRec, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall ECipherException(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_High, int AHelpContext) : System::Sysutils::Exception(ResStringRec, Args, Args_High, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~ECipherException(void) { }
	
};

#pragma pack(pop)

typedef System::DelphiInterface<System::Sysutils::TProc__2<int,int> > TProgressProc;

struct DECLSPEC_DRECORD TLbProgress
{
private:
	static System::DelphiInterface<System::Sysutils::TProc__2<int,int> > FOnProgress;
	static int FProgressSize;
	
private:
	static void __fastcall Init();
	
public:
	/* static */ __property int ProgressSize = {read=FProgressSize, write=FProgressSize};
	/* static */ __property System::DelphiInterface<System::Sysutils::TProc__2<int,int> > OnProgress = {read=FOnProgress, write=FOnProgress};
	
private:
	// __classmethod void __fastcall Create@();
	// __classmethod void __fastcall Destroy@();
};


#pragma pack(push,4)
class PASCALIMPLEMENTATION TBlowfishEncrypt : public Lbcipher::TBlowfish
{
	typedef Lbcipher::TBlowfish inherited;
	
public:
	static void __fastcall BFEncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile, const Lbcipher::TKey128 &Key, bool Encrypt);
	static void __fastcall BFEncryptFileCBC(const System::UnicodeString InFile, const System::UnicodeString OutFile, const Lbcipher::TKey128 &Key, bool Encrypt);
	static void __fastcall BFEncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const Lbcipher::TKey128 &Key, bool Encrypt);
	static void __fastcall BFEncryptStreamCBC(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const Lbcipher::TKey128 &Key, bool Encrypt);
public:
	/* TObject.Create */ inline __fastcall TBlowfishEncrypt(void) : Lbcipher::TBlowfish() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TBlowfishEncrypt(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TDESEncrypt : public Lbcipher::TDES
{
	typedef Lbcipher::TDES inherited;
	
public:
	static void __fastcall DESEncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile, const Lbcipher::TKey64 &Key, bool Encrypt);
	static void __fastcall DESEncryptFileCBC(const System::UnicodeString InFile, const System::UnicodeString OutFile, const Lbcipher::TKey64 &Key, bool Encrypt);
	static void __fastcall DESEncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const Lbcipher::TKey64 &Key, bool Encrypt);
	static void __fastcall DESEncryptStreamCBC(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const Lbcipher::TKey64 &Key, bool Encrypt);
	static void __fastcall TripleDESEncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile, const Lbcipher::TKey128 &Key, bool Encrypt);
	static void __fastcall TripleDESEncryptFileCBC(const System::UnicodeString InFile, const System::UnicodeString OutFile, const Lbcipher::TKey128 &Key, bool Encrypt);
	static void __fastcall TripleDESEncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const Lbcipher::TKey128 &Key, bool Encrypt);
	static void __fastcall TripleDESEncryptStreamCBC(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const Lbcipher::TKey128 &Key, bool Encrypt);
public:
	/* TObject.Create */ inline __fastcall TDESEncrypt(void) : Lbcipher::TDES() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TDESEncrypt(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLBCEncrypt : public Lbcipher::TLBC
{
	typedef Lbcipher::TLBC inherited;
	
public:
	static void __fastcall LBCEncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile, const Lbcipher::TKey128 &Key, int Rounds, bool Encrypt);
	static void __fastcall LBCEncryptFileCBC(const System::UnicodeString InFile, const System::UnicodeString OutFile, const Lbcipher::TKey128 &Key, int Rounds, bool Encrypt);
	static void __fastcall LBCEncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const Lbcipher::TKey128 &Key, int Rounds, bool Encrypt);
	static void __fastcall LBCEncryptStreamCBC(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const Lbcipher::TKey128 &Key, int Rounds, bool Encrypt);
	static void __fastcall LQCEncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile, const Lbcipher::TKey128 &Key, bool Encrypt);
	static void __fastcall LQCEncryptFileCBC(const System::UnicodeString InFile, const System::UnicodeString OutFile, const Lbcipher::TKey128 &Key, bool Encrypt);
	static void __fastcall LQCEncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const Lbcipher::TKey128 &Key, bool Encrypt);
	static void __fastcall LQCEncryptStreamCBC(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const Lbcipher::TKey128 &Key, bool Encrypt);
public:
	/* TObject.Create */ inline __fastcall TLBCEncrypt(void) : Lbcipher::TLBC() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TLBCEncrypt(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLSCEncrypt : public Lbcipher::TLSC
{
	typedef Lbcipher::TLSC inherited;
	
public:
	static void __fastcall LSCEncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile, const void *Key, int KeySize);
public:
	/* TObject.Create */ inline __fastcall TLSCEncrypt(void) : Lbcipher::TLSC() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TLSCEncrypt(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TRNGEncrypt : public Lbcipher::TRNG
{
	typedef Lbcipher::TRNG inherited;
	
public:
	static void __fastcall RNG32EncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile, int Key);
	static void __fastcall RNG64EncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile, int KeyHi, int KeyLo);
public:
	/* TObject.Create */ inline __fastcall TRNGEncrypt(void) : Lbcipher::TRNG() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TRNGEncrypt(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TRDLEncrypt : public Lbcipher::TRDL
{
	typedef Lbcipher::TRDL inherited;
	
public:
	static void __fastcall RDLEncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile, const void *Key, int KeySize, bool Encrypt);
	static void __fastcall RDLEncryptFileCBC(const System::UnicodeString InFile, const System::UnicodeString OutFile, const void *Key, int KeySize, bool Encrypt);
	static void __fastcall RDLEncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const void *Key, int KeySize, bool Encrypt);
	static void __fastcall RDLEncryptStreamCBC(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, const void *Key, int KeySize, bool Encrypt);
public:
	/* TObject.Create */ inline __fastcall TRDLEncrypt(void) : Lbcipher::TRDL() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TRDLEncrypt(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TMD5Encrypt : public Lbcipher::TMD5
{
	typedef Lbcipher::TMD5 inherited;
	
public:
	static void __fastcall FileHashMD5(Lbcipher::TMD5Digest &Digest, const System::UnicodeString AFileName);
	static void __fastcall StreamHashMD5(Lbcipher::TMD5Digest &Digest, System::Classes::TStream* AStream);
public:
	/* TObject.Create */ inline __fastcall TMD5Encrypt(void) : Lbcipher::TMD5() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TMD5Encrypt(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TSHA1Encrypt : public Lbcipher::TSHA1
{
	typedef Lbcipher::TSHA1 inherited;
	
public:
	static void __fastcall FileHashSHA1(Lbcipher::TSHA1Digest &Digest, const System::UnicodeString AFileName);
	static void __fastcall StreamHashSHA1(Lbcipher::TSHA1Digest &Digest, System::Classes::TStream* AStream);
public:
	/* TObject.Create */ inline __fastcall TSHA1Encrypt(void) : Lbcipher::TSHA1() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TSHA1Encrypt(void) { }
	
};

#pragma pack(pop)

//-- var, const, procedure ---------------------------------------------------
}	/* namespace Lbproc */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBPROC)
using namespace Lbproc;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// LbprocHPP
