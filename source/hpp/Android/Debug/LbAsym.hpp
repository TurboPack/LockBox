// CodeGear C++Builder
// Copyright (c) 1995, 2015 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbAsym.pas' rev: 30.00 (Android)

#ifndef LbasymHPP
#define LbasymHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member 
#pragma pack(push,8)
#include <System.hpp>
#include <SysInit.hpp>
#include <System.Classes.hpp>
#include <System.SysUtils.hpp>
#include <LbBigInt.hpp>
#include <LbClass.hpp>
#include <LbConst.hpp>

//-- user supplied -----------------------------------------------------------

namespace Lbasym
{
//-- forward type declarations -----------------------------------------------
class DELPHICLASS TLbAsymmetricKey;
class DELPHICLASS TLbAsymmetricCipher;
class DELPHICLASS TLbSignature;
//-- type declarations -------------------------------------------------------
typedef System::Byte *PByte;

enum DECLSPEC_DENUM TLbAsymKeySize : unsigned char { aks128, aks256, aks512, aks768, aks1024 };

typedef void __fastcall (__closure *TLbProgressEvent)(System::TObject* Sender, bool &Abort);

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbAsymmetricKey : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	System::Sysutils::TEncoding* FEncoding;
	System::UnicodeString FPassphrase;
	void __fastcall MovePtr(PByte &Ptr, int &Max);
	void __fastcall MovePtrCount(PByte &Ptr, int &Max, int Count);
	
protected:
	TLbAsymKeySize FKeySize;
	void __fastcall CreateASN1(void *Buf, int &BufLen, System::Byte Tag);
	virtual int __fastcall CreateASNKey(System::Sysutils::PByteArray Input, int Length) = 0 ;
	int __fastcall EncodeASN1(Lbbigint::TLbBigInt* biValue, System::Sysutils::PByteArray &pBuf, int &MaxLen);
	int __fastcall GetASN1StructLen(PByte &input, int &len);
	int __fastcall GetASN1StructNum(PByte &input, int &len);
	System::TArray__1<System::Byte> __fastcall GetBytes(const System::UnicodeString AString);
	void __fastcall ParseASN1(PByte &input, int &length, Lbbigint::TLbBigInt* biValue);
	virtual bool __fastcall ParseASNKey(PByte Input, int Length) = 0 ;
	virtual void __fastcall SetKeySize(TLbAsymKeySize Value);
	
public:
	__fastcall virtual TLbAsymmetricKey(TLbAsymKeySize aKeySize);
	virtual void __fastcall Assign(TLbAsymmetricKey* aKey);
	virtual void __fastcall LoadFromStream(System::Classes::TStream* aStream);
	virtual void __fastcall StoreToStream(System::Classes::TStream* aStream);
	virtual void __fastcall LoadFromFile(System::UnicodeString aFileName);
	virtual void __fastcall StoreToFile(System::UnicodeString aFileName);
	__property System::Sysutils::TEncoding* Encoding = {read=FEncoding, write=FEncoding};
	__property TLbAsymKeySize KeySize = {read=FKeySize, write=SetKeySize, nodefault};
	__property System::UnicodeString Passphrase = {read=FPassphrase, write=FPassphrase};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TLbAsymmetricKey(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbAsymmetricCipher : public Lbclass::TLbCipher
{
	typedef Lbclass::TLbCipher inherited;
	
private:
	TLbProgressEvent FOnProgress;
	
protected:
	TLbAsymKeySize FKeySize;
	virtual void __fastcall SetKeySize(TLbAsymKeySize Value);
	
public:
	__fastcall virtual TLbAsymmetricCipher(System::Classes::TComponent* AOwner);
	virtual void __fastcall GenerateKeyPair(void) = 0 ;
	__property TLbAsymKeySize KeySize = {read=FKeySize, write=SetKeySize, nodefault};
	__property TLbProgressEvent OnProgress = {read=FOnProgress, write=FOnProgress};
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TLbAsymmetricCipher(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbSignature : public Lbclass::TLBBaseComponent
{
	typedef Lbclass::TLBBaseComponent inherited;
	
protected:
	TLbAsymKeySize FKeySize;
	TLbProgressEvent FOnProgress;
	virtual void __fastcall SetKeySize(TLbAsymKeySize Value);
	
public:
	__fastcall virtual TLbSignature(System::Classes::TComponent* AOwner);
	virtual void __fastcall GenerateKeyPair(void) = 0 ;
	virtual void __fastcall SignBuffer(const void *Buf, unsigned BufLen) = 0 ;
	virtual void __fastcall SignFile(const System::UnicodeString AFileName) = 0 ;
	virtual void __fastcall SignStream(System::Classes::TStream* AStream) = 0 ;
	virtual void __fastcall SignString(const System::UnicodeString AStr) = 0 ;
	virtual bool __fastcall VerifyBuffer(const void *Buf, unsigned BufLen) = 0 ;
	virtual bool __fastcall VerifyFile(const System::UnicodeString AFileName) = 0 ;
	virtual bool __fastcall VerifyStream(System::Classes::TStream* AStream) = 0 ;
	virtual bool __fastcall VerifyString(const System::UnicodeString AStr) = 0 ;
	__property TLbAsymKeySize KeySize = {read=FKeySize, write=SetKeySize, nodefault};
	__property TLbProgressEvent OnProgress = {read=FOnProgress, write=FOnProgress};
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TLbSignature(void) { }
	
};

#pragma pack(pop)

//-- var, const, procedure ---------------------------------------------------
static const TLbAsymKeySize cLbDefAsymKeySize = (TLbAsymKeySize)(2);
extern DELPHI_PACKAGE System::StaticArray<System::Word, 5> cLbAsymKeyBytes;
}	/* namespace Lbasym */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBASYM)
using namespace Lbasym;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// LbasymHPP
