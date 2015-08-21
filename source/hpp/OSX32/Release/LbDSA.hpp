// CodeGear C++Builder
// Copyright (c) 1995, 2015 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbDSA.pas' rev: 30.00 (MacOS)

#ifndef LbdsaHPP
#define LbdsaHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member 
#pragma pack(push,8)
#include <System.hpp>
#include <SysInit.hpp>
#include <System.Types.hpp>
#include <System.Classes.hpp>
#include <System.SysUtils.hpp>
#include <LbRandom.hpp>
#include <LbCipher.hpp>
#include <LbBigInt.hpp>
#include <LbAsym.hpp>
#include <LbConst.hpp>

//-- user supplied -----------------------------------------------------------

namespace Lbdsa
{
//-- forward type declarations -----------------------------------------------
class DELPHICLASS TLbDSAParameters;
class DELPHICLASS TLbDSAPrivateKey;
class DELPHICLASS TLbDSAPublicKey;
class DELPHICLASS TLbDSA;
//-- type declarations -------------------------------------------------------
typedef System::StaticArray<System::Byte, 20> TLbDSABlock;

typedef void __fastcall (__closure *TLbGetDSABlockEvent)(System::TObject* Sender, TLbDSABlock &Block);

typedef void __fastcall (__closure *TLbDSACallback)(bool &Abort);

class PASCALIMPLEMENTATION TLbDSAParameters : public Lbasym::TLbAsymmetricKey
{
	typedef Lbasym::TLbAsymmetricKey inherited;
	
private:
	Lbbigint::TLbBigInt* F2Tog;
	TLbDSACallback FCallback;
	Lbbigint::TLbBigInt* FMostLeast;
	System::Byte FPrimeTestIterations;
	bool __fastcall GenerateG(void);
	bool __fastcall GenerateP(const TLbDSABlock &ASeed);
	bool __fastcall GenerateQ(const TLbDSABlock &ASeed);
	System::UnicodeString __fastcall GetGAsString(void);
	System::UnicodeString __fastcall GetPAsString(void);
	System::UnicodeString __fastcall GetQAsString(void);
	void __fastcall SetGAsString(const System::UnicodeString Value);
	void __fastcall SetPAsString(const System::UnicodeString Value);
	void __fastcall SetQAsString(const System::UnicodeString Value);
	
protected:
	Lbbigint::TLbBigInt* FG;
	Lbbigint::TLbBigInt* FP;
	Lbbigint::TLbBigInt* FQ;
	virtual void __fastcall SetKeySize(Lbasym::TLbAsymKeySize Value);
	
public:
	__fastcall virtual TLbDSAParameters(Lbasym::TLbAsymKeySize aKeySize);
	__fastcall virtual ~TLbDSAParameters(void);
	virtual void __fastcall Clear(void);
	void __fastcall CopyDSAParameters(TLbDSAParameters* AKey);
	bool __fastcall GenerateDSAParameters(const TLbDSABlock &ASeed);
	__property Lbbigint::TLbBigInt* G = {read=FG};
	__property System::UnicodeString GAsString = {read=GetGAsString, write=SetGAsString};
	__property Lbbigint::TLbBigInt* P = {read=FP};
	__property System::UnicodeString PAsString = {read=GetPAsString, write=SetPAsString};
	__property System::Byte PrimeTestIterations = {read=FPrimeTestIterations, write=FPrimeTestIterations, nodefault};
	__property Lbbigint::TLbBigInt* Q = {read=FQ};
	__property System::UnicodeString QAsString = {read=GetQAsString, write=SetQAsString};
	__property TLbDSACallback Callback = {read=FCallback, write=FCallback};
};


class PASCALIMPLEMENTATION TLbDSAPrivateKey : public TLbDSAParameters
{
	typedef TLbDSAParameters inherited;
	
private:
	Lbbigint::TLbBigInt* FX;
	TLbDSABlock FXKey;
	System::UnicodeString __fastcall GetXAsString(void);
	void __fastcall SetXAsString(const System::UnicodeString Value);
	
protected:
	virtual int __fastcall CreateASNKey(System::Sysutils::PByteArray Input, int Length);
	virtual bool __fastcall ParseASNKey(Lbasym::PByte Input, int Length);
	
public:
	__fastcall virtual TLbDSAPrivateKey(Lbasym::TLbAsymKeySize aKeySize);
	__fastcall virtual ~TLbDSAPrivateKey(void);
	virtual void __fastcall Clear(void);
	void __fastcall GenerateX(const TLbDSABlock &AXKey);
	__property Lbbigint::TLbBigInt* X = {read=FX};
	__property System::UnicodeString XAsString = {read=GetXAsString, write=SetXAsString};
};


class PASCALIMPLEMENTATION TLbDSAPublicKey : public TLbDSAParameters
{
	typedef TLbDSAParameters inherited;
	
private:
	Lbbigint::TLbBigInt* FY;
	System::UnicodeString __fastcall GetYAsString(void);
	void __fastcall SetYAsString(const System::UnicodeString Value);
	
protected:
	virtual int __fastcall CreateASNKey(System::Sysutils::PByteArray Input, int Length);
	virtual bool __fastcall ParseASNKey(Lbasym::PByte Input, int Length);
	
public:
	__fastcall virtual TLbDSAPublicKey(Lbasym::TLbAsymKeySize aKeySize);
	__fastcall virtual ~TLbDSAPublicKey(void);
	virtual void __fastcall Clear(void);
	void __fastcall GenerateY(Lbbigint::TLbBigInt* aX);
	__property Lbbigint::TLbBigInt* Y = {read=FY};
	__property System::UnicodeString YAsString = {read=GetYAsString, write=SetYAsString};
};


class PASCALIMPLEMENTATION TLbDSA : public Lbasym::TLbSignature
{
	typedef Lbasym::TLbSignature inherited;
	
private:
	static TLbDSABlock cZeroBlock;
	TLbDSAPrivateKey* FPrivateKey;
	TLbDSAPublicKey* FPublicKey;
	System::Byte FPrimeTestIterations;
	Lbbigint::TLbBigInt* FSignatureR;
	Lbbigint::TLbBigInt* FSignatureS;
	TLbGetDSABlockEvent FOnGetR;
	TLbGetDSABlockEvent FOnGetS;
	TLbGetDSABlockEvent FOnGetSeed;
	TLbGetDSABlockEvent FOnGetXKey;
	TLbGetDSABlockEvent FOnGetKKey;
	void __fastcall SignHash(const Lbcipher::TSHA1Digest &ADigest);
	bool __fastcall VerifyHash(const Lbcipher::TSHA1Digest &ADigest);
	void __fastcall RandomBlock(TLbDSABlock &ABlock);
	void __fastcall DoGetR(void);
	void __fastcall DoGetS(void);
	void __fastcall DoGetSeed(TLbDSABlock &ASeed);
	void __fastcall DoGetXKey(TLbDSABlock &AXKey);
	void __fastcall DoGetKKey(TLbDSABlock &AKKey);
	void __fastcall SetPrimeTestIterations(System::Byte Value);
	void __fastcall DSAParameterCallback(bool &Abort);
	
protected:
	virtual void __fastcall SetKeySize(Lbasym::TLbAsymKeySize Value);
	void __fastcall SHA1KKey(TLbDSABlock &AKKey);
	
public:
	__fastcall virtual TLbDSA(System::Classes::TComponent* AOwner);
	__fastcall virtual ~TLbDSA(void);
	virtual void __fastcall GenerateKeyPair(void);
	virtual void __fastcall SignBuffer(const void *Buf, unsigned BufLen);
	virtual void __fastcall SignFile(const System::UnicodeString AFileName);
	virtual void __fastcall SignStream(System::Classes::TStream* AStream);
	virtual void __fastcall SignString(const System::UnicodeString AStr);
	virtual bool __fastcall VerifyBuffer(const void *Buf, unsigned BufLen);
	virtual bool __fastcall VerifyFile(const System::UnicodeString AFileName);
	virtual bool __fastcall VerifyStream(System::Classes::TStream* AStream);
	virtual bool __fastcall VerifyString(const System::UnicodeString AStr);
	void __fastcall Clear(void);
	bool __fastcall GeneratePQG(void);
	void __fastcall GenerateXY(void);
	__property TLbDSAPrivateKey* PrivateKey = {read=FPrivateKey};
	__property TLbDSAPublicKey* PublicKey = {read=FPublicKey};
	__property Lbbigint::TLbBigInt* SignatureR = {read=FSignatureR};
	__property Lbbigint::TLbBigInt* SignatureS = {read=FSignatureS};
	
__published:
	__property System::Byte PrimeTestIterations = {read=FPrimeTestIterations, write=SetPrimeTestIterations, nodefault};
	__property KeySize;
	__property TLbGetDSABlockEvent OnGetR = {read=FOnGetR, write=FOnGetR};
	__property TLbGetDSABlockEvent OnGetS = {read=FOnGetS, write=FOnGetS};
	__property TLbGetDSABlockEvent OnGetSeed = {read=FOnGetSeed, write=FOnGetSeed};
	__property TLbGetDSABlockEvent OnGetXKey = {read=FOnGetXKey, write=FOnGetXKey};
	__property TLbGetDSABlockEvent OnGetKKey = {read=FOnGetKKey, write=FOnGetKKey};
	__property OnProgress;
};


//-- var, const, procedure ---------------------------------------------------
}	/* namespace Lbdsa */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBDSA)
using namespace Lbdsa;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// LbdsaHPP
