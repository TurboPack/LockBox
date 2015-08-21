// CodeGear C++Builder
// Copyright (c) 1995, 2015 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbRSA.pas' rev: 30.00 (iOSSIM)

#ifndef LbrsaHPP
#define LbrsaHPP

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
#include <LbBigInt.hpp>
#include <LbAsym.hpp>
#include <LbCipher.hpp>
#include <LbConst.hpp>

//-- user supplied -----------------------------------------------------------

namespace Lbrsa
{
//-- forward type declarations -----------------------------------------------
class DELPHICLASS TLbRSAKey;
class DELPHICLASS TLbRSA;
class DELPHICLASS TLbRSASSA;
struct TRSA;
//-- type declarations -------------------------------------------------------
enum DECLSPEC_DENUM TRSABlockType : unsigned char { bt00, bt01, bt02 };

typedef System::StaticArray<System::Byte, 16> TRSACipherBlock128;

typedef TRSACipherBlock128 *PRSACipherBlock128;

typedef System::StaticArray<System::Byte, 32> TRSACipherBlock256;

typedef TRSACipherBlock256 *PRSACipherBlock256;

typedef System::StaticArray<System::Byte, 64> TRSACipherBlock512;

typedef TRSACipherBlock512 *PRSACipherBlock512;

typedef System::StaticArray<System::Byte, 96> TRSACipherBlock768;

typedef TRSACipherBlock768 *PRSACipherBlock768;

typedef System::StaticArray<System::Byte, 128> TRSACipherBlock1024;

typedef TRSACipherBlock1024 *PRSACipherBlock1024;

typedef System::StaticArray<System::Byte, 5> TRSAPlainBlock128;

typedef TRSAPlainBlock128 *PRSAPlainBlock128;

typedef System::StaticArray<System::Byte, 21> TRSAPlainBlock256;

typedef TRSAPlainBlock256 *PRSAPlainBlock256;

typedef System::StaticArray<System::Byte, 53> TRSAPlainBlock512;

typedef TRSAPlainBlock512 *PRSAPlainBlock512;

typedef System::StaticArray<System::Byte, 85> TRSAPlainBlock768;

typedef TRSAPlainBlock768 *PRSAPlainBlock768;

typedef System::StaticArray<System::Byte, 117> TRSAPlainBlock1024;

typedef TRSAPlainBlock1024 *PRSAPlainBlock1024;

typedef TRSAPlainBlock512 TRSAPlainBlock;

typedef TRSACipherBlock512 TRSACipherBlock;

typedef System::StaticArray<System::Byte, 128> TRSASignatureBlock;

enum DECLSPEC_DENUM TRSAHashMethod : unsigned char { hmMD5, hmSHA1 };

typedef void __fastcall (__closure *TLbRSAGetSignatureEvent)(System::TObject* Sender, TRSASignatureBlock &Sig);

typedef void __fastcall (__closure *TLbRSACallback)(bool &Abort);

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbRSAKey : public Lbasym::TLbAsymmetricKey
{
	typedef Lbasym::TLbAsymmetricKey inherited;
	
private:
	Lbbigint::TLbBigInt* FModulus;
	Lbbigint::TLbBigInt* FExponent;
	System::UnicodeString __fastcall GetModulusAsString(void);
	void __fastcall SetModulusAsString(System::UnicodeString Value);
	System::UnicodeString __fastcall GetExponentAsString(void);
	void __fastcall SetExponentAsString(System::UnicodeString Value);
	
protected:
	virtual int __fastcall CreateASNKey(System::Sysutils::PByteArray Input, int Length);
	virtual bool __fastcall ParseASNKey(Lbasym::PByte Input, int Length);
	
public:
	__fastcall virtual TLbRSAKey(Lbasym::TLbAsymKeySize aKeySize);
	__fastcall virtual ~TLbRSAKey(void);
	virtual void __fastcall Assign(Lbasym::TLbAsymmetricKey* aKey);
	void __fastcall Clear(void);
	__property Lbbigint::TLbBigInt* Modulus = {read=FModulus};
	__property System::UnicodeString ModulusAsString = {read=GetModulusAsString, write=SetModulusAsString};
	__property Lbbigint::TLbBigInt* Exponent = {read=FExponent};
	__property System::UnicodeString ExponentAsString = {read=GetExponentAsString, write=SetExponentAsString};
};

#pragma pack(pop)

class PASCALIMPLEMENTATION TLbRSA : public Lbasym::TLbAsymmetricCipher
{
	typedef Lbasym::TLbAsymmetricCipher inherited;
	
private:
	TLbRSAKey* FPrivateKey;
	TLbRSAKey* FPublicKey;
	System::Byte FPrimeTestIterations;
	
protected:
	virtual void __fastcall SetKeySize(Lbasym::TLbAsymKeySize Value);
	
public:
	__fastcall virtual TLbRSA(System::Classes::TComponent* AOwner);
	__fastcall virtual ~TLbRSA(void);
	virtual void __fastcall DecryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile);
	virtual void __fastcall DecryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
	virtual System::UnicodeString __fastcall DecryptString(const System::UnicodeString InString);
	virtual void __fastcall EncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile);
	virtual void __fastcall EncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
	virtual System::UnicodeString __fastcall EncryptString(const System::UnicodeString InString);
	virtual void __fastcall GenerateKeyPair(void);
	virtual unsigned __fastcall OutBufSizeNeeded(unsigned InBufSize);
	void __fastcall RSACallback(bool &Abort);
	__property TLbRSAKey* PrivateKey = {read=FPrivateKey};
	__property TLbRSAKey* PublicKey = {read=FPublicKey};
	
__published:
	__property System::Byte PrimeTestIterations = {read=FPrimeTestIterations, write=FPrimeTestIterations, nodefault};
	__property KeySize;
	__property OnProgress;
};


class PASCALIMPLEMENTATION TLbRSASSA : public Lbasym::TLbSignature
{
	typedef Lbasym::TLbSignature inherited;
	
private:
	TLbRSAKey* FPrivateKey;
	TLbRSAKey* FPublicKey;
	TRSAHashMethod FHashMethod;
	System::Byte FPrimeTestIterations;
	Lbbigint::TLbBigInt* FSignature;
	TLbRSAGetSignatureEvent FOnGetSignature;
	void __fastcall DoGetSignature(void);
	void __fastcall EncryptHash(const void *HashDigest, unsigned DigestLen);
	void __fastcall DecryptHash(void *HashDigest, unsigned DigestLen);
	void __fastcall RSACallback(bool &Abort);
	
protected:
	virtual void __fastcall SetKeySize(Lbasym::TLbAsymKeySize Value);
	
public:
	__fastcall virtual TLbRSASSA(System::Classes::TComponent* AOwner);
	__fastcall virtual ~TLbRSASSA(void);
	virtual void __fastcall GenerateKeyPair(void);
	virtual void __fastcall SignBuffer(const void *Buf, unsigned BufLen);
	virtual void __fastcall SignFile(const System::UnicodeString AFileName);
	virtual void __fastcall SignStream(System::Classes::TStream* AStream);
	virtual void __fastcall SignString(const System::UnicodeString AStr);
	virtual bool __fastcall VerifyBuffer(const void *Buf, unsigned BufLen);
	virtual bool __fastcall VerifyFile(const System::UnicodeString AFileName);
	virtual bool __fastcall VerifyStream(System::Classes::TStream* AStream);
	virtual bool __fastcall VerifyString(const System::UnicodeString AStr);
	__property TLbRSAKey* PrivateKey = {read=FPrivateKey};
	__property TLbRSAKey* PublicKey = {read=FPublicKey};
	__property Lbbigint::TLbBigInt* Signature = {read=FSignature};
	
__published:
	__property TRSAHashMethod HashMethod = {read=FHashMethod, write=FHashMethod, nodefault};
	__property System::Byte PrimeTestIterations = {read=FPrimeTestIterations, write=FPrimeTestIterations, nodefault};
	__property KeySize;
	__property TLbRSAGetSignatureEvent OnGetSignature = {read=FOnGetSignature, write=FOnGetSignature};
	__property OnProgress;
};


struct DECLSPEC_DRECORD TRSA
{
private:
	static void __fastcall RSADecodeBlock(Lbbigint::TLbBigInt* biBlock);
	static void __fastcall RSAEncryptBigInt(Lbbigint::TLbBigInt* biBlock, TLbRSAKey* Key, TRSABlockType BlockType, bool Encrypt);
	static void __fastcall RSAFormatBlock(Lbbigint::TLbBigInt* biBlock, TRSABlockType BlockType);
	
public:
	static int __fastcall DecryptRSA(TLbRSAKey* PrivateKey, const TRSACipherBlock512 &InBlock, TRSAPlainBlock512 &OutBlock);
	static int __fastcall DecryptRSA1024(TLbRSAKey* PrivateKey, const TRSACipherBlock1024 &InBlock, TRSAPlainBlock1024 &OutBlock);
	static int __fastcall DecryptRSA128(TLbRSAKey* PrivateKey, const TRSACipherBlock128 &InBlock, TRSAPlainBlock128 &OutBlock);
	static int __fastcall DecryptRSA256(TLbRSAKey* PrivateKey, const TRSACipherBlock256 &InBlock, TRSAPlainBlock256 &OutBlock);
	static int __fastcall DecryptRSA512(TLbRSAKey* PrivateKey, const TRSACipherBlock512 &InBlock, TRSAPlainBlock512 &OutBlock);
	static int __fastcall DecryptRSA768(TLbRSAKey* PrivateKey, const TRSACipherBlock768 &InBlock, TRSAPlainBlock768 &OutBlock);
	static int __fastcall DecryptRSAEx(TLbRSAKey* PrivateKey, System::Sysutils::PByteArray pInBlock, System::Sysutils::PByteArray pOutBlock);
	static int __fastcall EncryptRSA(TLbRSAKey* PublicKey, const TRSAPlainBlock512 &InBlock, TRSACipherBlock512 &OutBlock);
	static int __fastcall EncryptRSA1024(TLbRSAKey* PublicKey, const TRSAPlainBlock1024 &InBlock, TRSACipherBlock1024 &OutBlock);
	static int __fastcall EncryptRSA128(TLbRSAKey* PublicKey, const TRSAPlainBlock128 &InBlock, TRSACipherBlock128 &OutBlock);
	static int __fastcall EncryptRSA256(TLbRSAKey* PublicKey, const TRSAPlainBlock256 &InBlock, TRSACipherBlock256 &OutBlock);
	static int __fastcall EncryptRSA512(TLbRSAKey* PublicKey, const TRSAPlainBlock512 &InBlock, TRSACipherBlock512 &OutBlock);
	static int __fastcall EncryptRSA768(TLbRSAKey* PublicKey, const TRSAPlainBlock768 &InBlock, TRSACipherBlock768 &OutBlock);
	static int __fastcall EncryptRSAEx(TLbRSAKey* PublicKey, System::Sysutils::PByteArray pInBlock, System::Sysutils::PByteArray pOutBlock, int InDataSize);
	static void __fastcall GenerateRSAKeys(TLbRSAKey* &PrivateKey, TLbRSAKey* &PublicKey);
	static void __fastcall GenerateRSAKeysEx(TLbRSAKey* &PrivateKey, TLbRSAKey* &PublicKey, Lbasym::TLbAsymKeySize KeySize, System::Byte PrimeTestIterations, TLbRSACallback Callback);
	static void __fastcall RSAEncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile, TLbRSAKey* Key, bool Encrypt);
	static void __fastcall RSAEncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream, TLbRSAKey* Key, bool Encrypt);
	static System::TArray__1<System::Byte> __fastcall RSAEncryptBytes(const System::TArray__1<System::Byte> InBytes, TLbRSAKey* Key, bool Encrypt);
};


//-- var, const, procedure ---------------------------------------------------
static constexpr System::Int8 cRSAMinPadBytes = System::Int8(0xb);
extern DELPHI_PACKAGE System::StaticArray<System::Word, 5> cRSACipherBlockSize;
extern DELPHI_PACKAGE System::StaticArray<System::Word, 5> cRSAPlainBlockSize;
}	/* namespace Lbrsa */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBRSA)
using namespace Lbrsa;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// LbrsaHPP
