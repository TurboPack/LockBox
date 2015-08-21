// CodeGear C++Builder
// Copyright (c) 1995, 2015 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbBigInt.pas' rev: 30.00 (Windows)

#ifndef LbbigintHPP
#define LbbigintHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member 
#pragma pack(push,8)
#include <System.hpp>
#include <SysInit.hpp>
#include <System.Types.hpp>
#include <System.SysUtils.hpp>
#include <LbRandom.hpp>

//-- user supplied -----------------------------------------------------------

namespace Lbbigint
{
//-- forward type declarations -----------------------------------------------
struct LbIntBuf;
struct LbInteger;
class DELPHICLASS TLbBigInt;
//-- type declarations -------------------------------------------------------
#pragma pack(push,1)
struct DECLSPEC_DRECORD LbIntBuf
{
public:
	int dwLen;
	System::Byte *pBuf;
};
#pragma pack(pop)


#pragma pack(push,1)
struct DECLSPEC_DRECORD LbInteger
{
public:
	bool bSign;
	int dwUsed;
	LbIntBuf IntBuf;
};
#pragma pack(pop)


class PASCALIMPLEMENTATION TLbBigInt : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	LbInteger FI;
	void __fastcall setSign(bool value);
	bool __fastcall getSign(void);
	int __fastcall GetSize(void);
	System::UnicodeString __fastcall GetIntStr(void);
	System::PByte __fastcall GetIntBuf(void);
	
public:
	__fastcall TLbBigInt(int ALen);
	__fastcall virtual ~TLbBigInt(void);
	void __fastcall Add(TLbBigInt* I2);
	void __fastcall Subtract(TLbBigInt* I2);
	void __fastcall Multiply(TLbBigInt* I2);
	void __fastcall Divide(TLbBigInt* I2);
	void __fastcall Modulus(TLbBigInt* I2);
	bool __fastcall ModInv(TLbBigInt* Modulus);
	void __fastcall PowerAndMod(TLbBigInt* Exponent, TLbBigInt* modulus);
	void __fastcall AddByte(System::Byte b);
	void __fastcall SubtractByte(System::Byte b);
	void __fastcall MultiplyByte(System::Byte b);
	void __fastcall DivideByte(System::Byte b);
	void __fastcall ModByte(System::Byte b);
	void __fastcall Clear(void);
	void __fastcall Trim(void);
	System::Int8 __fastcall Compare(TLbBigInt* I2);
	bool __fastcall IsZero(void);
	bool __fastcall IsOne(void);
	bool __fastcall IsOdd(void);
	bool __fastcall IsEven(void);
	bool __fastcall IsComposite(unsigned Iterations);
	System::Int8 __fastcall Abs(TLbBigInt* I2);
	void __fastcall ReverseBits(void);
	void __fastcall ReverseBytes(void);
	bool __fastcall GetBit(int bit);
	void __fastcall Shr_(int _shr);
	void __fastcall Shl_(int _shl);
	void __fastcall OR_(TLbBigInt* I2);
	void __fastcall XOR_(TLbBigInt* I2);
	void __fastcall RandomBytes(unsigned Count);
	void __fastcall RandomPrime(System::Byte Iterations);
	void __fastcall RandomSimplePrime(void);
	void __fastcall Copy(TLbBigInt* I2);
	void __fastcall CopyLen(TLbBigInt* I2, int Len);
	void __fastcall CopyByte(System::Byte b);
	void __fastcall CopyWord(System::Word w);
	void __fastcall CopyDWord(unsigned d);
	void __fastcall CopyBuffer(const void *Buf, int BufLen);
	void __fastcall Append(TLbBigInt* I);
	void __fastcall AppendByte(System::Byte b);
	void __fastcall AppendWord(System::Word w);
	void __fastcall AppendDWord(unsigned d);
	void __fastcall AppendBuffer(const void *Buf, int BufLen);
	void __fastcall Prepend(TLbBigInt* I);
	void __fastcall PrependByte(System::Byte b);
	void __fastcall PrependWord(System::Word w);
	void __fastcall PrependDWord(unsigned d);
	void __fastcall PrependBuffer(const void *Buf, int BufLen);
	int __fastcall ToBuffer(void *Buf, int BufLen);
	System::Byte __fastcall GetByteValue(int place);
	__property bool Sign = {read=getSign, write=setSign, nodefault};
	__property LbInteger Int = {read=FI};
	__property System::PByte IntBuf = {read=GetIntBuf};
	__property System::UnicodeString IntStr = {read=GetIntStr};
	__property int Size = {read=GetSize, nodefault};
};


//-- var, const, procedure ---------------------------------------------------
static const System::Int8 cLESS_THAN = System::Int8(-1);
static const System::Int8 cEQUAL_TO = System::Int8(0);
static const System::Int8 cGREATER_THAN = System::Int8(1);
static const bool cPOSITIVE = true;
static const bool cNEGATIVE = false;
}	/* namespace Lbbigint */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBBIGINT)
using namespace Lbbigint;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// LbbigintHPP
