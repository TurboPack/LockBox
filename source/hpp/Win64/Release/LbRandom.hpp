// CodeGear C++Builder
// Copyright (c) 1995, 2015 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbRandom.pas' rev: 30.00 (Windows)

#ifndef LbrandomHPP
#define LbrandomHPP

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
#include <System.Math.hpp>
#include <LbCipher.hpp>

//-- user supplied -----------------------------------------------------------

namespace Lbrandom
{
//-- forward type declarations -----------------------------------------------
class DELPHICLASS TLbRandomGenerator;
class DELPHICLASS TLbRanLFS;
//-- type declarations -------------------------------------------------------
class PASCALIMPLEMENTATION TLbRandomGenerator : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int RandCount;
	Lbcipher::TMD5Digest Seed;
	void __fastcall ChurnSeed(void);
	
public:
	__fastcall TLbRandomGenerator(void);
	__fastcall virtual ~TLbRandomGenerator(void);
	void __fastcall RandomBytes(void *buff, unsigned len);
};


class PASCALIMPLEMENTATION TLbRanLFS : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	unsigned ShiftRegister;
	void __fastcall SetSeed(void);
	System::Byte __fastcall LFS(void);
	
public:
	__fastcall TLbRanLFS(void);
	void __fastcall FillBuf(void *buff, unsigned len);
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TLbRanLFS(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
}	/* namespace Lbrandom */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBRANDOM)
using namespace Lbrandom;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// LbrandomHPP
