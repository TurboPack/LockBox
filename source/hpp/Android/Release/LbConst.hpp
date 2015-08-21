// CodeGear C++Builder
// Copyright (c) 1995, 2015 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbConst.pas' rev: 30.00 (Android)

#ifndef LbconstHPP
#define LbconstHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member 
#pragma pack(push,8)
#include <System.hpp>
#include <SysInit.hpp>

//-- user supplied -----------------------------------------------------------

namespace Lbconst
{
//-- forward type declarations -----------------------------------------------
//-- type declarations -------------------------------------------------------
//-- var, const, procedure ---------------------------------------------------
static constexpr System::Int8 cBytes128 = System::Int8(0x10);
static constexpr System::Int8 cBytes160 = System::Int8(0x14);
static constexpr System::Int8 cBytes192 = System::Int8(0x18);
static constexpr System::Int8 cBytes256 = System::Int8(0x20);
static constexpr System::Int8 cBytes512 = System::Int8(0x40);
static constexpr System::Int8 cBytes768 = System::Int8(0x60);
static constexpr System::Byte cBytes1024 = System::Byte(0x80);
static constexpr System::Int8 cDefIterations = System::Int8(0x14);
static constexpr System::Int8 ASN1_TYPE_SEQUENCE = System::Int8(0x10);
static constexpr System::Int8 ASN1_TYPE_Integer = System::Int8(0x2);
static constexpr System::Int8 ASN1_TAG_NUM_MASK = System::Int8(0x1f);
static constexpr System::Int8 ASN1_TYPE_HIGH_TAG_NUMBER = System::Int8(0x1f);
static constexpr System::Byte HIGH_BIT_MASK = System::Byte(0x80);
static constexpr System::Int8 BIT_MASK_7F = System::Int8(0x7f);
extern DELPHI_PACKAGE System::ResourceString _sLbVersion;
#define Lbconst_sLbVersion System::LoadResourceString(&Lbconst::_sLbVersion)
extern DELPHI_PACKAGE System::ResourceString _sBIBufferUnderflow;
#define Lbconst_sBIBufferUnderflow System::LoadResourceString(&Lbconst::_sBIBufferUnderflow)
extern DELPHI_PACKAGE System::ResourceString _sBIBufferNotAssigned;
#define Lbconst_sBIBufferNotAssigned System::LoadResourceString(&Lbconst::_sBIBufferNotAssigned)
extern DELPHI_PACKAGE System::ResourceString _sBINoNumber;
#define Lbconst_sBINoNumber System::LoadResourceString(&Lbconst::_sBINoNumber)
extern DELPHI_PACKAGE System::ResourceString _sBISubtractErr;
#define Lbconst_sBISubtractErr System::LoadResourceString(&Lbconst::_sBISubtractErr)
extern DELPHI_PACKAGE System::ResourceString _sBIZeroDivide;
#define Lbconst_sBIZeroDivide System::LoadResourceString(&Lbconst::_sBIZeroDivide)
extern DELPHI_PACKAGE System::ResourceString _sBIQuotientErr;
#define Lbconst_sBIQuotientErr System::LoadResourceString(&Lbconst::_sBIQuotientErr)
extern DELPHI_PACKAGE System::ResourceString _sBIZeroFactor;
#define Lbconst_sBIZeroFactor System::LoadResourceString(&Lbconst::_sBIZeroFactor)
extern DELPHI_PACKAGE System::ResourceString _sBIIterationCount;
#define Lbconst_sBIIterationCount System::LoadResourceString(&Lbconst::_sBIIterationCount)
extern DELPHI_PACKAGE System::ResourceString _sASNKeyTooLarge;
#define Lbconst_sASNKeyTooLarge System::LoadResourceString(&Lbconst::_sASNKeyTooLarge)
extern DELPHI_PACKAGE System::ResourceString _sASNKeyBufferOverflow;
#define Lbconst_sASNKeyBufferOverflow System::LoadResourceString(&Lbconst::_sASNKeyBufferOverflow)
extern DELPHI_PACKAGE System::ResourceString _sASNKeyBadModulus;
#define Lbconst_sASNKeyBadModulus System::LoadResourceString(&Lbconst::_sASNKeyBadModulus)
extern DELPHI_PACKAGE System::ResourceString _sASNKeyBadExponent;
#define Lbconst_sASNKeyBadExponent System::LoadResourceString(&Lbconst::_sASNKeyBadExponent)
extern DELPHI_PACKAGE System::ResourceString _sASNKeyBufferTooSmall;
#define Lbconst_sASNKeyBufferTooSmall System::LoadResourceString(&Lbconst::_sASNKeyBufferTooSmall)
extern DELPHI_PACKAGE System::ResourceString _sASNKeyBadKey;
#define Lbconst_sASNKeyBadKey System::LoadResourceString(&Lbconst::_sASNKeyBadKey)
extern DELPHI_PACKAGE System::ResourceString _sRSAKeyBadKey;
#define Lbconst_sRSAKeyBadKey System::LoadResourceString(&Lbconst::_sRSAKeyBadKey)
extern DELPHI_PACKAGE System::ResourceString _sModulusStringTooBig;
#define Lbconst_sModulusStringTooBig System::LoadResourceString(&Lbconst::_sModulusStringTooBig)
extern DELPHI_PACKAGE System::ResourceString _sExponentStringTooBig;
#define Lbconst_sExponentStringTooBig System::LoadResourceString(&Lbconst::_sExponentStringTooBig)
extern DELPHI_PACKAGE System::ResourceString _sRSAKeyPairErr;
#define Lbconst_sRSAKeyPairErr System::LoadResourceString(&Lbconst::_sRSAKeyPairErr)
extern DELPHI_PACKAGE System::ResourceString _sRSAPublicKeyErr;
#define Lbconst_sRSAPublicKeyErr System::LoadResourceString(&Lbconst::_sRSAPublicKeyErr)
extern DELPHI_PACKAGE System::ResourceString _sRSAPrivateKeyErr;
#define Lbconst_sRSAPrivateKeyErr System::LoadResourceString(&Lbconst::_sRSAPrivateKeyErr)
extern DELPHI_PACKAGE System::ResourceString _sRSAEncryptErr;
#define Lbconst_sRSAEncryptErr System::LoadResourceString(&Lbconst::_sRSAEncryptErr)
extern DELPHI_PACKAGE System::ResourceString _sRSADecryptErr;
#define Lbconst_sRSADecryptErr System::LoadResourceString(&Lbconst::_sRSADecryptErr)
extern DELPHI_PACKAGE System::ResourceString _sRSABlockSize128Err;
#define Lbconst_sRSABlockSize128Err System::LoadResourceString(&Lbconst::_sRSABlockSize128Err)
extern DELPHI_PACKAGE System::ResourceString _sRSABlockSize256Err;
#define Lbconst_sRSABlockSize256Err System::LoadResourceString(&Lbconst::_sRSABlockSize256Err)
extern DELPHI_PACKAGE System::ResourceString _sRSABlockSize512Err;
#define Lbconst_sRSABlockSize512Err System::LoadResourceString(&Lbconst::_sRSABlockSize512Err)
extern DELPHI_PACKAGE System::ResourceString _sRSABlockSize768Err;
#define Lbconst_sRSABlockSize768Err System::LoadResourceString(&Lbconst::_sRSABlockSize768Err)
extern DELPHI_PACKAGE System::ResourceString _sRSABlockSize1024Err;
#define Lbconst_sRSABlockSize1024Err System::LoadResourceString(&Lbconst::_sRSABlockSize1024Err)
extern DELPHI_PACKAGE System::ResourceString _sRSAEncodingErr;
#define Lbconst_sRSAEncodingErr System::LoadResourceString(&Lbconst::_sRSAEncodingErr)
extern DELPHI_PACKAGE System::ResourceString _sRSADecodingErrBTS;
#define Lbconst_sRSADecodingErrBTS System::LoadResourceString(&Lbconst::_sRSADecodingErrBTS)
extern DELPHI_PACKAGE System::ResourceString _sRSADecodingErrBTL;
#define Lbconst_sRSADecodingErrBTL System::LoadResourceString(&Lbconst::_sRSADecodingErrBTL)
extern DELPHI_PACKAGE System::ResourceString _sRSADecodingErrIBT;
#define Lbconst_sRSADecodingErrIBT System::LoadResourceString(&Lbconst::_sRSADecodingErrIBT)
extern DELPHI_PACKAGE System::ResourceString _sRSADecodingErrIBF;
#define Lbconst_sRSADecodingErrIBF System::LoadResourceString(&Lbconst::_sRSADecodingErrIBF)
extern DELPHI_PACKAGE System::ResourceString _sDSAKeyBadKey;
#define Lbconst_sDSAKeyBadKey System::LoadResourceString(&Lbconst::_sDSAKeyBadKey)
extern DELPHI_PACKAGE System::ResourceString _sDSAParametersPQGErr;
#define Lbconst_sDSAParametersPQGErr System::LoadResourceString(&Lbconst::_sDSAParametersPQGErr)
extern DELPHI_PACKAGE System::ResourceString _sDSAParametersXYErr;
#define Lbconst_sDSAParametersXYErr System::LoadResourceString(&Lbconst::_sDSAParametersXYErr)
extern DELPHI_PACKAGE System::ResourceString _sDSASignatureZeroR;
#define Lbconst_sDSASignatureZeroR System::LoadResourceString(&Lbconst::_sDSASignatureZeroR)
extern DELPHI_PACKAGE System::ResourceString _sDSASignatureZeroS;
#define Lbconst_sDSASignatureZeroS System::LoadResourceString(&Lbconst::_sDSASignatureZeroS)
extern DELPHI_PACKAGE System::ResourceString _sDSASignatureErr;
#define Lbconst_sDSASignatureErr System::LoadResourceString(&Lbconst::_sDSASignatureErr)
extern DELPHI_PACKAGE System::ResourceString _SNoStart;
#define Lbconst_SNoStart System::LoadResourceString(&Lbconst::_SNoStart)
}	/* namespace Lbconst */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBCONST)
using namespace Lbconst;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// LbconstHPP
