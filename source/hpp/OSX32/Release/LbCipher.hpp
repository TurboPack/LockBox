// CodeGear C++Builder
// Copyright (c) 1995, 2015 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbCipher.pas' rev: 30.00 (MacOS)

#ifndef LbcipherHPP
#define LbcipherHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member 
#pragma pack(push,8)
#include <System.hpp>
#include <SysInit.hpp>
#include <System.Types.hpp>
#include <System.SysUtils.hpp>
#include <System.Classes.hpp>

//-- user supplied -----------------------------------------------------------

namespace Lbcipher
{
//-- forward type declarations -----------------------------------------------
class DELPHICLASS TLBBase;
struct TIntegerRec;
struct TInt64;
struct TRDLVector;
struct TDesConverter;
struct TBFContext;
struct TDESContext;
struct TLBCContext;
struct TRDLContext;
struct TLSCContext;
struct TSHA1Context;
class DELPHICLASS TBlowfish;
class DELPHICLASS TDES;
class DELPHICLASS TSHA1;
class DELPHICLASS TLBC;
class DELPHICLASS TMD5;
class DELPHICLASS TRDL;
struct TLMD;
class DELPHICLASS TRNG;
class DELPHICLASS TLSC;
struct TMISC;
//-- type declarations -------------------------------------------------------
class PASCALIMPLEMENTATION TLBBase : public System::Classes::TComponent
{
	typedef System::Classes::TComponent inherited;
	
public:
	/* TComponent.Create */ inline __fastcall virtual TLBBase(System::Classes::TComponent* AOwner) : System::Classes::TComponent(AOwner) { }
	/* TComponent.Destroy */ inline __fastcall virtual ~TLBBase(void) { }
	
};


typedef System::StaticArray<int, 512000000> TIntegerArray;

typedef TIntegerArray *pIntegerArray;

#pragma pack(push,1)
struct DECLSPEC_DRECORD TIntegerRec
{
	
public:
	union
	{
		struct 
		{
			System::Byte LoLo;
			System::Byte LoHi;
			System::Byte HiLo;
			System::Byte HiHi;
		};
		struct 
		{
			System::Word Lo;
			System::Word Hi;
		};
		
	};
};
#pragma pack(pop)


#pragma pack(push,1)
struct DECLSPEC_DRECORD TInt64
{
	
public:
	union
	{
		struct 
		{
			System::Byte LoLoLo;
			System::Byte LoLoHi;
			System::Byte LoHiLo;
			System::Byte LoHiHi;
			System::Byte HiLoLo;
			System::Byte HiLoHi;
			System::Byte HiHiLo;
			System::Byte HiHiHi;
		};
		struct 
		{
			System::Word LoLo;
			System::Word LoHi;
			System::Word HiLo;
			System::Word HiHi;
		};
		struct 
		{
			int Lo;
			int Hi;
		};
		
	};
};
#pragma pack(pop)


struct DECLSPEC_DRECORD TRDLVector
{
	
public:
	union
	{
		struct 
		{
			System::StaticArray<System::Byte, 4> bt;
		};
		struct 
		{
			unsigned dw;
		};
		
	};
};


typedef System::StaticArray<System::Byte, 8> TKey64;

typedef TKey64 *PKey64;

typedef System::StaticArray<System::Byte, 16> TKey128;

typedef TKey128 *PKey128;

typedef System::StaticArray<System::Byte, 24> TKey192;

typedef TKey192 *PKey192;

typedef System::StaticArray<System::Byte, 32> TKey256;

typedef TKey256 *PKey256;

typedef System::StaticArray<int, 4> TLBCBlock;

typedef TLBCBlock *PLBCBlock;

typedef System::StaticArray<System::Byte, 8> TDESBlock;

typedef System::StaticArray<int, 2> TLQCBlock;

typedef System::StaticArray<int, 2> TBFBlock;

typedef System::StaticArray<System::Byte, 16> TRDLBlock;

struct DECLSPEC_DRECORD TDesConverter
{
	
public:
	union
	{
		struct 
		{
			System::StaticArray<unsigned, 2> DWords;
		};
		struct 
		{
			System::StaticArray<System::Byte, 8> Bytes;
		};
		
	};
};


#pragma pack(push,1)
struct DECLSPEC_DRECORD TBFContext
{
public:
	System::StaticArray<int, 18> PBox;
	System::StaticArray<System::StaticArray<int, 256>, 4> SBox;
};
#pragma pack(pop)


#pragma pack(push,1)
struct DECLSPEC_DRECORD TDESContext
{
public:
	System::StaticArray<int, 32> TransformedKey;
	bool Encrypt;
};
#pragma pack(pop)


typedef System::StaticArray<TDESContext, 2> TTripleDESContext;

typedef System::StaticArray<TDESContext, 3> TTripleDESContext3Key;

#pragma pack(push,1)
struct DECLSPEC_DRECORD TLBCContext
{
public:
	bool Encrypt;
	System::StaticArray<System::Byte, 3> Dummy;
	int Rounds;
	
public:
	union
	{
		struct 
		{
			System::StaticArray<System::StaticArray<int, 8>, 4> SubKeysInts;
		};
		struct 
		{
			System::StaticArray<System::StaticArray<System::Byte, 8>, 16> SubKeys64;
		};
		
	};
};
#pragma pack(pop)


#pragma pack(push,1)
struct DECLSPEC_DRECORD TRDLContext
{
public:
	bool Encrypt;
	System::StaticArray<System::Byte, 3> Dummy;
	unsigned Rounds;
	
public:
	union
	{
		struct 
		{
			System::StaticArray<System::StaticArray<System::Byte, 16>, 15> Rk;
		};
		struct 
		{
			System::StaticArray<TRDLVector, 57> W;
		};
		
	};
};
#pragma pack(pop)


#pragma pack(push,1)
struct DECLSPEC_DRECORD TLSCContext
{
public:
	int Index;
	int Accumulator;
	System::StaticArray<System::Byte, 256> SBox;
};
#pragma pack(pop)


typedef System::StaticArray<System::Byte, 4> TRNG32Context;

typedef System::StaticArray<System::Byte, 8> TRNG64Context;

typedef System::StaticArray<System::Byte, 16> TMD5Digest;

typedef System::StaticArray<System::Byte, 20> TSHA1Digest;

typedef System::StaticArray<System::Byte, 280> TLMDContext;

typedef System::StaticArray<System::Byte, 88> TMD5Context;

struct DECLSPEC_DRECORD TSHA1Context
{
public:
	unsigned sdHi;
	unsigned sdLo;
	unsigned sdIndex;
	System::StaticArray<unsigned, 5> sdHash;
	System::StaticArray<System::Byte, 64> sdBuf;
};


#pragma pack(push,4)
class PASCALIMPLEMENTATION TBlowfish : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	static void __fastcall EncryptBF(const TBFContext &Context, TBFBlock &Block, bool Encrypt);
	static void __fastcall EncryptBFCBC(const TBFContext &Context, const TBFBlock &Prev, TBFBlock &Block, bool Encrypt);
	static void __fastcall InitEncryptBF(const TKey128 &Key, TBFContext &Context);
public:
	/* TObject.Create */ inline __fastcall TBlowfish(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TBlowfish(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TDES : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	static void __fastcall JoinBlock(const int L, const int R, TDESBlock &Block);
	static void __fastcall SplitBlock(const TDESBlock &Block, unsigned &L, unsigned &R);
	
public:
	static void __fastcall EncryptDES(const TDESContext &Context, TDESBlock &Block);
	static void __fastcall EncryptDESCBC(const TDESContext &Context, const TDESBlock &Prev, TDESBlock &Block);
	static void __fastcall EncryptTripleDES(const TTripleDESContext &Context, TDESBlock &Block);
	static void __fastcall EncryptTripleDES3Key(const TTripleDESContext3Key &Context, TDESBlock &Block);
	static void __fastcall EncryptTripleDESCBC(const TTripleDESContext &Context, const TDESBlock &Prev, TDESBlock &Block);
	static void __fastcall EncryptTripleDESCBC3Key(const TTripleDESContext3Key &Context, const TDESBlock &Prev, TDESBlock &Block);
	static void __fastcall InitEncryptDES(const TKey64 &Key, TDESContext &Context, bool Encrypt);
	static void __fastcall InitEncryptTripleDES(const TKey128 &Key, TTripleDESContext &Context, bool Encrypt);
	static void __fastcall InitEncryptTripleDES3Key(const TKey64 &Key1, const TKey64 &Key2, const TKey64 &Key3, TTripleDESContext3Key &Context, bool Encrypt);
	static void __fastcall ShrinkDESKey(TKey64 &Key);
public:
	/* TObject.Create */ inline __fastcall TDES(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TDES(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TSHA1 : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	static void __fastcall SHA1Clear(TSHA1Context &Context);
	static void __fastcall SHA1Hash(TSHA1Context &Context);
	static unsigned __fastcall SHA1SwapByteOrder(unsigned n);
	static void __fastcall SHA1UpdateLen(TSHA1Context &Context, unsigned Len);
	
public:
	static void __fastcall FinalizeSHA1(TSHA1Context &Context, TSHA1Digest &Digest);
	static void __fastcall HashSHA1(TSHA1Digest &Digest, const void *Buf, int BufSize);
	static void __fastcall InitSHA1(TSHA1Context &Context);
	static void __fastcall StringHashSHA1(TSHA1Digest &Digest, const System::DynamicArray<System::Byte> ABytes);
	static void __fastcall UpdateSHA1(TSHA1Context &Context, const void *Buf, int BufSize);
public:
	/* TObject.Create */ inline __fastcall TSHA1(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TSHA1(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLBC : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	static void __fastcall EncryptLBC(const TLBCContext &Context, TLBCBlock &Block);
	static void __fastcall EncryptLBCCBC(const TLBCContext &Context, const TLBCBlock &Prev, TLBCBlock &Block);
	static void __fastcall EncryptLQC(const TKey128 &Key, TLQCBlock &Block, bool Encrypt);
	static void __fastcall EncryptLQCCBC(const TKey128 &Key, const TLQCBlock &Prev, TLQCBlock &Block, bool Encrypt);
	static void __fastcall InitEncryptLBC(const TKey128 &Key, TLBCContext &Context, int Rounds, bool Encrypt);
public:
	/* TObject.Create */ inline __fastcall TLBC(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TLBC(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TMD5 : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	static void __fastcall FinalizeMD5(TMD5Context &Context, TMD5Digest &Digest);
	static void __fastcall GenerateMD5Key(TKey128 &Key, const System::DynamicArray<System::Byte> ABytes);
	static void __fastcall HashMD5(TMD5Digest &Digest, const void *Buf, int BufSize);
	static void __fastcall InitMD5(TMD5Context &Context);
	static void __fastcall StringHashMD5(TMD5Digest &Digest, const System::DynamicArray<System::Byte> ABytes);
	static void __fastcall UpdateMD5(TMD5Context &Context, const void *Buf, int BufSize);
public:
	/* TObject.Create */ inline __fastcall TMD5(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TMD5(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TRDL : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	static void __fastcall RdlInvRound(const TRDLBlock &RoundKey, TRDLBlock &State, bool First);
	static TRDLVector __fastcall RdlRotateVector(TRDLVector v, System::Byte Count);
	static void __fastcall RdlRound(const TRDLBlock &RoundKey, TRDLBlock &State, bool AFinal);
	static TRDLVector __fastcall RdlSubVector(TRDLVector v);
	
public:
	static void __fastcall EncryptRDL(const TRDLContext &Context, TRDLBlock &Block);
	static void __fastcall EncryptRDLCBC(const TRDLContext &Context, const TRDLBlock &Prev, TRDLBlock &Block);
	static void __fastcall InitEncryptRDL(const void *Key, int KeySize, TRDLContext &Context, bool Encrypt);
public:
	/* TObject.Create */ inline __fastcall TRDL(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TRDL(void) { }
	
};

#pragma pack(pop)

struct DECLSPEC_DRECORD TLMD
{
public:
	static void __fastcall FinalizeLMD(TLMDContext &Context, void *Digest, int DigestSize);
	static void __fastcall GenerateLMDKey(void *Key, int KeySize, const System::DynamicArray<System::Byte> ABytes);
	static void __fastcall HashLMD(void *Digest, int DigestSize, const void *Buf, int BufSize);
	static void __fastcall InitLMD(TLMDContext &Context);
	static void __fastcall StringHashLMD(void *Digest, int DigestSize, const System::DynamicArray<System::Byte> ABytes);
	static void __fastcall UpdateLMD(TLMDContext &Context, const void *Buf, int BufSize);
};


#pragma pack(push,4)
class PASCALIMPLEMENTATION TRNG : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	static void __fastcall EncryptRNG32(TRNG32Context &Context, void *Buf, int BufSize);
	static void __fastcall EncryptRNG64(TRNG64Context &Context, void *Buf, int BufSize);
	static void __fastcall InitEncryptRNG32(int Key, TRNG32Context &Context);
	static void __fastcall InitEncryptRNG64(int KeyHi, int KeyLo, TRNG64Context &Context);
public:
	/* TObject.Create */ inline __fastcall TRNG(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TRNG(void) { }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLSC : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	static void __fastcall EncryptLSC(TLSCContext &Context, void *Buf, int BufSize);
	static void __fastcall InitEncryptLSC(const void *Key, int KeySize, TLSCContext &Context);
public:
	/* TObject.Create */ inline __fastcall TLSC(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TLSC(void) { }
	
};

#pragma pack(pop)

typedef System::StaticArray<unsigned, 4> T128Bit;

typedef System::StaticArray<unsigned, 8> T256Bit;

struct DECLSPEC_DRECORD TMISC
{
private:
	static void __fastcall Mix128(T128Bit &X);
	static int __fastcall Ran0Prim(int &Seed, int IA, int IQ, int IR);
	static int __fastcall Random64(TInt64 &Seed);
	
private:
	static void __fastcall Transform(unsigned *Buffer, const int Buffer_High, unsigned const *InBuf, const int InBuf_High);
	static void __fastcall XorMemPrim(void *Mem1, const void *Mem2, unsigned Count);
	
public:
	static void __fastcall GenerateRandomKey(void *Key, int KeySize);
	static void __fastcall HashELF(int &Digest, const void *Buf, int BufSize);
	static void __fastcall HashMix128(int &Digest, const void *Buf, int BufSize);
	static int __fastcall Ran01(int &Seed);
	static int __fastcall Ran02(int &Seed);
	static int __fastcall Ran03(int &Seed);
	static System::Byte __fastcall Random32Byte(int &Seed);
	static System::Byte __fastcall Random64Byte(TInt64 &Seed);
	static unsigned __fastcall RolX(unsigned I, unsigned C);
	static void __fastcall StringHashELF(int &Digest, const System::DynamicArray<System::Byte> ABytes);
	static void __fastcall StringHashMix128(int &Digest, const System::DynamicArray<System::Byte> ABytes);
	static void __fastcall XorMem(void *Mem1, const void *Mem2, unsigned Count);
};


//-- var, const, procedure ---------------------------------------------------
static const int MaxStructSize = int(0x7a120000);
static const System::Int8 BFRounds = System::Int8(0x10);
static const System::Int8 MaxRDLRounds = System::Int8(0xe);
}	/* namespace Lbcipher */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBCIPHER)
using namespace Lbcipher;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// LbcipherHPP
