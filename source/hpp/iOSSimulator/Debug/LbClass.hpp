// CodeGear C++Builder
// Copyright (c) 1995, 2015 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbClass.pas' rev: 30.00 (iOSSIM)

#ifndef LbclassHPP
#define LbclassHPP

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

namespace Lbclass
{
//-- forward type declarations -----------------------------------------------
class DELPHICLASS TLBBaseComponent;
class DELPHICLASS TLbCipher;
class DELPHICLASS TLbSymmetricCipher;
class DELPHICLASS TLbBlowfish;
class DELPHICLASS TLbDES;
class DELPHICLASS TLb3DES;
class DELPHICLASS TLbRijndael;
class DELPHICLASS TLbHash;
class DELPHICLASS TLbMD5;
class DELPHICLASS TLbSHA1;
class DELPHICLASS TLbSCStream;
class DELPHICLASS TLbSCFileStream;
class DELPHICLASS TLbRNG32Stream;
class DELPHICLASS TLbRNG32FileStream;
class DELPHICLASS TLbRNG64Stream;
class DELPHICLASS TLbRNG64FileStream;
//-- type declarations -------------------------------------------------------
class PASCALIMPLEMENTATION TLBBaseComponent : public Lbcipher::TLBBase
{
	typedef Lbcipher::TLBBase inherited;
	
private:
	System::Sysutils::TEncoding* FEncoding;
	System::UnicodeString __fastcall GetVersion(void);
	void __fastcall SetVersion(const System::UnicodeString Value);
	
protected:
	System::TArray__1<System::Byte> __fastcall GetBytes(const System::UnicodeString AString);
	System::UnicodeString __fastcall GetString(const System::TArray__1<System::Byte> ABytes);
	
public:
	__fastcall virtual TLBBaseComponent(System::Classes::TComponent* AOwner);
	__property System::Sysutils::TEncoding* Encoding = {read=FEncoding, write=FEncoding};
	
__published:
	__property System::UnicodeString Version = {read=GetVersion, write=SetVersion, stored=false};
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TLBBaseComponent(void) { }
	
};


enum DECLSPEC_DENUM TLbCipherMode : unsigned char { cmECB, cmCBC };

class PASCALIMPLEMENTATION TLbCipher : public TLBBaseComponent
{
	typedef TLBBaseComponent inherited;
	
public:
	unsigned __fastcall DecryptBuffer(const void *InBuf, int InBufSize, void *OutBuf);
	unsigned __fastcall EncryptBuffer(const void *InBuf, int InBufSize, void *OutBuf);
	virtual void __fastcall DecryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile) = 0 ;
	virtual void __fastcall DecryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream) = 0 ;
	virtual System::UnicodeString __fastcall DecryptString(const System::UnicodeString InString) = 0 ;
	virtual void __fastcall EncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile) = 0 ;
	virtual void __fastcall EncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream) = 0 ;
	virtual System::UnicodeString __fastcall EncryptString(const System::UnicodeString InString) = 0 ;
	virtual unsigned __fastcall OutBufSizeNeeded(unsigned InBufSize) = 0 ;
public:
	/* TLBBaseComponent.Create */ inline __fastcall virtual TLbCipher(System::Classes::TComponent* AOwner) : TLBBaseComponent(AOwner) { }
	
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TLbCipher(void) { }
	
};


class PASCALIMPLEMENTATION TLbSymmetricCipher : public TLbCipher
{
	typedef TLbCipher inherited;
	
private:
	TLbCipherMode FCipherMode;
	
public:
	virtual void __fastcall GenerateKey(const System::UnicodeString Passphrase) = 0 ;
	virtual void __fastcall GenerateRandomKey(void) = 0 ;
	__property TLbCipherMode CipherMode = {read=FCipherMode, write=FCipherMode, nodefault};
public:
	/* TLBBaseComponent.Create */ inline __fastcall virtual TLbSymmetricCipher(System::Classes::TComponent* AOwner) : TLbCipher(AOwner) { }
	
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TLbSymmetricCipher(void) { }
	
};


class PASCALIMPLEMENTATION TLbBlowfish : public TLbSymmetricCipher
{
	typedef TLbSymmetricCipher inherited;
	
private:
	Lbcipher::TKey128 FKey;
	
public:
	virtual void __fastcall DecryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile);
	virtual void __fastcall DecryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
	virtual System::UnicodeString __fastcall DecryptString(const System::UnicodeString InString);
	virtual void __fastcall EncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile);
	virtual void __fastcall EncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
	virtual System::UnicodeString __fastcall EncryptString(const System::UnicodeString InString);
	virtual void __fastcall GenerateKey(const System::UnicodeString Passphrase);
	virtual void __fastcall GenerateRandomKey(void);
	void __fastcall GetKey(Lbcipher::TKey128 &Key);
	void __fastcall SetKey(const Lbcipher::TKey128 &Key);
	virtual unsigned __fastcall OutBufSizeNeeded(unsigned InBufSize);
	
__published:
	__property CipherMode;
public:
	/* TLBBaseComponent.Create */ inline __fastcall virtual TLbBlowfish(System::Classes::TComponent* AOwner) : TLbSymmetricCipher(AOwner) { }
	
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TLbBlowfish(void) { }
	
};


class PASCALIMPLEMENTATION TLbDES : public TLbSymmetricCipher
{
	typedef TLbSymmetricCipher inherited;
	
private:
	Lbcipher::TKey64 FKey;
	
public:
	virtual void __fastcall DecryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile);
	virtual void __fastcall DecryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
	virtual System::UnicodeString __fastcall DecryptString(const System::UnicodeString InString);
	virtual void __fastcall EncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile);
	virtual void __fastcall EncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
	virtual System::UnicodeString __fastcall EncryptString(const System::UnicodeString InString);
	virtual void __fastcall GenerateKey(const System::UnicodeString Passphrase);
	virtual void __fastcall GenerateRandomKey(void);
	void __fastcall GetKey(Lbcipher::TKey64 &Key);
	void __fastcall SetKey(const Lbcipher::TKey64 &Key);
	virtual unsigned __fastcall OutBufSizeNeeded(unsigned InBufSize);
	
__published:
	__property CipherMode;
public:
	/* TLBBaseComponent.Create */ inline __fastcall virtual TLbDES(System::Classes::TComponent* AOwner) : TLbSymmetricCipher(AOwner) { }
	
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TLbDES(void) { }
	
};


class PASCALIMPLEMENTATION TLb3DES : public TLbSymmetricCipher
{
	typedef TLbSymmetricCipher inherited;
	
private:
	Lbcipher::TKey128 FKey;
	
public:
	virtual void __fastcall DecryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile);
	virtual void __fastcall DecryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
	virtual System::UnicodeString __fastcall DecryptString(const System::UnicodeString InString);
	virtual void __fastcall EncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile);
	virtual void __fastcall EncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
	virtual System::UnicodeString __fastcall EncryptString(const System::UnicodeString InString);
	virtual void __fastcall GenerateKey(const System::UnicodeString Passphrase);
	virtual void __fastcall GenerateRandomKey(void);
	void __fastcall GetKey(Lbcipher::TKey128 &Key);
	void __fastcall SetKey(const Lbcipher::TKey128 &Key);
	virtual unsigned __fastcall OutBufSizeNeeded(unsigned InBufSize);
	
__published:
	__property CipherMode;
public:
	/* TLBBaseComponent.Create */ inline __fastcall virtual TLb3DES(System::Classes::TComponent* AOwner) : TLbSymmetricCipher(AOwner) { }
	
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TLb3DES(void) { }
	
};


enum DECLSPEC_DENUM TLbKeySizeRDL : unsigned char { ks128, ks192, ks256 };

class PASCALIMPLEMENTATION TLbRijndael : public TLbSymmetricCipher
{
	typedef TLbSymmetricCipher inherited;
	
private:
	static System::StaticArray<int, 3> RDLKeySizeMap;
	Lbcipher::TKey256 FKey;
	TLbKeySizeRDL FKeySize;
	int FKeySizeBytes;
	void __fastcall SetKeySize(TLbKeySizeRDL Value);
	
public:
	__fastcall virtual ~TLbRijndael(void);
	virtual void __fastcall DecryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile);
	virtual void __fastcall DecryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
	virtual System::UnicodeString __fastcall DecryptString(const System::UnicodeString InString);
	virtual void __fastcall EncryptFile(const System::UnicodeString InFile, const System::UnicodeString OutFile);
	virtual void __fastcall EncryptStream(System::Classes::TStream* InStream, System::Classes::TStream* OutStream);
	virtual System::UnicodeString __fastcall EncryptString(const System::UnicodeString InString);
	virtual void __fastcall GenerateKey(const System::UnicodeString Passphrase);
	virtual void __fastcall GenerateRandomKey(void);
	void __fastcall GetKey(void *Key);
	void __fastcall SetKey(const void *Key);
	virtual unsigned __fastcall OutBufSizeNeeded(unsigned InBufSize);
	
__published:
	__property CipherMode;
	__property TLbKeySizeRDL KeySize = {read=FKeySize, write=SetKeySize, nodefault};
public:
	/* TLBBaseComponent.Create */ inline __fastcall virtual TLbRijndael(System::Classes::TComponent* AOwner) : TLbSymmetricCipher(AOwner) { }
	
};


class PASCALIMPLEMENTATION TLbHash : public TLBBaseComponent
{
	typedef TLBBaseComponent inherited;
	
private:
	System::StaticArray<System::Byte, 1024> FBuf;
	
public:
	virtual void __fastcall HashBuffer(const void *Buf, unsigned BufSize) = 0 ;
	virtual void __fastcall HashFile(const System::UnicodeString AFileName) = 0 ;
	virtual void __fastcall HashStream(System::Classes::TStream* AStream) = 0 ;
	virtual void __fastcall HashString(const System::UnicodeString AStr) = 0 ;
public:
	/* TLBBaseComponent.Create */ inline __fastcall virtual TLbHash(System::Classes::TComponent* AOwner) : TLBBaseComponent(AOwner) { }
	
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TLbHash(void) { }
	
};


class PASCALIMPLEMENTATION TLbMD5 : public TLbHash
{
	typedef TLbHash inherited;
	
private:
	Lbcipher::TMD5Digest FDigest;
	
public:
	void __fastcall GetDigest(Lbcipher::TMD5Digest &Digest);
	virtual void __fastcall HashBuffer(const void *Buf, unsigned BufSize);
	virtual void __fastcall HashFile(const System::UnicodeString AFileName);
	virtual void __fastcall HashStream(System::Classes::TStream* AStream);
	virtual void __fastcall HashString(const System::UnicodeString AStr);
public:
	/* TLBBaseComponent.Create */ inline __fastcall virtual TLbMD5(System::Classes::TComponent* AOwner) : TLbHash(AOwner) { }
	
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TLbMD5(void) { }
	
};


class PASCALIMPLEMENTATION TLbSHA1 : public TLbHash
{
	typedef TLbHash inherited;
	
private:
	Lbcipher::TSHA1Digest FDigest;
	
public:
	void __fastcall GetDigest(Lbcipher::TSHA1Digest &Digest);
	virtual void __fastcall HashBuffer(const void *Buf, unsigned BufSize);
	virtual void __fastcall HashFile(const System::UnicodeString AFileName);
	virtual void __fastcall HashStream(System::Classes::TStream* AStream);
	virtual void __fastcall HashString(const System::UnicodeString AStr);
public:
	/* TLBBaseComponent.Create */ inline __fastcall virtual TLbSHA1(System::Classes::TComponent* AOwner) : TLbHash(AOwner) { }
	
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TLbSHA1(void) { }
	
};


#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbSCStream : public System::Classes::TMemoryStream
{
	typedef System::Classes::TMemoryStream inherited;
	
private:
	Lbcipher::TLSCContext FContext;
	
public:
	__fastcall TLbSCStream(const void *Key, int KeySize);
	virtual void __fastcall Reinitialize(const void *Key, int KeySize);
	virtual void __fastcall ChangeKey(const void *Key, int KeySize);
	virtual int __fastcall Read(void *Buffer, int Count)/* overload */;
	virtual int __fastcall Write(const void *Buffer, int Count)/* overload */;
public:
	/* TMemoryStream.Destroy */ inline __fastcall virtual ~TLbSCStream(void) { }
	
	/* Hoisted overloads: */
	
public:
	inline int __fastcall  Read(System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::TCustomMemoryStream::Read(Buffer, Offset, Count); }
	inline int __fastcall  Read(System::TArray__1<System::Byte> &Buffer, int Count){ return System::Classes::TStream::Read(Buffer, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::TMemoryStream::Write(Buffer, Offset, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Count){ return System::Classes::TStream::Write(Buffer, Count); }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbSCFileStream : public System::Classes::TFileStream
{
	typedef System::Classes::TFileStream inherited;
	
private:
	Lbcipher::TLSCContext FContext;
	
public:
	__fastcall TLbSCFileStream(const System::UnicodeString FileName, System::Word Mode, const void *Key, int KeySize);
	virtual void __fastcall Reinitialize(const void *Key, int KeySize);
	virtual void __fastcall ChangeKey(const void *Key, int KeySize);
	virtual int __fastcall Read(void *Buffer, int Count)/* overload */;
	virtual int __fastcall Write(const void *Buffer, int Count)/* overload */;
public:
	/* TFileStream.Destroy */ inline __fastcall virtual ~TLbSCFileStream(void) { }
	
	/* Hoisted overloads: */
	
public:
	inline int __fastcall  Read(System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::THandleStream::Read(Buffer, Offset, Count); }
	inline int __fastcall  Read(System::TArray__1<System::Byte> &Buffer, int Count){ return System::Classes::TStream::Read(Buffer, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::THandleStream::Write(Buffer, Offset, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Count){ return System::Classes::TStream::Write(Buffer, Count); }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbRNG32Stream : public System::Classes::TMemoryStream
{
	typedef System::Classes::TMemoryStream inherited;
	
private:
	Lbcipher::TRNG32Context FContext;
	
public:
	__fastcall TLbRNG32Stream(const int Key);
	virtual void __fastcall Reinitialize(const int Key);
	virtual void __fastcall ChangeKey(const int Key);
	virtual int __fastcall Read(void *Buffer, int Count)/* overload */;
	virtual int __fastcall Write(const void *Buffer, int Count)/* overload */;
public:
	/* TMemoryStream.Destroy */ inline __fastcall virtual ~TLbRNG32Stream(void) { }
	
	/* Hoisted overloads: */
	
public:
	inline int __fastcall  Read(System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::TCustomMemoryStream::Read(Buffer, Offset, Count); }
	inline int __fastcall  Read(System::TArray__1<System::Byte> &Buffer, int Count){ return System::Classes::TStream::Read(Buffer, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::TMemoryStream::Write(Buffer, Offset, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Count){ return System::Classes::TStream::Write(Buffer, Count); }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbRNG32FileStream : public System::Classes::TFileStream
{
	typedef System::Classes::TFileStream inherited;
	
private:
	Lbcipher::TRNG32Context FContext;
	
public:
	__fastcall TLbRNG32FileStream(const System::UnicodeString FileName, System::Word Mode, const int Key);
	virtual void __fastcall Reinitialize(const int Key);
	virtual void __fastcall ChangeKey(const int Key);
	virtual int __fastcall Read(void *Buffer, int Count)/* overload */;
	virtual int __fastcall Write(const void *Buffer, int Count)/* overload */;
public:
	/* TFileStream.Destroy */ inline __fastcall virtual ~TLbRNG32FileStream(void) { }
	
	/* Hoisted overloads: */
	
public:
	inline int __fastcall  Read(System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::THandleStream::Read(Buffer, Offset, Count); }
	inline int __fastcall  Read(System::TArray__1<System::Byte> &Buffer, int Count){ return System::Classes::TStream::Read(Buffer, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::THandleStream::Write(Buffer, Offset, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Count){ return System::Classes::TStream::Write(Buffer, Count); }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbRNG64Stream : public System::Classes::TMemoryStream
{
	typedef System::Classes::TMemoryStream inherited;
	
private:
	Lbcipher::TRNG64Context FContext;
	
public:
	__fastcall TLbRNG64Stream(const int KeyHi, const int KeyLo);
	virtual void __fastcall Reinitialize(const int KeyHi, const int KeyLo);
	virtual void __fastcall ChangeKey(const int KeyHi, const int KeyLo);
	virtual int __fastcall Read(void *Buffer, int Count)/* overload */;
	virtual int __fastcall Write(const void *Buffer, int Count)/* overload */;
public:
	/* TMemoryStream.Destroy */ inline __fastcall virtual ~TLbRNG64Stream(void) { }
	
	/* Hoisted overloads: */
	
public:
	inline int __fastcall  Read(System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::TCustomMemoryStream::Read(Buffer, Offset, Count); }
	inline int __fastcall  Read(System::TArray__1<System::Byte> &Buffer, int Count){ return System::Classes::TStream::Read(Buffer, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::TMemoryStream::Write(Buffer, Offset, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Count){ return System::Classes::TStream::Write(Buffer, Count); }
	
};

#pragma pack(pop)

#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbRNG64FileStream : public System::Classes::TFileStream
{
	typedef System::Classes::TFileStream inherited;
	
private:
	Lbcipher::TRNG64Context FContext;
	
public:
	__fastcall TLbRNG64FileStream(const System::UnicodeString FileName, System::Word Mode, const int KeyHi, const int KeyLo);
	virtual void __fastcall Reinitialize(const int KeyHi, const int KeyLo);
	virtual void __fastcall ChangeKey(const int KeyHi, const int KeyLo);
	virtual int __fastcall Read(void *Buffer, int Count)/* overload */;
	virtual int __fastcall Write(const void *Buffer, int Count)/* overload */;
public:
	/* TFileStream.Destroy */ inline __fastcall virtual ~TLbRNG64FileStream(void) { }
	
	/* Hoisted overloads: */
	
public:
	inline int __fastcall  Read(System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::THandleStream::Read(Buffer, Offset, Count); }
	inline int __fastcall  Read(System::TArray__1<System::Byte> &Buffer, int Count){ return System::Classes::TStream::Read(Buffer, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Offset, int Count){ return System::Classes::THandleStream::Write(Buffer, Offset, Count); }
	inline int __fastcall  Write(const System::TArray__1<System::Byte> Buffer, int Count){ return System::Classes::TStream::Write(Buffer, Count); }
	
};

#pragma pack(pop)

//-- var, const, procedure ---------------------------------------------------
}	/* namespace Lbclass */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBCLASS)
using namespace Lbclass;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// LbclassHPP
