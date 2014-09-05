// CodeGear C++Builder
// Copyright (c) 1995, 2014 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbKeyEd1.pas' rev: 28.00 (Windows)

#ifndef Lbkeyed1HPP
#define Lbkeyed1HPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member 
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <SysInit.hpp>	// Pascal unit
#include <Winapi.Windows.hpp>	// Pascal unit
#include <Vcl.Controls.hpp>	// Pascal unit
#include <Vcl.Forms.hpp>	// Pascal unit
#include <Vcl.Dialogs.hpp>	// Pascal unit
#include <Vcl.Graphics.hpp>	// Pascal unit
#include <Vcl.Buttons.hpp>	// Pascal unit
#include <Vcl.ExtCtrls.hpp>	// Pascal unit
#include <Vcl.StdCtrls.hpp>	// Pascal unit
#include <Vcl.ComCtrls.hpp>	// Pascal unit
#include <Vcl.TabNotBk.hpp>	// Pascal unit
#include <DesignIntf.hpp>	// Pascal unit
#include <DesignEditors.hpp>	// Pascal unit
#include <System.SysUtils.hpp>	// Pascal unit
#include <System.Classes.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Lbkeyed1
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TfrmSymmetricKey;
class PASCALIMPLEMENTATION TfrmSymmetricKey : public Vcl::Forms::TForm
{
	typedef Vcl::Forms::TForm inherited;
	
__published:
	Vcl::Stdctrls::TButton* btnClose;
	Vcl::Stdctrls::TLabel* Label2;
	Vcl::Stdctrls::TLabel* Label3;
	Vcl::Stdctrls::TEdit* edtKey;
	Vcl::Extctrls::TBevel* Bevel1;
	Vcl::Stdctrls::TLabel* Label9;
	Vcl::Stdctrls::TComboBox* cbxKeySize;
	Vcl::Stdctrls::TLabel* Label1;
	Vcl::Stdctrls::TComboBox* cbxKeyType;
	Vcl::Stdctrls::TButton* btnGenerate;
	Vcl::Stdctrls::TEdit* edtPassphrase;
	void __fastcall FormCreate(System::TObject* Sender);
	void __fastcall btnGenerateClick(System::TObject* Sender);
	void __fastcall rgKeyTypeChange(System::TObject* Sender);
	void __fastcall rgKeySizeChange(System::TObject* Sender);
	void __fastcall edtPassphraseChange(System::TObject* Sender);
public:
	/* TCustomForm.Create */ inline __fastcall virtual TfrmSymmetricKey(System::Classes::TComponent* AOwner) : Vcl::Forms::TForm(AOwner) { }
	/* TCustomForm.CreateNew */ inline __fastcall virtual TfrmSymmetricKey(System::Classes::TComponent* AOwner, int Dummy) : Vcl::Forms::TForm(AOwner, Dummy) { }
	/* TCustomForm.Destroy */ inline __fastcall virtual ~TfrmSymmetricKey(void) { }
	
public:
	/* TWinControl.CreateParented */ inline __fastcall TfrmSymmetricKey(HWND ParentWindow) : Vcl::Forms::TForm(ParentWindow) { }
	
};


class DELPHICLASS TLbSymmetricKeyEditor;
#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbSymmetricKeyEditor : public Designeditors::TDefaultEditor
{
	typedef Designeditors::TDefaultEditor inherited;
	
public:
	virtual void __fastcall ExecuteVerb(int Index);
	virtual System::UnicodeString __fastcall GetVerb(int Index);
	virtual int __fastcall GetVerbCount(void);
public:
	/* TComponentEditor.Create */ inline __fastcall virtual TLbSymmetricKeyEditor(System::Classes::TComponent* AComponent, Designintf::_di_IDesigner ADesigner) : Designeditors::TDefaultEditor(AComponent, ADesigner) { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TLbSymmetricKeyEditor(void) { }
	
};

#pragma pack(pop)

//-- var, const, procedure ---------------------------------------------------
}	/* namespace Lbkeyed1 */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBKEYED1)
using namespace Lbkeyed1;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Lbkeyed1HPP
