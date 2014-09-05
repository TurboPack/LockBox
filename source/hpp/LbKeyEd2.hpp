// CodeGear C++Builder
// Copyright (c) 1995, 2014 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'LbKeyEd2.pas' rev: 28.00 (Windows)

#ifndef Lbkeyed2HPP
#define Lbkeyed2HPP

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

namespace Lbkeyed2
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TfrmRSAKeys;
class PASCALIMPLEMENTATION TfrmRSAKeys : public Vcl::Forms::TForm
{
	typedef Vcl::Forms::TForm inherited;
	
__published:
	Vcl::Stdctrls::TButton* btnClose;
	Vcl::Stdctrls::TLabel* Label4;
	Vcl::Stdctrls::TEdit* edtModulus;
	Vcl::Stdctrls::TLabel* Label5;
	Vcl::Stdctrls::TEdit* edtPublicExponent;
	Vcl::Stdctrls::TLabel* Label6;
	Vcl::Stdctrls::TEdit* edtPrivateExponent;
	Vcl::Extctrls::TBevel* Bevel1;
	Vcl::Comctrls::TStatusBar* StatusBar1;
	Vcl::Stdctrls::TLabel* Label9;
	Vcl::Stdctrls::TComboBox* cbxKeySize;
	Vcl::Stdctrls::TLabel* Label1;
	Vcl::Stdctrls::TLabel* Label8;
	Vcl::Stdctrls::TEdit* edtIterations;
	Vcl::Stdctrls::TButton* btnGenerate;
	Vcl::Stdctrls::TButton* btnClear;
	void __fastcall btnGenRSAKeysClick(System::TObject* Sender);
	void __fastcall FormCreate(System::TObject* Sender);
	void __fastcall btnCloseClick(System::TObject* Sender);
	void __fastcall btnClearClick(System::TObject* Sender);
	
private:
	bool FAbort;
	void __fastcall RSACallback(bool &Abort);
public:
	/* TCustomForm.Create */ inline __fastcall virtual TfrmRSAKeys(System::Classes::TComponent* AOwner) : Vcl::Forms::TForm(AOwner) { }
	/* TCustomForm.CreateNew */ inline __fastcall virtual TfrmRSAKeys(System::Classes::TComponent* AOwner, int Dummy) : Vcl::Forms::TForm(AOwner, Dummy) { }
	/* TCustomForm.Destroy */ inline __fastcall virtual ~TfrmRSAKeys(void) { }
	
public:
	/* TWinControl.CreateParented */ inline __fastcall TfrmRSAKeys(HWND ParentWindow) : Vcl::Forms::TForm(ParentWindow) { }
	
};


class DELPHICLASS TLbRSAKeyEditor;
#pragma pack(push,4)
class PASCALIMPLEMENTATION TLbRSAKeyEditor : public Designeditors::TDefaultEditor
{
	typedef Designeditors::TDefaultEditor inherited;
	
public:
	virtual void __fastcall ExecuteVerb(int Index);
	virtual System::UnicodeString __fastcall GetVerb(int Index);
	virtual int __fastcall GetVerbCount(void);
public:
	/* TComponentEditor.Create */ inline __fastcall virtual TLbRSAKeyEditor(System::Classes::TComponent* AComponent, Designintf::_di_IDesigner ADesigner) : Designeditors::TDefaultEditor(AComponent, ADesigner) { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TLbRSAKeyEditor(void) { }
	
};

#pragma pack(pop)

//-- var, const, procedure ---------------------------------------------------
}	/* namespace Lbkeyed2 */
#if !defined(DELPHIHEADER_NO_IMPLICIT_NAMESPACE_USE) && !defined(NO_USING_NAMESPACE_LBKEYED2)
using namespace Lbkeyed2;
#endif
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Lbkeyed2HPP
