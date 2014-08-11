//---------------------------------------------------------------------------
#ifndef DSASig2H
#define DSASig2H
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
//---------------------------------------------------------------------------
class TdlgKeySize : public TForm
{
__published:	// IDE-managed Components
    TLabel *Label9;
    TLabel *Label8;
    TLabel *Label5;
    TComboBox *cbxKeySize;
    TComboBox *cbxIterations;
    TButton *btnOK;
    TButton *btnCancel;
private:	// User declarations
public:		// User declarations
    __fastcall TdlgKeySize(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TdlgKeySize *dlgKeySize;
//---------------------------------------------------------------------------
#endif
