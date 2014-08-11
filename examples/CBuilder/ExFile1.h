//---------------------------------------------------------------------------
#ifndef ExFile1H
#define ExFile1H
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include <Buttons.hpp>
#include <Dialogs.hpp>
#include <LbCipher.hpp>
#include <LbProc.hpp>
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
    TLabel *Label4;
    TSpeedButton *SpeedButton1;
    TSpeedButton *SpeedButton2;
    TLabel *Label1;
    TLabel *Label2;
    TLabel *Label3;
    TButton *btnGo;
    TComboBox *cbxCipher;
    TEdit *edtInFile;
    TEdit *edtOutFile;
    TCheckBox *chkEncrypt;
    TEdit *edtPassphrase;
    TOpenDialog *OpenDialog1;
    TSaveDialog *SaveDialog1;
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall btnGoClick(TObject *Sender);
    void __fastcall SpeedButton1Click(TObject *Sender);
    void __fastcall SpeedButton2Click(TObject *Sender);
private:	// User declarations
public:		// User declarations
    __fastcall TForm1(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif
