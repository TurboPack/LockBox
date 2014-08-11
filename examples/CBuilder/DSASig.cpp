//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop
USERES("DSASig.res");
USEFORM("DSASig1.cpp", frmDSASig);
USEFORM("DSASig2.cpp", dlgKeySize);
//---------------------------------------------------------------------------
WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    try
    {
        Application->Initialize();
        Application->CreateForm(__classid(TfrmDSASig), &frmDSASig);
        Application->CreateForm(__classid(TdlgKeySize), &dlgKeySize);
        Application->Run();
    }
    catch (Exception &exception)
    {
        Application->ShowException(&exception);
    }
    return 0;
}
//---------------------------------------------------------------------------
