program RSAKeys;

uses
{$IFDEF WIN32}
  Forms,
{$ENDIF}
{$IFDEF LINUX}
  QForms,
{$ENDIF}
  RSAKeys1 in 'RSAKeys1.pas' {Form1},

{$IFDEF WIN32}
  LbUtils in '..\..\LbUtils.pas';
{$ENDIF}
{$IFDEF LINUX}
  LbUtils in '../../LbUtils.pas';
{$ENDIF}

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
