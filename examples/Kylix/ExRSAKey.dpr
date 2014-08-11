program ExRSAKey;

uses
{$IFDEF WIN32}
  Forms,
{$ENDIF}
{$IFDEF LINUX}
  QForms,
{$ENDIF}
  ExRSAKe1 in 'ExRSAKe1.pas' {Form1},
  LbUtils in '../../LbUtils.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
