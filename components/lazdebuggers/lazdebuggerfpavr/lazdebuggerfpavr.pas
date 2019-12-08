{ This file was automatically created by Lazarus. Do not edit!
  This source is only used to compile and install the package.
 }

unit lazdebuggerfpavr;

{$warn 5023 off : no warning about unused units}
interface

uses
  FpDebugDebuggerAvr, LazarusPackageIntf;

implementation

procedure Register;
begin
  RegisterUnit('FpDebugDebuggerAvr', @FpDebugDebuggerAvr.Register);
end;

initialization
  RegisterPackage('lazdebuggerfpavr', @Register);
end.
