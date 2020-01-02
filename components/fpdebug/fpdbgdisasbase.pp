{ $Id$ }
{
 ---------------------------------------------------------------------------
 fpdbgdisasbase.pp  -  Native Freepascal debugger - Disassembler base class
 ---------------------------------------------------------------------------

 This unit contains a base class disassembler for the Native Freepascal debugger

 ---------------------------------------------------------------------------

 @created()
 @lastmod($Date$)
 @author()

 ***************************************************************************
 *                                                                         *
 *   This source is free software; you can redistribute it and/or modify   *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This code is distributed in the hope that it will be useful, but      *
 *   WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     *
 *   General Public License for more details.                              *
 *                                                                         *
 *   A copy of the GNU General Public License is available on the World    *
 *   Wide Web at <http://www.gnu.org/copyleft/gpl.html>. You can also      *
 *   obtain it by writing to the Free Software Foundation,                 *
 *   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1335, USA.   *
 *                                                                         *
 ***************************************************************************
}
unit FpDbgDisasBase;
{$mode objfpc}{$H+}
interface

{.$define debug_OperandSize}
{.$define verbose_string_instructions}

uses
  SysUtils,
  FpDbgUtil, FpDbgInfo, DbgIntfBaseTypes, LazLoggerBase, FpDbgCommon;

type
  TGenericOpCode = (OPG_InternalUnknown, OPG_Invalid, OPG_Call, OPG_Ret, OPG_Mov, OPG_Other);

  TGenericOperand = record
    Value: string;
  end;

  TGenericInstruction = record
    OpCode: TGenericOpCode;
    Operand: array[1..4] of TGenericOperand;
    OperCnt: Integer;
  end;

  { TDisassembler }

  TDisassembler = class
  protected
    // Size of largest opcode, used to overestimate buffer required for disassembling
    FMaxInstructionSize: integer;
    FTarget: TTargetDescriptor;
  public
    procedure Disassemble(var AAddress: Pointer; out ACodeBytes: String; out ACode: String); virtual; abstract;
    procedure Disassemble(var AAddress: Pointer; out AnInstruction: TGenericInstruction); virtual; abstract;
    function IsCallInstruction(AAddress: Pointer): Integer; virtual; abstract;
    function GetFunctionFrameInfo(AData: PByte; ADataLen: Cardinal;
      out AnIsOutsideFrame: Boolean): Boolean; virtual; abstract;
    function IsReturnInstruction(AAddress: Pointer): Integer; virtual; abstract;

    class function isSupported(ATarget: TTargetDescriptor): boolean; virtual;

    property MaxInstructionSize: integer read FMaxInstructionSize;
    property Target: TTargetDescriptor read FTarget write FTarget;
  end;
  TDisassemblerClass = class of TDisassembler;


  function GetDisassemblerInstance(target: TTargetDescriptor): TDisassembler;
  procedure RegisterDisassemblerClass(ADisassembler: TDisassemblerClass);

implementation

uses
  Classes, FpDbgClasses;

var
  RegisteredDisassemblerClasses: TFPList;

function GetDisassemblerInstance(target: TTargetDescriptor): TDisassembler;
var
  i   : Integer;
  cls : TDisassemblerClass;
begin
  Result := nil;
  // Only one instance allowed at a time, so free previous instance
  if assigned(GDisassembler) then
    FreeAndNil(GDisassembler);

  for i := 0 to RegisteredDisassemblerClasses.Count - 1 do
  begin
    cls :=  TDisassemblerClass(RegisteredDisassemblerClasses[i]);
    try
      if cls.isSupported(target) then
      begin
        Result := cls.Create();
        Exit;
      end;
    except
      on e: exception do
      begin
        //writeln('exception! WHY? ', e.Message);
      end;
    end;
  end;
end;

procedure RegisterDisassemblerClass(ADisassembler: TDisassemblerClass);
begin
  if Assigned(ADisassembler) and (RegisteredDisassemblerClasses.IndexOf(ADisassembler) < 0) then
    RegisteredDisassemblerClasses.Add(ADisassembler)
end;

{ TDisassembler }

class function TDisassembler.isSupported(ATarget: TTargetDescriptor): boolean;
begin
  result := false;
end;

initialization
  RegisteredDisassemblerClasses := TFPList.Create;

finalization
  FreeAndNil(RegisteredDisassemblerClasses);

end.
