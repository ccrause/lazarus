{
    This file is part of the Free Component Library.
    Copyright (c) 2017 Michael Van Canneyt, member of the Free Pascal development team

    Report data component property editor for object inspector.

    See the file COPYING.FPC, included in this distribution,
    for details about the copyright.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

 **********************************************************************}
unit regfpdesigner;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fpreport, ideintf, propedits, ObjInspStrConsts, frmfpreportmemoedit;

Type

  { TPaperNamePropertyEditor }

  TPaperNamePropertyEditor = class(TStringPropertyEditor)
  Protected
    procedure GetValues(Proc: TGetStrProc); override;
    Function GetAttributes: TPropertyAttributes; override;
  end;


  { TReportComponentPropertyEditor }

  TReportComponentPropertyEditor = class(TComponentPropertyEditor)
  Protected
    Function GetReport : TFPCustomReport;
    Function GetPage : TFPReportCustomPage;
  end;

  { TDataComponentPropertyEditor }

  TDataComponentPropertyEditor = class(TReportComponentPropertyEditor)
  Public
    procedure GetValues(Proc: TGetStrProc); override;
    procedure SetValue(const NewValue: ansistring); override;
  end;

  { TReportBandPropertyEditor }

  TReportBandPropertyEditor = class(TReportComponentPropertyEditor)
  Public
    Function BandTypes : TFPReportBandTypes; virtual;
    procedure GetValues(Proc: TGetStrProc); override;
    procedure SetValue(const NewValue: ansistring); override;
  end;

  { TChildBandPropertyEditor }

  TChildBandPropertyEditor = Class(TReportBandPropertyEditor)
  Public
    Function BandTypes : TFPReportBandTypes; override;
  end;

  { TDataFooterBandPropertyEditor }

  TDataFooterBandPropertyEditor = Class(TReportBandPropertyEditor)
  Public
    Function BandTypes : TFPReportBandTypes; override;
  end;

  { TDataHeaderBandPropertyEditor }

  TDataHeaderBandPropertyEditor = Class(TReportBandPropertyEditor)
  Public
    Function BandTypes : TFPReportBandTypes; override;
  end;

  { TDataBandPropertyEditor }

  TDataBandPropertyEditor = Class(TReportBandPropertyEditor)
  Public
    Function BandTypes : TFPReportBandTypes; override;
  end;

  { TGroupHeaderBandPropertyEditor }

  TGroupHeaderBandPropertyEditor = Class(TReportBandPropertyEditor)
  Public
    Function BandTypes : TFPReportBandTypes; override;
  end;

  { TGroupFooterBandPropertyEditor }

  TGroupFooterBandPropertyEditor = Class(TReportBandPropertyEditor)
  Public
    Function BandTypes : TFPReportBandTypes; override;
  end;


Procedure RegisterFPReportPropEditors;

implementation

Procedure RegisterFPReportPropEditors;

begin
  RegisterPropertyEditor(TypeInfo(TFPReportData), TFPreportElement, 'Data', TDataComponentPropertyEditor);
  RegisterPropertyEditor(TypeInfo(TFPReportCustomBand), TFPReportCustomBand, 'Child', TChildBandPropertyEditor);
  RegisterPropertyEditor(TypeInfo(TFPReportCustomDataFooterBand), TFPReportCustomBand, 'FooterBand', TDataFooterBandPropertyEditor);
  RegisterPropertyEditor(TypeInfo(TFPReportCustomDataHeaderBand), TFPReportCustomBand, 'HeaderBand', TDataHeaderBandPropertyEditor);
  RegisterPropertyEditor(TypeInfo(TFPReportCustomDataBand), TFPReportCustomBand, 'MasterBand', TDataBandPropertyEditor);
  RegisterPropertyEditor(TypeInfo(TFPReportCustomGroupHeaderBand),TFPReportCustomGroupHeaderBand, 'ParentGroupHeader', TGroupHeaderBandPropertyEditor);
  RegisterPropertyEditor(TypeInfo(TFPReportCustomGroupFooterBand),TFPReportCustomGroupHeaderBand, 'GroupFooter', TGroupFooterBandPropertyEditor);
  RegisterPropertyEditor(TypeInfo(String),TFPReportPageSize,'PaperName',TPaperNamePropertyEditor);
end;

{ TPaperNamePropertyEditor }

procedure TPaperNamePropertyEditor.GetValues(Proc: TGetStrProc);

Var
  I : integer;

begin
  for I:=0 to PaperManager.PaperCount-1 do
    Proc(PaperManager.PaperNames[i]);
end;

function TPaperNamePropertyEditor.GetAttributes: TPropertyAttributes;
begin
  Result:=[paValueList, paPickList, paAutoUpdate, paSortList];
end;

{ TGroupFooterBandPropertyEditor }

function TGroupFooterBandPropertyEditor.BandTypes: TFPReportBandTypes;
begin
  Result:=[btGroupFooter];
end;

{ TGroupHeaderBandPropertyEditor }

function TGroupHeaderBandPropertyEditor.BandTypes: TFPReportBandTypes;
begin
  Result:=[btGroupHeader];
end;

{ TDataBandPropertyEditor }

function TDataBandPropertyEditor.BandTypes: TFPReportBandTypes;
begin
  Result:=[btDataband];
end;

{ TDataHeaderBandPropertyEditor }

function TDataHeaderBandPropertyEditor.BandTypes: TFPReportBandTypes;
begin
  Result:=[btDataHeader];
end;

{ TDataFooterBandPropertyEditor }

function TDataFooterBandPropertyEditor.BandTypes: TFPReportBandTypes;
begin
  Result:=[btDataFooter];
end;

{ TChildBandPropertyEditor }

function TChildBandPropertyEditor.BandTypes: TFPReportBandTypes;
begin
  Result:=[btChild];
end;

{ TReportBandPropertyEditor }

function TReportBandPropertyEditor.BandTypes: TFPReportBandTypes;
begin
  Result:=[]
end;

procedure TReportBandPropertyEditor.GetValues(Proc: TGetStrProc);

Var
  P : TFPReportCustomPage;
  I : Integer;
  BT : TFPReportBandTypes;

  Function BandAllowed(B : TFPReportCustomBand) : Boolean;

  begin
    Result:=(B.Name<>'');
    if Result and (BT<>[]) then
      Result:=B.ReportBandType in BT;
  end;

begin
  P:=GetPage;
  BT:=BandTypes;
  proc(oisNone);
  if Assigned(P) then
    For I:=0 to P.BandCount-1 do
      if BandAllowed(P.Bands[i]) then
        Proc(P.Bands[i].Name);
end;

procedure TReportBandPropertyEditor.SetValue(const NewValue: ansistring);

Var
  P : TFPReportCustomPage;
  B : TFPReportCustomBand;
  I : integer;

begin
  B:=nil;
  if (NewValue<>oisNone) then
    begin
    P:=GetPage;
    I:=0;
    if Assigned(P) then
      While (B=Nil) and (I<P.BandCount) do
        begin
        if SameText(NewValue,P.Bands[I].Name) then
          B:=P.Bands[I];
        Inc(I);
        end;
    end;
  if Assigned(PropertyHook) then
    PropertyHook.ObjectReferenceChanged(Self,B);
  SetPtrValue(B);
end;

{ TReportComponentPropertyEditor }

Function TReportComponentPropertyEditor.GetPage : TFPReportCustomPage;

Var
  C : TPersistent;
begin
  Result:=Nil;
  C:=GetComponent(0);
  // Latest SVN has page
  if C is TFPReportCustomPage then
    Result:=C as TFPReportCustomPage
  else if C is TFPReportCustomBand then
    Result:=TFPReportCustomBand(C).Page
  else if C is TFPReportElement then
    Result:=TFPReportElement(C).Page;
end;

function TReportComponentPropertyEditor.GetReport: TFPCustomReport;
Var
  C : TPersistent;
begin
  Result:=Nil;
  C:=GetComponent(0);
  if C is TFPCustomReport then
    Result:=C as TFPCustomReport
  else if C is TFPReportElement then
    Result:=TFPReportElement(C).Report;
end;

{ TDataComponentPropertyEditor }

procedure TDataComponentPropertyEditor.GetValues(Proc: TGetStrProc);

Var
  Report : TFPCustomReport;
  I : Integer;

begin
  Report:=GetReport;
  proc(oisNone);
  if Assigned(Report) then
    For I:=0 to Report.ReportData.Count-1 do
      Proc(Report.ReportData[i].Data.Name);
end;

procedure TDataComponentPropertyEditor.SetValue(const NewValue: ansistring);

Var
  Report:TFPCustomReport;
  RD : TFPReportData;

begin
  RD:=nil;
  if (NewValue<>oisNone) then
    begin
    Report:=GetReport;
    if Assigned(Report) then
      RD:=Report.ReportData.FindReportData(NewValue);
    end;
  if Assigned(PropertyHook) then
    PropertyHook.ObjectReferenceChanged(Self,RD);
  SetPtrValue(RD);
end;

end.

