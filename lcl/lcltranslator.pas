unit LCLTranslator;

{ Copyright (C) 2004-2015 V.I.Volchenko and Lazarus Developers Team

  This library is free software; you can redistribute it and/or modify it
  under the terms of the GNU Library General Public License as published by
  the Free Software Foundation; either version 2 of the License, or (at your
  option) any later version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Library General Public License
  for more details.

  You should have received a copy of the GNU Library General Public License
  along with this library; if not, write to the Free Software Foundation,
  Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1335, USA.
}
{
This unit is needed for using translated form strings made by Lazarus IDE.
It searches for translated .po/.mo files in some common places. If you need
to have .po/.mo files anywhere else, don't use this unit but initialize
LRSMoFile variable from LResources in your project by yourself.

If you need standard translation, just use this unit in your project and enable
i18n in project options. Note that you will have to call SetDefaultLang manually.
If you want it to be called automatically, use DefaultTranslator unit instead.

Another reason for including this unit may be using translated LCL messages.
This unit localizes LCL too, if it finds lclstrconsts.xx.po/lclstrconsts.xx.mo
in directory where your program translation files are placed.
}
{$mode objfpc}{$H+}

interface

uses
  // RTL + FCL
  Classes, SysUtils, typinfo, GetText,
  // LCL
  LResources, Forms, LCLType,
  // LazUtils
  {$IFDEF VerbosePOTranslator}
  LazLoggerBase,
  {$ENDIF}
  Translations, LazFileUtils, LazUTF8;

type

  { TUpdateTranslator }

  TUpdateTranslator = class(TAbstractTranslator)
  private
    FStackPath: string;
    procedure IntUpdateTranslation(AnInstance: TPersistent; Level: integer = 0);
  public
    procedure UpdateTranslation(AnInstance: TPersistent);
  end;

  TDefaultTranslator = class(TUpdateTranslator)
  private
    FMOFile: TMOFile;
  public
    constructor Create(MOFileName: string);
    destructor Destroy; override;
    procedure TranslateStringProperty(Sender: TObject; const Instance: TPersistent;
      PropInfo: PPropInfo; var Content: string); override;
  end;

  { TPOTranslator }

  TPOTranslator = class(TUpdateTranslator)
  private
    FPOFile: TPOFile;
  public
    constructor Create(POFileName: string);
    constructor Create(aPOFile: TPOFile);
    destructor Destroy; override;
    procedure TranslateStringProperty(Sender: TObject; const Instance: TPersistent;
      PropInfo: PPropInfo; var Content: string); override;
  end;

procedure TranslateLCLResourceStrings(Lang, Dir: string);
procedure SetDefaultLang(Lang: string; Dir: string = ''; LocaleFileName: string = ''; ForceUpdate: boolean = true);
function GetDefaultLang: String;

implementation


type
  TPersistentAccess = class(TPersistent);

var
  DefaultLang: String = '';

procedure FindLang(var Lang: string);
var
  T, CurParam: string;
  i: integer;
begin
  if Lang = '' then
    for i := 1 to ParamCount do
    begin
      CurParam := ParamStrUTF8(i);
      if (CurParam = '-l') or (UTF8LowerCase(CurParam) = '--lang') then
      begin
        if i < ParamCount then
          Lang := ParamStrUTF8(i + 1);
      end
      else
        if UTF8StartsText('--lang=', CurParam) then
        begin
          Lang := CurParam;
          UTF8Delete(Lang, 1, Length('--lang='));
        end;
    end;

  //User can decide to override locale with LANG variable.
  if Lang = '' then
    Lang := GetEnvironmentVariableUTF8('LANG');

  if Lang = '' then
    LazGetLanguageIDs(Lang, T);
end;

function FindLocaleFileName(LCExt: string; LangID: string; Dir: string; LocaleFileName: string): string;
var
  LangShortID: string;
  AppDir,LCFileName,FullLCFileName: String;
  absoluteDir: Boolean;

  function GetLCFileName: string;
  begin
    if LocaleFileName = '' then
      Result := ExtractFileName(ParamStrUTF8(0))
    else
      Result := LocaleFileName;
  end;

begin
  Result := '';
  FindLang(LangID);

  DefaultLang := LangID;

  AppDir := ExtractFilePath(ParamStrUTF8(0));
  LCFileName := ChangeFileExt(GetLCFileName, LCExt);

  if LangID <> '' then
  begin
    FullLCFileName := ChangeFileExt(GetLCFileName, '.' + LangID) + LCExt;

    if Dir<>'' then
    begin
      Dir := AppendPathDelim(Dir);
      absoluteDir := FilenameIsAbsolute(Dir);
      if absoluteDir then
        Result := Dir + LangID + DirectorySeparator + LCFileName
      else
        Result := AppDir + Dir + LangID + DirectorySeparator + LCFileName;
      if FileExistsUTF8(Result) then
        exit;
    end;

    //ParamStrUTF8(0) is said not to work properly in linux, but I've tested it
    Result := AppDir + LangID + DirectorySeparator + LCFileName;
    if FileExistsUTF8(Result) then
      exit;

    Result := AppDir + 'languages' + DirectorySeparator + LangID +
      DirectorySeparator + LCFileName;
    if FileExistsUTF8(Result) then
      exit;

    Result := AppDir + 'locale' + DirectorySeparator + LangID +
      DirectorySeparator + LCFileName;
    if FileExistsUTF8(Result) then
      exit;

    Result := AppDir + 'locale' + DirectorySeparator + LangID +
      DirectorySeparator + 'LC_MESSAGES' + DirectorySeparator + LCFileName;
    if FileExistsUTF8(Result) then
      exit;

    {$IFDEF UNIX}
    //In unix-like systems we can try to search for global locale
    Result := '/usr/share/locale/' + LangID + '/LC_MESSAGES/' + LCFileName;
    if FileExistsUTF8(Result) then
      exit;
    {$ENDIF}
    //Let us search for short id files
    LangShortID := copy(LangID, 1, 2);
    Defaultlang := LangShortID;

    if Dir<>'' then
    begin
      if absoluteDir then
        Result := Dir + LangShortID + DirectorySeparator + LCFileName
      else
        Result := AppDir + Dir + LangShortID + DirectorySeparator + LCFileName;
      if FileExistsUTF8(Result) then
        exit;
    end;

    //At first, check all was checked
    Result := AppDir + LangShortID + DirectorySeparator + LCFileName;
    if FileExistsUTF8(Result) then
      exit;

    Result := AppDir + 'languages' + DirectorySeparator +
      LangShortID + DirectorySeparator + LCFileName;
    if FileExistsUTF8(Result) then
      exit;

    Result := AppDir + 'locale' + DirectorySeparator
      + LangShortID + DirectorySeparator + LCFileName;
    if FileExistsUTF8(Result) then
      exit;

    Result := AppDir + 'locale' + DirectorySeparator + LangShortID +
      DirectorySeparator + 'LC_MESSAGES' + DirectorySeparator + LCFileName;
    if FileExistsUTF8(Result) then
      exit;

    //Full language in file name - this will be default for the project
    //We need more careful handling, as it MAY result in incorrect filename
    try
      if Dir<>'' then
      begin
        if absoluteDir then
          Result := Dir + FullLCFileName
        else
          Result := AppDir + Dir + FullLCFileName;
        if FileExistsUTF8(Result) then
          exit;
      end;

      Result := AppDir + FullLCFileName;
      if FileExistsUTF8(Result) then
        exit;

      //Common location (like in Lazarus)
      Result := AppDir + 'locale' + DirectorySeparator + FullLCFileName;
      if FileExistsUTF8(Result) then
        exit;

      Result := AppDir + 'languages' + DirectorySeparator + FullLCFileName;
      if FileExistsUTF8(Result) then
        exit;
    except
      Result := '';//Or do something else (useless)
    end;
    {$IFDEF UNIX}
    Result := '/usr/share/locale/' + LangShortID + '/LC_MESSAGES/' +
      LCFileName;
    if FileExistsUTF8(Result) then
      exit;
    {$ENDIF}

    FullLCFileName := ChangeFileExt(GetLCFileName, '.' + LangShortID) + LCExt;

    if Dir<>'' then
    begin
      if absoluteDir then
        Result := Dir + FullLCFileName
      else
        Result := AppDir + Dir + FullLCFileName;
      if FileExistsUTF8(Result) then
        exit;
    end;

    Result := AppDir + FullLCFileName;
    if FileExistsUTF8(Result) then
      exit;

    Result := AppDir + 'locale' + DirectorySeparator + FullLCFileName;
    if FileExistsUTF8(Result) then
      exit;

    Result := AppDir + 'languages' + DirectorySeparator + FullLCFileName;
    if FileExistsUTF8(Result) then
      exit;
  end;

  //master files have .pot extension
  if LCExt = '.po' then
    LCFileName := ChangeFileExt(GetLCFileName, '.pot');

  Result := AppDir + LCFileName;
  if FileExistsUTF8(Result) then
    exit;

  Result := AppDir + 'locale' + DirectorySeparator + LCFileName;
  if FileExistsUTF8(Result) then
    exit;

  Result := AppDir + 'languages' + DirectorySeparator + LCFileName;
  if FileExistsUTF8(Result) then
    exit;

  Result := '';
  DefaultLang := '';
end;

function GetIdentifierPath(Sender: TObject;
                           const Instance: TPersistent;
                           PropInfo: PPropInfo): string;
var
  Tmp: TPersistent;
  Component: TComponent;
  Reader: TReader;
begin
  Result := '';
  if (PropInfo=nil) or (PropInfo^.PropType<>TypeInfo(TTranslateString)) then
    exit;

  // do not translate at design time
  // get the component
  Tmp := Instance;
  while Assigned(Tmp) and not (Tmp is TComponent) do
    Tmp := TPersistentAccess(Tmp).GetOwner;
  if not Assigned(Tmp) then
    exit;
  Component := Tmp as TComponent;
  if (csDesigning in Component.ComponentState) then
    exit;

  if (Sender is TReader) then
  begin
    Reader := TReader(Sender);
    if Reader.Driver is TLRSObjectReader then
      Result := TLRSObjectReader(Reader.Driver).GetStackPath
    else
      Result := Instance.ClassName + '.' + PropInfo^.Name;
  end else if (Sender is TUpdateTranslator) then
    Result := TUpdateTranslator(Sender).FStackPath + '.' + PropInfo^.Name;
  Result := LowerCase(Result); // GetText requires same case as in .po file, which is lowercase
end;

{ TUpdateTranslator }

procedure TUpdateTranslator.IntUpdateTranslation(AnInstance: TPersistent; Level: integer = 0);
var
  i,j: integer;
  APropCount: integer;
  APropList: PPropList;
  APropInfo: PPropInfo;
  TmpStr: string;
  APersistentProp: TPersistent;
  StoreStackPath: string;
  AComponent, SubComponent: TComponent;
begin
  {$IFDEF VerbosePOTranslator}
  debugln(['TUpdateTranslator.IntUpdateTranslation START ',DbgSName(AnInstance),' Level=',Level]);
  {$ENDIF}
  APropCount := GetPropList(AnInstance.ClassInfo, APropList);
  try
    for i := 0 to APropCount-1 do
      begin
      APropInfo:=APropList^[i];
      if Assigned(PPropInfo(APropInfo)^.GetProc) and
         Assigned(APropInfo^.PropType) and
         Assigned(PPropInfo(APropInfo)^.SetProc) then
        case APropInfo^.PropType^.Kind of
          tkSString,
          tkLString,
          tkAString:
            if APropInfo^.PropType=TypeInfo(TTranslateString) then
            begin
              TmpStr := GetStrProp(AnInstance, APropInfo);
              {$IFDEF VerbosePOTranslator}
              debugln(['TUpdateTranslator.IntUpdateTranslation ',GetStrProp(AnInstance,APropInfo)]);
              {$ENDIF}
              LRSTranslator.TranslateStringProperty(Self,AnInstance,APropInfo,TmpStr);
              if TmpStr <>'' then
                SetStrProp(AnInstance, APropInfo, TmpStr);
            end;
          tkClass:
            begin
              APersistentProp := TPersistent(GetObjectProp(AnInstance, APropInfo, TPersistent));
              if Assigned(APersistentProp) then
              begin
                if APersistentProp is TCollection then
                begin
                  for j := 0 to TCollection(APersistentProp).Count-1 do
                  begin
                    StoreStackPath:=FStackPath;
                    FStackPath:=FStackPath+'.'+APropInfo^.Name+'['+IntToStr(j)+']';
                    IntUpdateTranslation(TCollection(APersistentProp).Items[j],Level+1);
                    FStackPath:=StoreStackPath;
                  end;
                end
                else
                begin
                  if APersistentProp is TComponent then
                  begin
                    AComponent:=TComponent(APersistentProp);
                    if (csSubComponent in AComponent.ComponentStyle) then
                    begin
                      StoreStackPath:=FStackPath;
                      FStackPath:=FStackPath+'.'+APropInfo^.Name;
                      IntUpdateTranslation(APersistentProp,Level+1);
                      FStackPath:=StoreStackPath;
                    end
                  end
                  else
                  begin
                    StoreStackPath:=FStackPath;
                    FStackPath:=FStackPath+'.'+APropInfo^.Name;
                    IntUpdateTranslation(APersistentProp,Level+1);
                    FStackPath:=StoreStackPath;
                  end;
                end;
              end;
            end;
          end;
      end;
  finally
    Freemem(APropList);
  end;

  if (Level=0) and (AnInstance is TComponent) then
  begin
    AComponent:=TComponent(AnInstance);
    for i := 0 to AComponent.ComponentCount-1 do
    begin
      SubComponent:=AComponent.Components[i];
      StoreStackPath:=FStackPath;
      if SubComponent is TCustomFrame then
        UpdateTranslation(SubComponent);
      if SubComponent.Name='' then continue;
      FStackPath:=StoreStackPath+'.'+SubComponent.Name;
      IntUpdateTranslation(SubComponent,Level+1);
      FStackPath:=StoreStackPath;
    end;
  end;
end;

procedure TUpdateTranslator.UpdateTranslation(AnInstance: TPersistent);
begin
  FStackPath:=AnInstance.ClassName;
  IntUpdateTranslation(AnInstance);
end;

{ TDefaultTranslator }

constructor TDefaultTranslator.Create(MOFileName: string);
begin
  inherited Create;
  FMOFile := TMOFile.Create(UTF8ToSys(MOFileName));
end;

destructor TDefaultTranslator.Destroy;
begin
  FMOFile.Free;
  //If someone will use this class incorrectly, it can be destroyed
  //before Reader destroying. It is a very bad thing, but in THIS situation
  //in this case is impossible. Maybe, in future we can overcome this difficulty
  inherited Destroy;
end;

procedure TDefaultTranslator.TranslateStringProperty(Sender: TObject;
  const Instance: TPersistent; PropInfo: PPropInfo; var Content: string);
var
  s, ContentStr: string;
begin
  if Assigned(FMOFile) then
  begin
    s := GetIdentifierPath(Sender, Instance, PropInfo);
    if s <> '' then
    begin
      //If the string has lineendings, convert them to Unix style.
      //This is needed, because incoming string may have lineendings in any style,
      //and MO format seems to always store them in Unix style.
      //More elaborate processing of linendings is not needed (they are consistent),
      //because input string to this procedure is maintained by IDE.
      ContentStr := AdjustLineBreaks(Content, tlbsLF);

      s := FMoFile.Translate(s + #4 + ContentStr);

      if s = '' then
        s := FMOFile.Translate(ContentStr);

      if s <> '' then
        Content := s;
    end;
  end;
end;

{ TPOTranslator }

constructor TPOTranslator.Create(POFileName: string);
begin
  inherited Create;
  // TPOFile expects AFileName in UTF-8 encoding, no conversion required
  FPOFile := TPOFile.Create(POFileName, true);
end;

constructor TPOTranslator.Create(aPOFile: TPOFile);
begin
  inherited Create;
  FPOFile := aPOFile;
end;

destructor TPOTranslator.Destroy;
begin
  FPOFile.Free;
  //If someone will use this class incorrectly, it can be destroyed
  //before Reader destroying. It is a very bad thing, but in THIS situation
  //in this case is impossible. May be, in future we can overcome this difficulty
  inherited Destroy;
end;

procedure TPOTranslator.TranslateStringProperty(Sender: TObject;
  const Instance: TPersistent; PropInfo: PPropInfo; var Content: string);
var
  s: string;
begin
  if Assigned(FPOFile) then
  begin
    s := GetIdentifierPath(Sender, Instance, PropInfo);
    {$IFDEF VerbosePOTranslator}
    debugln(['TPOTranslator.TranslateStringProperty Content="',Content,'" s="',s,'" Instance=',Instance.ClassName,' PropInfo.Name=',PropInfo^.Name]);
    {$ENDIF}
    if s <> '' then
    begin
      s := FPOFile.Translate(s, Content);

      if s <> '' then
        Content := s;
    end;
  end;
end;

procedure TranslateLCLResourceStrings(Lang, Dir: string);
var
  LCLPath, DefaultLangBackup: string;
begin
  // DefaultLang value is preserved when translating LCL, so it will depend only
  // on presence of interface translation. Useful when interface translation present
  // and LCL one missing, or the other way round.
  DefaultLangBackup:=DefaultLang;
  LCLPath:=FindLocaleFileName('.po', Lang, ExtractFilePath(Dir), 'lclstrconsts');
  if LCLPath<>'' then
    Translations.TranslateUnitResourceStrings('LCLStrConsts', LCLPath)
  else
  begin
    LCLPath:=FindLocaleFileName('.mo', Lang, ExtractFilePath(Dir), 'lclstrconsts');
    if LCLPath<>'' then
      GetText.TranslateResourceStrings(UTF8ToSys(LCLPath));
  end;
  DefaultLang:=DefaultLangBackup;
end;

procedure SetDefaultLang(Lang: string; Dir: string = ''; LocaleFileName: string = ''; ForceUpdate: boolean = true);
{ Arguments:
  Lang - language (e.g. 'ru', 'de'); empty argument is default language.
  Dir - custom translation files subdirectory (e.g. 'mylng'); empty argument means searching only in predefined subdirectories.
  LocaleFileName - custom translation file name; empty argument means that the name is the same as the one of executable.
  ForceUpdate - true means forcing immediate interface update. Only should be set to false when the procedure is
    called from unit Initialization section. User code normally should not specify it.
}
var
  lcfn: string;
  LocalTranslator: TUpdateTranslator;
  i: integer;

begin
  LocalTranslator := nil;
  // search first po translation resources
  try
    lcfn := FindLocaleFileName('.po', Lang, Dir, LocaleFileName);
    if lcfn <> '' then
    begin
      Translations.TranslateResourceStrings(lcfn);
      LocalTranslator := TPOTranslator.Create(lcfn);
    end;
  except
    lcfn := '';
  end;

  if lcfn='' then
  begin
    // try now with MO translation resources
    try
      lcfn := FindLocaleFileName('.mo', Lang, Dir, LocaleFileName);
      if lcfn <> '' then
      begin
        GetText.TranslateResourceStrings(UTF8ToSys(lcfn));
        LocalTranslator := TDefaultTranslator.Create(lcfn);
      end;
    except
      lcfn := '';
    end;
  end;

  if lcfn<>'' then
    TranslateLCLResourceStrings(Lang, lcfn);

  if LocalTranslator<>nil then
  begin
    if Assigned(LRSTranslator) then
      LRSTranslator.Free;
    LRSTranslator := LocalTranslator;

    // Do not update the translations when this function is called from within
    // the unit initialization.
    if ForceUpdate=true then
    begin
      for i := 0 to Screen.CustomFormCount-1 do
        LocalTranslator.UpdateTranslation(Screen.CustomForms[i]);
      for i := 0 to Screen.DataModuleCount-1 do
        LocalTranslator.UpdateTranslation(Screen.DataModules[i]);
    end;
  end;
end;

function GetDefaultLang: String;
begin
  if DefaultLang = '' then SetDefaultLang('');
  GetDefaultLang := DefaultLang;
end;

finalization
  LRSTranslator.Free;

end.
