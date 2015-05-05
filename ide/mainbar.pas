{
 /***************************************************************************
                          mainbar.pp  -  Toolbar
                          ----------------------
  TMainIDEBar is the main window of the IDE, containing the menu and the
  component palette.

 ***************************************************************************/

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
 *   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.        *
 *                                                                         *
 ***************************************************************************
}
unit MainBar;

{$mode objfpc}{$H+}

interface

{$I ide.inc}

uses
{$IFDEF IDE_MEM_CHECK}
  MemCheck,
{$ENDIF}
  Classes, SysUtils, LCLProc, Forms, Controls, Buttons, Menus,
  ComCtrls, ExtCtrls, LMessages,
  // IDEIntf
  ProjectIntf, NewItemIntf, MenuIntf, LazIDEIntf, LazFileCache,
  EnvironmentOpts, LazarusIDEStrConsts, IDEImagesIntf, ToolbarData;


type
  { TMainIDEBar }


  TMainIDEBar = class(TForm)
    //Coolbar and PopUpMenus
    CoolBar: TCoolBar;
    OptionsPopupMenu: TPopupMenu;
    IDEHeightTimer: TTimer;
    OptionsMenuItem: TMenuItem;
    OpenFilePopUpMenu: TPopupMenu;
    SetBuildModePopupMenu: TPopupMenu;
    NewUnitFormPopupMenu: TPopupMenu;
    NewUFSetDefaultMenuItem: TMenuItem;

    //splitter between the Coolbar and MainMenu
    MainSplitter: TSplitter;

    // MainMenu
    mnuMainMenu: TMainMenu;
    //mnuMain: TIDEMenuSection;

    // file menu
    //mnuFile: TIDEMenuSection;
      //itmFileNew: TIDEMenuSection;
        itmFileNewUnit: TIDEMenuCommand;
        itmFileNewForm: TIDEMenuCommand;
        itmFileNewOther: TIDEMenuCommand;
      //itmFileOpenSave: TIDEMenuSection;
        itmFileOpen: TIDEMenuCommand;
        itmFileRevert: TIDEMenuCommand;
        //itmFileRecentOpen: TIDEMenuSection;
        itmFileSave: TIDEMenuCommand;
        itmFileSaveAs: TIDEMenuCommand;
        itmFileSaveAll: TIDEMenuCommand;
        itmFileExportHtml: TIDEMenuCommand;
        itmFileClose: TIDEMenuCommand;
        itmFileCloseAll: TIDEMenuCommand;
      //itmFileDirectories: TIDEMenuSection;
        itmFileCleanDirectory: TIDEMenuCommand;
      //itmFileIDEStart: TIDEMenuSection;
        itmFileRestart: TIDEMenuCommand;
        itmFileQuit: TIDEMenuCommand;

    // edit menu
    //mnuEdit: TIDEMenuSection;
      //itmEditReUndo: TIDEMenuSection;
        itmEditUndo: TIDEMenuCommand;
        itmEditRedo: TIDEMenuCommand;
      //itmEditClipboard: TIDEMenuSection;
        itmEditCut: TIDEMenuCommand;
        itmEditCopy: TIDEMenuCommand;
        itmEditPaste: TIDEMenuCommand;
      //itmEditSelect: TIDEMenuSection;
        itmEditSelectAll: TIDEMenuCommand;
        itmEditSelectToBrace: TIDEMenuCommand;
        itmEditSelectCodeBlock: TIDEMenuCommand;
        itmEditSelectWord: TIDEMenuCommand;
        itmEditSelectLine: TIDEMenuCommand;
        itmEditSelectParagraph: TIDEMenuCommand;
      //itmEditBlockActions: TIDEMenuSection;
        itmEditIndentBlock: TIDEMenuCommand;
        itmEditUnindentBlock: TIDEMenuCommand;
        itmEditUpperCaseBlock: TIDEMenuCommand;
        itmEditLowerCaseBlock: TIDEMenuCommand;
        itmEditSwapCaseBlock: TIDEMenuCommand;
        itmEditSortBlock: TIDEMenuCommand;
        itmEditTabsToSpacesBlock: TIDEMenuCommand;
        itmEditSelectionBreakLines: TIDEMenuCommand;
      //itmEditInsertions: TIDEMenuSection;
        itmEditInsertCharacter: TIDEMenuCommand;

    // search menu
    //mnuSearch: TIDEMenuSection;
      //itmSearchFindReplace: TIDEMenuSection;
        itmSearchFind: TIDEMenuCommand;
        itmSearchFindNext: TIDEMenuCommand;
        itmSearchFindPrevious: TIDEMenuCommand;
        itmSearchFindInFiles: TIDEMenuCommand;
        itmSearchReplace: TIDEMenuCommand;
        itmIncrementalFind: TIDEMenuCommand;
      //itmJumpings: TIDEMenuSection;
        itmGotoLine: TIDEMenuCommand;
        itmJumpBack: TIDEMenuCommand;
        itmJumpForward: TIDEMenuCommand;
        itmAddJumpPoint: TIDEMenuCommand;
        itmJumpToNextError: TIDEMenuCommand;
        itmJumpToPrevError: TIDEMenuCommand;
      //itmBookmarks: TIDEMenuSection;
        itmSetFreeBookmark: TIDEMenuCommand;
        itmJumpToNextBookmark: TIDEMenuCommand;
        itmJumpToPrevBookmark: TIDEMenuCommand;
      //itmCodeToolSearches: TIDEMenuSection;
        itmFindDeclaration: TIDEMenuCommand;
        itmFindBlockOtherEnd: TIDEMenuCommand;
        itmFindBlockStart: TIDEMenuCommand;
        itmOpenFileAtCursor: TIDEMenuCommand;
        itmGotoIncludeDirective: TIDEMenuCommand;
        itmSearchFindIdentifierRefs: TIDEMenuCommand;
        itmSearchProcedureList: TIDEMenuCommand;

    // view menu
    //mnuView: TIDEMenuSection;
      //itmViewMainWindows: TIDEMenuSection;
        itmViewToggleFormUnit: TIDEMenuCommand;
        itmViewInspector: TIDEMenuCommand;
        itmViewSourceEditor: TIDEMenuCommand;
        itmViewCodeExplorer: TIDEMenuCommand;
        itmViewFPDocEditor: TIDEMenuCommand;
        itmViewCodeBrowser: TIDEMenuCommand;
        itmSourceUnitDependencies: TIDEMenuCommand;
        itmViewRestrictionBrowser: TIDEMenuCommand;
        itmViewComponents: TIDEMenuCommand;
        itmJumpHistory: TIDEMenuCommand;
        itmMacroListView: TIDEMenuCommand;
      //itmViewSecondaryWindows: TIDEMenuSection;
        itmViewAnchorEditor: TIDEMenuCommand;
        itmViewTabOrder: TIDEMenuCommand;
        itmViewComponentPalette: TIDEMenuCommand;
        itmViewIDESpeedButtons: TIDEMenuCommand;
        itmViewMessage: TIDEMenuCommand;
        itmViewSearchResults: TIDEMenuCommand;
        //itmViewDebugWindows: TIDEMenuSection;
          itmViewWatches: TIDEMenuCommand;
          itmViewBreakpoints: TIDEMenuCommand;
          itmViewLocals: TIDEMenuCommand;
          itmViewRegisters: TIDEMenuCommand;
          itmViewCallStack: TIDEMenuCommand;
          itmViewThreads: TIDEMenuCommand;
          itmViewAssembler: TIDEMenuCommand;
          itmViewDebugOutput: TIDEMenuCommand;
          itmViewDebugEvents: TIDEMenuCommand;
          itmViewPseudoTerminal: TIDEMenuCommand;
          itmViewDbgHistory: TIDEMenuCommand;
        //itmViewIDEInternalsWindows: TIDEMenuSection;
          itmViewFPCInfo: TIDEMenuCommand;
          itmViewIDEInfo: TIDEMenuCommand;
          itmViewNeedBuild: TIDEMenuCommand;
          itmSearchInFPDocFiles: TIDEMenuCommand;

    // source menu
    //mnuSource: TIDEMenuSection;
      //itmSourceBlockActions: TIDEMenuSection;
        itmSourceCommentBlock: TIDEMenuCommand;
        itmSourceUncommentBlock: TIDEMenuCommand;
        itmSourceToggleComment: TIDEMenuCommand;
        itmSourceEncloseBlock: TIDEMenuCommand;
        itmSourceEncloseInIFDEF: TIDEMenuCommand;
        itmSourceCompleteCode: TIDEMenuCommand;
        itmSourceUseUnit: TIDEMenuCommand;
      //itmSourceCodeToolChecks: TIDEMenuSection;
        itmSourceSyntaxCheck: TIDEMenuCommand;
        itmSourceGuessUnclosedBlock: TIDEMenuCommand;
        itmSourceGuessMisplacedIFDEF: TIDEMenuCommand;
      //itmSourceInsertCVSKeyWord: TIDEMenuSection;
        itmSourceInsertCVSAuthor: TIDEMenuCommand;
        itmSourceInsertCVSDate: TIDEMenuCommand;
        itmSourceInsertCVSHeader: TIDEMenuCommand;
        itmSourceInsertCVSID: TIDEMenuCommand;
        itmSourceInsertCVSLog: TIDEMenuCommand;
        itmSourceInsertCVSName: TIDEMenuCommand;
        itmSourceInsertCVSRevision: TIDEMenuCommand;
        itmSourceInsertCVSSource: TIDEMenuCommand;
      //itmSourceInsertGeneral: TIDEMenuSection;
        itmSourceInsertGPLNotice: TIDEMenuCommand;
        itmSourceInsertGPLNoticeTranslated: TIDEMenuCommand;
        itmSourceInsertLGPLNotice: TIDEMenuCommand;
        itmSourceInsertLGPLNoticeTranslated: TIDEMenuCommand;
        itmSourceInsertModifiedLGPLNotice: TIDEMenuCommand;
        itmSourceInsertModifiedLGPLNoticeTranslated: TIDEMenuCommand;
        itmSourceInsertMITNotice: TIDEMenuCommand;
        itmSourceInsertMITNoticeTranslated: TIDEMenuCommand;
        itmSourceInsertUsername: TIDEMenuCommand;
        itmSourceInsertDateTime: TIDEMenuCommand;
        itmSourceInsertChangeLogEntry: TIDEMenuCommand;
        itmSourceInsertGUID: TIDEMenuCommand;
        itmSourceInsertTodo: TIDEMenuCommand;
      itmSourceInsertFilename: TIDEMenuCommand;
    // itmSourceTools
      itmSourceUnitInfo: TIDEMenuCommand;

    // refactor menu
    //mnuRefactor: TIDEMenuSection;
      //itmRefactorCodeTools: TIDEMenuSection;
        itmRefactorRenameIdentifier: TIDEMenuCommand;
        itmRefactorExtractProc: TIDEMenuCommand;
        itmRefactorInvertAssignment: TIDEMenuCommand;
      //itmRefactorAdvanced: TIDEMenuSection;
        itmRefactorShowAbstractMethods: TIDEMenuCommand;
        itmRefactorShowEmptyMethods: TIDEMenuCommand;
        itmRefactorShowUnusedUnits: TIDEMenuCommand;
        itmRefactorFindOverloads: TIDEMenuCommand;
      //itmRefactorTools: TIDEMenuSection;
        itmRefactorMakeResourceString: TIDEMenuCommand;

    // project menu
    //mnuProject: TIDEMenuSection;
      //itmProjectNewSection: TIDEMenuSection;
        itmProjectNew: TIDEMenuCommand;
        itmProjectNewFromFile: TIDEMenuCommand;
      //itmProjectOpenSection: TIDEMenuSection;
        itmProjectOpen: TIDEMenuCommand;
        //itmProjectRecentOpen: TIDEMenuSection;
        itmProjectClose: TIDEMenuCommand;
      //itmProjectSaveSection: TIDEMenuSection;
        itmProjectSave: TIDEMenuCommand;
        itmProjectSaveAs: TIDEMenuCommand;
        itmProjectPublish: TIDEMenuCommand;
      //itmProjectWindowSection: TIDEMenuSection;
        itmProjectInspector: TIDEMenuCommand;
        itmProjectOptions: TIDEMenuCommand;
        //itmProjectCompilerOptions: TIDEMenuCommand;
      //itmProjectAddRemoveSection: TIDEMenuSection;
        itmProjectAddTo: TIDEMenuCommand;
        itmProjectRemoveFrom: TIDEMenuCommand;
        itmProjectViewUnits: TIDEMenuCommand;
        itmProjectViewForms: TIDEMenuCommand;
        itmProjectViewSource: TIDEMenuCommand;
        itmProjectBuildMode: TIDEMenuCommand;

    // run menu
    //mnuRun: TIDEMenuSection;
      //itmRunBuilding: TIDEMenuSection;
        itmRunMenuCompile: TIDEMenuCommand;
        itmRunMenuBuild: TIDEMenuCommand;
        itmRunMenuQuickCompile: TIDEMenuCommand;
        itmRunMenuCleanUpAndBuild: TIDEMenuCommand;
        itmRunMenuBuildManyModes: TIDEMenuCommand;
        itmRunMenuAbortBuild: TIDEMenuCommand;
      //itmRunnning: TIDEMenuSection;
        itmRunMenuRun: TIDEMenuCommand;
        itmRunMenuPause: TIDEMenuCommand;
        itmRunMenuShowExecutionPoint: TIDEMenuCommand;
        itmRunMenuStepInto: TIDEMenuCommand;
        itmRunMenuStepOver: TIDEMenuCommand;
        itmRunMenuStepOut: TIDEMenuCommand;
        itmRunMenuRunToCursor: TIDEMenuCommand;
        itmRunMenuStop: TIDEMenuCommand;
        itmRunMenuAttach: TIDEMenuCommand;
        itmRunMenuDetach: TIDEMenuCommand;
        itmRunMenuRunParameters: TIDEMenuCommand;
        itmRunMenuResetDebugger: TIDEMenuCommand;
      //itmRunBuildingFile: TIDEMenuSection;
        itmRunMenuBuildFile: TIDEMenuCommand;
        itmRunMenuRunFile: TIDEMenuCommand;
        itmRunMenuConfigBuildFile: TIDEMenuCommand;
      //itmRunDebugging: TIDEMenuSection;
        itmRunMenuInspect: TIDEMenuCommand;
        itmRunMenuEvaluate: TIDEMenuCommand;
        itmRunMenuAddWatch: TIDEMenuCommand;
        //itmRunMenuAddBreakpoint: TIDEMenuSection;
          itmRunMenuAddBpSource: TIDEMenuCommand;
          itmRunMenuAddBpAddress: TIDEMenuCommand;
          itmRunMenuAddBpWatchPoint: TIDEMenuCommand;

    // packages menu
    //mnuComponents: TIDEMenuSection;
      //itmPkgOpening: TIDEMenuSection;
        itmPkgNewPackage: TIDEMenuCommand;
        itmPkgOpenPackage: TIDEMenuCommand;
        itmPkgOpenPackageFile: TIDEMenuCommand;
        itmPkgOpenPackageOfCurUnit: TIDEMenuCommand;
        //itmPkgOpenRecent: TIDEMenuSection;
      //itmPkgUnits: TIDEMenuSection;
        itmPkgAddCurFileToPkg: TIDEMenuCommand;
        itmPkgAddNewComponentToPkg: TIDEMenuCommand;
      //itmPkgGraphSection: TIDEMenuSection;
        itmPkgPkgGraph: TIDEMenuCommand;
        itmPkgPackageLinks: TIDEMenuCommand;
        itmPkgEditInstallPkgs: TIDEMenuCommand;
        {$IFDEF CustomIDEComps}
        itmCompsConfigCustomComps: TIDEMenuCommand;
        {$ENDIF}

    // tools menu
    //mnuTools: TIDEMenuSection;
      //itmOptionsDialogs: TIDEMenuSection;
        itmEnvGeneralOptions: TIDEMenuCommand;
        itmToolRescanFPCSrcDir: TIDEMenuCommand;
        itmEnvCodeTemplates: TIDEMenuCommand;
        itmEnvCodeToolsDefinesEditor: TIDEMenuCommand;
      //itmCustomTools: TIDEMenuSection;
        itmToolConfigure: TIDEMenuCommand;
      //itmSecondaryTools: TIDEMenuSection;
        itmToolDiff: TIDEMenuCommand;
      //itmDelphiConversion: TIDEMenuSection;
        itmToolCheckLFM: TIDEMenuCommand;
        itmToolConvertDelphiUnit: TIDEMenuCommand;
        itmToolConvertDelphiProject: TIDEMenuCommand;
        itmToolConvertDelphiPackage: TIDEMenuCommand;
        itmToolConvertDFMtoLFM: TIDEMenuCommand;
        itmToolConvertEncoding: TIDEMenuCommand;
      //itmBuildingLazarus: TIDEMenuSection;
        itmToolManageExamples: TIDEMenuCommand;
        itmToolBuildLazarus: TIDEMenuCommand;
        itmToolConfigureBuildLazarus: TIDEMenuCommand;

    // windows menu
    //mnuWindow: TIDEMenuSection;
      //itmWindowManagers: TIDEMenuSection;
        itmWindowManager: TIDEMenuCommand;

    // help menu
    //mnuHelp: TIDEMenuSection;
      //itmOnlineHelps: TIDEMenuSection;
        itmHelpOnlineHelp: TIDEMenuCommand;
        itmHelpReportingBug: TIDEMenuCommand;
        //itmHelpConfigureHelp: TIDEMenuCommand;
      //itmInfoHelps: TIDEMenuSection;
        itmHelpAboutLazarus: TIDEMenuCommand;
      //itmHelpTools: TIDEMenuSection;

    // component palette
    ComponentPageControl: TPageControl;
    GlobalMouseSpeedButton: TSpeedButton;
    procedure MainIDEBarDropFiles(Sender: TObject;
      const FileNames: array of String);
    procedure CoolBarOnChange(Sender: TObject);
    procedure MainSplitterMoved(Sender: TObject);
    procedure OnTimer(Sender: TObject);
  private
    FOldWindowState: TWindowState;
    FOnActive: TNotifyEvent;
    FNonClientHeight: Integer;
    procedure NewUnitFormDefaultClick(Sender: TObject);
    procedure NewUnitFormPopupMenuPopup(Sender: TObject);
  protected
    procedure DoActive;
    procedure WndProc(var Message: TLMessage); override;
  public
    constructor Create(TheOwner: TComponent); override;
    procedure HideIDE;
    procedure UnhideIDE;
    procedure CreatePopupMenus(TheOwner: TComponent);
    property OnActive: TNotifyEvent read FOnActive write FOnActive;
    procedure UpdateDockCaption({%H-}Exclude: TControl); override;
    procedure RefreshCoolbar;
    procedure SetMainIDEHeight;
  public
    property NonClientHeight: Integer read FNonClientHeight write FNonClientHeight;
  end;


var
  MainIDEBar: TMainIDEBar = nil;

implementation

{ TMainIDEBar }

procedure TMainIDEBar.MainIDEBarDropFiles(Sender: TObject;
  const FileNames: array of String);
begin
  // the Drop event comes before the Application activate event
  // => invalidate file state
  InvalidateFileStateCache;
  LazarusIDE.DoDropFiles(Sender,FileNames);
end;

procedure TMainIDEBar.NewUnitFormDefaultClick(Sender: TObject);
var
  Category: TNewIDEItemCategory;
  i: Integer;
  Item: TMenuItem;
  Template: TNewIDEItemTemplate;
begin
  Item:=Sender as TMenuItem;
  Category:=NewIDEItems.FindCategoryByPath(FileDescGroupName,true);
  i:=Item.MenuIndex;
  if (i<0) or (i>=Category.Count) then exit;
  Template:=Category[i];
  if NewUnitFormPopupMenu.Tag=1 then
    EnvironmentOptions.NewUnitTemplate:=Template.Name
  else
    EnvironmentOptions.NewFormTemplate:=Template.Name;
  //DebugLn(['TMainIDEBar.NewUFDefaultClick ',Template.Name]);

  EnvironmentOptions.Save(False);
end;

procedure TMainIDEBar.NewUnitFormPopupMenuPopup(Sender: TObject);
var
  TemplateName: String;
  Category: TNewIDEItemCategory;
  i: Integer;
  CurTemplate: TNewIDEItemTemplate;
  Index: Integer;
  Item: TMenuItem;
begin
  Category:=NewIDEItems.FindCategoryByPath(FileDescGroupName,true);
  // find default template name
  if NewUnitFormPopupMenu.PopupComponent.Name = 'itmFileNewUnit' then begin
    TemplateName:=EnvironmentOptions.NewUnitTemplate;
    if (TemplateName='') or (Category.FindTemplateByName(TemplateName)=nil) then
      TemplateName:=FileDescNamePascalUnit;
    NewUnitFormPopupMenu.Tag:=1;
  end else begin
    TemplateName:=EnvironmentOptions.NewFormTemplate;
    if (TemplateName='') or (Category.FindTemplateByName(TemplateName)=nil) then
      TemplateName:=FileDescNameLCLForm;
    NewUnitFormPopupMenu.Tag:=2;
  end;
  // create menu items
  Index:=0;
  for i:=0 to Category.Count-1 do begin
    CurTemplate:=Category[i];
    if not CurTemplate.VisibleInNewDialog then continue;
    if Index<NewUFSetDefaultMenuItem.Count then
      Item:=NewUFSetDefaultMenuItem[Index]
    else begin
      Item:=TMenuItem.Create(NewUFSetDefaultMenuItem);
      Item.Name:='NewUFSetDefaultMenuItem'+IntToStr(Index);
      Item.OnClick:=@NewUnitFormDefaultClick;
      NewUFSetDefaultMenuItem.Add(Item);
    end;
    Item.Caption:=CurTemplate.LocalizedName;
    Item.ShowAlwaysCheckable:=true;
    Item.Checked:=SysUtils.CompareText(TemplateName,CurTemplate.Name)=0;
    inc(Index);
  end;
  // remove unneeded items
  while NewUFSetDefaultMenuItem.Count>Index do
    NewUFSetDefaultMenuItem.Items[NewUFSetDefaultMenuItem.Count-1].Free;
end;

procedure TMainIDEBar.DoActive;
begin
  if Assigned(FOnActive) then
    FOnActive(Self);
end;

procedure TMainIDEBar.WndProc(var Message: TLMessage);
begin
  inherited WndProc(Message);
  if (Message.Msg=LM_ACTIVATE) and (Message.Result=0) then
    DoActive;
end;

procedure TMainIDEBar.UpdateDockCaption(Exclude: TControl);
begin
  // keep IDE caption
end;

constructor TMainIDEBar.Create(TheOwner: TComponent);
begin
  // This form has no resource => must be constructed using CreateNew
  inherited CreateNew(TheOwner, 1);
  AllowDropFiles:=true;
  OnDropFiles:=@MainIDEBarDropFiles;
  try
    Icon.LoadFromResourceName(HInstance, 'WIN_MAIN');
  except
  end;
end;

procedure TMainIDEBar.HideIDE;
begin
  if WindowState=wsMinimized then exit;
  FOldWindowState:=WindowState;
  WindowState:=wsMinimized;
end;

procedure TMainIDEBar.UnhideIDE;
begin
  WindowState:=FOldWindowState;
end;

procedure TMainIDEBar.CreatePopupMenus(TheOwner: TComponent);
begin
  // create the popupmenu for the MainIDEBar.OpenFileArrowSpeedBtn
  OpenFilePopUpMenu := TPopupMenu.Create(TheOwner);
  OpenFilePopupMenu.Name:='OpenFilePopupMenu';

  SetBuildModePopupMenu:=TPopupMenu.Create(TheOwner);
  SetBuildModePopupMenu.Name:='SetBuildModePopupMenu';

  NewUnitFormPopupMenu:=TPopupMenu.Create(TheOwner);
  NewUnitFormPopupMenu.Name:='NewUnitFormPopupMenu';
  NewUnitFormPopupMenu.OnPopup:=@NewUnitFormPopupMenuPopup;

  NewUFSetDefaultMenuItem:=TMenuItem.Create(TheOwner);
  NewUFSetDefaultMenuItem.Name:='NewUFSetDefaultMenuItem';
  NewUFSetDefaultMenuItem.Caption:=lisSetDefault;
  NewUnitFormPopupMenu.Items.Add(NewUFSetDefaultMenuItem);

  OptionsPopupMenu := TPopupMenu.Create(TheOwner);
  OptionsPopupMenu.Images := IDEImages.Images_16;
  OptionsMenuItem := TMenuItem.Create(TheOwner);
  with MainIDEBar.OptionsMenuItem do
  begin
     Name := 'miToolbarOption';
     Caption := lisOptions;
     Enabled := True;
     Visible := True;
     ImageIndex := IDEImages.LoadImage(16, 'menu_environment_options');
   end;
  MainIDEBar.OptionsPopupMenu.Items.Add(MainIDEBar.OptionsMenuItem);
end;

procedure TMainIDEBar.RefreshCoolbar;
var
  I, J: Integer;
  CoolBand: TCoolBand;
  CoolBarOpts: TIDECoolBarOptions;
begin
  CoolBarOpts := EnvironmentOptions.IDECoolBarOptions;
  //read general settings
  if not (CoolBarOpts.IDECoolBarGrabStyle in [0..5]) then
    CoolBarOpts.IDECoolBarGrabStyle := 4;
  Coolbar.GrabStyle := TGrabStyle(CoolBarOpts.IDECoolBarGrabStyle);
  if not (CoolBarOpts.IDECoolBarGrabWidth in [1..50]) then
    CoolBarOpts.IDECoolBarGrabWidth := 5;
  Coolbar.GrabWidth := CoolBarOpts.IDECoolBarGrabWidth;
  Coolbar.BandBorderStyle := TBorderStyle(CoolBarOpts.IDECoolBarBorderStyle);
  Coolbar.Width := CoolBarOpts.IDECoolBarWidth;
  //read toolbars
  CoolBar.Bands.Clear;
  IDECoolBar.CopyFromOptions(CoolBarOpts);
  IDECoolBar.Sort;
  for I := 0 to IDECoolBar.ToolBars.Count - 1 do
  begin
    CoolBand := CoolBar.Bands.Add;
    CoolBand.Break := IDECoolBar.ToolBars[I].Break;
    CoolBand.Control := IDECoolBar.ToolBars[I].Toolbar;
    CoolBand.MinWidth := 25;
    CoolBand.MinHeight := 22;
    CoolBand.FixedSize := True;
    IDECoolBar.ToolBars[I].ClearToolbar;
    for J := 0 to IDECoolBar.ToolBars[I].ButtonNames.Count - 1 do
      IDECoolBar.ToolBars[I].AddCustomItems(J);
  end;
  CoolBar.AutosizeBands;

  CoolBar.Visible := CoolBarOpts.IDECoolBarVisible;
  itmViewIDESpeedButtons.Checked := CoolBar.Visible;
  MainSplitter.Align := alLeft;
  MainSplitter.Visible := MainIDEBar.Coolbar.Visible and
                          MainIDEBar.ComponentPageControl.Visible;
  MainIDEBar.SetMainIDEHeight;
end;

procedure TMainIDEBar.MainSplitterMoved(Sender: TObject);
begin
  EnvironmentOptions.IDECoolBarOptions.IDECoolBarWidth := CoolBar.Width;
  SetMainIDEHeight
end;


procedure TMainIDEBar.CoolBarOnChange(Sender: TObject);
var
  I, J: Integer;
  ToolBar: TToolBar;
begin
  for I := 0 to Coolbar.Bands.Count - 1 do
  begin
    if Coolbar.Bands[I].Control = nil then
      Continue;
    ToolBar := (Coolbar.Bands[I].Control as TToolBar);
    J := IDECoolBar.FindByToolBar(ToolBar);
    if J <> -1 then
    begin
      IDECoolBar.ToolBars[J].Position := Coolbar.Bands[I].Index;
      IDECoolBar.ToolBars[J].Break := Coolbar.Bands[I].Break;
    end
  end;
  IDECoolBar.Sort;
  IDECoolBar.CopyToOptions(EnvironmentOptions.IDECoolBarOptions);
  SetMainIDEHeight;
end;

procedure TMainIDEBar.SetMainIDEHeight;
begin
  if IDEHeightTimer.Enabled then
    Exit;
  IDEHeightTimer.Enabled := True;
end;

procedure TMainIDEBar.OnTimer(Sender: TObject);
var
  CoolBarVisible: Boolean;
  ComponentsVisible: Boolean;
  CoolBarHeigth: Integer;
  CoolBarDefHeight: Integer;
  NewClientHeight: Integer;
begin
  CoolBarVisible := EnvironmentOptions.IDECoolBarOptions.IDECoolBarVisible;
  ComponentsVisible := EnvironmentOptions.ComponentPaletteVisible;
  CoolBarDefHeight := CoolBar.Bands.Items[0].Height; //there is at least one band
  CoolBarHeigth := CoolBar.Bands.Items[CoolBar.Bands.Count - 1].Top +
                   CoolBar.Bands.Items[CoolBar.Bands.Count - 1].Height;

  if (MainIDEBar.Parent=nil) and (MainIDEBar.DockManager=nil) then
  begin
    //only the menu is visible
    if (not CoolBarVisible) and (not ComponentsVisible) then
      NewClientHeight := 0
    //only the coolbar is visible
    else if (CoolBarVisible) and (not ComponentsVisible) then
      NewClientHeight := CoolBarHeigth
    //only the component palette is visible
    else if (not CoolBarVisible) and (ComponentsVisible) then
      NewClientHeight := 2*CoolBarDefHeight
    //both coolbar and component palette is visible
    else if (CoolBarVisible) and (ComponentsVisible) then
    begin
      if CoolBarHeigth > 2*CoolBarDefHeight then
        NewClientHeight := CoolBarHeigth
      else
        NewClientHeight := 2*CoolBarHeigth;
    end;

    MainIDEBar.Constraints.MaxHeight := 0;
    MainIDEBar.Constraints.MinHeight := 0;
    MainIDEBar.ClientHeight := NewClientHeight;
    MainIDEBar.Constraints.MaxHeight := NonClientHeight + NewClientHeight;
   // MainIDEBar.Constraints.MinHeight := NonClientHeight + NewClientHeight;
  end;
  IDEHeightTimer.Enabled := False;
end;


end.

