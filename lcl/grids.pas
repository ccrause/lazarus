{ $Id$}
{
 /***************************************************************************
                               Grids.pas
                               ---------
                     An interface to DB aware Controls
                     Initial Revision : Sun Sep 14 2003


 ***************************************************************************/

 *****************************************************************************
 *                                                                           *
 *  This file is part of the Lazarus Component Library (LCL)                 *
 *                                                                           *
 *  See the file COPYING.modifiedLGPL, included in this distribution,        *
 *  for details about the copyright.                                         *
 *                                                                           *
 *  This program is distributed in the hope that it will be useful,          *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of           *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                     *
 *                                                                           *
 *****************************************************************************
}
{

TCustomGrid, TDrawGrid and TStringGrid for Lazarus
Copyright (C) 2002  Jesus Reyes Aguilar.
email: jesusrmx@yahoo.com.mx

}

{$define UseClipRect}
{$define LooseCount}

{$IF defined(VER2_0_2) and defined(win32)}
// FPC <= 2.0.2 compatibility code
// WINDOWS define was added after FPC 2.0.2
  {$define WINDOWS}
{$endif}

unit Grids;

{$mode objfpc}{$H+}

interface

uses
  Types, Classes, SysUtils, Math, LCLStrConsts, LCLProc, LCLType, LCLIntf,
  Controls, GraphType, Graphics, Forms, DynamicArray, LMessages, XMLCfg,
  StdCtrls, LResources, MaskEdit, Buttons, Clipbrd;

const
  //GRIDFILEVERSION = 1; // Original
  //GRIDFILEVERSION = 2; // Introduced goSmoothScroll
  GRIDFILEVERSION = 3; // Introduced Col/Row FixedAttr and NormalAttr

const
  GM_SETVALUE   = LM_USER + 100;
  GM_GETVALUE   = LM_USER + 101;
  GM_SETGRID    = LM_USER + 102;
  GM_SETPOS     = LM_USER + 103;
  GM_SELECTALL  = LM_USER + 104;
  GM_SETMASK    = LM_USER + 105;

const
  EO_AUTOSIZE     =   $1;
  EO_HOOKKEYDOWN  =   $2;
  EO_HOOKKEYPRESS =   $4;
  EO_HOOKKEYUP    =   $8;
  EO_HOOKEXIT     =   $10;
  EO_SELECTALL    =   $20;

const
  DEFCOLWIDTH = 64;
  DEFROWHEIGHT= 20;

type
  EGridException = class(Exception);

type
  TGridOption = (
    goFixedVertLine,      // Ya
    goFixedHorzLine,      // Ya
    goVertLine,           // Ya
    goHorzLine,           // Ya
    goRangeSelect,        // Ya
    goDrawFocusSelected,  // Ya
    goRowSizing,          // Ya
    goColSizing,          // Ya
    goRowMoving,          // Ya
    goColMoving,          // Ya
    goEditing,            // Ya
    goTabs,               // Ya
    goRowSelect,          // Ya
    goAlwaysShowEditor,   // Ya
    goThumbTracking,      // ya
    // Additional Options
    goColSpanning,        // Enable cellextent calcs
    goRelaxedRowSelect,   // User can see focused cell on goRowSelect
    goDblClickAutoSize,   // dblclicking columns borders (on hdrs) resize col.
    goSmoothScroll,       // Switch scrolling mode (pixel scroll is by default)
    goFixedRowNumbering,  // Ya
    goScrollKeepVisible   // keeps focused cell visible while scrolling
  );
  TGridOptions = set of TGridOption;

  TGridSaveOptions = (
    soDesign,             // Save grid structure (col/row count and Options)
    soAttributes,         // Save grid attributes (Font,Brush,TextStyle)
    soContent,            // Save Grid Content (Text in stringgrid)
    soPosition            // Save Grid cursor and selection position
  );
  TSaveOptions = set of TGridSaveOptions;

  TGridDrawState = set of (gdSelected, gdFocused, gdFixed);
  TGridState =(gsNormal, gsSelecting, gsRowSizing, gsColSizing, gsRowMoving, gsColMoving);
  TGridZone = (gzNormal, gzFixedCols, gzFixedRows, gzFixedCells, gzInvalid);

  TUpdateOption = (uoNone, uoQuick, uoFull);
  TAutoAdvance = (aaNone,aaDown,aaRight,aaLeft, aaRightDown, aaLeftDown,
    aaRightUp, aaLeftUp);

  TItemType = (itNormal,itCell,itColumn,itRow,itFixed,itFixedColumn,itFixedRow,itSelected);

  TColumnButtonStyle = (cbsAuto, cbsEllipsis, cbsNone, cbsPickList, cbsCheckboxColumn); //SSY
  TCleanOptions = set of TGridZone;

  TTitleStyle = (tsLazarus, tsStandard, tsNative);
  
  TGridFlagsOption = (gfEditorUpdateLock, gfNeedsSelectActive, gfEditorTab, gfRevEditorTab);
  TGridFlags = set of TGridFlagsOption;

const
  soAll: TSaveOptions = [soDesign, soAttributes, soContent, soPosition];
  constRubberSpace: byte = 2;

type

  TCustomGrid = class;
  TGridColumn = class;


  PCellProps= ^TCellProps;
  TCellProps=record
    Attr: pointer;
    Data: TObject;
    Text: pchar;
  end;

  PColRowProps= ^TColRowProps;
  TColRowProps=record
    Size: Integer;
    FixedAttr: pointer;
    NormalAttr: pointer;
  end;

  PGridMessage=^TGridMessage;
  TGridMessage=record
    MsgID: Cardinal;
    Grid: TCustomGrid;
    Col,Row: Integer;
    Value: string;
    CellRect: TRect;
    Options: Integer;
  end;

 type

  { Default cell editor for TStringGrid }

  { TStringCellEditor }

  TStringCellEditor=class(TCustomMaskEdit)
  private
    FGrid: TCustomGrid;
    FCol,FRow:Integer;
  protected
    procedure WndProc(var TheMessage : TLMessage); override;
    procedure Change; override;
    procedure KeyDown(var Key : Word; Shift : TShiftState); override;
    procedure msg_SetMask(var Msg: TGridMessage); message GM_SETMASK;
    procedure msg_SetValue(var Msg: TGridMessage); message GM_SETVALUE;
    procedure msg_GetValue(var Msg: TGridMessage); message GM_GETVALUE;
    procedure msg_SetGrid(var Msg: TGridMessage); message GM_SETGRID;
    procedure msg_SelectAll(var Msg: TGridMessage); message GM_SELECTALL;
  public
    procedure EditingDone; override;
  end;

  TButtonCellEditor = class(TButton)
  private
    FGrid: TCustomGrid;
    FCol,FRow: Integer;
  protected
    procedure msg_SetGrid(var Msg: TGridMessage); message GM_SETGRID;
    procedure msg_SetPos(var Msg: TGridMessage); message GM_SETPOS;
  public
    property Col: Integer read FCol;
    property Row: Integer read FRow;
  end;

  { TPickListCellEditor }

  TPickListCellEditor = class(TCustomComboBox)
  private
    FGrid: TCustomGrid;
    FCol,FRow: Integer;
  protected
    procedure WndProc(var TheMessage : TLMessage); override;
    procedure KeyDown(var Key : Word; Shift : TShiftState); override;
    procedure DropDown; override;
    procedure CloseUp; override;
    procedure Select; override;
    procedure msg_GetValue(var Msg: TGridMessage); message GM_GETVALUE;
    procedure msg_SetGrid(var Msg: TGridMessage); message GM_SETGRID;
    procedure msg_SetValue(var Msg: TGridMessage); message GM_SETVALUE;
  public
    procedure EditingDone; override;
    property BorderStyle;
  end;


  TOnDrawCell =
    procedure(Sender: TObject; aCol, aRow: Integer; aRect: TRect;
              aState:TGridDrawState) of object;

  TOnSelectCellEvent =
    procedure(Sender: TObject; aCol, aRow: Integer;
              var CanSelect: Boolean) of object;

  TOnSelectEvent =
    procedure(Sender: TObject; aCol, aRow: Integer) of object;

  TGridOperationEvent =
    procedure (Sender: TObject; IsColumn:Boolean;
               sIndex, tIndex: Integer) of object;

  THdrEvent =
    procedure(Sender: TObject; IsColumn: Boolean; Index: Integer) of object;

  TOnCompareCells =
    procedure (Sender: TObject; ACol, ARow, BCol,BRow: Integer;
               var Result: integer) of object;

  TSelectEditorEvent =
    procedure(Sender: TObject; aCol, aRow: Integer;
              var Editor: TWinControl) of object;

  TOnPrepareCanvasEvent =
    procedure(sender: TObject; aCol, aRow: Integer;
              aState: TGridDrawState) of object;

  { TVirtualGrid }

  TVirtualGrid=class
    private
      FColCount: Integer;
      FRowCount: Integer;
      FCells, FCols, FRows: TArray;
      function  GetCells(Col, Row: Integer): PCellProps;
      function  Getrows(Row: Integer): PColRowprops;
      function  Getcols(Col: Integer): PColRowprops;
      procedure SetCells(Col, Row: Integer; const AValue: PCellProps);
      procedure Setrows(Row: Integer; const Avalue: PColRowprops);
      procedure Setcolcount(const Avalue: Integer);
      procedure Setrowcount(const Avalue: Integer);
      procedure Setcols(Col: Integer; const Avalue: PColRowprops);
    protected
      procedure doDestroyItem(Sender: TObject; Col,Row:Integer; var Item: Pointer);
      procedure doNewItem(Sender: TObject; Col,Row:Integer; var Item: Pointer);
      procedure DeleteColRow(IsColumn: Boolean; index: Integer);
      procedure MoveColRow(IsColumn: Boolean; FromIndex, ToIndex: Integer);
      procedure ExchangeColRow(IsColumn:Boolean; index,WithIndex: Integer);
      procedure InsertColRow(IsColumn:Boolean; Index: Integer);
      procedure DisposeCell(var P: PCellProps); virtual;
      procedure DisposeColRow(var p: PColRowProps); virtual;
    public
      constructor Create;
      destructor Destroy; override;
      procedure Clear;
      function GetDefaultCell: PcellProps;
      function GetDefaultColRow: PColRowProps;

      property ColCount: Integer read FColCount write SetColCount;
      property RowCount: Integer read FRowCount write SetRowCount;

      property Celda[Col,Row: Integer]: PCellProps read GetCells write SetCells;
      property Cols[Col: Integer]: PColRowProps read GetCols write SetCols;
      property Rows[Row: Integer]: PColRowProps read GetRows write SetRows;
  end;

  { TColumnTitle }

  TGridColumnTitle = class(TPersistent)
  private
    FColumn: TGridColumn;
    FCaption: PChar;
    FColor: ^TColor;
    FAlignment: ^TAlignment;
    FFont: TFont;
    FIsDefaultTitleFont: boolean;
    FLayout: ^TTextLayout;
    procedure FontChanged(Sender: TObject);
    function GetAlignment: TAlignment;
    function GetCaption: string;
    function GetColor: TColor;
    function GetFont: TFont;
    function GetLayout: TTextLayout;
    function IsAlignmentStored: boolean;
    function IsCaptionStored: boolean;
    function IsColorStored: boolean;
    function IsFontStored: boolean;
    function IsLayoutStored: boolean;
    procedure SetAlignment(const AValue: TAlignment);
    procedure SetCaption(const AValue: string);
    procedure SetColor(const AValue: TColor);
    procedure SetFont(const AValue: TFont);
    procedure SetLayout(const AValue: TTextLayout);
    property IsDefaultFont: boolean read FIsDefaultTitleFont;
  protected
    procedure Assign(Source: TPersistent); override;
    function  GetDefaultCaption: string; virtual;
    function  GetDefaultAlignment: TAlignment;
    function  GetDefaultColor: TColor;
    function  GetDefaultLayout: TTextLayout;
  public
    constructor Create(TheColumn: TGridColumn); virtual;
    destructor Destroy; override;
    procedure FillTitleDefaultFont;
    function IsDefault: boolean;
    property Column: TGridColumn read FColumn;
  published
    property Alignment: TAlignment read GetAlignment write SetAlignment stored IsAlignmentStored;
    property Layout: TTextLayout read GetLayout write SetLayout stored IsLayoutStored;
    property Caption: string read GetCaption write SetCaption stored IsCaptionStored;
    property Color: TColor read GetColor write SetColor stored IsColorStored;
    property Font: TFont read GetFont write SetFont stored IsFontStored;
  end;

  { TGridColumn }

  TGridColumn = class(TCollectionItem)
  private
    FButtonStyle: TColumnButtonStyle;
    FDropDownRows: Longint;
    FTitle: TGridColumnTitle;
    FWidthChanged: boolean;

    FAlignment: ^TAlignment;
    FColor: ^TColor;
    FLayout: ^TTextLayout;
    FVisible: ^Boolean;
    FReadOnly: ^Boolean;
    FWidth: ^Integer;
    FFont: TFont;
    FisDefaultFont: Boolean;
    FPickList: TStrings;
    FMinSize, FMaxSize, FSizePriority: ^Integer;

    procedure FontChanged(Sender: TObject);
    function GetAlignment: TAlignment;
    function GetColor: TColor;
    function GetExpanded: Boolean;
    function GetFont: TFont;
    function GetGrid: TCustomGrid;
    function GetLayout: TTextLayout;
    function GetMaxSize: Integer;
    function GetMinSize: Integer;
    function GetSizePriority: Integer;
    function GetPickList: TStrings;
    function GetReadOnly: Boolean;
    function GetVisible: Boolean;
    function GetWidth: Integer;
    function IsAlignmentStored: boolean;
    function IsColorStored: boolean;
    function IsFontStored: boolean;
    function IsLayoutStored: boolean;
    function IsMinSizeStored: boolean;
    function IsMaxSizeStored: boolean;
    function IsReadOnlyStored: boolean;
    function IsSizePriorityStored: boolean;
    function IsVisibleStored: boolean;
    function IsWidthStored: boolean;
    procedure SetAlignment(const AValue: TAlignment);
    procedure SetButtonStyle(const AValue: TColumnButtonStyle);
    procedure SetColor(const AValue: TColor);
    procedure SetExpanded(const AValue: Boolean);
    procedure SetFont(const AValue: TFont);
    procedure SetLayout(const AValue: TTextLayout);
    procedure SetMaxSize(const AValue: Integer);
    procedure SetMinSize(const Avalue: Integer);
    procedure SetPickList(const AValue: TStrings);
    procedure SetReadOnly(const AValue: Boolean);
    procedure SetSizePriority(const AValue: Integer);
    procedure SetTitle(const AValue: TGridColumnTitle);
    procedure SetVisible(const AValue: Boolean);
    procedure SetWidth(const AValue: Integer);
  protected
    procedure Assign(Source: TPersistent); override;
    function  GetDisplayName: string; override;
    function  GetDefaultAlignment: TAlignment; virtual;
    function  GetDefaultColor: TColor; virtual;
    function  GetDefaultLayout: TTextLayout; virtual;
    function  GetDefaultMaxSize: Integer; virtual;
    function  GetDefaultMinSize: Integer; virtual;
    function  GetDefaultReadOnly: boolean; virtual;
    function  GetDefaultSizePriority: Integer;
    function  GetDefaultVisible: boolean; virtual;
    function  GetDefaultWidth: Integer; virtual;
    procedure ColumnChanged;
    procedure AllColumnsChange;
    function  CreateTitle: TGridColumnTitle; virtual;

    property  IsDefaultFont: boolean read FIsDefaultFont;
  public
    constructor Create(ACollection: TCollection); override;
    destructor Destroy; override;
    procedure FillDefaultFont;
    function  IsDefault: boolean; virtual;
    property Grid: TCustomGrid read GetGrid;
    property WidthChanged: boolean read FWidthChanged;

  published
    property Alignment: TAlignment read GetAlignment write SetAlignment stored IsAlignmentStored;
    property ButtonStyle: TColumnButtonStyle read FButtonStyle write SetButtonStyle default cbsAuto;
    property Color: TColor read GetColor write SetColor stored IsColorStored;
    property DropDownRows: Longint read FDropDownRows write FDropDownRows default 7;
    property Expanded: Boolean read GetExpanded write SetExpanded default True;
    property Font: TFont read GetFont write SetFont stored IsFontStored;
    property Layout: TTextLayout read GetLayout write SetLayout stored IsLayoutStored;
    property MinSize: Integer read GetMinSize write SetMinSize stored IsMinSizeStored;
    property MaxSize: Integer read GetMaxSize write SetMaxSize stored isMaxSizeStored;
    property PickList: TStrings read GetPickList write SetPickList;
    property ReadOnly: Boolean read GetReadOnly write SetReadOnly stored IsReadOnlyStored;
    property SizePriority: Integer read GetSizePriority write SetSizePriority stored IsSizePriorityStored;
    property Title: TGridColumnTitle read FTitle write SetTitle;
    property Width: Integer read GetWidth write SetWidth stored IsWidthStored default DEFCOLWIDTH;
    property Visible: Boolean read GetVisible write SetVisible stored IsVisibleStored default true;
  end;

  TGridPropertyBackup=record
    ValidData: boolean;
    FixedRowCount: Integer;
    FixedColCount: Integer;
  end;

  { TGridColumns }

  TGridColumns = class(TCollection)
  private
    FGrid: TCustomGrid;
    function GetColumn(Index: Integer): TGridColumn;
    function GetEnabled: Boolean;
    procedure SetColumn(Index: Integer; Value: TGridColumn);
    function GetVisibleCount: Integer;
  protected
    procedure Update(Item: TCollectionItem); override;
    procedure TitleFontChanged;
    procedure FontChanged;
    procedure RemoveColumn(Index: Integer);
    procedure MoveColumn(FromIndex,ToIndex: Integer); virtual;
    procedure ExchangeColumn(Index,WithIndex: Integer);
    procedure InsertColumn(Index: Integer);
  public
    constructor Create(AGrid: TCustomGrid; aItemClass: TCollectionItemClass);
    function Add: TGridColumn;
    function RealIndex(Index: Integer): Integer;
    function IndexOf(Column: TGridColumn): Integer;
    function IsDefault: boolean;
    function HasIndex(Index: Integer): boolean;
    property Grid: TCustomGrid read FGrid;
    property Items[Index: Integer]: TGridColumn read GetColumn write SetColumn; default;
    property VisibleCount: Integer read GetVisibleCount;
    property Enabled: Boolean read GetEnabled;
  end;

  type
    TGridCoord = TPoint;
    TGridRect  = TRect;

    TGridDataCache=record
      FixedWidth: Integer;    // Sum( Fixed ColsWidths[i] )
      FixedHeight: Integer;   // Sum( Fixed RowsHeights[i] )
      GridWidth: Integer;     // Sum( ColWidths[i] )
      GridHeight: Integer;    // Sum( RowHeights[i] )
      ClientWidth: Integer;   // Width-VertScrollbar.Size
      ClientHeight: Integer;  // Height-HorzScrollbar.Size
      ScrollWidth: Integer;   // ClientWidth-FixedWidth
      ScrollHeight: Integer;  // ClientHeight-FixedHeight
      VisibleGrid: TRect;     // Visible non fixed rectangle of cellcoordinates
      MaxClientXY: Tpoint;    // VisibleGrid.BottomRight (pixel) coordinates
      ValidRows: boolean;     // true if there are not fixed columns to show
      ValidCols: boolean;     // true if there are not fixed rows to show
      ValidGrid: boolean;     // true if there are not fixed cells to show
      AccumWidth: TList;      // Accumulated width per column
      AccumHeight: TList;     // Accumulated Height per row
      TLColOff,TLRowOff: Integer;   // TopLeft Offset in pixels
      MaxTopLeft: TPoint;     // Max Top left ( cell coorditates)
    end;

type

  { TCustomGrid }

  TCustomGrid=class(TCustomControl)
  private
    FAlternateColor: TColor;
    FAutoAdvance: TAutoAdvance;
    FAutoFillColumns: boolean;
    FBorderColor: TColor;
    FDefaultDrawing: Boolean;
    FEditor: TWinControl;
    FEditorHidingCount: Integer;
    FEditorMode: Boolean;
    FEditorShowing: Boolean;
    FEditorKey: Boolean;
    FEditorOptions: Integer;
    FExtendedSelect: boolean;
    FFastEditing: boolean;
    FAltColorStartNormal: boolean;
    FFlat: Boolean;
    FTitleStyle: TTitleStyle;
    FOnCompareCells: TOnCompareCells;
    FGridLineStyle: TPenStyle;
    FGridLineWidth: Integer;
    FDefColWidth, FDefRowHeight: Integer;
    FCol,FRow, FFixedCols, FFixedRows: Integer;
    FOnEditButtonClick: TNotifyEvent;
    FOnPickListSelect: TNotifyEvent;
    FOnPrepareCanvas: TOnPrepareCanvasEvent;
    FOnSelectEditor: TSelectEditorEvent;
    FGridLineColor: TColor;
    FFixedcolor, FFocusColor, FSelectedColor: TColor;
    FFocusRectVisible: boolean;
    FCols,FRows: TList;
    FsaveOptions: TSaveOptions;
    FScrollBars: TScrollStyle;
    FSelectActive: Boolean;
    FTopLeft: TPoint;
    FSplitter, FPivot: TPoint;
    FRange: TRect;
    FDragDx: Integer;
    FMoveLast: TPoint;
    FUpdateCount: Integer;
    FUpdateScrollBarsCount: Integer;
    FGCache: TGridDataCache;
    FOptions: TGridOptions;
    FOnDrawCell: TOnDrawcell;
    FOnBeforeSelection: TOnSelectEvent;
    FOnSelection: TOnSelectEvent;
    FOnTopLeftChanged: TNotifyEvent;
    FGSMHBar, FGSMVBar: Integer; // Scrollbar's metrics
    FUseXORFeatures: boolean;
    FVSbVisible, FHSbVisible: boolean;
    FDefaultTextStyle: TTextStyle;
    FLastWidth: Integer;
    FTitleFont, FLastFont: TFont;
    FTitleFontIsDefault: boolean;
    FColumns: TGridColumns;
    FButtonEditor: TButtonCellEditor;
    FStringEditor: TStringCellEditor;
    FPickListEditor: TPickListCellEditor;
    FExtendedColSizing: boolean;
    FExtendedRowSizing: boolean;
    FUpdatingAutoFillCols: boolean;
    FPrevLine: boolean;
    FPrevValue: Integer;
    FGridBorderStyle: TBorderStyle;
    FGridFlags: TGridFlags;
    FGridPropBackup: TGridPropertyBackup;
    FStrictSort: boolean;
    procedure AdjustCount(IsColumn:Boolean; OldValue, NewValue:Integer);
    procedure CacheVisibleGrid;
    procedure CancelSelection;
    procedure CheckFixedCount(aCol,aRow,aFCol,aFRow: Integer);
    procedure CheckCount(aNewColCount, aNewRowCount: Integer);
    procedure CheckIndex(IsColumn: Boolean; Index: Integer);
    function  CheckTopLeft(aCol,aRow: Integer; CheckCols,CheckRows: boolean): boolean;
    function  GetSelectedColumn: TGridColumn;
    procedure SetAlternateColor(const AValue: TColor);
    procedure SetAutoFillColumns(const AValue: boolean);
    procedure SetBorderColor(const AValue: TColor);
    procedure SetColumns(const AValue: TGridColumns);
    procedure SetEditorOptions(const AValue: Integer);
    procedure SetEditorBorderStyle(const AValue: TBorderStyle);
    procedure SetAltColorStartNormal(const AValue: boolean);
    procedure SetFlat(const AValue: Boolean);
    procedure SetFocusRectVisible(const AValue: Boolean);
    procedure SetTitleFont(const AValue: TFont);
    procedure SetTitleStyle(const AValue: TTitleStyle);
    procedure SetUseXorFeatures(const AValue: boolean);
    function  doColSizing(X,Y: Integer): Boolean;
    function  doRowSizing(X,Y: Integer): Boolean;
    procedure doColMoving(X,Y: Integer);
    procedure doRowMoving(X,Y: Integer);
    procedure doTopleftChange(DimChg: Boolean);
    procedure DrawXORVertLine(X: Integer);
    procedure DrawXORHorzLine(Y: Integer);
    function  EditorCanProcessKey(var Key: Char): boolean;
    procedure EditorGetValue;
    procedure EditorPos;
    procedure EditorShowChar(Ch: Char);
    procedure EditorSetMode(const AValue: Boolean);
    procedure EditorSetValue;
    function  EditorAlwaysShown: Boolean;
    procedure FixPosition;
    function  GetLeftCol: Integer;
    function  GetColCount: Integer;
    function  GetColWidths(Acol: Integer): Integer;
    function  GetColumns: TGridColumns;
    function  GetEditorBorderStyle: TBorderStyle;
    function  GetBorderWidth: Integer;
    function  GetRowCount: Integer;
    function  GetRowHeights(Arow: Integer): Integer;
    function  GetSelection: TGridRect;
    function  GetSystemMetricsGapSize(const Index: Integer): Integer;
    function  GetTopRow: Longint;
    function  GetVisibleColCount: Integer;
    function  GetVisibleGrid: TRect;
    function  GetVisibleRowCount: Integer;
    procedure InternalAutoFillColumns;
    function  InternalNeedBorder: boolean;
    procedure InternalSetColWidths(aCol,aValue: Integer);
    procedure InternalSetFixedCols(const AValue: Integer);
    procedure InternalUpdateColumnWidths;
    procedure InvalidateMovement(DCol,DRow: Integer; OldRange: TRect);
    function  IsAltColorStored: boolean;
    function  IsColumnsStored: boolean;
    procedure OnTitleFontChanged(Sender: TObject);
    procedure ReadColumns(Reader: TReader);
    procedure ReadColWidths(Reader: TReader);
    procedure ReadRowHeights(Reader: TReader);
    function  ScrollToCell(const aCol,aRow: Integer): Boolean;
    function  ScrollGrid(Relative:Boolean; DCol,DRow: Integer): TPoint;
    procedure SetCol(AValue: Integer);
    procedure SetColwidths(Acol: Integer; Avalue: Integer);
    procedure SetRawColWidths(ACol: Integer; AValue: Integer);
    procedure SetColCount(AValue: Integer);
    procedure SetDefColWidth(AValue: Integer);
    procedure SetDefRowHeight(AValue: Integer);
    procedure SetDefaultDrawing(const AValue: Boolean);
    procedure SetEditor(AValue: TWinControl);
    procedure SetFixedCols(const AValue: Integer);
    procedure SetFixedRows(const AValue: Integer);
    procedure SetFocusColor(const AValue: TColor);
    procedure SetGridLineColor(const AValue: TColor);
    procedure SetGridLineStyle(const AValue: TPenStyle);
    procedure SetGridLineWidth(const AValue: Integer);
    procedure SetLeftCol(const AValue: Integer);
    procedure SetOptions(const AValue: TGridOptions);
    procedure SetRow(AValue: Integer);
    procedure SetRowCount(AValue: Integer);
    procedure SetRowheights(Arow: Integer; Avalue: Integer);
    procedure SetScrollBars(const AValue: TScrollStyle);
    procedure SetSelectActive(const AValue: Boolean);
    procedure SetSelection(const AValue: TGridRect);
    procedure SetTopRow(const AValue: Integer);
    procedure TryScrollTo(aCol,aRow: integer);
    procedure UpdateScrollBarPos(Which: TScrollStyle);
    procedure WriteColumns(Writer: TWriter);
    procedure WriteColWidths(Writer: TWriter);
    procedure WriteRowHeights(Writer: TWriter);
    procedure WMEraseBkgnd(var message: TLMEraseBkgnd); message LM_ERASEBKGND;
    procedure WMGetDlgCode(var Msg: TLMNoParams); message LM_GETDLGCODE;
    procedure WMChar(var message: TLMChar); message LM_CHAR;
  protected
    fGridState: TGridState;
    procedure AutoAdjustColumn(aCol: Integer); virtual;
    procedure BeforeMoveSelection(const DCol,DRow: Integer); virtual;
    procedure CalcAutoSizeColumn(const Index: Integer; var AMin,AMax,APriority: Integer); dynamic;
    procedure CalcFocusRect(var ARect: TRect);
    function  CanEditShow: Boolean; virtual;
    function  CanGridAcceptKey(Key: Word; Shift: TShiftState): Boolean; dynamic;
    procedure CellClick(const aCol,aRow: Integer); virtual;
    procedure CheckLimits(var aCol,aRow: Integer);
    procedure ColRowDeleted(IsColumn: Boolean; index: Integer); dynamic;
    procedure ColRowExchanged(IsColumn: Boolean; index,WithIndex: Integer); dynamic;
    procedure ColRowInserted(IsColumn: boolean; index: integer); dynamic;
    procedure ColRowMoved(IsColumn: Boolean; FromIndex,ToIndex: Integer); dynamic;
    function  ColRowToOffset(IsCol, Relative: Boolean; Index:Integer;
                             var StartPos, EndPos: Integer): Boolean;
    function  ColumnIndexFromGridColumn(Column: Integer): Integer;
    function  ColumnFromGridColumn(Column: Integer): TGridColumn;
    procedure ColumnsChanged(aColumn: TGridColumn);
    procedure ColWidthsChanged; dynamic;
    function  CreateColumns: TGridColumns; virtual;
    procedure CheckNewCachedSizes(var AGCache:TGridDataCache); virtual;
    procedure CreateWnd; override;
    procedure CreateParams(var Params: TCreateParams); override;
    procedure DblClick; override;
    procedure DefineProperties(Filer: TFiler); override;
    procedure DestroyHandle; override;
    function  DoCompareCells(Acol,ARow,Bcol,BRow: Integer): Integer; dynamic;
    procedure DoCopyToClipboard; virtual;
    procedure DoCutToClipboard; virtual;
    procedure DoEditorHide; virtual;
    procedure DoEditorShow; virtual;
    procedure DoExit; override;
    procedure DoEnter; override;
    function  DoMouseWheelDown(Shift: TShiftState; MousePos: TPoint): Boolean; override;
    function  DoMouseWheelUp(Shift: TShiftState; MousePos: TPoint): Boolean; override;
    procedure DoOnChangeBounds; override;
    procedure DoOPDeleteColRow(IsColumn: Boolean; index: Integer);
    procedure DoOPExchangeColRow(IsColumn: Boolean; index, WithIndex: Integer);
    procedure DoOPInsertColRow(IsColumn: boolean; index: integer);
    procedure DoOPMoveColRow(IsColumn: Boolean; FromIndex, ToIndex: Integer);
    procedure DoPasteFromClipboard; virtual;
    procedure DoSetBounds(ALeft, ATop, AWidth, AHeight: integer); override;
    procedure DrawBorder;
    procedure DrawAllRows; virtual;
    procedure DrawCell(aCol,aRow:Integer; aRect:TRect; aState:TGridDrawState); virtual;
    procedure DrawCellGrid(aCol,aRow: Integer; aRect: TRect; aState: TGridDrawState); virtual;
    procedure DrawCellText(aCol,aRow: Integer; aRect: TRect; aState: TGridDrawState; aText: String); virtual;
    procedure DrawColRowMoving;
    procedure DrawEdges;
    procedure DrawFocusRect(aCol,aRow:Integer; ARect:TRect); virtual;
    procedure DrawRow(aRow: Integer); virtual;
    procedure EditButtonClicked(Sender: TObject);
    procedure EditordoGetValue; virtual;
    procedure EditordoSetValue; virtual;
    function  EditorCanAcceptKey(const ch: Char): boolean; virtual;
    function  EditorIsReadOnly: boolean; virtual;
    procedure EditorHide; virtual;
    function  EditorLocked: boolean;
    procedure EditorSelectAll;
    procedure EditorShow(const SelAll: boolean); virtual;
    procedure EditorShowInCell(const aCol,aRow:Integer); virtual;
    procedure EditorWidthChanged(aCol,aWidth: Integer); virtual;
    function  FixedGrid: boolean;
    procedure FontChanged(Sender: TObject); override;
    procedure GetAutoFillColumnInfo(const Index: Integer; var aMin,aMax,aPriority: Integer); dynamic;
    function  GetColumnAlignment(Column: Integer; ForTitle: Boolean): TAlignment;
    function  GetColumnColor(Column: Integer; ForTitle: Boolean): TColor;
    function  GetColumnFont(Column: Integer; ForTitle: Boolean): TFont;
    function  GetColumnLayout(Column: Integer; ForTitle: boolean): TTextLayout;
    function  GetColumnReadonly(Column: Integer): boolean;
    function  GetColumnTitle(Column: Integer): string;
    function  GetColumnWidth(Column: Integer): Integer;
    function  GetDeltaMoveNext(const Inverse: boolean; var ACol,ARow: Integer): boolean; virtual;
    function  GetDefaultColumnAlignment(Column: Integer): TAlignment; virtual;
    function  GetDefaultColumnWidth(Column: Integer): Integer; virtual;
    function  GetDefaultColumnLayout(Column: Integer): TTextLayout; virtual;
    function  GetDefaultColumnReadOnly(Column: Integer): boolean; virtual;
    function  GetDefaultColumnTitle(Column: Integer): string; virtual;
    function  GetDefaultEditor(Column: Integer): TWinControl;
    function  GetScrollBarPosition(Which: integer): Integer;
    function  GetEditMask(ACol, ARow: Longint): string; dynamic;
    function  GetEditText(ACol, ARow: Longint): string; dynamic;
    function  GetFixedcolor: TColor; virtual;
    function  GetSelectedColor: TColor; virtual;

    procedure HeaderClick(IsColumn: Boolean; index: Integer); dynamic;
    procedure HeaderSized(IsColumn: Boolean; index: Integer); dynamic;
    procedure InternalSetColCount(ACount: Integer);
    procedure InvalidateCell(aCol, aRow: Integer); overload;
    procedure InvalidateCell(aCol, aRow: Integer; Redraw: Boolean); overload;
    procedure InvalidateRange(const aRange: TRect);
    procedure InvalidateCol(ACol: Integer);
    procedure InvalidateFromCol(ACol: Integer);
    procedure InvalidateGrid;
    procedure InvalidateRow(ARow: Integer);
    procedure InvalidateFocused;
    function  GetIsCellSelected(aCol, aRow: Integer): boolean; virtual;
    procedure KeyDown(var Key : Word; Shift : TShiftState); override;
    procedure KeyUp(var Key : Word; Shift : TShiftState); override;
    procedure LoadContent(cfg: TXMLConfig; Version: Integer); virtual;
    procedure Loaded; override;
    procedure LockEditor;
    procedure MouseDown(Button: TMouseButton; Shift:TShiftState; X,Y:Integer); override;
    procedure MouseMove(Shift: TShiftState; X,Y: Integer);override;
    procedure MouseUp(Button: TMouseButton; Shift:TShiftState; X,Y:Integer); override;
    function  MoveExtend(Relative: Boolean; DCol, DRow: Integer): Boolean;
    function  MoveNextAuto(const Inverse: boolean): boolean;
    function  MoveNextSelectable(Relative:Boolean; DCol, DRow: Integer): Boolean;
    procedure MoveSelection; virtual;
    function  OffsetToColRow(IsCol,Fisical:Boolean; Offset:Integer;
                             var Index,Rest:Integer): boolean;
    procedure Paint; override;
    procedure PickListItemSelected(Sender: TObject);
    procedure PrepareCanvas(aCol,aRow: Integer; aState:TGridDrawState); virtual;
    procedure ResetOffset(chkCol, ChkRow: Boolean);
    procedure ResizeColumn(aCol, aWidth: Integer);
    procedure ResizeRow(aRow, aHeight: Integer);
    procedure RowHeightsChanged; dynamic;
    procedure SaveContent(cfg: TXMLConfig); virtual;
    procedure ScrollBarRange(Which:Integer; aRange,aPage: Integer);
    procedure ScrollBarPosition(Which, Value: integer);
    function  ScrollBarIsVisible(Which:Integer): Boolean;
    procedure ScrollBarPage(Which: Integer; aPage: Integer);
    procedure ScrollBarShow(Which: Integer; aValue: boolean);
    function  ScrollBarAutomatic(Which: TScrollStyle): boolean; virtual;
    procedure SelectEditor; virtual;
    function  SelectCell(ACol, ARow: Integer): Boolean; virtual;
    procedure SetCanvasFont(aFont: TFont);
    procedure SetColor(Value: TColor); override;
    procedure SetColRow(const ACol,ARow: Integer);
    procedure SetEditText(ACol, ARow: Longint; const Value: string); dynamic;
    procedure SetBorderStyle(NewStyle: TBorderStyle); override;
    procedure SetFixedcolor(const AValue: TColor); virtual;
    procedure SetSelectedColor(const AValue: TColor); virtual;
    procedure SizeChanged(OldColCount, OldRowCount: Integer); dynamic;
    procedure Sort(ColSorting: Boolean; index,IndxFrom,IndxTo:Integer); virtual;
    procedure TopLeftChanged; dynamic;
    function  TryMoveSelection(Relative: Boolean; var DCol, DRow: Integer): Boolean;
    procedure UnLockEditor;
    procedure UpdateHorzScrollBar(const aVisible: boolean; const aRange,aPage: Integer); virtual;
    procedure UpdateSelectionRange;
    procedure UpdateVertScrollbar(const aVisible: boolean; const aRange,aPage: Integer); virtual;
    procedure UpdateBorderStyle;
    procedure VisualChange; virtual;
    procedure WMHScroll(var message : TLMHScroll); message LM_HSCROLL;
    procedure WMVScroll(var message : TLMVScroll); message LM_VSCROLL;
    procedure WMKillFocus(var message: TLMKillFocus); message LM_KILLFOCUS;
    procedure WMSetFocus(var message: TLMSetFocus); message LM_SETFOCUS;
    procedure WndProc(var TheMessage : TLMessage); override;

    property AlternateColor: TColor read FAlternateColor write SetAlternateColor stored IsAltColorStored;
    property AutoAdvance: TAutoAdvance read FAutoAdvance write FAutoAdvance default aaRight;
    property AutoFillColumns: boolean read FAutoFillColumns write SetAutoFillColumns;
    property BorderStyle default bsSingle;
    property BorderColor: TColor read FBorderColor write SetBorderColor default cl3DDKShadow;
    property Col: Integer read FCol write SetCol;
    property ColCount: Integer read GetColCount write SetColCount;
    property Columns: TGridColumns read GetColumns write SetColumns stored IsColumnsStored;
    property ColWidths[aCol: Integer]: Integer read GetColWidths write SetColWidths;
    property DefaultColWidth: Integer read FDefColWidth write SetDefColWidth default DEFCOLWIDTH;
    property DefaultRowHeight: Integer read FDefRowHeight write SetDefRowHeight default DEFROWHEIGHT;
    property DefaultDrawing: Boolean read FDefaultDrawing write SetDefaultDrawing default True;
    property DefaultTextStyle: TTextStyle read FDefaultTextStyle write FDefaultTextStyle;
    property DragDx: Integer read FDragDx write FDragDx;
    property Editor: TWinControl read FEditor write SetEditor;
    property EditorBorderStyle: TBorderStyle read GetEditorBorderStyle write SetEditorBorderStyle;
    property EditorMode: Boolean read FEditorMode write EditorSetMode;
    property EditorKey: boolean read FEditorKey write FEditorKey;
    property EditorOptions: Integer read FEditorOptions write SetEditorOptions;
    property EditorShowing: boolean read FEditorShowing write FEditorShowing;
    property ExtendedColSizing: boolean read FExtendedColSizing write FExtendedColSizing;
    property ExtendedRowSizing: boolean read FExtendedRowSizing write FExtendedRowSizing;
    property ExtendedSelect: boolean read FExtendedSelect write FExtendedSelect;
    property FastEditing: boolean read FFastEditing write FFastEditing;
    property AltColorStartNormal: boolean read FAltColorStartNormal write SetAltColorStartNormal;
    property FixedCols: Integer read FFixedCols write SetFixedCols default 1;
    property FixedRows: Integer read FFixedRows write SetFixedRows default 1;
    property FixedColor: TColor read GetFixedColor write SetFixedcolor;
    property Flat: Boolean read FFlat write SetFlat default false;
    property FocusColor: TColor read FFocusColor write SetFocusColor;
    property FocusRectVisible: Boolean read FFocusRectVisible write SetFocusRectVisible;
    property GCache: TGridDataCache read FGCAChe;
    property GridFlags: TGridFlags read FGridFlags write FGridFlags;
    property GridHeight: Integer read FGCache.GridHeight;
    property GridLineColor: TColor read FGridLineColor write SetGridLineColor default clSilver;
    property GridLineStyle: TPenStyle read FGridLineStyle write SetGridLineStyle;
    property GridLineWidth: Integer read FGridLineWidth write SetGridLineWidth default 1;
    property GridWidth: Integer read FGCache.GridWidth;
    property InplaceEditor: TWinControl read FEditor;
    property IsCellSelected[aCol,aRow: Integer]: boolean read GetIsCellSelected;
    property LeftCol:Integer read GetLeftCol write SetLeftCol;
    property Options: TGridOptions read FOptions write SetOptions;
    property Row: Integer read FRow write SetRow;
    property RowCount: Integer read GetRowCount write SetRowCount;
    property RowHeights[aRow: Integer]: Integer read GetRowHeights write SetRowHeights;
    property SaveOptions: TSaveOptions read FsaveOptions write FSaveOptions;
    property SelectActive: Boolean read FSelectActive write SetSelectActive;
    property SelectedColor: TColor read GetSelectedColor write SetSelectedColor;
    property SelectedColumn: TGridColumn read GetSelectedColumn;
    property Selection: TGridRect read GetSelection write SetSelection;
    property ScrollBars: TScrollStyle read FScrollBars write SetScrollBars;
    property StrictSort: boolean read FStrictSort write FStrictSort;
    property TitleFont: TFont read FTitleFont write SetTitleFont;
    property TitleStyle: TTitleStyle read FTitleStyle write SetTitleStyle;
    property TopRow: Integer read GetTopRow write SetTopRow;
    property UseXORFeatures: boolean read FUseXORFeatures write SetUseXorFeatures;
    property VisibleColCount: Integer read GetVisibleColCount stored false;
    property VisibleRowCount: Integer read GetVisibleRowCount stored false;

    property OnBeforeSelection: TOnSelectEvent read FOnBeforeSelection write FOnBeforeSelection;
    property OnCompareCells: TOnCompareCells read FOnCompareCells write FOnCompareCells;
    property OnPrepareCanvas: TOnPrepareCanvasEvent read FOnPrepareCanvas write FOnPrepareCanvas;
    property OnDrawCell: TOnDrawCell read FOnDrawCell write FOnDrawCell;
    property OnEditButtonClick: TNotifyEvent read FOnEditButtonClick write FOnEditButtonClick;
    property OnPickListSelect: TNotifyEvent read FOnPickListSelect write FOnPickListSelect;
    property OnSelection: TOnSelectEvent read fOnSelection write fOnSelection;
    property OnSelectEditor: TSelectEditorEvent read FOnSelectEditor write FOnSelectEditor;
    property OnTopLeftChanged: TNotifyEvent read FOnTopLeftChanged write FOnTopLeftChanged;

  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure Invalidate; override;
    procedure EditingDone; override;

    { Exposed procs }
    procedure AutoAdjustColumns;
    procedure BeginUpdate;
    function  CellRect(ACol, ARow: Integer): TRect;
    function  CellToGridZone(aCol,aRow: Integer): TGridZone;
    procedure CheckPosition;
    procedure Clear;

    function  EditorByStyle(Style: TColumnButtonStyle): TWinControl; virtual;
    procedure EditorExit(Sender: TObject);
    procedure EditorKeyDown(Sender: TObject; var Key:Word; Shift:TShiftState);
    procedure EditorKeyPress(Sender: TObject; var Key: Char);
    procedure EditorKeyUp(Sender: TObject; var key:Word; shift:TShiftState);
    procedure EndUpdate(UO: TUpdateOption); overload;
    procedure EndUpdate(FullUpdate: Boolean); overload;
    procedure EndUpdate; overload;
    procedure EraseBackground(DC: HDC); override;

    function  IscellVisible(aCol, aRow: Integer): Boolean;
    procedure LoadFromFile(FileName: string);
    function  MouseCoord(X,Y: Integer): TGridCoord;
    function  MouseToCell(const Mouse: TPoint): TPoint; overload;
    procedure MouseToCell(X,Y: Integer; var ACol,ARow: Longint); overload;
    function  MouseToLogcell(Mouse: TPoint): TPoint;
    function  MouseToGridZone(X,Y: Integer): TGridZone;
    procedure SaveToFile(FileName: string);
    procedure SetFocus; override;
  end;

  TGetEditEvent = procedure (Sender: TObject; ACol, ARow: Integer; var Value: string) of object;
  TSetEditEvent = procedure (Sender: TObject; ACol, ARow: Integer; const Value: string) of object;

  { TCustomDrawGrid }

  TCustomDrawGrid=class(TCustomGrid)
  private
    FOnColRowDeleted: TgridOperationEvent;
    FOnColRowExchanged: TgridOperationEvent;
    FOnColRowInserted: TGridOperationEvent;
    FOnColRowMoved: TgridOperationEvent;
    FOnGetEditMask: TGetEditEvent;
    FOnGetEditText: TGetEditEvent;
    FOnHeaderClick, FOnHeaderSized: THdrEvent;
    FOnSelectCell: TOnSelectcellEvent;
    FOnSetEditText: TSetEditEvent;
  protected
    FGrid: TVirtualGrid;
    procedure CalcCellExtent(acol, aRow: Integer; var aRect: TRect); virtual;
    procedure ColRowDeleted(IsColumn: Boolean; index: Integer); override;
    procedure ColRowExchanged(IsColumn: Boolean; index,WithIndex: Integer); override;
    procedure ColRowInserted(IsColumn: boolean; index: integer); override;
    procedure ColRowMoved(IsColumn: Boolean; FromIndex,ToIndex: Integer); override;
    function  CreateVirtualGrid: TVirtualGrid; virtual;
    procedure DrawCell(aCol,aRow: Integer; aRect: TRect; aState:TGridDrawState); override;
    procedure DrawCellAutonumbering(aCol,aRow: Integer; aRect: TRect; const aValue: string); virtual;
    procedure DrawFocusRect(aCol,aRow: Integer; ARect: TRect); override;
    procedure GetAutoFillColumnInfo(const Index: Integer; var aMin,aMax,aPriority: Integer); override;
    function  GetEditMask(aCol, aRow: Longint): string; override;
    function  GetEditText(aCol, aRow: Longint): string; override;
    procedure HeaderClick(IsColumn: Boolean; index: Integer); override;
    procedure HeaderSized(IsColumn: Boolean; index: Integer); override;
    procedure NotifyColRowChange(WasInsert,IsColumn:boolean; FromIndex,ToIndex:Integer);
    function  SelectCell(aCol,aRow: Integer): boolean; override;
    procedure SetColor(Value: TColor); override;
    procedure SetEditText(ACol, ARow: Longint; const Value: string); override;
    procedure SizeChanged(OldColCount, OldRowCount: Integer); override;
    
  public

    // to easy user call
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure DeleteColRow(IsColumn: Boolean; index: Integer);
    procedure ExchangeColRow(IsColumn: Boolean; index, WithIndex: Integer);
    procedure InsertColRow(IsColumn: boolean; index: integer);
    procedure MoveColRow(IsColumn: Boolean; FromIndex, ToIndex: Integer);
    procedure SortColRow(IsColumn: Boolean; index:Integer); overload;
    procedure SortColRow(IsColumn: Boolean; Index,FromIndex,ToIndex: Integer); overload;

    procedure DefaultDrawCell(aCol,aRow: Integer; var aRect: TRect; aState:TGridDrawState); virtual;
    // properties
    property BorderColor;
    property Canvas;
    property Col;
    property ColWidths;
    property Editor;
    property EditorBorderStyle;
    property EditorMode;
    property ExtendedColSizing;
    property AltColorStartNormal;
    property FocusColor;
    property FocusRectVisible;
    property GridHeight;
    property GridLineColor;
    property GridLineStyle;
    property GridWidth;
    property IsCellSelected;
    property LeftCol;
    property Row;
    property RowHeights;
    property SaveOptions;
    property SelectedColor;
    property SelectedColumn;
    property Selection;
    property StrictSort;
    //property TabStops;
    property TopRow;
    property UseXORFeatures;
  public
    property Align;
    property Anchors;
    property AutoAdvance;
    property AutoFillColumns;
    //property BiDiMode;
    property BorderSpacing;
    property BorderStyle;
    property Color default clWindow;
    property ColCount;
    property Columns;
    //property Constraints;
    //property Ctl3D; // Deprecated
    property DefaultColWidth;
    property DefaultDrawing;
    property DefaultRowHeight;
    //property DragCursor;
    //property DragKind;
    //property DragMode;
    property Enabled;
    property FixedColor;
    property FixedCols;
    property FixedRows;
    property Flat;
    property Font;
    property GridLineWidth;
    property Options;
    //property ParentBiDiMode;
    //property ParentColor;
    //property ParentCtl3D; // Deprecated
    //property ParentFont;
    property ParentShowHint;
    property PopupMenu;
    property RowCount;
    property ScrollBars;
    property ShowHint;
    property TabOrder;
    property TabStop;
    property Visible;
    property VisibleColCount;
    property VisibleRowCount;


    property OnBeforeSelection;
    property OnClick;
    property OnColRowDeleted: TgridOperationEvent read FOnColRowDeleted write FOnColRowDeleted;
    property OnColRowExchanged: TgridOperationEvent read FOnColRowExchanged write FOnColRowExchanged;
    property OnColRowInserted: TGridOperationEvent read FOnColRowInserted write FOnColRowInserted;
    property OnColRowMoved: TgridOperationEvent read FOnColRowMoved write FOnColRowMoved;
    property OnCompareCells;
    property OnDblClick;
    property OnDrawCell;
    property OnEditButtonClick;
    property OnEnter;
    property OnExit;
    property OnGetEditMask: TGetEditEvent read FOnGetEditMask write FOnGetEditMask;
    property OnGetEditText: TGetEditEvent read FOnGetEditText write FOnGetEditText;
    property OnHeaderClick: THdrEvent read FOnHeaderClick write FOnHeaderClick;
    property OnHeaderSized: THdrEvent read FOnHeaderSized write FOnHeaderSized;
    property OnKeyDown;
    property OnKeyPress;
    property OnKeyUp;
    property OnMouseDown;
    property OnMouseMove;
    property OnMouseUp;
    property OnMouseWheelDown;
    property OnMouseWheelUp;
    property OnPickListSelect;
    property OnPrepareCanvas;
    property OnSelectEditor;
    property OnSelection;
    property OnSelectCell: TOnSelectCellEvent read FOnSelectCell write FOnSelectCell;
    property OnSetEditText: TSetEditEvent read FOnSetEditText write FOnSetEditText;
    property OnTopleftChanged;

{
    property OnContextPopup;
    property OnDragDrop;
    property OnDragOver;
    property OnEndDock;
    property OnEndDrag;
    property OnStartDock;
    property OnStartDrag;
}
  end;



  { TDrawGrid }

  TDrawGrid = class(TCustomDrawGrid)
  published
    property Align;
    property AlternateColor;
    property Anchors;
    property AutoAdvance;
    property AutoFillColumns;
    //property BiDiMode;
    property BorderSpacing;
    property BorderStyle;
    property Color;
    property ColCount;
    property Columns;
    //property Constraints;
    //property Ctl3D; // Deprecated
    property DefaultColWidth;
    property DefaultDrawing;
    property DefaultRowHeight;
    property DragCursor;
    //property DragKind;
    property DragMode;
    property Enabled;
    property FixedColor;
    property FixedCols;
    property FixedRows;
    property Flat;
    property Font;
    property GridLineWidth;
    property Options;
    //property ParentBiDiMode;
    //property ParentColor;
    //property ParentCtl3D; // Deprecated
    //property ParentFont;
    property ParentShowHint;
    property PopupMenu;
    property RowCount;
    property ScrollBars;
    property ShowHint;
    property TabOrder;
    property TabStop;
    property TitleFont;
    property TitleStyle;
    property Visible;
    property VisibleColCount;
    property VisibleRowCount;


    property OnBeforeSelection;
    property OnClick;
    property OnColRowDeleted;
    property OnColRowExchanged;
    property OnColRowInserted;
    property OnColRowMoved;
    property OnCompareCells;
    property OnDblClick;
    property OnDrawCell;
    property OnEditButtonClick;
    property OnEnter;
    property OnExit;
    property OnGetEditMask;
    property OnGetEditText;
    property OnHeaderClick;
    property OnHeaderSized;
    property OnKeyDown;
    property OnKeyPress;
    property OnKeyUp;
    property OnMouseDown;
    property OnMouseMove;
    property OnMouseUp;
    property OnMouseWheelDown;
    property OnMouseWheelUp;
    property OnPickListSelect;
    property OnPrepareCanvas;
    property OnSelectEditor;
    property OnSelection;
    property OnSelectCell;
    property OnSetEditText;
    property OnTopleftChanged;
    //property OnContextPopup;
    property OnDragDrop;
    property OnDragOver;
    //property OnEndDock;
    property OnEndDrag;
    //property OnStartDock;
    property OnStartDrag;
  end;


  { TCustomStringGrid }

  TCustomStringGrid = class(TCustomDrawGrid)
    private
      FModified: boolean;
      function  GetCells(ACol, ARow: Integer): string;
      function  GetCols(index: Integer): TStrings;
      function  GetObjects(ACol, ARow: Integer): TObject;
      function  GetRows(index: Integer): TStrings;
      procedure ReadCells(Reader: TReader);
      procedure SetCells(ACol, ARow: Integer; const AValue: string);
      procedure SetCols(index: Integer; const AValue: TStrings);
      procedure SetObjects(ACol, ARow: Integer; AValue: TObject);
      procedure SetRows(index: Integer; const AValue: TStrings);
      procedure WriteCells(Writer: TWriter);
    protected
      procedure AutoAdjustColumn(aCol: Integer); override;
      procedure CalcCellExtent(acol, aRow: Integer; var aRect: TRect); override;
      procedure DefineProperties(Filer: TFiler); override;
      function  DoCompareCells(Acol,ARow,Bcol,BRow: Integer): Integer; override;
      procedure DoCopyToClipboard; override;
      procedure DoCutToClipboard; override;
      procedure DoPasteFromClipboard; override;
      procedure DrawCell(aCol,aRow: Integer; aRect: TRect; aState:TGridDrawState); override;
      procedure DrawCellAutonumbering(aCol,aRow: Integer; aRect: TRect; const aValue: string); override;
      //procedure EditordoGetValue; override;
      //procedure EditordoSetValue; override;
      function  GetEditText(aCol, aRow: Integer): string; override;
      procedure LoadContent(cfg: TXMLConfig; Version: Integer); override;
      procedure Loaded; override;
      procedure SaveContent(cfg: TXMLConfig); override;
      //procedure DrawInteriorCells; override;
      //procedure SelectEditor; override;
      procedure SelectionSetText(TheText: String);
      procedure SetEditText(aCol, aRow: Longint; const aValue: string); override;
      
      property Modified: boolean read FModified write FModified;

    public
      constructor Create(AOwner: TComponent); override;
      //destructor Destroy; override;
      procedure AutoSizeColumn(aCol: Integer);
      procedure AutoSizeColumns;
      procedure Clean; overload;
      procedure Clean(CleanOptions: TCleanOptions); overload;
      procedure Clean(aRect: TRect; CleanOptions: TCleanOptions); overload;
      procedure Clean(StartCol,StartRow,EndCol,EndRow: integer; CleanOptions: TCleanOptions); overload;
      property Cells[ACol, ARow: Integer]: string read GetCells write SetCells;
      property Cols[index: Integer]: TStrings read GetCols write SetCols;
      property DefaultTextStyle;
      property EditorMode;
      property ExtendedSelect;
      property Objects[ACol, ARow: Integer]: TObject read GetObjects write SetObjects;
      property Rows[index: Integer]: TStrings read GetRows write SetRows;
      property UseXORFeatures;
  end;


  { TStringGrid }

  TStringGrid = class(TCustomStringGrid)
  public
    property Modified;
  published
    property Align;
    property AlternateColor;
    property Anchors;
    property AutoAdvance;
    property AutoFillColumns;
    //property BiDiMode;
    property BorderSpacing;
    property BorderStyle;
    property Color;
    property ColCount;
    property Columns;
    //property Constraints;
    //property Ctl3D; // Deprecated
    property DefaultColWidth;
    property DefaultDrawing;
    property DefaultRowHeight;
    //property DragCursor;
    //property DragKind;
    //property DragMode;
    property Enabled;
    property FixedColor;
    property FixedCols;
    property FixedRows;
    property Flat;
    property Font;
    property GridLineWidth;
    property Options;
    //property ParentBiDiMode;
    //property ParentColor;
    //property ParentCtl3D; // Deprecated
    //property ParentFont;
    property ParentShowHint;
    property PopupMenu;
    property RowCount;
    property ScrollBars;
    property ShowHint;
    property TabOrder;
    property TabStop;
    property TitleFont;
    property TitleStyle;
    property Visible;
    property VisibleColCount;
    property VisibleRowCount;


    property OnBeforeSelection;
    property OnChangeBounds;
    property OnClick;
    property OnColRowDeleted;
    property OnColRowExchanged;
    property OnColRowInserted;
    property OnColRowMoved;
    property OnCompareCells;
    property OnDblClick;
    property OnDrawCell;
    property OnEditButtonClick;
    property OnEditingDone;
    property OnEnter;
    property OnExit;
    property OnGetEditMask;
    property OnGetEditText;
    property OnHeaderClick;
    property OnHeaderSized;
    property OnKeyDown;
    property OnKeyPress;
    property OnKeyUp;
    property OnMouseDown;
    property OnMouseMove;
    property OnMouseUp;
    property OnMouseWheelDown;
    property OnMouseWheelUp;
    property OnPickListSelect;
    property OnPrepareCanvas;
    property OnResize;
    property OnSelectEditor;
    property OnSelection;
    property OnSelectCell;
    property OnSetEditText;
    property OnShowHint;
    property OnTopLeftChanged;

{
    property OnContextPopup;
    property OnDragDrop;
    property OnDragOver;
    property OnEndDock;
    property OnEndDrag;
    property OnStartDock;
    property OnStartDrag;
}
  end;


procedure DrawRubberRect(Canvas: TCanvas; aRect: TRect; Color: TColor);


procedure Register;

implementation

function PointIgual(const P1,P2: TPoint): Boolean;
begin
  result:=(P1.X=P2.X)and(P1.Y=P2.Y);
end;

function NormalizarRect(const R:TRect): TRect;
begin
  Result.Left:=Min(R.Left, R.Right);

  Result.Top:=Min(R.Top, R.Bottom);
  Result.Right:=Max(R.Left, R.Right);
  Result.Bottom:=Max(R.Top, R.Bottom);
end;

procedure SwapInt(var I1,I2: Integer);
var
  Tmp: Integer;
begin
  Tmp:=I1;
  I1:=I2;
  I2:=Tmp;
end;

{$ifdef GridTraceMsg}
function TransMsg(const S: String; const TheMsg: TLMessage): String;
begin
  case TheMsg.Msg of
    CM_BASE..CM_MOUSEWHEEL:
      case TheMsg.Msg of
        CM_MOUSEENTER:            exit; //Result := 'CM_MOUSEENTER';
        CM_MOUSELEAVE:            exit; //Result := 'CM_MOUSELEAVE';
        CM_TEXTCHANGED:           Result := 'CM_TEXTCHANGED';
        CM_PARENTCTL3DCHANGED:    Result := 'CM_PARENTCTL3DCHANGED';
        CM_UIACTIVATE:            Result := 'CM_UIACTIVATE';
        CM_CONTROLLISTCHANGE:     Result := 'CM_CONTROLLISTCHANGE';

        CM_PARENTCOLORCHANGED:    Result := 'CM_PARENTCOLORCHANGED';
        CM_PARENTSHOWHINTCHANGED: Result := 'CM_PARENTSHOWHINTCHANGED';
        CM_PARENTBIDIMODECHANGED: Result := 'CM_PARENTBIDIMODECHANGED';
        CM_CONTROLCHANGE:         Result := 'CM_CONTROLCHANGE';
        CM_SHOWINGCHANGED:        Result := 'CM_SHOWINGCHANGED';
        CM_VISIBLECHANGED:        Result := 'CM_VISIBLECHANGED';
        CM_HITTEST:               exit;//Result := 'CM_HITTEST';
        else                      Result := 'CM_BASE + '+ IntToStr(TheMsg.Msg - CM_BASE);
      end;
    else
      case TheMsg.Msg of
        //CN_BASE MESSAGES
        CN_COMMAND:               Result := 'CN_COMMAND';
        CN_KEYDOWN:               Result := 'CN_KEYDOWN';
        CN_KEYUP:                 Result := 'CN_KEYUP';
        CN_CHAR:                  Result := 'CN_CHAR';

        // NORMAL MESSAGES
        LM_SETFOCUS:              Result := 'LM_SetFocus';
        LM_LBUTTONDOWN:           Result := 'LM_MOUSEDOWN';
        LM_LBUTTONUP:             Result := 'LM_LBUTTONUP';
        LM_LBUTTONDBLCLK:         Result := 'LM_LBUTTONDBLCLK';
        LM_RBUTTONDOWN:           Result := 'LM_RBUTTONDOWN';
        LM_RBUTTONUP:             Result := 'LM_RBUTTONUP';
        LM_RBUTTONDBLCLK:         Result := 'LM_RBUTTONDBLCLK';
        LM_GETDLGCODE:            Result := 'LM_GETDLGCODE';
        LM_KEYDOWN:               Result := 'LM_KEYDOWN';
        LM_KEYUP:                 Result := 'LM_KEYUP';
        LM_CAPTURECHANGED:        Result := 'LM_CAPTURECHANGED';
        LM_ERASEBKGND:            Result := 'LM_ERASEBKGND';
        LM_KILLFOCUS:             Result := 'LM_KILLFOCUS';
        LM_CHAR:                  Result := 'LM_CHAR';
        LM_SHOWWINDOW:            Result := 'LM_SHOWWINDOW';
        LM_SIZE:                  Result := 'LM_SIZE';
        LM_WINDOWPOSCHANGED:      Result := 'LM_WINDOWPOSCHANGED';
        LM_HSCROLL:               Result := 'LM_HSCROLL';
        LM_VSCROLL:               Result := 'LM_VSCROLL';
        LM_MOUSEMOVE:             exit;//Result := 'LM_MOUSEMOVE';
        LM_MOUSEWHEEL:            Result := 'LM_MOUSEWHEEL';
        1105:                     exit;//Result := '?EM_SETWORDBREAKPROCEX?';
        else                      Result := GetMessageName(TheMsg.Msg);
      end;
  end;
  Result:= S + '['+IntToHex(TheMsg.msg, 8)+'] W='+IntToHex(TheMsg.WParam,8)+
    ' L='+IntToHex(TheMsg.LParam,8)+' '+Result;
  DebugLn(Result);
end;
{$Endif GridTraceMsg}


procedure DrawRubberRect(Canvas: TCanvas; aRect: TRect; Color: TColor);
  procedure DrawVertLine(X1,Y1,Y2: integer);
  begin
    if Y2<Y1 then
      while Y2<Y1 do begin
        Canvas.Pixels[X1, Y1] := Color;
        dec(Y1, constRubberSpace);
      end
    else
      while Y1<Y2 do begin
        Canvas.Pixels[X1, Y1] := Color;
        inc(Y1, constRubberSpace);
      end;
  end;
  procedure DrawHorzLine(X1,Y1,X2: integer);
  begin
    if X2<X1 then
      while X2<X1 do begin
        Canvas.Pixels[X1, Y1] := Color;
        dec(X1, constRubberSpace);
      end
    else
      while X1<X2 do begin
        Canvas.Pixels[X1, Y1] := Color;
        inc(X1, constRubberSpace);
      end;
  end;
begin
  with aRect do begin
    DrawHorzLine(Left, Top, Right-1);
    DrawVertLine(Right-1, Top, Bottom-1);
    DrawHorzLine(Right-1, Bottom-1, Left);
    DrawVertLine(Left, Bottom-1, Top);
  end;
end;

{ TCustomGrid }

function TCustomGrid.GetRowHeights(Arow: Integer): Integer;
begin
  if (aRow<RowCount) and (aRow>=0) then
    Result:=PtrInt(FRows[aRow])
  else
    Result:=-1;
  if Result<0 then Result:=fDefRowHeight;
end;

function TCustomGrid.GetTopRow: Longint;
begin
  Result:=fTopLeft.y;
end;

function TCustomGrid.GetVisibleColCount: Integer;
var
  R: TRect;
begin
  R:=FGCache.VisibleGrid;
  Result:=R.Right-R.left+1;
end;

function TCustomGrid.GetVisibleRowCount: Integer;
var
  R: TRect;
begin
  R:=FGCache.VisibleGrid;
  Result:=r.bottom-r.top+1;
end;

procedure TCustomGrid.InternalAutoFillColumns;
  procedure SetColumnWidth(aCol,aWidth: Integer);
  begin
    if csLoading in ComponentState then
      SetRawColWidths(aCol, aWidth)
    else
      SetColWidths(aCol, aWidth);
  end;
var
  I, ForcedIndex: Integer;
  Count: Integer;
  aPriority, aMin, aMax: Integer;
  AvailableSize: Integer;
  TotalWidth: Integer;     // total grid's width
  FixedSizeWidth: Integer; // total width of Fixed Sized Columns
begin
  if not AutoFillColumns then
    exit;

  if FUpdatingAutoFillCols then
    exit;

  FUpdatingAutoFillCols:=True;
  try
    // if needed, last size can be obtained from FLastWidth
    // when InternalAutoFillColumns is called from DoChangeBounds
    // for example.

    // Insert the algorithm that modify ColWidths accordingly
    //
    // For testing purposes, a simple algortihm is implemented:
    // if SizePriority=0, column size should be unmodified
    // if SizePriority<>0 means variable size column, its size
    // is the average avalilable size.

    Count := 0;
    FixedSizeWidth := 0;
    TotalWidth := 0;
    for i:=0 to ColCount-1 do begin
      GetAutoFillColumnInfo(i, aMin, aMax, aPriority);
      AvailableSize := GetColWidths(i);
      if aPriority>0 then
        Inc(Count)
      else
        Inc(FixedSizeWidth, AvailableSize);
      Inc(TotalWidth, AvailableSize);
    end;

    if Count=0 then begin
      //it's an autofillcolumns grid, so at least one
      // of the columns must fill completly the grid's
      // available width, let it be that column the last
      ForcedIndex := ColCount-1;
      Count := 1;
    end else
      ForcedIndex := -1;

    AvailableSize := Width {ClientWidth} - FixedSizeWidth - GetBorderWidth;
    if AvailableSize<0 then begin
      // There is no space available to fill with
      // Variable Size Columns, what to do?

      // Simply set all Variable Size Columns
      // to 0, decreasing the size beyond this
      // shouldn't be allowed.
      for i:=0 to ColCount-1 do begin
        GetAutoFillColumnInfo(i, aMin, aMax, aPriority);
        if aPriority>0 then
          SetColumnWidth(i, 0);
      end;
    end else begin
      // Simpler case: There is actually available space to
      //     to be shared for variable size columns.
      FixedSizeWidth := AvailableSize mod Count; // space left after filling columns
      AvailableSize := AvailableSize div Count;
      for i:=0 to ColCount-1 do begin
        GetAutoFillColumnInfo(i, aMin, aMax, aPriority);
        if (APriority>0) or (i=ForcedIndex) then
          if i=ColCount-1 then
            // the last column gets all space left
            SetColumnWidth(i, AvailableSize + FixedSizeWidth)
          else
            SetColumnWidth(i, AvailableSize);
      end;
    end;
  finally
    FUpdatingAutoFillCols:=False;
  end;
end;

function TCustomGrid.InternalNeedBorder: boolean;
begin
  {$IFDEF WINDOWS}
  result := FFlat and (FGridBorderStyle = bsSingle);
  {$ELSE}
  result := FGridBorderStyle = bsSingle;
  {$ENDIF}
end;

procedure TCustomGrid.InternalSetColCount(ACount: Integer);
var
  OldC: Integer;
begin
  OldC := FCols.Count;
  if ACount=OldC then Exit;
  if ACount<1 then
    Clear
  else begin
    CheckFixedCount(ACount, RowCount, FFixedCols, FFixedRows);
    CheckCount(ACount, RowCount);
    AdjustCount(True, OldC, ACount);
  end;
end;

procedure TCustomGrid.InternalSetColWidths(aCol, aValue: Integer);
begin
  if AValue<0 then Avalue:=-1;
  if Avalue<>PtrInt(FCols[ACol]) then begin
    SetRawColWidths(ACol, Avalue);
    if not (csLoading in ComponentState) then begin
      VisualChange;
      if (FEditor<>nil)and(Feditor.Visible)and(ACol<=FCol) then
        EditorWidthChanged(aCol, aValue);
      ColWidthsChanged;
    end;
  end;
end;

procedure TCustomGrid.InternalSetFixedCols(const AValue: Integer);
begin
  if FFixedCols=AValue then exit;
  CheckFixedCount(ColCount, RowCount, AValue, FFixedRows);
  FFixedCols:=AValue;
  fTopLeft.x:=AValue;
  fCol:=Avalue;
  UpdateSelectionRange;
  if not (csLoading in componentState) then
    doTopleftChange(true);
end;

procedure TCustomGrid.InternalUpdateColumnWidths;
var
  i: Integer;
  C: TGridColumn;
begin
  for i:= FixedCols to ColCount-1 do begin
    C := ColumnFromGridColumn(i);
    if C<>nil then
      SetRawColWidths(i, C.Width);
  end;
end;

procedure TCustomGrid.InvalidateMovement(DCol, DRow: Integer; OldRange: TRect);

  procedure doInvalidateRange(Col1,Row1,Col2,Row2: Integer);
  begin
    InvalidateRange(Rect(Col1,Row1,Col2,Row2));
  end;
  
begin
  if SelectActive then begin
  
    if DCol>FCol then begin
      // expanded cols
      if not (goRowSelect in Options) then
        doInvalidateRange(FCol, OldRange.Top, DCol, Oldrange.Bottom)
        
      else if (goRelaxedRowSelect in Options) and (DRow=FRow) then
        InvalidateRow(DRow)
        
    end else if DCol<FCol then begin
      // shrunk cols
      if not (goRowSelect in Options) then
        doInvalidateRange(DCol,OldRange.Top,FCol,OldRange.Bottom)
        
      else if (goRelaxedRowSelect in Options) and (DRow=FRow) then
        InvalidateRow(DRow)
        
    end;

    if DRow>FRow then
      // expanded rows
      doInvalidateRange(OldRange.Left, FRow, OldRange.Right, DRow)
      
    else if DRow<FRow then
      // shrunk rows
      doInvalidateRange(OldRange.Left, DRow, OldRange.Right, FRow);
    
    if not (goRowSelect in Options) then begin

      // Above rules do work only if either rows or cols remain
      // constant, if both rows and cols change there may be gaps
      //
      // four cases are left.
      //
      
      if (DCol>FCol)and(DRow<FRow) then // (1: I   Cuadrant)
        // Rect(FCol+1,FRow-1,DCol,DRow) normalized -v
        doInvalidateRange(FCol+1, DRow, DCol, FRow-1)
      else
      if (DCol<FCol)and(DRow<FRow) then // (2: II  Cuadrant)
        // Rect(FCol-1,FRow-1,DCol,DRow) normalized -v
        doInvalidateRange(DCol, DRow, FCol-1, FRow-1)
      else
      if (DCol<FCol)and(DRow>FRow) then // (3: III Cuadrant)
        // Rect(FCol-1,FRow+1,DCol,DRow) normalized -v
        doInvalidateRange(DCol, FRow+1, FCol-1, DRow)
      else
      if (DCol>FCol)and(DRow>FRow) then // (4: IV  Cuadrant)
        // normalization not needed
        doInvalidateRange(FCol+1,FRow+1,DCol,DRow);
        
    end;

  end else begin
  
    if (OldRange.Right-OldRange.Left>0) or
      (OldRange.Bottom-OldRange.Top>0) then
      // old selected range gone, invalidate old area
      InvalidateRange(OldRange)
    else
      // Single cell
      InvalidateCell(FCol, FRow);
    
    // and invalidate current selecion, cell or full row
    if goRowSelect in Options then
      InvalidateRow(Drow)
    else
      InvalidateCell(DCol, DRow);
      
  end;
  
end;

function TCustomGrid.IsColumnsStored: boolean;
begin
  result := Columns.Enabled;
end;

function TCustomGrid.GetLeftCol: Integer;
begin
  result:=fTopLeft.x;
end;

function TCustomGrid.Getcolcount: Integer;
begin
  Result:=FCols.Count;
end;

function TCustomGrid.Getrowcount: Integer;
begin
  Result:=FRows.Count;
end;

function TCustomGrid.GetColWidths(Acol: Integer): Integer;
var
  C: TGridColumn;
begin
  if not Columns.Enabled or (aCol<FixedCols) then begin
    if (aCol<ColCount) and (aCol>=0) then
      Result:=PtrInt(FCols[aCol])
    else
      Result:=-1;
    if result<0 then
      Result:=fDefColWidth;
  end else begin
    C := ColumnFromGridColumn(Acol);
    if C<>nil then
      Result := C.Width
    else
      result := FDefColWidth;
  end;
end;

procedure TCustomGrid.SetEditor(AValue: TWinControl);
var
  Msg: TGridMessage;
begin
  if FEditor=AValue then exit;
  FEditor:=AValue;
  if FEditor<>nil then begin

    if FEditor.Parent=nil then
      FEditor.Visible:=False;

    if FEditor.Parent<>Self then
      FEditor.Parent:=Self;

    FEditor.TabStop:=False;

    Msg.MsgID:=GM_SETGRID;
    Msg.Grid:=Self;
    Msg.Options:=0;
    FEditor.Dispatch(Msg);

    FEditorOptions := Msg.Options + 1; // force new editor setup
    SetEditorOptions(Msg.Options);
  end;
end;

procedure TCustomGrid.SetFixedCols(const AValue: Integer);
begin
  if Columns.Enabled then begin
    if FFixedCols=Avalue then Exit;
    CheckFixedCount(ColCount, RowCount, AValue, FFixedRows);
    FFixedCols:=AValue;
    fTopLeft.x:=AValue;
    fCol:=Avalue;
    UpdateSelectionRange;
    if not (csLoading in componentState) then TopLeftChanged;
    ColumnsChanged(nil);
  end else
    InternalSetFixedCols(AValue);
end;

procedure TCustomGrid.SetFixedRows(const AValue: Integer);
begin
  if FFixedRows=AValue then exit;
  CheckFixedCount(ColCount, RowCount, FFixedCols, AValue);
  FFixedRows:=AValue;
  fTopLeft.y:=AValue;
  //DebugLn('TCustomGrid.SetFixedRows ',DbgSName(Self),' FTopLeft=',dbgs(FTopLeft));
  FRow:=AValue;
  UpdateSelectionRange;
  if not (csLoading in ComponentState) then
    doTopleftChange(true);
end;

procedure TCustomGrid.SetGridLineColor(const AValue: TColor);
begin
  if FGridLineColor=AValue then exit;
  FGridLineColor:=AValue;
  Invalidate;
end;

procedure TCustomGrid.SetLeftCol(const AValue: Integer);
begin
  TryScrollTo(AValue, FTopLeft.Y);
end;

procedure TCustomGrid.SetOptions(const AValue: TGridOptions);
begin
  if FOptions=AValue then exit;
  FOptions:=AValue;
  {
  if goRangeSelect in Options then
    FOptions:=FOptions - [goAlwaysShowEditor];
  }
  UpdateSelectionRange;
  if goAlwaysShowEditor in Options then begin
    EditorShow(true);
  end else begin
    EditorHide;
  end;
  VisualChange;
end;

procedure TCustomGrid.SetScrollBars(const AValue: TScrollStyle);
begin
  if FScrollBars=AValue then exit;
  FScrollBars:=AValue;
  VisualChange;
end;

procedure TCustomGrid.SetTopRow(const AValue: Integer);
begin
  TryScrollTo(FTopLeft.X, Avalue);
end;

procedure TCustomGrid.Setrowheights(Arow: Integer; Avalue: Integer);
begin
  if AValue<0 then AValue:=-1;
  if AValue<>PtrInt(FRows[ARow]) then begin
    FRows[ARow]:=Pointer(PtrInt(AValue));
    VisualChange;
    if (FEditor<>nil)and(Feditor.Visible)and(ARow<=FRow) then EditorPos;
    RowHeightsChanged;
  end;
end;

procedure TCustomGrid.Setcolwidths(Acol: Integer; Avalue: Integer);
var
  c: TGridColumn;
begin
  if not Columns.Enabled or (aCol<FFixedCols) then
    internalSetColWidths(aCol, aValue)
  else begin
    C := ColumnFromGridColumn(ACol);
    if C<>nil then
      C.Width := AValue;
  end;
end;

procedure TCustomGrid.SetRawColWidths(ACol: Integer; AValue: Integer);
begin
  FCols[ACol]:=Pointer(PtrInt(Avalue));
end;

procedure TCustomGrid.AdjustCount(IsColumn: Boolean; OldValue, newValue: Integer);
  procedure AddDel(Lst: TList; aCount: Integer);
  begin
    while lst.Count<aCount do Lst.Add(Pointer(-1)); // default width/height
    Lst.Count:=aCount;
  end;
var
  OldCount: integer;
begin
  if IsColumn then begin
    AddDel(FCols, NewValue);
    FGCache.AccumWidth.Count:=NewValue;
    OldCount:=RowCount;
    if (OldValue=0)and(NewValue>=0) then begin
      FTopLeft.X:=FFixedCols;
      if RowCount=0 then begin
        if Columns.Enabled then
          FFixedRows := 1
        else
          FFixedRows := 0;
        FTopLeft.Y:=FFixedRows;
        //DebugLn('TCustomGrid.AdjustCount A ',DbgSName(Self),' FTopLeft=',dbgs(FTopLeft));
        AddDel(FRows, 1);
        FGCache.AccumHeight.Count:=1;
      end;
    end;
    SizeChanged(OldValue, OldCount);
  end else begin
    AddDel(FRows, NewValue);
    FGCache.AccumHeight.Count:=NewValue;
    OldCount:=ColCount;
    if (OldValue=0)and(NewValue>=0) then begin
      FTopleft.Y:=FFixedRows;
      //DebugLn('TCustomGrid.AdjustCount B ',DbgSName(Self),' FTopLeft=',dbgs(FTopLeft));
      if FCols.Count=0 then begin
        FFixedCols:=0;
        FTopLeft.X:=0;
        AddDel(FCols, 1);
        FGCache.AccumWidth.Count:=1;
      end;
    end;
    SizeChanged(OldCount, OldValue);
  end;
  FixPosition;

end;

procedure TCustomGrid.SetColCount(AValue: Integer);
begin
  if Columns.Enabled then
    raise EGridException.Create('Use Columns property to add/remove columns');
  InternalSetColCount(AValue);
end;

procedure TCustomGrid.SetRowCount(AValue: Integer);
var
  OldR: Integer;
begin
  OldR := FRows.Count;
  if AValue=OldR then Exit;
  if AValue<1 then
    clear
  else begin
    if (OldR=0) and Columns.Enabled then begin
      // there are custom columns, setup first enough columns
      if FGridPropBackup.ValidData then begin
        // Take in count previus fixed columns too.
        // This value will be used in ColumnsChanged get
        // the right number of columns to setup
        //
        FFixedCols := FGridPropBackup.FixedColCount;
        FGridPropBackup.ValidData:=False;
      end;
      // setup custom columns
      Self.ColumnsChanged(nil);
      // still need to adjust rowcount?
      if AValue=FRows.Count then
        exit;
    end;
    CheckFixedCount(ColCount, AValue, FFixedCols, FFixedRows);
    CheckCount(ColCount, AValue);
    AdjustCount(False, OldR, AValue);
  end;
end;

procedure TCustomGrid.SetDefColWidth(AValue: Integer);
var
  i: Integer;
begin
  if AValue=fDefColwidth then
    Exit;
  FDefColWidth:=AValue;
  if not AutoFillColumns then begin
    for i:=0 to ColCount-1 do
      FCols[i] := Pointer(-1);
    VisualChange;
  end;
end;

procedure TCustomGrid.SetDefRowHeight(AValue: Integer);
var
  i: Integer;
begin
  if AValue=fDefRowHeight then Exit;
  FDefRowheight:=AValue;
  for i:=0 to RowCount-1 do
    FRows[i] := Pointer(-1);
  VisualChange;
end;

procedure TCustomGrid.SetCol(AValue: Integer);
begin
  if AValue=FCol then Exit;
  MoveExtend(False, AValue, FRow);
end;

procedure TCustomGrid.SetRow(AValue: Integer);
begin
  if AValue=FRow then Exit;
  MoveExtend(False, FCol, AValue);
end;

procedure TCustomGrid.Sort(ColSorting: Boolean; index, IndxFrom, IndxTo: Integer);
  procedure QuickSort(L,R: Integer);
  var
    I,J: Integer;
    P{,Q}: Integer;
  begin
    repeat
      I:=L;
      J:=R;
      P:=(L+R) div 2;
      repeat
        if ColSorting then begin
          while DoCompareCells(index, P, index, I)>0 do I:=I+1;
          while DoCompareCells(index, P, index, J)<0 do J:=J-1;
        end else begin
          while DoCompareCells(P, index, I, index)>0 do I:=I+1;
          while DoCompareCells(P, index, J, index)<0 do J:=J-1;
        end;
        if I<=J then begin

          if I<>J then
            if not FStrictSort or
              (ColSorting     and (DoCompareCells(index, I, index, J)<>0)) or
              (not ColSorting and (DoCompareCells(I, index, J, index)<>0))
            then
              DoOPExchangeColRow(not ColSorting, I,J);
          
          if P=I then
            P:=J
          else if P=J then
            P:=I;

          I:=I+1;
          J:=J-1;
        end;
      until I>J;
      
      if L<J then
        QuickSort(L,J);

      L:=I;
    until I>=R;
  end;
begin
  CheckIndex(ColSorting, Index);
  CheckIndex(not ColSorting, IndxFrom);
  CheckIndex(not ColSorting, IndxTo);
  BeginUpdate;
  QuickSort(IndxFrom, IndxTo);
  EndUpdate(True);
end;

procedure TCustomGrid.doTopleftChange(dimChg: Boolean);
begin
  TopLeftChanged;
  if dimchg then begin
    VisualChange;
  end else begin
    CacheVisibleGrid;
    Invalidate;
  end;
  updateScrollBarPos(ssBoth);
end;

procedure TCustomGrid.DrawXORVertLine(X: Integer);
var
  OldPenMode: TPenMode;
  OldPenColor: TColor;
begin
  OldPenMode := Canvas.Pen.Mode;
  OldPenColor := Canvas.Pen.Color;
  Canvas.Pen.Color := clWhite;
  Canvas.Pen.Mode := pmXOR;
  Canvas.MoveTo(X,0);
  Canvas.LineTo(X,FGCache.MaxClientXY.Y);
  Canvas.Pen.Mode := OldPenMode;
  Canvas.Pen.Color := OldPenColor;
end;

procedure TCustomGrid.DrawXORHorzLine(Y: Integer);
var
  OldPenMode: TPenMode;
  OldPenColor: TColor;
begin
  OldPenMode := Canvas.Pen.Mode;
  OldPenColor := Canvas.Pen.Color;
  Canvas.Pen.Color := clWhite;
  Canvas.Pen.Mode := pmXOR;
  Canvas.MoveTo(0,Y);
  Canvas.LineTo(FGCache.MaxClientXY.X,Y);
  Canvas.Pen.Mode := OldPenMode;
  Canvas.Pen.Color := OldPenColor;
end;

function TCustomGrid.EditorCanProcessKey(var Key: Char): boolean;
begin
  result := EditorCanAcceptKey(Key) and not EditorIsReadOnly;
  if not Result then
    Key := #0;
end;

procedure TCustomGrid.VisualChange;
{ $DEFINE dbgVisualChange}
var
  Tw,Th: Integer;
  Dh,DV: Integer;
  HsbVisible, VsbVisible: boolean;
  HsbRange, VsbRange: Integer;

  function CalcMaxTopLeft: TPoint;
  var
    i: Integer;
    W,H: Integer;
  begin
    Result:=Point(ColCount-1, RowCount-1);
    W:=0;
    for i:=ColCount-1 downto FFixedCols do begin
      W:=W+GetColWidths(i);
      if W<FGCache.ScrollWidth then Result.x:=i
      else         Break;
    end;
    H:=0;
    for i:=RowCount-1 downto FFixedRows do begin
      H:=H+GetRowHeights(i);
      if H<FGCache.ScrollHeight then Result.y:=i
      else         Break;
    end;
  end;
  procedure CalcNewCachedSizes;
  var
    i: Integer;
  begin
    // Calculate New Cached Values
    FGCache.GridWidth:=0;
    FGCache.FixedWidth:=0;
    For i:=0 To ColCount-1 do begin
      FGCache.AccumWidth[i]:=Pointer(PtrInt(FGCache.GridWidth));
      FGCache.GridWidth:=FGCache.GridWidth + GetColWidths(i);
      if i<FixedCols then FGCache.FixedWidth:=FGCache.GridWidth;
      {$IfDef dbgVisualChange}
      //DebugLn('FGCache.AccumWidth[',dbgs(i),']=',dbgs(Integer(FGCache.AccumWidth[i])));
      {$Endif}
    end;
    FGCache.Gridheight:=0;
    FGCache.FixedHeight:=0;
    For i:=0 To RowCount-1 do begin
      FGCache.AccumHeight[i]:=Pointer(PtrInt(FGCache.Gridheight));
      FGCache.Gridheight:=FGCache.Gridheight+GetRowHeights(i);
      if i<FixedRows then FGCache.FixedHeight:=FGCache.GridHeight;
      {$IfDef dbgVisualChange}
      //DebugLn('FGCache.AccumHeight[',dbgs(i),']=',dbgs(Integer(FGCache.AccumHeight[i])));
      {$Endif}
    end;
  end;
  procedure CalcScrollbarsVisibility;
  begin
    Dh:=FGSMHBar;
    DV:=FGSMVBar;
    TW:=FGCache.GridWidth;
    TH:=FGCache.GridHeight;
    FGCache.ClientWidth:= Width - GetBorderWidth;
    FGCache.ClientHeight := Height - GetBorderWidth;

    HsbRange:=Width - Dv;
    VsbRange:=Height - Dh;

    HsbVisible := (FScrollBars in [ssHorizontal, ssBoth]) or
      (ScrollBarAutomatic(ssHorizontal) and (FGCache.GridWidth > FGCache.ClientWidth));
      
    VsbVisible := (FScrollBars in [ssVertical, ssBoth]) or
      (ScrollBarAutomatic(ssVertical) and (FGCache.GridHeight > FGCache.ClientHeight));

    if ScrollBarAutomatic(ssHorizontal) then
      HsbVisible := not AutoFillColumns and (HsbVisible or (VsbVisible and (TW>HsbRange)));
      
    if ScrollBarAutomatic(ssVertical) then
      VsbVisible := VsbVisible or (HsbVisible and (TH>VsbRange));

    if not HSBVisible then DH:=0;
    if not VSbVisible then DV:=0;

    Dec(FGCache.ClientWidth, DV);
    Dec(FGCache.ClientHeight, DH);
  end;
  procedure CalcScrollbarsRange;
  begin
    with FGCache do begin
      // Horizontal scrollbar
      if HsbVisible then begin
        HsbRange:=GridWidth + 2 - GetBorderWidth;
        if not (goSmoothScroll in Options) then begin
          TW:= PtrInt(AccumWidth[MaxTopLeft.X])-(HsbRange-ClientWidth);
          HsbRange:=HsbRange + TW - FixedWidth + 1;
        end;
      end else
        HsbRange:=0;
        
      // Vertical scrollbar
      if VsbVisible then begin
        VSbRange:= GridHeight + 2 - GetBorderWidth;
        if not (goSmoothScroll in Options) then begin
          TH:= PtrInt(accumHeight[MaxTopLeft.Y])-(VsbRange-ClientHeight);
          VsbRange:=VsbRange + TH -FixedHeight + 1;
        end;
      end else
        VsbRange:= 0;
    end;
  end;
begin
  //DebugLn('TCustomGrid.VisualChange ',DbgSName(Self));
  if (FCols=nil) or ([csLoading,csDestroying]*ComponentState<>[])
  or (not HandleAllocated) then
    exit; // not yet initialized or already destroyed

  if AutoFillColumns then
    InternalAutoFillColumns;
  CalcNewCachedSizes;
  CalcScrollbarsVisibility;
  CheckNewCachedSizes(FGCache);

  FGCache.ScrollWidth:=FGCache.ClientWidth-FGCache.FixedWidth;
  FGCache.ScrollHeight:=FGCache.ClientHeight-FGCache.FixedHeight;
  FGCache.MaxTopLeft:=CalcMaxTopLeft;
  if not(goSmoothScroll in Options) then begin
    FGCache.TLColOff:=0;
    FGCache.TLRowOff:=0;
  end;
  {$Ifdef DbgVisualChange}
  DebugLn('TCustomGrid.VisualChange ',DbgSName(Self));
  DbgOut('Width=',dbgs(Width));
  DbgOut(' Height=',dbgs(height));
  DbgOut(' GWidth=',dbgs(TW));
  DbgOut(' GHeight=',dbgs(TH));
  DbgOut(' HsbRange=',dbgs(HsbRange));
  DbgOut(' VsbRange=',dbgs(VSbRange));
  DbgOut(' Vbar=',dbgs(VSbVisible));
  DebugLn(' Hbar=',dbgs(HsbVisible));
  DbgOut('ClientWidth=',dbgs(FGCAche.ClientWidth));
  DebugLn(' ClientHeight=',dbgs(FGCache.ClientHeight));
  DebugLn('MaxTopLeft',dbgs(FGCache.MaxTopLeft));
  {$Endif}
  CacheVisibleGrid;
  CalcScrollbarsRange;
  UpdateVertScrollBar(VsbVisible, VsbRange, FGCache.ClientHeight);
  UpdateHorzScrollBar(HsbVisible, HsbRange, FGCache.ClientWidth);
  Invalidate;
end;

procedure TCustomGrid.CreateParams(var Params: TCreateParams);
const
  ClassStylesOff = CS_VREDRAW or CS_HREDRAW;
begin
  inherited CreateParams(Params);
  with Params do begin
    WindowClass.Style := WindowClass.Style and DWORD(not ClassStylesOff);
    Style := Style or WS_VSCROLL or WS_HSCROLL or WS_CLIPCHILDREN;
  end;
end;

procedure TCustomGrid.ScrollBarRange(Which: Integer; aRange,aPage: Integer);
var
  ScrollInfo: TScrollInfo;
begin
  if HandleAllocated then begin
    {$Ifdef DbgScroll}
    DebugLn('ScrollbarRange: Which=',IntToStr(Which),' Range=',IntToStr(aRange));
    {$endif}
    FillChar(ScrollInfo, SizeOf(ScrollInfo), 0);
    ScrollInfo.cbSize := SizeOf(ScrollInfo);
    ScrollInfo.fMask := SIF_RANGE or SIF_PAGE or SIF_DISABLENOSCROLL;
    {$ifdef Unix}
    ScrollInfo.fMask := ScrollInfo.fMask or SIF_UPDATEPOLICY;
    if goThumbTracking in Options then
      ScrollInfo.ntrackPos := SB_POLICY_CONTINUOUS
    else
      ScrollInfo.ntrackPos := SB_POLICY_DISCONTINUOUS;
    {$endif}
    ScrollInfo.nMin := 0;
    ScrollInfo.nMax := ARange;
    if APage<0 then
      APage := 0;
    ScrollInfo.nPage := APage;
    SetScrollInfo(Handle, Which, ScrollInfo, True);
  end;
end;

procedure TCustomGrid.ScrollBarPosition(Which, Value: integer);
var
  ScrollInfo: TScrollInfo;
  Vis: Boolean;
begin
  if HandleAllocated then begin
    {$Ifdef DbgScroll}
    DebugLn('ScrollbarPosition: Which=',IntToStr(Which), ' Value= ',IntToStr(Value));
    {$endif}
    if Which = SB_VERT then Vis := FVSbVisible else
    if Which = SB_HORZ then Vis := FHSbVisible
    else vis := false;
    FillChar(ScrollInfo, SizeOf(ScrollInfo), 0);
    ScrollInfo.cbSize := SizeOf(ScrollInfo);
    ScrollInfo.fMask := SIF_POS;
    ScrollInfo.nPos:= Value;
    SetScrollInfo(Handle, Which, ScrollInfo, Vis);
  end;
end;

function TCustomGrid.ScrollBarIsVisible(Which: Integer): Boolean;
begin
  Result:=false;
  if HandleAllocated then begin
    {$IFNDEF WINDOWS}
    Result:= getScrollbarVisible(handle, Which);
    {$ELSE}
    // Is up to the widgetset to implement GetScrollbarvisible
    // FVSbVisible, FHSbVisible are supposed to be update (if used ScrolLBarShow)
    // how can we know if GetScrollbarVisible is indeed implemented?....
    if Which = SB_VERT then result := FVSbVisible else
    if Which = SB_HORZ then result := FHsbVisible else
    if Which = SB_BOTH then result := FHsbVisible and FVsbVisible;
    {$ENDIF}
  end;
end;

procedure TCustomGrid.ScrollBarPage(Which: Integer; aPage: Integer);
var
  ScrollInfo: TScrollInfo;
begin
  if HandleAllocated then begin
    ScrollInfo.cbSize := SizeOf(ScrollInfo);
    ScrollInfo.fMask := SIF_PAGE;
    ScrollInfo.nPage:= aPage;
    SetScrollInfo(Handle, Which, ScrollInfo, True);
  end;
end;

procedure TCustomGrid.ScrollBarShow(Which: Integer; aValue: boolean);
begin
  if HandleAllocated then begin
    {$Ifdef DbgScroll}
    DebugLn('ScrollbarShow: Which=',IntToStr(Which), ' Avalue=',BoolToStr(AValue));
    {$endif}
    ShowScrollBar(Handle,Which,aValue);
    if Which in [SB_BOTH, SB_VERT] then FVSbVisible := AValue else
    if Which in [SB_BOTH, SB_HORZ] then FHSbVisible := AValue;
  end;
end;

function TCustomGrid.ScrollBarAutomatic(Which: TScrollStyle): boolean;
begin
  result:=false;
  if (Which=ssVertical)or(Which=ssHorizontal) then begin
    if Which=ssVertical then Which:=ssAutoVertical
    else Which:=ssAutoHorizontal;
    Result:= FScrollBars in [Which, ssAutoBoth];
  end;
end;

{ Returns a reactagle corresponding to a fisical cell[aCol,aRow] }
function TCustomGrid.CellRect(ACol, ARow: Integer): TRect;
begin
  //Result:=ColRowToClientCellRect(aCol,aRow);
  ColRowToOffset(True, True, ACol, Result.Left, Result.Right);
  ColRowToOffSet(False,True, ARow, Result.Top, Result.Bottom);
end;

// The visible grid Depends on  TopLeft and ClientWidht,ClientHeight,
// Col/Row Count, So it Should be called inmediately after changing
// those properties.
function TCustomGrid.GetVisibleGrid: TRect;
var
  w: Integer;
begin

  if (FTopLeft.X<0)or(FTopLeft.y<0)or(csLoading in ComponentState) then begin
    Result := Rect(0,0,-1,-1);
    FGCache.MaxClientXY := point(0,0);
    Exit;
  end;
  // visible TopLeft Cell
  Result.TopLeft:=fTopLeft;
  Result.BottomRight:=Result.TopLeft;

  // Left Margin of next visible Column and Rightmost visible cell
  if ColCount>FixedCols then begin
    W:=GetColWidths(Result.Left) + FGCache.FixedWidth- FGCache.TLColOff;
    while (Result.Right<ColCount-1)and(W<FGCache.ClientWidth) do begin
      Inc(Result.Right);
      W:=W+GetColWidths(Result.Right);
    end;
    FGCache.MaxClientXY.X := W;
  end else begin
    FGCache.MaxClientXY.X := FGCache.FixedWidth;
    Result.Right := Result.Left - 1; // no visible cells here
  end;

  // Top Margin of next visible Row and Bottom most visible cell
  if RowCount>FixedRows then begin
    w:=GetRowheights(Result.Top) + FGCache.FixedHeight - FGCache.TLRowOff;
    while (Result.Bottom<RowCount-1)and(W<FGCache.ClientHeight) do begin
      Inc(Result.Bottom);
      W:=W+GetRowHeights(Result.Bottom);
    end;
    FGCache.MaxClientXY.Y := W;
  end else begin
    FGCache.MaxClientXY.Y := FGCache.FixedHeight;
    Result.Bottom := Result.Top - 1; // no visible cells here
  end;
end;

{ Scroll the grid until cell[aCol,aRow] is shown }
function TCustomGrid.ScrollToCell(const aCol,aRow: Integer): Boolean;
var
  RNew: TRect;
  OldTopLeft:TPoint;
  Xinc,YInc: Integer;
begin
  OldTopLeft:=fTopLeft;

  while (fTopLeft.x>=0) and
        (fTopLeft.x<ColCount)and
        (fTopLeft.y>=0) and
        (fTopLeft.y<RowCount) do begin

    RNew:=CellRect(aCol,aRow);

    Xinc:=0;
    if RNew.Left + FGCache.TLColOff < FGCache.FixedWidth then Xinc:=-1
    else if (RNew.Right+FGCache.TLColOff > (FGCache.ClientWidth+GetBorderWidth))
            and (RNew.Left+FGCache.TLColOff-GetColWidths(aCol) >= FGCache.FixedWidth)
            then XInc:=1;
            // Only scroll left if the left edge of the cell does not become
            // invisible as a result
    Yinc:=0;
    if RNew.Top  + FGCache.TLRowOff < FGCache.FixedHeight then Yinc:=-1
    else if (RNew.Bottom+FGCache.TLRowOff > (FGCache.ClientHeight+GetBorderWidth))
            and (RNew.Top+FGCache.TLRowOff-GetRowHeights(aRow) >= FGCache.FixedHeight)
            then YInc:=1;
            // Only scroll up if the top edge of the cell does not become
            // invisible as a result

    with FTopLeft do
    if ((XInc=0)and(YInc=0)) or // the cell is already visible
       ((X=aCol)and(Y=aRow)) or // the cell is visible by definition
       ((X+XInc<0)or(Y+Yinc<0)) or // topleft can't be lower 0
       ((X+XInc>=ColCount)) or // leftmost column can't be equal/higher than colcount
       ((Y+Yinc>=RowCount)) // topmost column can't be equal/higher than rowcount
    then
      Break;
    Inc(FTopLeft.x, XInc);
    Inc(FTopLeft.y, YInc);
  end;
  //DebugLn('TCustomGrid.ScrollToCell A ',DbgSName(Self),' FTopLeft=',dbgs(FTopLeft));

  Result:=not PointIgual(OldTopleft,FTopLeft);
  if result then doTopleftChange(False)
  else ResetOffset(True, True);
end;

{Returns a valid TopLeft from a proposed TopLeft[DCol,DRow] which are
 relative or absolute coordinates }
function TCustomGrid.ScrollGrid(Relative: Boolean; DCol, DRow: Integer): TPoint;
begin
  Result:=FTopLeft;
  if not Relative then begin
    DCol:=DCol-Result.x;
    DRow:=DRow-Result.y;
  end;

  if DCol+Result.x<FFixedCols then DCol:=Result.x-FFixedCols else
  if DCol+Result.x>ColCount-1 then DCol:=ColCount-1-Result.x;
  if DRow+Result.y<FFixedRows then DRow:=Result.y-FFixedRows else
  if DRow+Result.y>RowCount-1 then DRow:=RowCount-1-Result.y;

  Inc(Result.x, DCol);
  Inc(Result.y, DRow);
end;

procedure TCustomGrid.TopLeftChanged;
begin
  if Assigned(OnTopLeftChanged) and not (csDesigning in ComponentState) then
    OnTopLeftChanged(Self);
end;

procedure TCustomGrid.HeaderClick(IsColumn: Boolean; index: Integer);
begin
end;
procedure TCustomGrid.HeaderSized(IsColumn: Boolean; index: Integer);
begin
end;
procedure TCustomGrid.ColRowMoved(IsColumn: Boolean; FromIndex,ToIndex: Integer);
begin
  if IsColumn and Columns.Enabled then
    Columns.MoveColumn(ColumnIndexFromGridColumn(FromIndex),
      ColumnIndexFromGridColumn(ToIndex));
end;
procedure TCustomGrid.ColRowExchanged(isColumn: Boolean; index, WithIndex: Integer);
begin
end;
procedure TCustomGrid.ColRowInserted(IsColumn: boolean; index: integer);
begin
end;
procedure TCustomGrid.DrawFocusRect(aCol, aRow: Integer; ARect: TRect);
begin
end;
procedure TCustomGrid.AutoAdjustColumn(aCol: Integer);
begin
end;
procedure TCustomGrid.SizeChanged(OldColCount, OldRowCount: Integer);
begin
end;
procedure TCustomGrid.ColRowDeleted(IsColumn: Boolean; index: Integer);
begin
end;

function TCustomGrid.CanEditShow: Boolean;
begin
  Result := (goEditing in Options) and not (csDesigning in ComponentState);
end;

procedure TCustomGrid.Paint;
begin
  //DebugLn('TCustomGrid.Paint ',DbgSName(Self),' Row=',dbgs(Row));
  inherited Paint;
  if FUpdateCount=0 then begin
    DrawEdges;
    DrawAllRows;
    DrawColRowMoving;
    DrawBorder;
  end;
end;

procedure TCustomGrid.PickListItemSelected(Sender: TObject);
begin
  if Assigned(OnPickListSelect) then
    OnPickListSelect(Self);
end;

procedure TCustomGrid.PrepareCanvas(aCol, aRow: Integer; aState: TGridDrawState);
var
  AColor: TColor;
begin
  if DefaultDrawing then begin
    Canvas.Pen.Mode := pmCopy;
    if gdSelected in aState then begin
      Canvas.Brush.Color := SelectedColor;
      SetCanvasFont(GetColumnFont(aCol, False));
      Canvas.Font.Color := clWindow;
      FLastFont:=nil;
    end else begin
      AColor := GetColumnColor(aCol, gdFixed in AState);
      if not (gdFixed in AState) and (FAlternateColor<>AColor) then  begin
        if AColor=Color then begin
          // column color = grid Color, Allow override color
          // 1. default color after fixed rows
          // 2. always use absolute alternate color based in odd & even row
          if (FAltColorStartNormal and Odd(ARow-FixedRows)) {(1)} or
             (not FAltColorStartNormal and Odd(ARow)) {(2)} then
              AColor := FAlternateColor;
        end;
      end;
      Canvas.Brush.Color := AColor;
      SetCanvasFont(GetColumnFont(aCol, gdFixed in aState));
    end;
    Canvas.TextStyle := DefaultTextStyle;
    Canvas.TextStyle.Alignment := GetColumnAlignment(aCol, gdFixed in AState);
    Canvas.TextStyle.Layout := GetColumnLayout(aCol, gdFixed in AState);
  end else begin
    Canvas.TextStyle := DefaultTextStyle;
    Canvas.Brush.Color := clWindow;
    Canvas.Font.Color := clWindowText;
  end;
  if Assigned(OnPrepareCanvas) then
    OnPrepareCanvas(Self, aCol, aRow, aState);
end;

procedure TCustomGrid.ResetOffset(chkCol, ChkRow: Boolean);
begin
  with FGCache do begin
    if ChkCol then ChkCol:=TLColOff<>0;
    if ChkCol then TlColOff:=0;
    if ChkRow then ChkRow:=TLRowOff<>0;
    if ChkRow then TlRowOff:=0;
    if ChkRow or ChkCol then begin
      CacheVisibleGrid;
      Invalidate;
      if ChkCol then updateScrollBarPos(ssHorizontal);
      if ChkRow then updateScrollBarPos(ssVertical);
    end;
  end;
end;

procedure TCustomGrid.ResizeColumn(aCol, aWidth: Integer);
var
  R: TRect;
  bigger: boolean;
begin
  BeginUpdate;
  if aWidth<0 then aWidth:=0;
  bigger := aWidth > ColWidths[aCol];
  ColWidths[aCol]:=aWidth;
  EndUpdate(uoNone);

  R := CellRect(aCol, 0);
  R.Bottom := FGCache.MaxClientXY.Y+1;
  if bigger then
    R.Right := FGCache.MaxClientXY.X+1
  else
    R.Right := FGCache.ClientWidth;
  if aCol=FTopLeft.x then
    R.Left := FGCache.FixedWidth;

  InvalidateRect(handle, @R, True);
end;

procedure TCustomGrid.ResizeRow(aRow, aHeight: Integer);
var
  R: TRect;
  bigger: boolean;
begin
  BeginUpdate;
  if aHeight<0 then aHeight:=0;
  bigger := aHeight > RowHeights[aRow];
  RowHeights[aRow] := aHeight;
  EndUpdate(uoNone);

  R := CellRect(0, aRow);
  R.Right := FGCache.MaxClientXY.X+1;
  if bigger then
    R.Bottom := FGCache.MaxClientXY.Y+1
  else
    R.Bottom := FGCache.ClientHeight;
  if aRow=FTopLeft.y then
    R.Top := FGCache.FixedHeight;

  InvalidateRect(handle, @R, True);
end;


function TCustomGrid.SelectCell(ACol, ARow: Integer): Boolean;
begin
  Result:=true;
  //Result:=MoveExtend(False, aCol, aRow);
end;

procedure TCustomGrid.SetCanvasFont(aFont: TFont);
begin
  if (aFont<>FLastFont) or
    not Canvas.Font.IsEqual(aFont) then 
  begin
    Canvas.Font := aFont;
    FLastFont := AFont;
  end;
end;

procedure TCustomGrid.SetColor(Value: TColor);
begin
  if AlternateColor = Color then
    FAlternateColor := Value;
  inherited SetColor(Value);
end;

procedure TCustomGrid.SetColRow(const ACol, ARow: Integer);
begin
  FCol := ACol;
  FRow := ARow;
  UpdateSelectionRange;
end;

procedure TCustomGrid.DrawBorder;
var
  R: TRect;
begin
  if InternalNeedBorder then begin
    {$ifdef sbars}
    R := Rect(0,0,Width-1,Height-1);
    {$else}
    R := Rect(0,0,FGCache.ClientWidth, FGCache.Clientheight);
    {$endif}
    with R, Canvas do begin
      Pen.Color := fBorderColor;
      Pen.Width := 1;
      MoveTo(0,0);
      LineTo(0,Bottom);
      LineTo(Right, Bottom);
      LineTo(Right, 0);
      LineTo(0,0);
      Pixels[Right, Bottom] := fBorderColor; // workaround
    end;
  end;
end;

procedure TCustomGrid.DrawColRowMoving;
{$ifdef AlternativeMoveIndicator}
var
  x, y, dx, dy: Integer;
  R: TRect;
{$endif}
begin
  if (FGridState=gsColMoving)and(fMoveLast.x>=0) then begin
    {$ifdef AlternativeMoveIndicator}
    dx := 4;
    dy := 4;
    Canvas.pen.Width := 1;
    Canvas.Pen.Color := clHighlight;
    Canvas.Brush.Color := clHighlight;
    R := CellRect(FMoveLast.X, 0);
    X := R.Left;
    Y := R.Bottom - dy;
    Canvas.Polygon([Point(x-dx,y),point(x+dx,y),point(x,y+dy), point(x-dx,y)]);
    Y := R.Top + dy;
    Canvas.Polygon([Point(x-dx,y),point(x+dx,y),point(x,y-dy), point(x-dx,y)]);
    {$else}
    Canvas.Pen.Width:=3;
    Canvas.Pen.Color:=clRed;
    Canvas.MoveTo(fMoveLast.y, 0);
    Canvas.Lineto(fMovelast.y, FGCache.MaxClientXY.Y);
    Canvas.Pen.Width:=1;
    {$endif}
  end else
  if (FGridState=gsRowMoving)and(FMoveLast.y>=0) then begin
    {$ifdef AlternativeMoveIndicator}
    dx := 4;
    dy := 4;
    Canvas.pen.Width := 1;
    Canvas.Pen.Color := clHighlight;
    Canvas.Brush.Color := clHighlight;
    R := CellRect(0, FMoveLast.Y);
    X := R.Right - dx;
    Y := R.Top;
    Canvas.Polygon([Point(x,y+dy),point(x,y-dy),point(x+dx,y), point(x,y+dy)]);
    X := R.Left + dx;
    Canvas.Polygon([Point(x,y+dy),point(x,y-dy),point(x-dx,y), point(x,y+dy)]);
    {$else}
    Canvas.Pen.Width:=3;
    Canvas.Pen.Color:=clRed;
    Canvas.MoveTo(0, FMoveLast.X);
    Canvas.LineTo(FGCache.MaxClientXY.X, FMoveLast.X);
    Canvas.Pen.Width:=1;
    {$endif}
  end;
end;

procedure TCustomGrid.DrawCell(aCol, aRow: Integer; aRect: TRect;
  aState: TGridDrawState);
begin
  PrepareCanvas(aCol, aRow, aState);
  Canvas.FillRect(aRect);
  DrawCellGrid(aCol,aRow,aRect,aState);
end;

procedure TCustomGrid.DrawAllRows;
var
  i: Integer;
begin
  // Draw Rows
  with FGCache.VisibleGrid do
    for i:=Top to Bottom do
      DrawRow(i);
  // Draw Fixed Rows
  for i:=0 to FFixedRows-1 do
    DrawRow(i);
end;

function VerticalIntersect(const aRect,bRect: TRect): boolean;
begin
  result := (aRect.Top < bRect.Bottom) and (aRect.Bottom > bRect.Top);
end;

function HorizontalIntersect(const aRect,bRect: TRect): boolean;
begin
  result := (aRect.Left < bRect.Right) and (aRect.Right > bRect.Left);
end;

procedure TCustomGrid.DrawRow(aRow: Integer);
var
  Gds: TGridDrawState;
  i: Integer;
  Rs: Boolean;
  R: TRect;
  ClipArea: Trect;
begin

  // Upper and Lower bounds for this row
  ColRowToOffSet(False, True, aRow, R.Top, R.Bottom);

  // is this row within the ClipRect?
  ClipArea := Canvas.ClipRect;
  if not VerticalIntersect( R, ClipArea) then begin
    {$IFDEF DbgVisualChange}
    DebugLn('Drawrow: Skipped row: ', IntToStr(aRow));
    {$ENDIF}
    exit;
  end;

  // Draw columns in this row
  with FGCache.VisibleGrid do begin
    for i:=left to Right do begin
      ColRowToOffset(True, True, i, R.Left, R.Right);
      if not HorizontalIntersect(R, ClipArea) then
        continue;
      gds := [];
      Rs := (goRowSelect in Options);
      if ARow<FFixedRows then
        include(gds, gdFixed)
      else begin
        if (i=FCol)and(aRow=FRow) then begin
          Include(gds, gdFocused);
          if (goDrawFocusSelected in Options) or
            (Rs and not(goRelaxedRowSelect in Options)) then
            include(gds, gdSelected);
        end else
        if IsCellSelected[i, aRow] then
          include(gds, gdSelected);
      end;
      DrawCell(i, aRow, R, gds);
    end;

    // Draw the focus Rect
    if FFocusRectVisible and (ARow=FRow) and
       ((Rs and (ARow>=Top) and (ARow<=Bottom)) or IsCellVisible(FCol,ARow))
    then begin
      if EditorMode then begin
      //if EditorAlwaysShown and (FEditor<>nil) and FEditor.Visible then begin
        //DebugLn('No Draw Focus Rect');
      end else begin
        ColRowToOffset(True, True, FCol, R.Left, R.Right);
        // is this column within the ClipRect?
        if HorizontalIntersect( R, ClipArea) then
          DrawFocusRect(FCol,FRow, R);
      end;
    end;

  end;


  // Draw Fixed Columns
  gds:=[gdFixed];
  For i:=0 to FFixedCols-1 do begin
    ColRowToOffset(True, True, i, R.Left, R.Right);
    // is this column within the ClipRect?
    if HorizontalIntersect( R, ClipArea) then
      DrawCell(i,aRow, R,gds);
  end;
end;

procedure TCustomGrid.EditButtonClicked(Sender: TObject);
var
  OldCol,OldRow: Integer;
begin
  if Assigned(OnEditButtonClick) then begin
    if Sender=FButtonEditor then begin
      OldCol:=FCol;
      OldRow:=FRow;
      try
        FCol:=FButtonEditor.Col;
        FRow:=FButtonEditor.Row;
        OnEditButtonClick(Self);
      finally
        if (FCol=FButtonEditor.Col) and (FRow=FButtonEditor.Row) then
        begin
          // didn't change FRow or FCol, restore old index.
          FCol:=OldCol;
          FRow:=OldRow;
        end;
      end;
    end else
      OnEditButtonClick(Self);
  end;
end;

procedure TCustomGrid.DrawEdges;
var
  P:  TPoint;
  Cr: TRect;
begin
  P:=FGCache.MaxClientXY;
  Cr:=Bounds(0,0, FGCache.ClientWidth, FGCache.ClientHeight);
  if P.x<Cr.Right then begin
    Cr.Left:=P.x;
    Canvas.Brush.Color:= Color;
    Canvas.FillRect(cr);
    Cr.Left:=0;
    Cr.Right:=p.x;
  end;
  if P.y<Cr.Bottom then begin
    Cr.Top:=p.y;
    Canvas.Brush.Color:= Color;
    Canvas.FillRect(cr);
  end;
end;

{
procedure TCustomGrid.DrawFocused;
var
  R: TRect;
  gds: TGridDrawState;
begin
  gds:=[gdFocused];
  if IsCellVisible(FCol,FRow) then begin
    if goDrawFocusSelected in Options then Include(gds,gdSelected);
    if (goRowSelect in Options) and not (goRelaxedRowSelect in Options) then
      Include(gds, gdSelected);
    R:=CellRect(fCol,fRow);
    DrawCell(fCol,fRow,R, gds);
    DrawFocusRect(fCol,fRow, R, gds);
  end else
    if  ((goRowSelect in Options) and
        (Frow>=FGCache.VisibleGrid.Top) and
        (Frow<=FGCache.VisibleGrid.Bottom))
    then begin
      R:=CellRect(fCol,fRow);
      DrawFocusRect(fcol,fRow, R, gds);
    end;
end;
}

procedure TCustomGrid.DrawCellGrid(aCol,aRow: Integer; aRect: TRect; aState: TGridDrawState);
var
  dv,dh: Boolean;
  aR: TRect;
begin
  // Draw Cell Grid or Maybe in the future Borders..
  with Canvas, aRect do begin
    if (gdFixed in aState) then
    begin
      Dv := goFixedVertLine in Options;
      Dh := goFixedHorzLine in Options;
      Pen.Style := psSolid;
      if FGridLineWidth > 0 then
        Pen.Width := 1
      else
        Pen.Width := 0;
      if not FFlat then
      begin
        if FTitleStyle=tsNative then
        begin
          aR := aRect;
          DrawFrameControl(Handle, ar, DFC_BUTTON, DFCS_BUTTONPUSH);
          exit;
        end
        else
        begin
          if FGridLineWidth > 0 then
          begin
            Pen.Color := cl3DHilight;
            MoveTo(Right - 1, Top);
            LineTo(Left, Top);
            LineTo(Left, Bottom);
            if FTitleStyle=tsStandard then
            begin
              // more contrast
              Pen.Color := cl3DShadow;
              MoveTo(Left+1, Bottom-2);
              LineTo(Right-2, Bottom-2);
              LineTo(Right-2, Top);
            end;
          end;
        end;
      end;
      Pen.Color := cl3DDKShadow;
    end
    else
    begin
      Dv := goVertLine in Options;
      Dh := goHorzLine in Options;
      Pen.Style := fGridLineStyle;
      Pen.Color := fGridLineColor;
      Pen.Width := fGridLineWidth;
    end;
    
    if fGridLineWidth > 0 then
    begin
      if Dh then begin
        MoveTo(Left, Bottom - 1);
        LineTo(Right, Bottom - 1);
      end;
      if Dv then begin
         MoveTo(Right - 1, Top);
         LineTo(Right - 1, Bottom);
      end;
    end;
  end;
end;

procedure TCustomGrid.DrawCellText(aCol, aRow: Integer; aRect: TRect;
  aState: TGridDrawState; aText: String);
begin
  dec(aRect.Right, 3);
  case Canvas.TextStyle.Alignment of
    Classes.taLeftJustify: Inc(aRect.Left, 3);
    Classes.taRightJustify: Dec(aRect.Right, 1);
  end;
  case Canvas.TextStyle.Layout of
    tlTop: Inc(aRect.Top, 3);
    tlBottom: Dec(aRect.Bottom, 3);
  end;
  Canvas.TextRect(aRect,ARect.Left,ARect.Top, aText);
end;

procedure TCustomGrid.OnTitleFontChanged(Sender: TObject);
begin
  FTitleFontIsDefault := False;
  if FColumns.Enabled then begin
    FColumns.TitleFontChanged;
    ColumnsChanged(nil);
  end;
end;

procedure TCustomGrid.ReadColumns(Reader: TReader);
begin
  Columns.Clear;
  Reader.ReadValue;
  Reader.ReadCollection(Columns);
end;

procedure TCustomGrid.ReadColWidths(Reader: TReader);
var
  i: integer;
begin
  with Reader do begin
    ReadListBegin;
    for i:=0 to ColCount-1 do
      ColWidths[I] := ReadInteger;
    ReadListEnd;
  end;
end;

procedure TCustomGrid.ReadRowHeights(Reader: TReader);
var
  i: integer;
begin
  with Reader do begin
    ReadListBegin;
    for i:=0 to RowCount-1 do
      RowHeights[I] := ReadInteger;
    ReadListEnd;
  end;
end;

procedure TCustomGrid.WMEraseBkgnd(var message: TLMEraseBkgnd);
begin
  message.Result:=1;
end;

procedure TCustomGrid.WMGetDlgCode(var Msg: TLMNoParams);
begin
  Msg.Result := DLGC_WANTARROWS or DLGC_WANTCHARS or DLGC_WANTALLKEYS;
  if goTabs in Options then Msg.Result:= Msg.Result or DLGC_WANTTAB;
end;

procedure TCustomGrid.WMHScroll(var message: TLMHScroll);
var
  C,TL,CTL: Integer;
  R: TRect;
begin

  {$IfDef dbgScroll}
  DebugLn('HSCROLL: Code=',IntToStr(message.ScrollCode),' Position=', IntToStr(message.Pos));
  {$Endif}

  if not FGCache.ValidGrid or not HandleAllocated then
    exit;

  if FEditor<>nil then
    EditorGetValue;

  TL:=  PtrInt(FGCache.AccumWidth[ FGCache.MaxTopLeft.X ]) - FGCache.FixedWidth;
  CTL:= PtrInt(FGCache.AccumWidth[ FtopLeft.X ]) - FGCache.FixedWidth;

  case message.ScrollCode of
      // Scrolls to start / end of the text
    SB_TOP:        C := 0;
    SB_BOTTOM:     C := TL;
      // Scrolls one line left / right
    SB_LINERIGHT:  C := CTL + GetColWidths( FTopLeft.X );
    SB_LINELEFT:   C := CTL - GetColWidths( FTopLeft.X - 1);
      // Scrolls one page of lines up / down
    SB_PAGERIGHT:  C := CTL + FGCache.ClientWidth;
    SB_PAGELEFT:   C := CTL - FGCache.ClientWidth;
      // Scrolls to the current scroll bar position
    SB_THUMBPOSITION:
      C := message.Pos;
    SB_THUMBTRACK:
      if goThumbTracking in Options then
        C := message.Pos
      else
        Exit;
      // Ends scrolling
    SB_ENDSCROLL:
      Exit;
  end;

  if C > TL then C := TL else
  if C < 0 then C := 0;


  {$Ifdef dbgScroll}
  DebugLn('---- Position=',IntToStr(C), ' FixedWidth=',IntToStr(FGCache.FixedWidth));
  {$Endif}
  ScrollBarPosition(SB_HORZ, C);
  C:= C + FGCache.FixedWidth + GetBorderWidth;
  {$Ifdef dbgScroll}
  DebugLn('---- Position=',IntToStr(C), ' FixedWidth=',IntToStr(FGCache.FixedWidth));
  {$Endif}
  //TL:=OffsetToColRow(True, False, C, FGCache.TLColOff);
  if not OffsetToColRow(True, False, C, TL, FGCache.TLColOff) then begin
    {$Ifdef dbgScroll}
    DebugLn('---- Offset= INVALID');
    {$Endif}
    exit;
  end;
  {$Ifdef dbgScroll}
  DebugLn('---- Offset=',IntToStr(C), ' TL=',IntToStr(TL),' TLColOFf=', IntToStr(FGCache.TLColOff));
  {$Endif}
  if not (goSmoothScroll in Options) then FGCache.TLColOff:=0;

  if TL<>FTopLeft.X then begin
    Inc(FUpdateScrollBarsCount);
    TryScrollTo(Tl, FTopLeft.Y);
    Dec(FUpdateScrollBarsCount);
  end else
  if goSmoothScroll in Options then begin
    CacheVisibleGrid;
    R.Topleft:=Point(FGCache.FixedWidth, 0);
    R.BottomRight:= FGCache.MaxClientXY;
    InvalidateRect(Handle, @R, false);
  end;
end;

procedure TCustomGrid.WMVScroll(var message: TLMVScroll);
var
  C, TL, CTL: Integer;
  R: TRect;
begin
  {$IfDef dbgScroll}
  DebugLn('VSCROLL: Code=',IntToStr(message.ScrollCode),' Position=', IntToStr(message.Pos));
  {$Endif}

  if not FGCache.ValidGrid or not HandleAllocated then
    exit;

  if FEditor<>nil then
    EditorGetValue;

  TL:=  PtrInt(FGCache.AccumHeight[ FGCache.MaxTopLeft.Y ]) - FGCache.FixedHeight;
  CTL:= PtrInt(FGCache.AccumHeight[ FTopLeft.Y ]) - FGCache.FixedHeight;

  case message.ScrollCode of
      // Scrolls to start / end of the text
    SB_TOP:        C := 0;
    SB_BOTTOM:     C := TL;
      // Scrolls one line up / down
    SB_LINEDOWN:   C := CTL + GetRowHeights( FTopleft.Y );
    SB_LINEUP:     C := CTL - GetRowHeights( FTopleft.Y - 1 );
      // Scrolls one page of lines up / down
    SB_PAGEDOWN:   C := CTL + FGCache.ClientHeight;
    SB_PAGEUP:     C := CTL - FGCache.ClientHeight;
      // Scrolls to the current scroll bar position
    SB_THUMBPOSITION:
      C := message.Pos;
    SB_THUMBTRACK:
      if goThumbTracking in Options then
        C := message.Pos
      else
        Exit;
      // Ends scrolling
    SB_ENDSCROLL: Exit;
  end;

  if C > TL then C := TL else
  if C < 0 then C := 0;

  {$Ifdef dbgScroll}
  DebugLn('---- Position=',IntToStr(C), ' FixedHeight=',IntToStr(FGCache.FixedHeight));
  {$Endif}
  ScrollBarPosition(SB_VERT, C);
  C:= C + FGCache.FixedHeight + GetBorderWidth;
  {$Ifdef dbgScroll}
  DebugLn('---- NewPosition=',IntToStr(C));
  {$Endif}
  if not OffsetToColRow(False, False, C, TL, FGCache.TLRowOff) then begin
    {$Ifdef dbgScroll}
    DebugLn('---- Offset= INVALID');
    {$Endif}
    exit;
  end;
  {$Ifdef dbgScroll}
  DebugLn('---- Offset=',IntToStr(C), ' TL=',IntToStr(TL), ' TLRowOFf=', IntToStr(FGCache.TLRowOff));
  {$Endif}
  if not (goSmoothScroll in Options) then FGCache.TLRowOff:=0;

  if TL<>FTopLeft.Y then begin
    Inc(FUpdateScrollBarsCount);
    TryScrollTo(FTopLeft.X, Tl);
    Dec(FUpdateScrollBarsCount);
  end else
  if goSmoothScroll in Options then begin
    CacheVisibleGrid;
    R.TopLeft:=Point(0, FGCache.FixedHeight);
    R.BottomRight:=FGCache.MaxClientXY;
    InvalidateRect(Handle, @R, false);
  end;
end;

procedure TCustomGrid.WMKillFocus(var message: TLMKillFocus);
begin
  {$ifdef dbgGrid}
  if csDestroying in ComponentState then exit;
  DbgOut('*** grid.WMKillFocus, FocusedWnd=', dbgs(Message.FocusedWnd),'[',dbgs(pointer(Message.FocusedWnd)),'] ');
  if EditorMode and (Message.FocusedWnd = FEditor.Handle) then
    DebugLn('Editor')
  else
    DebugLn('ExternalWindow');
  {$endif}
  inherited WMKillFocus(Message);
end;

procedure TCustomGrid.WMSetFocus(var message: TLMSetFocus);
begin
  {$ifdef dbgGrid}
  DbgOut('*** grid.WMSetFocus, FocusedWnd=', dbgs(Message.FocusedWnd),'[',dbgs(pointer(Message.FocusedWnd)),'] ');
  if EditorMode and (Message.FocusedWnd = FEditor.Handle) then
    DebugLn('Editor')
  else begin
    if Message.FocusedWnd=Self.Handle then
      DebugLn('Same Grid!')
    else
      DebugLn('ExternalWindow');
  end;
  {$endif}
  inherited WMSetFocus(Message);
end;

procedure TCustomGrid.WMChar(var message: TLMChar);
var
  Ch: Char;
begin
  Ch:=Char(message.CharCode);
  {$Ifdef GridTraceMsg}
  DebugLn(ClassName,'.WMchar CharCode= ', IntToStr(message.CharCode));
  {$Endif}
  if (goEditing in Options) and (Ch in [^H, #32..#255]) then begin
    EditorShowChar(Ch);
    message.CharCode := 0;
    message.Result := 1;
  end else
    inherited;
end;


procedure TCustomGrid.WndProc(var TheMessage: TLMessage);
begin
	{$ifdef GridTraceMsg}
	TransMsg('GRID: ', TheMessage);
	{$endif}
  case TheMessage.Msg of
    LM_HSCROLL, LM_VSCROLL:
      if csDesigning in ComponentState then
        exit;
  end;
  inherited WndProc(TheMessage);
end;

procedure TCustomGrid.CreateWnd;
begin
  //DebugLn('TCustomGrid.CreateWnd ',DbgSName(Self));
  inherited CreateWnd;
  CheckPosition;
  VisualChange;
end;

{ Scroll grid to the given Topleft[aCol,aRow] as needed }
procedure TCustomGrid.TryScrollTo(aCol, aRow: Integer);
var
  TryTL: TPoint;
  NewCol,NewRow: Integer;
begin
  TryTL:=ScrollGrid(False,aCol, aRow);
  if not PointIgual(TryTL, FTopLeft) then begin
    NewCol := TryTL.X - FTopLeft.X + Col;
    NewRow := TryTL.Y - FTopLeft.Y + Row;
    FTopLeft:=TryTL;
    //DebugLn('TCustomGrid.TryScrollTo A ',DbgSName(Self),' FTopLeft=',dbgs(FTopLeft));
    doTopleftChange(False);
    if goScrollKeepVisible in Options then
      MoveNextSelectable(False, NewCol, NewRow);
  end;
end;

procedure TCustomGrid.SetGridLineWidth(const AValue: Integer);
begin
  if FGridLineWidth = AValue then
    exit;
  FGridLineWidth := AValue;
  Invalidate;
end;

{ Reposition the scrollbars according to the current TopLeft }
procedure TCustomGrid.UpdateScrollbarPos(Which: TScrollStyle);
begin
  // Adjust ScrollBar Positions
  // Special condition only When scrolling by draging
  // the scrollbars see: WMHScroll and WVHScroll
  if (FUpdateScrollBarsCount=0) and not FixedGrid then begin
    if Which in [ssHorizontal, ssBoth] then begin
      if FScrollBars in [ssHorizontal,ssBoth,ssAutoHorizontal,ssAutoBoth] then begin
        with FGCache do
          ScrollBarPosition(SB_HORZ,
            PtrInt(AccumWidth[FTopLeft.x])-TLColOff-FixedWidth );
      end;
    end;

    if Which in [ssVertical, ssBoth] then begin
      if FScrollBars in [ssVertical,ssBoth,ssAutoVertical,ssAutoBoth] then begin
        with FGCache do
          ScrollBarPosition(SB_VERT,
            PtrInt(AccumHeight[FTopLeft.y])-TLRowOff-FixedHeight);
      end;
    end;
  end; {if FUpd...}
end;

procedure TCustomGrid.UpdateSelectionRange;
begin
  if goRowSelect in Options then begin
    FRange:=Rect(FFixedCols, FRow, ColCount-1, FRow);
  end
  else
    FRange:=Rect(FCol,FRow,FCol,FRow);
end;

procedure TCustomGrid.WriteColumns(Writer: TWriter);
begin
  if Columns.IsDefault then
    Writer.WriteCollection(nil)
  else
    Writer.WriteCollection(Columns);
end;

procedure TCustomGrid.WriteColWidths(Writer: TWriter);
var
  i: Integer;
begin
  with writer do begin
    WriteListBegin;
    for i:=0 to ColCount-1 do
      WriteInteger(ColWidths[i]);
    WriteListEnd;
  end;
end;

procedure TCustomGrid.WriteRowHeights(Writer: TWriter);
var
  i: integer;
begin
  with writer do begin
    WriteListBegin;
    for i:=0 to RowCount-1 do
      WriteInteger(RowHeights[i]);
    WriteListEnd;
  end;
end;

procedure TCustomGrid.CheckFixedCount(aCol,aRow,aFCol,aFRow: Integer);
begin
  if AFRow<0 then
    raise EGridException.Create('FixedRows<0');
  if AFCol<0 then
    raise EGridException.Create('FixedCols<0');

  {$ifdef LooseCount}
  if csLoading in ComponentState then
    exit;
  if (aCol=0)and(aFCol=0) then // invalid grid, ok
  else if (aFCol>ACol) then
    raise EGridException.Create(rsFixedColsTooBig);
  if (aRow=0)and(aFRow=0) then // Invalid grid, ok
  else if (aFRow>ARow) then
    raise EGridException.Create(rsFixedRowsTooBig);
  {$else}
  if (aCol=0)and(aFCol=0) then // invalid grid, ok
  else if (aFCol>=aCol) and not (csLoading in componentState) then
    raise EGridException.Create(rsFixedColsTooBig);
  if (aRow=0)and(aFRow=0) then // Invalid grid, ok
  else if (aFRow>=aRow) and not (csLoading in ComponentState) then
    raise EGridException.Create(rsFixedRowsTooBig);
  {$endif}
end;

procedure TCustomGrid.CheckCount(aNewColCount, aNewRowCount: Integer);
var
  NewCol,NewRow: Integer;
begin
  if HandleAllocated then begin
    if Col >= aNewColCount then NewCol := aNewColCount-1
    else                        NewCol := Col;
    if Row >= aNewRowCount then NewRow := aNewRowCount-1
    else                        NewRow := Row;
    if (NewCol>=0) and (NewRow>=0) and ((NewCol <> Col) or (NewRow <> Row)) then
    begin
      CheckTopleft(NewCol, NewRow , NewCol<>Col, NewRow<>Row);
      MoveNextSelectable(false, NewCol, NewRow);
    end;
  end;
end;

procedure TCustomGrid.CheckIndex(IsColumn: Boolean; Index: Integer);
begin
  if (IsColumn and ((Index<0) or (Index>ColCount-1))) or
     (not IsColumn and ((Index<0) or (Index>RowCount-1))) then
    raise EGridException.Create('Index out of range');
end;

function TCustomGrid.CheckTopLeft(aCol,aRow: Integer; CheckCols, CheckRows: boolean): boolean;
var
  OldTopLeft: TPoint;
  W: Integer;
begin
  OldTopLeft := FTopLeft;
  Result:= False;

  with FTopleft do begin
    if CheckCols and (X>FixedCols) then begin
      W := FGCache.ScrollWidth-ColWidths[aCol]-PtrInt(FGCache.AccumWidth[aCol]);
      while (x>FixedCols)and(W+PtrInt(FGCache.AccumWidth[x])>=ColWidths[x-1]) do
      begin
        Dec(x);
      end;
    end;
  end;

  with FTopleft do begin
    if CheckRows and (Y > FixedRows) then begin
      W := FGCache.ScrollHeight-RowHeights[aRow]-PtrInt(FGCache.AccumHeight[aRow]);
      while (y>FixedRows)and(W+PtrInt(FGCache.AccumHeight[y])>=RowHeights[y-1]) do
      begin
        Dec(y);
      end;
      //DebugLn('TCustomGrid.CheckTopLeft A ',DbgSName(Self),' FTopLeft=',dbgs(FTopLeft));
    end;
  end;

  Result := not PointIgual(OldTopleft,FTopLeft);
  if Result then
    doTopleftChange(False)
end;

function TCustomGrid.GetIsCellSelected(aCol, aRow: Integer): boolean;
begin
  Result:=  (FRange.Left<=aCol)   and
            (aCol<=FRange.Right)  and
            (FRange.Top<=aRow)    and
            (aRow<=FRange.Bottom);
end;

function TCustomGrid.GetSelectedColumn: TGridColumn;
begin
  Result := ColumnFromGridColumn(Col);
end;

function TCustomGrid.IsAltColorStored: boolean;
begin
  result := FAlternateColor <> Color;
end;

procedure TCustomGrid.SetAlternateColor(const AValue: TColor);
begin
  if FAlternateColor=AValue then exit;
  FAlternateColor:=AValue;
  Invalidate;
end;

function TCustomGrid.GetEditorBorderStyle: TBorderStyle;
begin
  result := bsSingle;
  if FEditor = FstringEditor then
    Result := FStringEditor.BorderStyle
  else if FEditor = FPickListEditor then
    Result := FStringEditor.BorderStyle;
end;

function TCustomGrid.GetBorderWidth: Integer;
begin
  if InternalNeedBorder then
    Result := 1
  else
    Result := 0
end;

function TCustomGrid.GetColumns: TGridColumns;
begin
  result := FColumns;
end;

function TCustomGrid.CreateColumns: TGridColumns;
begin
  result := TGridColumns.Create(Self, TGridColumn);
end;

procedure TCustomGrid.CheckNewCachedSizes(var AGCache:TGridDataCache);
begin

end;

procedure TCustomGrid.SetAutoFillColumns(const AValue: boolean);
begin
  FAutoFillColumns := AValue;
  if FAutoFillColumns then
    VisualChange;
end;

procedure TCustomGrid.SetBorderColor(const AValue: TColor);
begin
  if FBorderColor=AValue then exit;
  FBorderColor:=AValue;
  if BorderStyle<>bsNone then
    Invalidate;
end;

procedure TCustomGrid.SetColumns(const AValue: TGridColumns);
begin
  FColumns.Assign(Avalue);
end;

procedure TCustomGrid.SetEditorOptions(const AValue: Integer);
begin
  if FEditorOptions<>AValue then begin
    if FEditor=nil then exit;
    FEditorOptions:=AValue;

    if FEditorOptions and EO_HOOKKEYDOWN = EO_HOOKKEYDOWN then begin
      FEditor.OnKeyDown:=@EditorKeyDown;
    end;
    if FEditorOptions and EO_HOOKKEYPRESS = EO_HOOKKEYPRESS then begin
      FEditor.OnKeyPress := @EditorKeyPress;
    end;
    if FEditorOptions and EO_HOOKKEYUP = EO_HOOKKEYUP then begin
      FEditor.OnKeyUp := @EditorKeyUp;
    end;
    if FEditorOptions and EO_HOOKEXIT = EO_HOOKEXIT then begin
      FEditor.OnExit:=@EditorExit;
    end;

    {$IfDef DbgGrid}
    DBGOut('SetEditor-> Editor=',FEditor.Name,' ');
    if FEditorOptions and EO_AUTOSIZE = EO_AUTOSIZE then DBGOut('EO_AUTOSIZE ');
    if FEditorOptions and EO_HOOKKEYDOWN = EO_HOOKKEYDOWN then DBGOut('EO_HOOKKEYDOWN ');
    if FEditorOptions and EO_HOOKKEYPRESS = EO_HOOKKEYPRESS then DBGOut('EO_HOOKKEYPRESS ');
    if FEditorOptions and EO_HOOKKEYUP = EO_HOOKKEYUP then DBGOut('EO_HOOKKEYUP ');
    if FEditorOptions and EO_HOOKEXIT = EO_HOOKEXIT then DBGOut('EO_HOOKEXIT ');
    if FEditorOptions and EO_SELECTALL= EO_SELECTALL then DBGOut('EO_SELECTALL ');
    DebugLn;
    {$Endif}
  end;
end;

procedure TCustomGrid.SetEditorBorderStyle(const AValue: TBorderStyle);
begin
  // supposedly instances cannot access protected properties
  // of parent classes, so why the next works?
  {
  if FEditor.BorderStyle <> AValue then begin
    FEditor.BorderStyle := AValue;
    if EditorMode then
      EditorPos;
  end;
  }
  if FStringEditor.BorderStyle<>AValue then begin
    FStringEditor.BorderStyle := AValue;
    if (FEditor = FStringEditor) and EditorMode then
      EditorPos;
  end;
  if FPicklistEditor.BorderStyle<>AValue then begin
    FPicklistEditor.BorderStyle := AValue;
    if (FEditor = FPicklistEditor) and EditorMode then
      EditorPos;
  end;
end;

procedure TCustomGrid.SetAltColorStartNormal(const AValue: boolean);
begin
  if FAltColorStartNormal=AValue then exit;
  FAltColorStartNormal:=AValue;
  if IsAltColorStored then
    Invalidate;
end;

procedure TCustomGrid.SetFlat(const AValue: Boolean);
begin
  if FFlat=AValue then exit;
  FFlat:=AValue;
  if FGridBorderStyle=bsSingle then
    UpdateBorderStyle
  else
    Invalidate;
end;

procedure TCustomGrid.SetFocusRectVisible(const AValue: Boolean);
begin
  if FFocusRectVisible<>AValue then begin
    FFocusRectVisible := AValue;
    Invalidate;
  end;
end;

procedure TCustomGrid.SetTitleFont(const AValue: TFont);
begin
  FTitleFont.Assign(AValue);
  VisualChange;
end;

procedure TCustomGrid.SetTitleStyle(const AValue: TTitleStyle);
begin
  if FTitleStyle=AValue then exit;
  FTitleStyle:=AValue;
  Invalidate;
end;

procedure TCustomGrid.SetUseXorFeatures(const AValue: boolean);
begin
  if FUseXORFeatures=AValue then exit;
  FUseXORFeatures:=AValue;
  Invalidate;
end;

procedure TCustomGrid.SetBorderStyle(NewStyle: TBorderStyle);
begin
  if FGridBorderStyle<>NewStyle then begin
    FGridBorderStyle := NewStyle;
    UpdateBorderStyle;
  end;
end;

{ Save to the cache the current visible grid (excluding fixed cells) }
procedure TCustomGrid.CacheVisibleGrid;
begin
  with FGCache do begin
    VisibleGrid:=GetVisibleGrid;
    with VisibleGrid do begin
      ValidRows := (left>=0) and (Right>=Left) and (ColCount>0) and (RowCount>0);
      ValidCols := (top>=0) and (bottom>=Top) and (ColCount>0) and (RowCount>0);
      ValidGrid := ValidRows and ValidCols;
    end;
  end;
end;

procedure TCustomGrid.CancelSelection;
begin
  with FRange do
    if (Bottom-Top>0) or
      ((Right-Left>0) and not (goRowSelect in Options)) then begin
      InvalidateRange(FRange);
      if goRowSelect in Options then
        FRange:=Rect(FFixedCols, FRow, ColCount-1, FRow)
      else
        FRange:=Rect(FCol,FRow,FCol,FRow);
    end;
  SelectActive := False;
end;

function TCustomGrid.GetSelection: TGridRect;
begin
  Result:=FRange;
end;

function TCustomGrid.GetSystemMetricsGapSize(const Index: Integer): Integer;
begin
  {$ifdef WINDOWS}
    result := 0;
  {$else}
    result := 3;
  {$endif}
end;

procedure TCustomGrid.SetDefaultDrawing(const AValue: Boolean);
begin
  if FDefaultDrawing=AValue then exit;
  FDefaultDrawing:=AValue;
  Invalidate;
end;

procedure TCustomGrid.SetFocusColor(const AValue: TColor);
begin
  if FFocusColor=AValue then exit;
  FFocusColor:=AValue;
  InvalidateCell(FCol,FRow);
end;

procedure TCustomGrid.SetGridLineStyle(const AValue: TPenStyle);
begin
  if FGridLineStyle=AValue then exit;
  FGridLineStyle:=AValue;
  Invalidate;
end;

procedure TCustomGrid.SetSelectActive(const AValue: Boolean);
begin
  if FSelectActive=AValue then exit;
  FSelectActive:=AValue and
    (not(goEditing in Options) or (ExtendedSelect and not EditorAlwaysShown));
  if FSelectActive then FPivot:=Point(FCol,FRow);
end;

procedure TCustomGrid.SetSelection(const AValue: TGridRect);
begin
  if goRangeSelect in Options then
  with AValue do begin
    if (Left<0)and(Top<0)and(Right<0)and(Bottom<0) then
      CancelSelection
    else begin
      fRange:=NormalizarRect(aValue);
      Invalidate;
    end;
  end;
end;

function TCustomGrid.doColSizing(X, Y: Integer): Boolean;
var
  R: TRect;
  Loc: Integer;
begin
  Result:=False;
  if gsColSizing = fGridState then begin
    if FUseXORFeatures then begin
      if (x-FSplitter.Y)<=0 then
        x:= FSplitter.Y;
      if x<>FPrevValue then begin
        if FPrevLine then
          DrawXorVertLine(FPrevValue);
        DrawXorVertLine(X);
        FPrevLine:=True;
        FPrevValue:=X;
      end;
    end else
      ResizeColumn(FSplitter.x, x-FSplitter.y);
    Result:=True;
  end else
  if (fGridState=gsNormal) and (ColCount>FixedCols) and
     ((Y<FGCache.FixedHeight) or (FExtendedColSizing and (Y<FGCache.MaxClientXY.Y))) and
     (X>FGCache.FixedWidth)
  then begin
    //FSplitter.X:= OffsetToColRow(True, True, X, Loc);
    FSplitter.Y:=0;
    if OffsetToColRow(True, True, X, FSplitter.X, Loc) then begin
      R:=CellRect(FSplitter.x, FSplitter.y);
      FSplitter.y:=X;                       // Resizing X reference

      // if resizing column is partially visible, take the visible boundary.
      if R.Right>FGCache.ClientWidth then
        Loc:=FGCache.Clientwidth
      else
      if (R.Right-X)<(X-R.Left) then
        Loc:=R.Right
      else begin
        Loc:=R.Left;
        Dec(FSplitter.x);                   // Resizing col is the previous
      end;
      iF (Abs(Loc-x)<=2)and(FSplitter.X>=FFixedCols) then begin
        // start resizing
        Cursor:=crHSplit;
        {.$ifdef UseXOR}
        FPrevLine := False;
        FPrevValue := -1;
        {.$endif}
      end
      else
        Cursor:=crDefault;
      Result:=True;
    end;
  end
    else
      if (cursor=crHSplit) then
        Cursor:=crDefault;
end;

function TCustomGrid.doRowSizing(X, Y: Integer): Boolean;
var
  OffTop,OffBottom: Integer;
begin
  Result:=False;
  if gsRowSizing = fGridState then begin
    if FUseXORFeatures then begin
      if (y-FSplitter.x)<=0 then
        y:= FSplitter.x;
      if y<>FPrevValue then begin
        if FPrevLine then
          DrawXorHorzLine(FPrevValue);
        DrawXorHorzLine(Y);
        FPrevLine:=True;
        FPrevValue:=y;
      end;
    end else
      ResizeRow(FSplitter.y, y-FSplitter.x);
    Result:=True;
  end else
  if (fGridState=gsNormal) and (RowCount>FixedRows) and
     ((X<FGCache.FixedWidth) or (FExtendedRowSizing and (X<FGCache.MaxClientXY.X))) and
     (Y>FGCache.FixedHeight) then
  begin
    //fSplitter.Y:=OffsetToColRow(False, True, Y, OffTop{dummy});
    if OffsetToColRow(False, True, Y, FSplitter.Y, OffTop{dummy}) then begin
      ColRowToOffset(False, True, FSplitter.Y, OffTop, OffBottom);
      FSplitter.X:=Y;
      if (OffBottom-Y)<(Y-OffTop) then SwapInt(OffTop, OffBottom)
      else Dec(FSplitter.y);
      if (Abs(OffTop-y)<=2)and(FSplitter.Y>=FFixedRows) then begin
        // start resizing
        Cursor:=crVSplit;
        FPrevLine := False;
        FPrevValue := -1;
      end else
        Cursor:=crDefault;
      Result:=True;
    end;
  end
    else
      if Cursor=crVSplit then
        Cursor:=crDefault;
end;

procedure TCustomGrid.doColMoving(X, Y: Integer);
var
  P: TPoint;
  R: TRect;
begin
  //debugLn('DoColMoving: FDragDX=',IntToStr(FDragDX), ' Sp.x= ', IntTOStr(FSplitter.X), 'Sp.y= ', IntToStr(FSplitter.y));
  P:=MouseToCell(Point(X,Y));
  if (Abs(FSplitter.Y-X)>fDragDx)and(Cursor<>crMultiDrag) then begin
    Cursor:=crMultiDrag;
    FMoveLast:=Point(-1,-1);
    ResetOffset(True, False);
  end;
  if (Cursor=crMultiDrag)and
     (P.x>=FFixedCols) and
     ((P.X<=FSplitter.X)or(P.X>FSplitter.X))and
     (P.X<>FMoveLast.X) then begin
      R:=CellRect(P.x, P.y);
      if P.x<=FSplitter.X then fMoveLast.Y:=R.left
      else                     FMoveLast.Y:=R.Right;
      fMoveLast.X:=P.X;
      {$ifdef AlternativeMoveIndicator}
      InvalidateRow(0);
      {$else}
      Invalidate;
      {$endif}
  end;
end;

procedure TCustomGrid.doRowMoving(X, Y: Integer);
var
  P: TPoint;
  R: TRect;
begin
  P:=MouseToCell(Point(X,Y));
  if (Cursor<>crMultiDrag)and(Abs(FSplitter.X-Y)>fDragDx) then begin
    Cursor:=crMultiDrag;
    FMoveLast:=Point(-1,-1);
    ResetOffset(False, True);
  end;
  if (Cursor=crMultiDrag)and
     (P.y>=FFixedRows) and
     ((P.y<=FSplitter.Y)or(P.Y>FSplitter.Y))and
     (P.y<>FMoveLast.Y) then begin
      R:=CellRect(P.x, P.y);
      if P.y<=FSplitter.y then fMoveLast.X:=R.Top
      else                     FMoveLast.X:=R.Bottom;
      fMoveLast.Y:=P.Y;
      Invalidate;
  end;
end;


function TCustomGrid.OffsetToColRow(IsCol, Fisical: Boolean; Offset: Integer;
  var Index, Rest: Integer): boolean;
begin
  Index:=0;
  Rest:=0;
  Result := False;
  Offset := Offset - GetBorderWidth;
  if Offset<0 then Exit; // Out of Range;

  with FGCache do begin
    if IsCol then begin
      // begin to count Cols from 0 but ...
      if Fisical and (Offset>FixedWidth-1) then begin
        Index := FTopLeft.X;  // In scrolled view, then begin from FTopLeft col
        if (Index>=0) and (Index<ColCount) then
          Offset:=Offset-FixedWidth+PtrInt(AccumWidth[Index])+TLColOff;
        if (Index<0) or (Index>=ColCount) or (Offset>GridWidth-1) then begin
          Index := ColCount-1;
          exit;
        end;
      end;

      while Offset>(PtrInt(AccumWidth[Index])+GetColWidths(Index)-1) do
        Inc(Index);

      Rest:=Offset;
      if Index<>0 then Rest:=Offset-PtrInt(AccumWidth[Index]);

    end else begin

      //DebugLn('TCustomGrid.OffsetToColRow ',DbgSName(Self),' Fisical=',dbgs(Fisical),' Offset=',dbgs(Offset),' FixedHeight=',dbgs(FixedHeight),' FTopLeft=',dbgs(FTopLeft),' RowCount=',dbgs(RowCount),' TLRowOff=',dbgs(TLRowOff));
      if Fisical and (Offset>FixedHeight-1) then begin
        Index:=FTopLeft.Y;
        if (Index>=0) and (Index<RowCount) then
          Offset:=Offset-FixedHeight+PtrInt(AccumHeight[Index])+TLRowOff;
        if (Index<0) or (Index>=RowCount) or (Offset>GridHeight-1) then begin
          Index:=RowCount-1;
          Exit; // Out of Range
        end;
      end;

      while Offset>(PtrInt(AccumHeight[Index])+GetRowHeights(Index)-1) do
        Inc(Index);

      Rest:=Offset;
      if Index<>0 then Rest:=Offset-PtrInt(AccumHeight[Index]);

    end;
  end;
  result := True;
end;

{ ------------------------------------------------------------------------------
  Example:
  IsCol=true, Index:=100, TopLeft.x:=98, FixedCols:=1, all ColWidths:=20
  Relative => StartPos := WidthfixedCols+WidthCol98+WidthCol99
  not Relative = Absolute => StartPos := WidthCols(0..99) }
function TCustomGrid.ColRowToOffset(IsCol, Relative: Boolean; Index:Integer;
  var StartPos, EndPos: Integer): Boolean;
var
  Dim: Integer;
begin
  with FGCache do begin
    if IsCol then begin
      StartPos:=PtrInt(AccumWidth[index]);
      Dim:=GetColWidths(index);
    end else begin
      StartPos:=PtrInt(AccumHeight[index]);
      Dim:= GetRowHeights(index);
    end;
    StartPos := StartPos + GetBorderWidth;
    if not Relative then begin
      EndPos:=StartPos + Dim;
      Exit;
    end;
    if IsCol then begin
      if index>=FFixedCols then
        StartPos:=StartPos-PtrInt(AccumWidth[FTopLeft.X]) + FixedWidth -  TLColOff;
    end else begin
      if index>=FFixedRows then
        StartPos:=StartPos-PtrInt(AccumHeight[FTopLeft.Y]) + FixedHeight - TLRowOff;
    end;
    EndPos:=StartPos + Dim;
  end;
  Result:=true;
end;

function TCustomGrid.ColumnIndexFromGridColumn(Column: Integer): Integer;
begin
  Result := Columns.RealIndex( Column - FixedCols );
end;

function TCustomGrid.ColumnFromGridColumn(Column: Integer): TGridColumn;
var
  ColIndex: Integer;
begin
  ColIndex := Columns.RealIndex( Column - FixedCols );
  if ColIndex>=0 then
    result := Columns[ColIndex]
  else
    result := nil;
end;

procedure TCustomGrid.ColumnsChanged(aColumn: TGridColumn);
var
  aCol: Integer;
begin
  if csDestroying in ComponentState then
    exit;

  if AColumn=nil then begin
    if Columns.Enabled then begin
      if FixedCols + Columns.VisibleCount <> ColCount then
        InternalSetColCount( FixedCols + Columns.VisibleCount )
      else
        VisualChange;
    end else
      if not (csloading in ComponentState) then
        ColCount := FixedCols + 1
  end else begin
    aCol := Columns.IndexOf(AColumn);
    if ACol>=0 then begin
      VisualChange;
      {
      if aColumn.WidthChanged then
        VisualChange
      else
        InvalidateCol(FixedCols + ACol);
      }
    end;
  end;
end;

function TCustomGrid.MouseToGridZone(X, Y: Integer): TGridZone;
var
  aBorderWidth: Integer;
begin
  aBorderWidth := GetBorderWidth;
  if X<FGCache.FixedWidth+aBorderWidth then
    if Y<FGcache.FixedHeight+aBorderWidth then
      Result:=gzFixedCells
    else
      if RowCount>FixedRows then
        Result:=gzFixedRows
      else
        Result:=gzInvalid
  else
  if Y<FGCache.FixedHeight+aBorderWidth then
    if X<FGCache.FixedWidth+aBorderWidth then
      Result:=gzFixedCells
    else
      if ColCount>FixedCols then
        Result:=gzFixedCols
      else
        Result:=gzInvalid
  else
    if not fixedGrid then
      result := gzNormal
    else
      result := gzInvalid;
end;

function TCustomGrid.CellToGridZone(aCol, aRow: Integer): TGridZone;
begin
  if (aCol<FFixedCols) then
    if aRow<FFixedRows then
      Result:= gzFixedCells
    else
      Result:= gzFixedRows
  else
  if (aRow<FFixedRows) then
    if aCol<FFixedCols then
      Result:= gzFixedCells
    else
      Result:= gzFixedCols
  else
    Result := gzNormal;
end;

procedure TCustomGrid.DoOPExchangeColRow(IsColumn: Boolean; index, WithIndex: Integer
  );
begin
  if IsColumn and Columns.Enabled then begin
    Columns.ExchangeColumn( ColumnIndexFromGridColumn(Index),
      ColumnIndexFromGridColumn(WithIndex));
    ColRowExchanged(IsColumn, index, WithIndex);
    exit;
  end;
  if IsColumn then FCols.Exchange(index, WithIndex)
  else             FRows.Exchange(index, WithIndex);
  ColRowExchanged(IsColumn, index, WithIndex);
  VisualChange;
end;

procedure TCustomGrid.DoOPInsertColRow(IsColumn: boolean; index: integer);
begin
  if Index<0 then Index:=0;
  if IsColumn then begin
    if Index>ColCount-1 then
      Index := ColCount-1;
    if columns.Enabled then begin
      Columns.InsertColumn(ColumnIndexFromGridColumn(index));
      ColRowInserted(true, index);
      exit;
    end else begin
      FCols.Insert(Index, pointer(-1));
      FGCache.AccumWidth.Insert(Index, nil);
    end;
  end else begin
    Frows.Insert(Index, pointer(-1));
    FGCache.AccumHeight.Insert(Index, nil);
  end;
  ColRowInserted(IsColumn, index);
  VisualChange;
end;

procedure TCustomGrid.doOPMoveColRow(IsColumn: Boolean; FromIndex, ToIndex: Integer);
begin
  CheckIndex(IsColumn, FromIndex);
  CheckIndex(IsColumn, ToIndex);

  if IsColumn then
    FCols.Move(FromIndex, ToIndex)
  else
    FRows.Move(FromIndex, ToIndex);

  ColRowMoved(IsColumn, FromIndex, ToIndex);
  
  if not IsColumn or not Columns.Enabled then
    VisualChange;
end;

procedure TCustomGrid.DoOPDeleteColRow(IsColumn: Boolean; index: Integer);
  procedure doDeleteColumn;
  begin
    CheckIndex(IsColumn,Index);
    CheckFixedCount(ColCount-1, RowCount, FFixedCols, FFixedRows);
    CheckCount(ColCount-1, RowCount);
    if Columns.Enabled then begin
      Columns.RemoveColumn(ColumnIndexFromGridColumn(Index));
      ColRowDeleted(True, Index);
    end else begin
      if Index<FixedCols then begin
        Dec(FFixedCols);
        FTopLeft.x := FFixedCols;
      end;
      FCols.Delete(Index);
      FGCache.AccumWidth.Delete(Index);
      ColRowDeleted(True, Index);
      FixPosition;
    end;
  end;
  procedure doDeleteRow;
  begin
    CheckIndex(IsColumn, Index);
    CheckFixedCount(ColCount, RowCount-1, FFixedCols, FFixedRows);
    CheckCount(ColCount, RowCount-1);
    if Index<FixedRows then begin
      Dec(FFixedRows);
      FTopLeft.y := FFixedRows;
      //DebugLn('TCustomGrid.doDeleteColumn A ',DbgSName(Self),' FTopLeft=',dbgs(FTopLeft));
    end;
    FRows.Delete(Index);
    FGCache.AccumHeight.Delete(Index);
    ColRowDeleted(False,Index);
    FixPosition;
  end;
begin
  if IsColumn then
    doDeleteColumn
  else
    doDeleteRow;
end;

function TCustomGrid.EditorByStyle(Style: TColumnButtonStyle): TWinControl;
begin
  case Style of
    cbsNone, cbsCheckboxColumn:   //SSY
      Result := nil;
    cbsEllipsis:
      Result := FButtonEditor;
    cbsPicklist:
      Result := FPicklistEditor;
    cbsAuto:
      begin
        Result := FStringEditor;
      end;
  end;
end;

procedure TCustomGrid.MouseDown(Button: TMouseButton; Shift: TShiftState; X,
  Y: Integer);
var
  Gz: TGridZone;
  R: TRect;
  WasFocused: boolean;
begin
  inherited MouseDown(Button, Shift, X, Y);

  if (csDesigning in componentState) or not (ssLeft in Shift) then
    Exit;

  {$IfDef dbgGrid} DebugLn('MouseDown INIT'); {$Endif}

  Gz:=MouseToGridZone(X,Y);
  case Gz of
    gzFixedCols:
      begin
        if (goColSizing in Options)and(Cursor=crHSplit) then begin
          R:=CellRect(FSplitter.x, 0{FTopLeft.y});
          FSplitter.y:=R.Left;
          fGridState:= gsColSizing;
        end else begin
          // ColMoving or Clicking
          fGridState:=gsColMoving;
          FSplitter:=MouseToCell(Point(X,Y));
          FMoveLast:=Point(-1,-1);
          FSplitter.Y:=X;
        end;
      end;
      
    gzFixedRows:
      if (goRowSizing in Options)and(Cursor=crVSplit) then begin
        R:=CellRect(0{FTopLeft.X}, FSplitter.y);
        FSplitter.x:=R.top;
        fGridState:= gsRowSizing;
      end else begin
        // RowMoving or Clicking
        fGridState:=gsRowMoving;
        fSplitter:=MouseToCell(Point(X,Y));
        FMoveLast:=Point(-1,-1);
        FSplitter.X:=Y;
      end;
      
    gzNormal:
      begin
        WasFocused := Focused;
        if not WasFocused then
          SetFocus;

        if FExtendedColSizing and
          (Cursor=crHSplit) and
          (goColSizing in Options) then begin
          // extended column sizing
          R:=CellRect(FSplitter.x, FTopLeft.y);
          FSplitter.y:=R.Left;
          fGridState:= gsColSizing;
        end
        else if not FixedGrid then begin
          // normal selecting
          fGridState:=gsSelecting;
          FSplitter:=MouseToCell(Point(X,Y));

          if not (goEditing in Options) or
            (ExtendedSelect and not EditorAlwaysShown) then begin
            if ssShift in Shift then begin
              SelectActive:=(goRangeSelect in Options);
            end else begin
              // shift is not pressed any more cancel SelectActive if necessary
              if SelectActive then
                CancelSelection;

              if not SelectActive then begin
                FPivot:=FSplitter;
                Include(GridFlags, gfNeedsSelectActive);
                // delay select active until mouse reachs another cell
              end;
            end;
          end else if (FSplitter.X=Col) and (FSplitter.Y=Row) then begin
            //if WasFocused then begin
              SelectEditor;
              EditorShow(True);
              {$ifDef dbgGrid} DebugLn('MouseDown (autoedit) END'); {$Endif}
              exit;
            //end;
          end;

          if not MoveExtend(False, FSplitter.X, FSplitter.Y) then begin
            if EditorAlwaysShown then begin
              SelectEditor;
              EditorShow(true);
            end;
            MoveSelection;
          end;

        end;
      end;
  end;
  {$ifDef dbgGrid} DebugLn('MouseDown END'); {$Endif}
end;

procedure TCustomGrid.MouseMove(Shift: TShiftState; X, Y: Integer);
var
  p: TPoint;
begin
  inherited MouseMove(Shift, X, Y);

  case fGridState of

    gsSelecting:
      if not FixedGrid and (not (goEditing in Options) or
        (ExtendedSelect and not EditorAlwaysShown)) then begin
        P:=MouseToLogcell(Point(X,Y));
        if gfNeedsSelectActive in GridFlags then
          SelectActive := (P.x<>FPivot.x)or(P.y<>FPivot.y);
        MoveExtend(False, P.x, P.y);
      end;
      
    gsColMoving:
      if goColMoving in Options then
        doColMoving(X,Y);
      
    gsRowMoving:
      if goRowMoving in Options then
        doRowMoving(X,Y);
      
    else
      begin
        if goColSizing in Options then doColSizing(X,Y);
        if goRowSizing in Options then doRowSizing(X,Y);
      end;
  end;
end;

procedure TCustomGrid.MouseUp(Button: TMouseButton; Shift: TShiftState; X,
  Y: Integer);
var
   Cur: TPoint;
begin
  inherited MouseUp(Button, Shift, X, Y);
  {$IfDef dbgGrid}DebugLn('MouseUP INIT');{$Endif}
  
  Cur:=MouseToCell(Point(x,y));
  case fGridState of
  
    gsNormal:
      if not FixedGrid then
        CellClick(cur.x, cur.y);

    gsSelecting:
      begin
        if SelectActive then
          MoveExtend(False, Cur.x, Cur.y)
        else
          CellClick(cur.x, cur.y);
      end;
      
    gsColMoving:
      begin
        //DebugLn('Move Col From ',Fsplitter.x,' to ', FMoveLast.x);
        if FMoveLast.X>=0 then begin
          if FMoveLast.X=FSplitter.X then
            {$ifdef AlternativeMoveIndicator}
            InvalidateRow(0);
            {$else}
            Invalidate;
            {$endif}
          DoOPMoveColRow(True, Fsplitter.X, FMoveLast.X);
          Cursor:=crDefault;
        end else
          if Cur.X=FSplitter.X then
            HeaderClick(True, FSplitter.X);
      end;
      
    gsRowMoving:
      begin
        //DebugLn('Move Row From ',Fsplitter.Y,' to ', FMoveLast.Y);
        if FMoveLast.Y>=0 then begin
          DoOPMoveColRow(False, Fsplitter.Y, FMoveLast.Y);
          Cursor:=crDefault;
        end else
          if Cur.Y=FSplitter.Y then HeaderClick(False, FSplitter.Y);
      end;
      
    gsColSizing:
      begin
        if FUseXORFeatures then begin
          if FPrevLine then
            DrawXorVertLine(FPrevValue);
          FPrevLine := False;
          FPrevValue := -1;
          ResizeColumn(FSplitter.x, x-FSplitter.y);
        end;
        HeaderSized( True, FSplitter.X);
      end;
      
    gsRowSizing:
      begin
        if FUseXORFeatures then begin
          if FPrevLine then
            DrawXorHorzLine(FPrevValue);
          FPrevLine := False;
          FPrevValue := -1;
          ResizeRow(FSplitter.y, y-FSplitter.x);
        end;
        HeaderSized( False, FSplitter.Y);
      end;
      
  end;
  fGridState:=gsNormal;
  Exclude(GridFlags, gfNeedsSelectActive);
  {$IfDef dbgGrid}DebugLn('MouseUP  END  RND=', FloatToStr(Random));{$Endif}
end;

procedure TCustomGrid.DblClick;
begin
  {$IfDef dbgGrid}DebugLn('DoubleClick INIT');{$Endif}
  SelectActive:=False;
  fGridState:=gsNormal;
  if (goColSizing in Options) and (Cursor=crHSplit) then begin
    if (goDblClickAutoSize in Options) then begin
      AutoAdjustColumn( FSplitter.X );
    end {else
      DebugLn('Got Doubleclick on Col Resizing: AutoAdjust?');}
  end else
  if  (goDblClickAutoSize in Options) and
      (goRowSizing in Options) and
      (Cursor=crVSplit) then begin
      {
        DebugLn('Got DoubleClick on Row Resizing: AutoAdjust?');
      }
  end
  else
    Inherited DblClick;
  {$IfDef dbgGrid}DebugLn('DoubleClick END');{$Endif}
end;

procedure TCustomGrid.DefineProperties(Filer: TFiler);
  function SonRowsIguales(aGrid: TCustomGrid): boolean;
  var
    i: Integer;
  begin
    result := aGrid.RowCount = RowCount;
    if Result then
      for i:=0 to RowCount-1 do
        if aGrid.RowHeights[i]<>RowHeights[i] then begin
          result := false;
          break;
        end;
  end;
  function SonColsIguales(aGrid: TCustomGrid): boolean;
  var
    i: Integer;
  begin
    result := aGrid.ColCount = ColCount;
    if Result then
      for i:=0 to ColCount-1 do
        if aGrid.ColWidths[i]<>ColWidths[i] then begin
          result := false;
          break;
        end;
  end;
  function SonDefault(IsColumn: Boolean; L1: TList): boolean;
  var
    i: Integer;
    DefValue, Value: Integer;
  begin
    Result := True;
    if IsColumn then DefValue := DefaultColWidth
    else             DefValue := DefaultRowHeight;
    for i:=0 to L1.Count-1 do begin
      Value := PtrInt(L1[i]);
      Result := (Value = DefValue) or (Value<0);
      if not Result then
        break;
    end;
  end;
  function NeedWidths: boolean;
  begin
    if Filer.Ancestor <> nil then
      Result := not SonColsIguales(TCustomGrid(Filer.Ancestor))
    else
      Result := not SonDefault(True, FCols);
    result := Result and not AutoFillColumns;
  end;
  function NeedHeights: boolean;
  begin
    if Filer.Ancestor <> nil then
      Result := not SonRowsIguales(TCustomGrid(Filer.Ancestor))
    else
      Result := not SonDefault(false, FRows);
  end;
  function HasColumns: boolean;
  var
    C: TGridColumns;
  begin
    if Filer.Ancestor <> nil then
      C := TCustomGrid(Filer.Ancestor).Columns
    else
      C := Columns;
    if C<>nil then
      result := not C.IsDefault
    else
      result := false;
  end;
begin
  inherited DefineProperties(Filer);
  with Filer do begin
    //DefineProperty('Columns',    @ReadColumns,    @WriteColumns,    HasColumns);
    DefineProperty('ColWidths',  @ReadColWidths,  @WriteColWidths,  NeedWidths);
    DefineProperty('RowHeights', @ReadRowHeights, @WriteRowHeights, NeedHeights);
  end;
end;

procedure TCustomGrid.DestroyHandle;
begin
  editorGetValue;
  inherited DestroyHandle;
end;

function TCustomGrid.DoCompareCells(Acol, ARow, Bcol, BRow: Integer): Integer;
begin
  result := 0;
  if Assigned(OnCompareCells) then
    OnCompareCells(Self, ACol, ARow, BCol, BRow, Result);
end;

procedure TCustomGrid.DoCopyToClipboard;
begin
end;

procedure TCustomGrid.DoCutToClipboard;
begin
end;

procedure TCustomGrid.DoEditorHide;
begin
  Editor.Visible:=False;
  if HandleAllocated
  and ([csLoading,csDesigning,csDestroying]*ComponentState=[]) then
    LCLIntf.SetFocus(Handle);
end;

procedure TCustomGrid.DoEditorShow;
begin
  //DebugLn(['TCustomGrid.DoEditorShow ']);
  {$ifdef dbgGrid}DebugLn('grid.DoEditorShow INIT');{$endif}
  ScrollToCell(FCol,FRow);
  Editor.Parent := nil;
  EditorSetValue;
  Editor.Parent:=Self;
  Editor.Visible:=True;
  Editor.SetFocus;
  InvalidateCell(FCol,FRow,True);
  {$ifdef dbgGrid}DebugLn('grid.DoEditorShow FIN');{$endif}
end;

procedure TCustomGrid.DoOnChangeBounds;
begin
  inherited DoOnChangeBounds;
  VisualChange;
end;

procedure TCustomGrid.DoPasteFromClipboard;
begin
  //
end;

procedure TCustomGrid.DoSetBounds(ALeft, ATop, AWidth, AHeight: integer);
begin
  FLastWidth := ClientWidth;
  inherited DoSetBounds(ALeft, ATop, AWidth, AHeight);
end;

procedure TCustomGrid.doExit;
begin
  {$IfDef dbgGrid}DebugLn('DoExit - INIT');{$Endif}
  if FEditorShowing then begin
    {$IfDef dbgGrid}DebugLn('DoExit - EditorShowing');{$Endif}
  end else begin
    {$IfDef dbgGrid}DebugLn('DoExit - Ext');{$Endif}
    if not EditorAlwaysShown then
      InvalidateFocused;
    if FgridState=gsSelecting then begin
      if SelectActive then
        FSelectActive := False;
      FGridState := gsNormal;
    end;
  end;
  inherited DoExit;
  {$IfDef dbgGrid}DebugLn('DoExit - FIN');{$Endif}
end;

procedure TCustomGrid.DoEnter;
begin
  {$IfDef dbgGrid}DebugLn('DoEnter - INIT');{$Endif}
  inherited DoEnter;
  if EditorLocked then begin
    {$IfDef dbgGrid}DebugLn('DoEnter - EditorLocked');{$Endif}
  end else begin
    {$IfDef dbgGrid}DebugLn('DoEnter - Ext');{$Endif}
    if EditorAlwaysShown then begin
      // try to show editor only if focused cell is visible area
      // so a mouse click would use click coords to show up
      if IsCellVisible(Col,Row) then begin
        SelectEditor;
        if Feditor<>nil then
          EditorShow(true);
      end else begin
      {$IfDef dbgGrid}DebugLn('DoEnter - Ext - Cell was not visible');{$Endif}
      end;
    end else
      InvalidateFocused;
  end;
  {$IfDef dbgGrid}DebugLn('DoEnter - FIN');{$Endif}
end;

function TCustomGrid.DoMouseWheelDown(Shift: TShiftState; MousePos: TPoint
  ): Boolean;
begin
  {$ifdef dbgGrid}DebugLn('doMouseWheelDown INIT');{$endif}
  Result:=inherited DoMouseWheelDown(Shift, MousePos);
  if not result then begin
    // event wasn't handled by the user
    if ssCtrl in Shift then
      MoveExtend(true, 1, 0)
    else
      MoveExtend(true, 0, 1);
    Result := true;
  end;
  {$ifdef dbgGrid}DebugLn('doMouseWheelDown FIN');{$endif}
end;

function TCustomGrid.DoMouseWheelUp(Shift: TShiftState; MousePos: TPoint
  ): Boolean;
begin
  {$ifdef dbgGrid}DebugLn('doMouseWheelUP INIT');{$endif}
  Result:=inherited DoMouseWheelUp(Shift, MousePos);
  if not result then begin
    // event wasn't handled by the user
    if ssCtrl in Shift then
      MoveExtend(true, -1, 0)
    else
      MoveExtend(true, 0, -1);
    Result := True;
  end;
  {$ifdef dbgGrid}DebugLn('doMouseWheelUP FIN');{$endif}
end;

procedure TCustomGrid.KeyDown(var Key: Word; Shift: TShiftState);
var
  Sh: Boolean;
  R: TRect;
  Relaxed: Boolean;
  DeltaCol,DeltaRow: Integer;

  procedure MoveSel(Rel: Boolean; aCol,aRow: Integer);
  begin
    // Always reset Offset in keyboard Events
    FGCache.TLColOff:=0;
    FGCache.TLRowOff:=0;
    SelectActive:=Sh;
    MoveNextSelectable(Rel, aCol, aRow);
    Key:=0;
  end;
begin
  {$ifdef dbgGrid}DebugLn('Grid.KeyDown INIT Key=',IntToStr(Key));{$endif}
  inherited KeyDown(Key, Shift);
  //if not FGCache.ValidGrid then Exit;
  if not CanGridAcceptKey(Key, Shift) then
    Key:=0;  // Allow CanGridAcceptKey to override Key behaviour
  Sh:=(ssShift in Shift);
  Relaxed:=not (goRowSelect in Options) or (goRelaxedRowSelect in Options);

  case Key of
    VK_TAB:
      begin
        if goTabs in Options then begin
          if GetDeltaMoveNext(Sh, DeltaCol,DeltaRow) then begin
            Sh := False;
            MoveSel(True, DeltaCol, DeltaRow);
          end;
          Key:=0;
        end else
        if FEditorKey then begin
          {$IFDEF dbggrid}
          DebugLn('Got TAB, shift=',dbgs(sh));
          {$endif}
          if sh then
            include(GridFlags, gfRevEditorTab)
          else
            include(GridFlags, gfEditorTab);
        end;
      end;
    VK_LEFT:
      begin
        if Relaxed then MoveSel(True,-1, 0)
        else            MoveSel(true, 0,-1);
      end;
    VK_RIGHT:
      begin
        if Relaxed then MoveSel(True, 1, 0)
        else            MoveSel(True, 0, 1);
      end;
    VK_UP:
      begin
        MoveSel(True, 0, -1);
      end;
    VK_DOWN:
      begin
        MoveSel(True, 0, 1);
      end;
    VK_PRIOR:
      begin
        R:=FGCache.Visiblegrid;
        MoveSel(True, 0, R.Top-R.Bottom);
      end;
    VK_NEXT:
      begin
        R:=FGCache.VisibleGrid;
        MoveSel(True, 0, R.Bottom-R.Top);
      end;
    VK_HOME:
      begin
        if ssCtrl in Shift then MoveSel(False, FCol, FFixedRows)
        else
          if Relaxed then MoveSel(False, FFixedCols, FRow)
          else            MoveSel(False, FCol, FFixedRows);
      end;
    VK_END:
      begin
        if ssCtrl in Shift then MoveSel(False, FCol, RowCount-1)
        else
          if Relaxed then MoveSel(False, ColCount-1, FRow)
          else            MoveSel(False, FCol, RowCount-1);
      end;
    VK_F2: //, VK_RETURN:
      begin
        EditorShow(False);
        // if Key=VK_RETURN then EditorSelectAll;
        Key:=0;
      end;
    VK_RETURN:
      begin
        if not FEditorKey and (goEditing in FOptions) then begin
          EditorShow(True);
          Key := 0;
        end;
      end;
    VK_BACK:
      begin
        // Workaround: LM_CHAR doesnt trigger with BACKSPACE
        if not FEditorKey and (goEditing in FOptions) then begin
          EditorShowChar(^H);
          key:=0;
        end;
      end;
    VK_C:
      if not FEditorKey then begin
        if ssCtrl in Shift then begin
//          Key := 0;
          doCopyToClipboard;
        end;
      end;
    VK_V:
      if not FEditorKey then begin
        if ssCtrl in Shift then begin
//          Key := 0;
          doPasteFromClipboard;
        end;
      end;
    VK_X:
      if not FEditorKey then begin
        if ssCtrl in Shift then begin
//          Key := 0;
          doCutToClipboard;
        end;
      end;
  end;
  {$ifdef dbgGrid}DebugLn('Grid.KeyDown FIN Key=',IntToStr(Key));{$endif}
end;


procedure TCustomGrid.KeyUp(var Key: Word; Shift: TShiftState);
begin
  inherited KeyUp(Key, Shift);
end;

{ Convert a fisical Mouse coordinate into fisical a cell coordinate }
function TCustomGrid.MouseToCell(const Mouse: TPoint): TPoint;
begin
  MouseToCell(Mouse.X, Mouse.Y, Result.X, Result.Y);
end;

procedure TCustomGrid.MouseToCell(X, Y: Integer; var ACol, ARow: Longint);
var
  dummy: Integer;
begin
  // Do not raise Exception if out of range
  OffsetToColRow(True, True, X, ACol, dummy);
  OffsetToColRow(False,True, Y, ARow, dummy);
end;

{ Convert a fisical Mouse coordinate into a logical cell coordinate }
function TCustomGrid.MouseToLogcell(Mouse: TPoint): TPoint;
var
  gz: TGridZone;
begin
  Gz:=MouseToGridZone(Mouse.x, Mouse.y);
  Result:=MouseToCell(Mouse);
  if gz<>gzNormal then begin
    if (gz=gzFixedRows)or(gz=gzFixedCells) then begin
      Result.x:= fTopLeft.x-1;
      if Result.x<FFixedCols then Result.x:=FFixedCols;
    end;
    if (gz=gzFixedCols)or(gz=gzFixedCells) then begin
      Result.y:=fTopleft.y-1;
      if Result.y<fFixedRows then Result.y:=FFixedRows;
    end;
  end;
end;

function TCustomGrid.MouseCoord(X, Y: Integer): TGridCoord;
begin
  Result := MouseToCell(Point(X,Y));
end;

function TCustomGrid.ISCellVisible(aCol, aRow: Integer): Boolean;
begin
  with FGCache.VisibleGrid do
    Result:= (Left<=ACol)and(aCol<=Right)and(Top<=aRow)and(aRow<=Bottom);
end;

procedure TCustomGrid.InvalidateCol(ACol: Integer);
var
  R: TRect;
begin
  {$ifdef dbgPaint} DebugLn('InvalidateCol  Col=',IntToStr(aCol)); {$Endif}
  R:=CellRect(aCol, FTopLeft.y);
  R.Top:=0; // Full Column
  R.Bottom:=FGCache.MaxClientXY.Y;
  InvalidateRect(Handle, @R, True);
end;

procedure TCustomGrid.InvalidateFromCol(ACol: Integer);
var
  R: TRect;
begin
  {$IFDEF dbgPaint} DebugLn('InvalidateFromCol  Col=',IntToStr(aCol)); {$Endif}
  R:=CellRect(aCol, FTopLeft.y);
  R.Top:=0; // Full Column
  R.BottomRight := FGCache.MaxClientXY;
  InvalidateRect(Handle, @R, True);
end;

procedure TCustomGrid.InvalidateRow(ARow: Integer);
var
  R: TRect;
begin
  {$ifdef DbgPaint} DebugLn('InvalidateRow  Row=',IntToStr(aRow)); {$Endif}
  R:=CellRect(fTopLeft.x, aRow);
  R.Left:=0; // Full row
  R.Right:=FGCache.MaxClientXY.X;
  InvalidateRect(Handle, @R, True);
end;

procedure TCustomGrid.InvalidateFocused;
begin
  if FGCache.ValidGrid then begin
    {$ifdef dbgGrid}DebugLn('InvalidateFocused');{$Endif}
    if goRowSelect in Options then
      InvalidateRow(Row)
    else
      InvalidateCell(Col,Row);
  end;
end;

function TCustomGrid.MoveExtend(Relative: Boolean; DCol, DRow: Integer): Boolean;
var
  OldRange: TRect;
begin
  Result:=TryMoveSelection(Relative,DCol,DRow);
  if (not Result) then Exit;

  EditorGetValue;

  {$IfDef dbgGrid}DebugLn(' MoveExtend INIT FCol= ',IntToStr(FCol), ' FRow= ',IntToStr(FRow));{$Endif}
  BeforeMoveSelection(DCol,DRow);
  
  OldRange := FRange;

  if goRowSelect in Options then
    FRange:=Rect(FFixedCols, DRow, Colcount-1, DRow)
  else
    FRange:=Rect(DCol,DRow,DCol,DRow);

  if SelectActive and (goRangeSelect in Options) then
    if goRowSelect in Options then begin
      FRange.Top:=Min(fPivot.y, DRow);
      FRange.Bottom:=Max(fPivot.y, DRow);
    end else
      FRange:=NormalizarRect(Rect(Fpivot.x,FPivot.y, DCol, DRow));

  if not ScrollToCell(DCol, DRow) then
    InvalidateMovement(DCol, DRow, OldRange);
    
  SwapInt(DCol,FCol);
  SwapInt(DRow,FRow);

  MoveSelection;
  SelectEditor;

  if (FEditor<>nil) and EditorAlwaysShown then
    EditorShow(true);

  {$IfDef dbgGrid}DebugLn(' MoveExtend FIN FCol= ',IntToStr(FCol), ' FRow= ',IntToStr(FRow));{$Endif}
end;

function TCustomGrid.MoveNextAuto(const Inverse: boolean): boolean;
var
  aCol,aRow: Integer;
begin
  Result := GetDeltaMoveNext(Inverse, ACol, ARow);
  if result then begin
    FGCache.TLColOff:=0;
    FGCache.TLRowOff:=0;
    MoveNextSelectable(true, aCol, aRow);
  end;
end;

function TCustomGrid.MoveNextSelectable(Relative: Boolean; DCol, DRow: Integer
  ): Boolean;
var
  CInc,RInc: Integer;
  NCol,NRow: Integer;
  SelOk: Boolean;
begin
  // Reference
  if not Relative then begin
    NCol:=DCol;
    NRow:=DRow;
    DCol:=NCol-FCol;
    DRow:=NRow-FRow;
  end else begin
    NCol:=FCol + DCol;
    NRow:=FRow + DRow;
  end;

  Checklimits(NCol, NRow);

  // Increment
  if DCol<0 then CInc:=-1 else
  if DCol>0 then CInc:= 1
  else           CInc:= 0;
  if DRow<0 then RInc:=-1 else
  if DRow>0 then RInc:= 1
  else           RInc:= 0;

  // Calculate
  SelOk:=SelectCell(NCol,NRow);
  Result:=False;
  while not SelOk do begin
    if  (NRow+RInc>RowCount-1)or(NRow+RInc<FFixedRows) or
        (NCol+CInc>ColCount-1)or(NCol+CInc<FFixedCols) then Exit;
    Inc(NCol, CInc);
    Inc(NRow, RInc);
    SelOk:=SelectCell(NCol, NRow);
  end;
  Result:=MoveExtend(False, NCol, NRow);
  
  // whether or not a movement was valid if goAlwaysShowEditor
  // is set, editor should pop up if grid is focused
  if Focused and not EditorMode and EditorAlwaysShown then begin
    SelectEditor;
    if Feditor<>nil then
      EditorShow(true);
  end;
end;

function TCustomGrid.TryMoveSelection(Relative: Boolean; var DCol, DRow: Integer
  ): Boolean;
begin
  Result:=False;

  if FixedGrid then
    exit;

  dCol:=FCol*(1-Byte(not Relative))+DCol;
  dRow:=FRow*(1-Byte(not Relative))+DRow;

  CheckLimits( dCol, dRow );

  // Change on Focused cell?
  if (Dcol=FCol) and (DRow=FRow) then begin
    SelectCell(DCol,DRow);
  end else begin
    Result:=SelectCell(DCol,DRow);
  end;
end;

procedure TCustomGrid.UnLockEditor;
begin
  Dec(FEditorHidingCount);
  {$ifdef dbgGrid}DebugLn('==< LockEditor: ', dbgs(FEditorHidingCount)); {$endif}
end;

procedure TCustomGrid.UpdateHorzScrollBar(const aVisible: boolean;
  const aRange,aPage: Integer);
begin
  {$ifdef DbgScroll}
  DebugLn('TCustomGrid.UpdateHorzScrollbar: Vis=',dbgs(aVisible),
    ' Range=',dbgs(aRange),' Page=',dbgs(aPage));
  {$endif}
  ScrollBarShow(SB_HORZ, aVisible);
  if aVisible then
    ScrollBarRange(SB_HORZ, aRange, aPage);
end;

procedure TCustomGrid.UpdateVertScrollbar(const aVisible: boolean;
  const aRange,aPage: Integer);
begin
  {$ifdef DbgScroll}
  DebugLn('TCustomGrid.UpdateVertScrollbar: Vis=',dbgs(aVisible),
    ' Range=',dbgs(aRange),' Page=',dbgs(aPage));
  {$endif}
  ScrollBarShow(SB_VERT, aVisible);
  if aVisible then
    ScrollbarRange(SB_VERT, aRange, aPage );
end;

procedure TCustomGrid.UpdateBorderStyle;
var
  ABorderStyle: TBorderStyle;
begin
  if not Flat and (FGridBorderStyle=bsSingle) then
    ABorderStyle := bsSingle
  else
    ABorderStyle := bsNone;
  inherited SetBorderStyle(ABorderStyle);
  if HandleAllocated and ([csDestroying,csLoading]*ComponentState=[]) then
  begin
    VisualChange;
    if CheckTopLeft(Col, Row, True, True) then
      VisualChange;
  end;
end;

procedure TCustomGrid.BeforeMoveSelection(const DCol,DRow: Integer);
begin
  if Assigned(OnBeforeSelection) then OnBeforeSelection(Self, DCol, DRow);
end;

procedure TCustomGrid.CalcAutoSizeColumn(const Index: Integer; var AMin, AMax,
  APriority: Integer);
begin
  APriority := 0;
end;

procedure TCustomGrid.CalcFocusRect(var ARect: TRect);
{
var
  dx,dy: integer;
}
begin
  if goRowSelect in Options then begin
    aRect.Left := FGCache.FixedWidth + 1;
    aRect.Right := FGCache.MaxClientXY.x;
  end;
  if goHorzLine in Options then dec(aRect.Bottom, 1);
  if goVertLine in Options then dec(aRect.Right, 1);
  {
  if not (goHorzLine in Options) then begin
    aRect.Bottom := aRect.Bottom + 1;
    Dec(aRect.Botton, 1);
  end;
  if not (goVertLine in Options) then begin
    aRect.Right := aRect.Right + 1;
    Dec(aRect.Botton, 1);
  end;
  }
end;

procedure TCustomGrid.CellClick(const aCol, aRow: Integer);
begin
end;

procedure TCustomGrid.CheckLimits(var aCol, aRow: Integer);
begin
  if aCol<FFixedCols then aCol:=FFixedCols else
  if aCol>ColCount-1 then acol:=ColCount-1;
  if aRow<FFixedRows then aRow:=FFixedRows else
  if aRow>RowCount-1 then aRow:=RowCount-1;
end;

// This procedure checks if cursor cell position is allowed
// if not it tries to find a suitable position based on
// AutoAdvance and SelectCell.
procedure TCustomGrid.CheckPosition;
var
  OldAA: TAutoAdvance;
  DeltaCol,DeltaRow: Integer;
begin
  // first tries to find if current position is allowed
  if SelectCell(Col,Row) then
    exit;

  // current position is not valid, look for another position
  OldAA := FAutoAdvance;
  
  if OldAA=aaNone then
    FAutoAdvance := aaRightDown;

  try
    // try first normal movement then inverse movement
    if GetDeltaMoveNext(false, DeltaCol,DeltaRow) or
       GetDeltaMoveNext(true,  DeltaCol,DeltaRow)
    then begin
      MoveNextSelectable(True, DeltaCol, DeltaRow)
    end else begin
      // some combinations of AutoAdvance and current position
      // will always fail, for example if user set current
      // column not selectable and autoadvance is aaDown will
      // fail always, in this case as a last resource do a full
      // scan until a cell is available
      for DeltaCol:=FixedCols to ColCount-1 do
        for DeltaRow:=FixedRows to RowCount-1 do begin
          if SelectCell(DeltaCol,DeltaRow) then begin
            // found one selectable cell
            MoveNextSelectable(False, DeltaCol,DeltaRow);
            exit;
          end;
        end;
      // user has created weird situation.
      // can't do more about it.
    end;

  finally
    FAutoAdvance := OldAA;
  end;
end;

procedure TCustomGrid.MoveSelection;
begin
  if Assigned(OnSelection) then OnSelection(Self, FCol, FRow);
end;

procedure TCustomGrid.BeginUpdate;
begin
  Inc(FUpdateCount);
end;

procedure TCustomGrid.EndUpdate(UO: TUpdateOption);
begin
  Dec(FUpdateCount);
  if FUpdateCount=0 then
    case UO of
      uoQuick: Invalidate;
      uoFull: VisualChange;
    end;
end;

procedure TCustomGrid.EndUpdate(FullUpdate: Boolean);
begin
  if FullUpdate then
    EndUpdate(uoFull)
  else
    EndUpdate(uoQuick);
end;

procedure TCustomGrid.EndUpdate;
begin
  EndUpdate(true);
end;

procedure TCustomGrid.EraseBackground(DC: HDC);
begin
  //
end;

procedure TCustomGrid.InvalidateCell(aCol, aRow: Integer);
begin
  InvalidateCell(ACol,ARow, False);
end;

procedure TCustomGrid.InvalidateCell(aCol, aRow: Integer; Redraw: Boolean);
var
  R: TRect;
begin
  {$IfDef dbgPaint}
    DebugLn('InvalidateCell  Col=',IntToStr(aCol),
      ' Row=',IntToStr(aRow),' Redraw=', BoolToStr(Redraw));
  {$Endif}
  if not HandleAllocated then Exit;
  R:=CellRect(aCol, aRow);
  InvalidateRect(Handle, @R, Redraw);
end;

procedure TCustomGrid.InvalidateRange(const aRange: TRect);
var
  RIni,RFin: TRect;
begin
  RIni := CellRect(aRange.Left, aRange.Top);
  RFin := CellRect(aRange.Right, aRange.Bottom);
  RIni.Right := RFin.Right;
  RIni.Bottom:= RFin.Bottom;
  InvalidateRect(Handle, @RIni, False);
end;

procedure TCustomGrid.InvalidateGrid;
begin
  if FUpdateCount=0 then Invalidate;
end;

procedure TCustomGrid.Invalidate;
begin
  if FUpdateCount=0 then begin
    {$IfDef dbgPaint} DebugLn('Invalidate');{$Endif}
    inherited Invalidate;
end;
end;

procedure TCustomGrid.EditingDone;
begin
  if not FEditorShowing then
    inherited EditingDone;
end;

procedure TCustomGrid.EditorGetValue;
begin
  if not (csDesigning in ComponentState) and (Editor<>nil) and Editor.Visible then begin
    EditorDoGetValue;
    EditorHide;
  end;
end;

procedure TCustomGrid.EditorSetValue;
begin
  if not (csDesigning in ComponentState) then begin
    EditordoSetValue;
    EditorPos;
  end;
end;

procedure TCustomGrid.EditorHide;
begin
  if not EditorLocked and (Editor<>nil) and Editor.HandleAllocated
    and Editor.Visible then
  begin
    FEditorMode:=False;
    {$ifdef dbgGrid}DebugLn('EditorHide [',Editor.ClassName,'] INIT FCol=',IntToStr(FCol),' FRow=',IntToStr(FRow));{$endif}
    LockEditor;
    try
      DoEditorHide;
    finally
      UnLockEditor;
    end;
    {$ifdef dbgGrid}DebugLn('EditorHide FIN');{$endif}
  end;
end;

function TCustomGrid.EditorLocked: boolean;
begin
  Result := FEditorHidingCount <> 0;
end;

procedure TCustomGrid.EditorShow(const SelAll: boolean);
begin
  if csDesigning in ComponentState then
    exit;
    
  if not HandleAllocated then
    Exit;

  if (goEditing in Options) and CanEditShow and
     not FEditorShowing and (Editor<>nil) and not Editor.Visible then
  begin
    {$ifdef dbgGrid} DebugLn('EditorShow [',Editor.ClassName,'] INIT FCol=',IntToStr(FCol),' FRow=',IntToStr(FRow));{$endif}
    FEditorMode:=True;
    FEditorShowing:=True;
    doEditorShow;
    FEditorShowing:=False;
    if SelAll then
      EditorSelectAll;
    {$ifdef dbgGrid} DebugLn('EditorShow FIN');{$endif}
  end;
end;

procedure TCustomGrid.EditorShowInCell(const aCol, aRow: Integer);
var
  OldCol,OldRow: Integer;
begin
  OldCol:=FCol;
  OldRow:=FRow;
  try
    EditorGetValue;
    FCol:=aCol;
    FRow:=aRow;
    SelectEditor;
    EditorShow(True);
  finally
    if (FCol=aCol)and(FRow=aRow) then
    begin
      // Current col,row didn't change, restore old ones
      FCol:=OldCol;
      FRow:=OldRow;
    end;
  end;
end;

procedure TCustomGrid.EditorWidthChanged(aCol, aWidth: Integer);
begin
  EditorPos;
end;

function TCustomGrid.FixedGrid: boolean;
begin
  result := (FixedCols=ColCount) or (FixedRows=RowCount)
end;

procedure TCustomGrid.FontChanged(Sender: TObject);
begin
  inherited FontChanged(Sender);
  if FColumns.Enabled then
    FColumns.FontChanged;
  if FTitleFontIsDefault then begin
    FTitleFont.Assign(Font);
    FTitleFontIsDefault := True;
  end;
end;

procedure TCustomGrid.EditorPos;
var
  msg: TGridMessage;
begin
  {$ifdef dbgGrid} DebugLn('Grid.EditorPos INIT');{$endif}
  if FEditor<>nil then begin
    Msg.CellRect:=CellRect(FCol,FRow);
    if FEditorOptions and EO_AUTOSIZE = EO_AUTOSIZE then begin
      if EditorBorderStyle = bsNone then
          InflateRect(Msg.CellRect, -1, -1);
      FEditor.BoundsRect := Msg.CellRect;
    end else begin
      Msg.MsgID:=GM_SETPOS;
      Msg.Grid:=Self;
      Msg.Col:=FCol;
      Msg.Row:=FRow;
      FEditor.Dispatch(Msg);
    end;
  end;
  {$ifdef dbgGrid} DebugLn('Grid.EditorPos FIN');{$endif}
end;

procedure TCustomGrid.EditorSelectAll;
var
  Msg: TGridMessage;
begin
  {$ifdef dbgGrid}DebugLn('EditorSelectALL INIT');{$endif}
  if FEditor<>nil then
    if FEditorOptions and EO_SELECTALL = EO_SELECTALL then begin
      Msg.MsgID:=GM_SELECTALL;
      FEditor.Dispatch(Msg);
    end;
  {$ifdef dbgGrid}DebugLn('EditorSelectALL FIN');{$endif}
end;

procedure TCustomGrid.EditordoGetValue;
var
  msg: TGridMessage;
begin
  if (FEditor<>nil) and FEditor.Visible then begin
    Msg.MsgID:=GM_GETVALUE;
    Msg.grid:=Self;
    Msg.Col:=FCol;
    Msg.Row:=FRow;
    Msg.Value:=GetEditText(FCol, FRow);
    FEditor.Dispatch(Msg);
    SetEditText(Msg.Col, Msg.Row, Msg.Value);
  end;
end;

procedure TCustomGrid.EditordoSetValue;
var
  msg: TGridMessage;
begin
  if FEditor<>nil then begin
    // Set the editor mask
    Msg.MsgID:=GM_SETMASK;
    Msg.Grid:=Self;
    Msg.Col:=FCol;
    Msg.Row:=FRow;
    Msg.Value:=GetEditMask(FCol, FRow);
    FEditor.Dispatch(Msg);
    // Set the editor value
    Msg.MsgID:=GM_SETVALUE;
    Msg.Grid:=Self;
    Msg.Col:=FCol;
    Msg.Row:=FRow;
    Msg.Value:=GetEditText(Fcol, FRow); //Cells[FCol,FRow];
    FEditor.Dispatch(Msg);
  end;
end;

function TCustomGrid.EditorCanAcceptKey(const ch: Char): boolean;
begin
  result := True;
end;

function TCustomGrid.EditorIsReadOnly: boolean;
begin
  result := GetColumnReadonly(Col);
end;

procedure TCustomGrid.GetAutoFillColumnInfo(const Index: Integer; var aMin,aMax,aPriority: Integer);
var
  C: TGridColumn;
begin
  if Index<FixedCols then
    APriority := 0
  else if Columns.Enabled then begin
    C := ColumnFromGridColumn(Index);
    if C<>nil then begin
      aMin := C.MinSize;
      aMax := C.MaxSize;
      aPriority := C.SizePriority;
    end else
      APriority := 1;
  end else
    APriority := 1;
end;

procedure TCustomGrid.EditorExit(Sender: TObject);
begin
  if not EditorLocked then begin
    {$IfDef dbgGrid} DebugLn('EditorExit INIT');{$Endif}
    LockEditor;
    try
      EditorGetValue;
      if (FEditor<>nil)and(FEditor.Visible) then begin
        Editor.Visible:=False;
        //Editor.Parent:=nil;
        FEditorMode := False;
        //InvalidateCell(FCol,FRow, True);
      end;
    finally
      UnlockEditor;
      {$IfDef dbgGrid} DebugLn('EditorExit FIN'); {$Endif}
    end;
  end;
end;

procedure TCustomGrid.EditorKeyDown(Sender: TObject; var Key:Word; Shift:TShiftState);
begin
  {$ifdef dbgGrid}DebugLn('Grid.EditorKeyDown Key=',dbgs(Key),' INIT');{$endif}
  FEditorKey:=True; // Just a flag to see from where the event comes
  KeyDown(Key, shift);
  case Key of
    VK_LEFT, VK_RIGHT, VK_UP, VK_DOWN,
    VK_PRIOR, VK_NEXT:
    begin
      if ssShift in Shift then begin
        FeditorKey:=False;
        exit;
      end;
    end;
    {
    VK_TAB:
      begin
        if GoTabs in Options then begin
          MoveNextAuto;
          Key := 0;
        end;
      end;
    }
    VK_RETURN:
      begin
        Key := 0;
        if not MoveNextAuto(ssShift in Shift) then begin
          EditorGetValue;
          if EditorAlwaysShown then
            EditorShow(True);
        end;
      end;
  end;
  FEditorKey:=False;
  {$ifdef dbgGrid}DebugLn('Grid.EditorKeyDown Key=',dbgs(Key),' FIN');{$endif}
end;

procedure TCustomGrid.EditorKeyPress(Sender: TObject; var Key: Char);
{$ifdef dbgGrid}
function PrintKey:String;
begin
  Result := Dbgs(ord(key))+' $' + IntToHex(ord(key),2);
  if Key>#31 then
    Result := Key + ' ' + Result
end;
{$endif}
begin
  {$ifdef dbgGrid}DebugLn('Grid.EditorKeyPress: INIT Key=',PrintKey);{$Endif}
  FEditorKey := True;
  KeyPress(Key); // grid must get all keypresses, even if they are from the editor
  {$ifdef dbgGrid}DebugLn('Grid.EditorKeyPress: inter Key=',PrintKey);{$Endif}
  case Key of
    ^C,^V,^X:;
    ^M, #27: Key:=#0; // key is already handled in KeyDown
    #8:
      if EditorIsReadOnly then
        Key := #0;
    else
      EditorCanProcessKey(Key)
  end;
  FEditorKey := False;
  {$ifdef dbgGrid}DebugLn('Grid.EditorKeyPress: FIN Key=',PrintKey);{$Endif}
end;

procedure TCustomGrid.EditorKeyUp(Sender: TObject; var key: Word;
  shift: TShiftState);
begin
  FEditorKey := True;
  KeyUp(Key, Shift);
  FEditorKey := False;
end;

procedure TCustomGrid.SelectEditor;
var
  aEditor: TWinControl;
begin
  aEditor := GetDefaultEditor(Col);
  if (goEditing in Options) and Assigned(OnSelectEditor) then
    OnSelectEditor(Self, fCol, FRow, aEditor);
  if aEditor<>Editor then
    Editor:=aEditor;
end;

function TCustomGrid.EditorAlwaysShown: Boolean;
begin
  Result:=(goEditing in Options)and(goAlwaysShowEditor in Options)and not FixedGrid;
end;

procedure TCustomGrid.FixPosition;
  procedure FixSelection;
  begin
    if FRow > FRows.Count - 1 then
      FRow := FRows.Count - 1
    else if (FRow < FixedRows) and (FixedRows<FRows.Count) then
      FRow := FixedRows;
    if FCol > FCols.Count - 1 then
      FCol := FCols.Count - 1
    else if (FCol < FixedCols) and (FixedCols<FCols.Count) then
      FCol := FixedCols;
  end;
  procedure FixTopLeft;
  var
    oldTL: TPoint;
  begin
    OldTL:=FTopLeft;
    if OldTL.X+VisibleColCount>FCols.Count then begin
      OldTL.X := FCols.Count - VisibleColCount;
      if OldTL.X<FixedCols then
        OldTL.X := FixedCols;
    end;
    if OldTL.Y+VisibleRowCount>FRows.Count then begin
      OldTL.Y := FRows.Count - VisiblerowCount;
      if OldTL.Y<FixedRows then
        OldTL.Y:=FixedRows;
    end;
    if not PointIgual(OldTL, FTopleft) then begin
      fTopLeft := OldTL;
      //DebugLn('TCustomGrid.FixPosition ',DbgSName(Self),' FTopLeft=',dbgs(FTopLeft));
      topleftChanged;
    end;
  end;
begin
  FixTopleft;
  FixSelection;
  CheckPosition;
  UpdateSelectionRange;
  VisualChange;
end;

procedure TCustomGrid.EditorShowChar(Ch: Char);
{$ifndef WINDOWS}
var
  msg: TGridMessage;
{$endif}
begin
  SelectEditor;
  if FEditor<>nil then begin
    //DebugLn('Posting editor LM_CHAR, ch=',ch, ' ', InttoStr(Ord(ch)));
    if EditorCanProcessKey(ch) and not EditorIsReadOnly then begin
      EditorShow(true);
      {$ifdef WINDOWS}
      // lcl win32 interface does a big mess with the message
      // as we only need the message to be handled by destination
      // then we send it directly to it bypassing the queue.
      //PostMessage(FEditor.Handle, LM_CHAR, Word(Ch), 0);
      SendMessage(FEditor.Handle, LM_CHAR, Word(Ch), 0);
      {$else}
      ///
      // Note. this is a workaround because the call above doesn't work
      ///
      {$ifdef EnableFieldEditMask}
      if (FEditor=FStringEditor) and (FStringEditor.IsMasked) then
        SendMessage(FEditor.Handle, CN_CHAR, Word(Ch), 0)
      else begin
      {$Endif}
      Msg.MsgID:=GM_SETVALUE;
      Msg.Grid:=Self;
      Msg.Col:=FCol;
      Msg.Row:=FRow;
      if Ch=^H then Msg.Value:=''
      else          Msg.Value:=ch;
      FEditor.Dispatch(Msg);
      {$ifdef EnableFieldEditMask}
      end;
      {$endif}
      {$endif WIN32}
    end;
  end;
end;

procedure TCustomGrid.EditorSetMode(const AValue: Boolean);
begin
  {$ifdef dbgGrid}DebugLn('Grid.EditorSetMode=',dbgs(Avalue),' INIT');{$endif}
  if not AValue then
    EditorHide
  else
    EditorShow(false);
  {$ifdef dbgGrid}DebugLn('Grid.EditorSetMode FIN');{$endif}
end;

function TCustomGrid.GetSelectedColor: TColor;
begin
  Result:=FSelectedColor;
end;

function TCustomGrid.GetEditMask(ACol, ARow: Longint): string;
begin
  result:='';
end;

function TCustomGrid.GetEditText(ACol, ARow: Longint): string;
begin
  result:='';
end;

function TCustomGrid.GetColumnAlignment(Column: Integer; ForTitle: Boolean): TAlignment;
var
  C: TGridColumn;
begin
  C := ColumnFromGridColumn(Column);
  if C<>nil then
    if ForTitle then
      Result := C.Title.Alignment
    else
      Result := C.Alignment
  else
    result := GetDefaultColumnAlignment(Column);
end;

function TCustomGrid.GetColumnColor(Column: Integer; ForTitle: Boolean): TColor;
var
  C: TGridColumn;
begin
  C := ColumnFromGridColumn(Column);
  if C<>nil then
    if ForTitle then
      result := C.Title.Color
    else
      result := C.Color
  else
    if ForTitle then
      result := FixedColor
    else
      result := Self.Color;
end;

function TCustomGrid.GetColumnFont(Column: Integer; ForTitle: Boolean): TFont;
var
  C: TGridColumn;
begin
  C := ColumnFromGridColumn(Column);
  if C<>nil then
    if ForTitle then
      Result := C.Title.Font
    else
      Result := C.Font
  else begin
    if ForTitle then
      Result := TitleFont
    else
      Result := Self.Font;
  end;
end;

function TCustomGrid.GetColumnLayout(Column: Integer; ForTitle: boolean): TTextLayout;
var
  C: TGridColumn;
begin
  C := ColumnFromGridColumn(Column);
  if C<>nil then
    if ForTitle then
      Result := C.Title.Layout
    else
      Result := C.Layout
  else
    result := GetDefaultColumnLayout(Column);
end;

function TCustomGrid.GetColumnReadonly(Column: Integer): boolean;
var
  C: TGridColumn;
begin
  C := ColumnFromGridColumn(Column);
  if C<>nil then
    result := C.ReadOnly
  else
    result := GetDefaultColumnReadOnly(Column);
end;

function TCustomGrid.GetColumnTitle(Column: Integer): string;
var
  C: TGridColumn;
begin
  C := ColumnFromGridColumn(Column);
  if C<>nil then
    Result := C.Title.Caption
  else
    result := GetDefaultColumnTitle(Column);
end;

function TCustomGrid.GetColumnWidth(Column: Integer): Integer;
var
  C: TGridColumn;
begin
  C := ColumnFromGridColumn(Column);
  if C<>nil then
    Result := C.Width
  else
    Result := GetDefaultColumnWidth(Column);
end;

// return the relative cell coordinate of the next cell
// considering AutoAdvance property and selectable cells.
function TCustomGrid.GetDeltaMoveNext(const Inverse: boolean;
  var ACol, ARow: Integer): boolean;
var

  DeltaCol,DeltaRow: Integer;
  
  function CalcNextStep: boolean;
  var
    aa: TAutoAdvance;
    cCol,cRow: Integer;
  begin

    DeltaCol := 0;
    DeltaRow := 0;

    // invert direction if necessary
    //
    aa := FAutoAdvance;
    if Inverse then
      case FAutoAdvance of
        aaRight:      aa := aaLeft;
        aaLeft:       aa := aaRight;
        aaRightDown:  aa := aaLeftUp;
        aaLeftDown:   aa := aaRightUp;
        aaRightUP:    aa := aaLeftDown;
        aaLeftUP:     aa := aaRightDown;
      end;

    case aa of
      aaRight:
        DeltaCol := 1;
        
      aaLeft:
        DeltaCol := -1;
        
      aaDown:
        DeltaRow := 1;
        
      aaRightDown:
        if ACol<ColCount-1 then
          DeltaCol := 1
        else begin
          DeltaCol := FixedCols-ACol;
          DeltaRow := 1;
        end;
        
      aaRightUP:
        if ACol<ColCount-1 then
          DeltaCol := 1
        else begin
          DeltaCol := FixedCols-ACol;
          DeltaRow := -1;
        end;
        
      aaLeftUP:
        if ACol>FixedCols then
          DeltaCol := -1
        else begin
          DeltaCol := ColCount-1-ACol;
          DeltaRow := -1;
        end;
        
      aaLeftDown:
        if ACol>FixedCols then
          DeltaCol := -1
        else begin
          DeltaCol := ColCount-1-ACol;
          DeltaRow := 1;
        end;
    end;
    
    CCol := ACol + DeltaCol;
    CRow := ARow + DeltaRow;

    // is CCol,CRow within range?
    result :=
      (CCol<=ColCount-1)and(CCol>=FixedCols)and
      (CRow<=RowCount-1)and(CRow>=FixedRows);
  end;
begin

  ACol := FCol;
  ARow := FRow;

  result := False;
  
  if FAutoAdvance=aaNone then
    exit; // quick case, no auto movement allowed
  
  // browse the grid in autoadvance order
  while CalcNextStep do begin
    ACol := ACol + DeltaCol;
    ARow := ARow + DeltaRow;
    // is cell ACol,ARow selectable?
    result := SelectCell(ACol,ARow);
    if Result then
      break;
  end;
  
  if result then begin
    // return relative position
    ACol := ACol - FCol;
    ARow := ARow - FRow;
  end else begin
    // no available next cell, return delta anyway
    ACol := DeltaCol;
    ARow := DeltaRow;
  end;
end;

function TCustomGrid.GetDefaultColumnAlignment(Column: Integer): TAlignment;
begin
  result := DefaultTextStyle.Alignment;
end;

function TCustomGrid.GetDefaultEditor(Column: Integer): TWinControl;
var
  C: TGridColumn;
  bs: TColumnButtonStyle;
begin
  result := nil;
  if (goEditing in Options) then begin
    C := ColumnFromGridColumn(Column);
    if C<>nil then begin
      bs := C.ButtonStyle;
      if (bs=cbsAuto) and (C.PickList<>nil) and (C.PickList.Count>0) then
        bs := cbsPicklist
    end else
      bs := cbsAuto;

    result := EditorByStyle( Bs );

    // by default do the editor setup here
    // if user wants to change our setup, this can
    // be done in OnSelectEditor
    if (bs=cbsPickList) and (C<>nil) and (C.PickList<>nil) and
        (result = FPicklistEditor) then begin
      FPickListEditor.Items.Assign(C.PickList);
      FPickListEditor.DropDownCount := C.DropDownRows;
    end

  end;
end;

function TCustomGrid.GetScrollBarPosition(Which: integer): Integer;
var
  ScrollInfo: TScrollInfo;
begin
  if HandleAllocated then begin
    ScrollInfo.cbSize := SizeOf(ScrollInfo);
    ScrollInfo.fMask := SIF_POS;
    GetScrollInfo(Handle, Which, ScrollInfo);
    Result:=ScrollInfo.nPos;
  end;
end;

function TCustomGrid.GetDefaultColumnWidth(Column: Integer): Integer;
begin
  result := FDefColWidth;
end;

function TCustomGrid.GetDefaultColumnLayout(Column: Integer): TTextLayout;
begin
  result := DefaultTextStyle.Layout;
end;

function TCustomGrid.GetDefaultColumnReadOnly(Column: Integer): boolean;
begin
  result := false;
end;

function TCustomGrid.GetDefaultColumnTitle(Column: Integer): string;
begin
  result := '';
end;

procedure TCustomGrid.SetEditText(ACol, ARow: Longint; const Value: string);
begin
end;

function TCustomGrid.CanGridAcceptKey(Key: Word; Shift: TShiftState): Boolean;
begin
  Result := True;
end;

procedure TCustomGrid.SetSelectedColor(const AValue: TColor);
begin
  if FSelectedColor<>AValue then begin
    FSelectedColor:=AValue;
    Invalidate;
  end;
end;

procedure TCustomGrid.SetFixedcolor(const AValue: TColor);
begin
  if FFixedColor<>AValue then begin
    FFixedColor:=Avalue;
    Invalidate;
  end;
end;

function TCustomGrid.GetFixedcolor: TColor;
begin
  result:=FFixedColor;
end;

procedure TCustomGrid.ColWidthsChanged;
begin
  //
end;
procedure TCustomGrid.RowHeightsChanged;
begin
  //
end;

procedure TCustomGrid.SaveContent(cfg: TXMLConfig);
var
  i,j,k: Integer;
  Path: string;
begin
  cfg.SetValue('grid/version', GRIDFILEVERSION);

  Cfg.SetValue('grid/saveoptions/create', soDesign in SaveOptions);
  if soDesign in SaveOptions then begin
    Cfg.SetValue('grid/design/columncount',  ColCount);
    Cfg.SetValue('grid/design/rowcount',  RowCount);
    Cfg.SetValue('grid/design/fixedcols', FixedCols);
    Cfg.SetValue('grid/design/fixedrows', Fixedrows);
    Cfg.SetValue('grid/design/defaultcolwidth', DefaultColWidth);
    Cfg.SetValue('grid/design/defaultRowHeight',DefaultRowHeight);

    j:=0;
    For i:=0 to ColCount-1 do begin
      k:=PtrInt(FCols[i]);
      if (k>=0)and(k<>DefaultColWidth) then begin
        inc(j);
        cfg.SetValue('grid/design/columns/columncount',j);
        cfg.SetValue('grid/design/columns/column'+IntToStr(j)+'/index', i);
        cfg.SetValue('grid/design/columns/column'+IntToStr(j)+'/width', k);
      end;
    end;
    j:=0;
    For i:=0 to RowCount-1 do begin
      k:=PtrInt(FRows[i]);
      if (k>=0)and(k<>DefaultRowHeight) then begin
        inc(j);
        cfg.SetValue('grid/design/rows/rowcount',j);
        cfg.SetValue('grid/design/rows/row'+IntToStr(j)+'/index', i);
        cfg.SetValue('grid/design/rows/row'+IntToStr(j)+'/height',k);
      end;
    end;


    Path:='grid/design/options/';
    Cfg.SetValue(Path+'goFixedVertLine/value', goFixedVertLine in options);
    Cfg.SetValue(Path+'goFixedHorzLine/value', goFixedHorzLine in options);
    Cfg.SetValue(Path+'goVertLine/value',  goVertLine in options);
    Cfg.SetValue(Path+'goHorzLine/value',  goHorzLine in options);
    Cfg.SetValue(Path+'goRangeSelect/value', goRangeSelect in options);
    Cfg.SetValue(Path+'goDrawFocusSelected/value', goDrawFocusSelected in options);
    Cfg.SetValue(Path+'goRowSizing/value', goRowSizing in options);
    Cfg.SetValue(Path+'goColSizing/value', goColSizing in options);
    Cfg.SetValue(Path+'goRowMoving/value', goRowMoving in options);
    Cfg.SetValue(Path+'goColMoving/value', goColMoving in options);
    Cfg.SetValue(Path+'goEditing/value', goEditing in options);
    Cfg.SetValue(Path+'goTabs/value', goTabs in options);
    Cfg.SetValue(Path+'goRowSelect/value', goRowSelect in options);
    Cfg.SetValue(Path+'goAlwaysShowEditor/value', goAlwaysShowEditor in options);
    Cfg.SetValue(Path+'goThumbTracking/value', goThumbTracking in options);
    Cfg.SetValue(Path+'goColSpanning/value', goColSpanning in options);
    cfg.SetValue(Path+'goRelaxedRowSelect/value', goRelaxedRowSelect in options);
    cfg.SetValue(Path+'goDblClickAutoSize/value', goDblClickAutoSize in options);
    Cfg.SetValue(Path+'goSmoothScroll/value', goSmoothScroll in Options);
  end;

  Cfg.SetValue('grid/saveoptions/position', soPosition in SaveOptions);
  if soPosition in SaveOptions then begin
    Cfg.SetValue('grid/position/topleftcol',ftopleft.x);
    Cfg.SetValue('grid/position/topleftrow',ftopleft.y);
    Cfg.SetValue('grid/position/col',fCol);
    Cfg.SetValue('grid/position/row',fRow);
    if goRangeSelect in Options then begin
      Cfg.SetValue('grid/position/selection/left',Selection.left);
      Cfg.SetValue('grid/position/selection/top',Selection.top);
      Cfg.SetValue('grid/position/selection/right',Selection.right);
      Cfg.SetValue('grid/position/selection/bottom',Selection.bottom);
    end;
  end;
end;


procedure TCustomGrid.LoadContent(cfg: TXMLConfig; Version: Integer);
var
  CreateSaved: Boolean;
  Opt: TGridOptions;
  i,j,k: Integer;
  path: string;

    procedure GetValue(optStr:string; aOpt:TGridOption);
    begin
      if Cfg.GetValue(Path+OptStr+'/value', False) then Opt:=Opt+[aOpt];
    end;

begin
  if soDesign in FSaveOptions then begin
    CreateSaved:=Cfg.GetValue('grid/saveoptions/create', false);
    if CreateSaved then begin
      Clear;
      FixedCols:=0;
      FixedRows:=0;
      ColCount:=Cfg.GetValue('grid/design/columncount', 5);
      RowCount:=Cfg.GetValue('grid/design/rowcount', 5);
      FixedCols:=Cfg.GetValue('grid/design/fixedcols', 1);
      FixedRows:=Cfg.GetValue('grid/design/fixedrows', 1);
      DefaultRowheight:=Cfg.GetValue('grid/design/defaultrowheight', DEFROWHEIGHT);
      DefaultColWidth:=Cfg.getValue('grid/design/defaultcolwidth', DEFCOLWIDTH);

      Path:='grid/design/columns/';
      k:=cfg.getValue(Path+'columncount',0);
      For i:=1 to k do begin
        j:=cfg.getValue(Path+'column'+IntToStr(i)+'/index',-1);
        if (j>=0)and(j<=ColCount-1) then begin
          ColWidths[j]:=cfg.getValue(Path+'column'+IntToStr(i)+'/width',-1);
        end;
      end;
      Path:='grid/design/rows/';
      k:=cfg.getValue(Path+'rowcount',0);
      For i:=1 to k do begin
        j:=cfg.getValue(Path+'row'+IntToStr(i)+'/index',-1);
        if (j>=0)and(j<=ColCount-1) then begin
          RowHeights[j]:=cfg.getValue(Path+'row'+IntToStr(i)+'/height',-1);
        end;
      end;

      Opt:=[];
      Path:='grid/design/options/';
      GetValue('goFixedVertLine', goFixedVertLine);
      GetValue('goFixedHorzLine', goFixedHorzLine);
      GetValue('goVertLine',goVertLine);
      GetValue('goHorzLine',goHorzLine);
      GetValue('goRangeSelect',goRangeSelect);
      GetValue('goDrawFocusSelected',goDrawFocusSelected);
      GetValue('goRowSizing',goRowSizing);
      GetValue('goColSizing',goColSizing);
      GetValue('goRowMoving',goRowMoving);
      GetValue('goColMoving',goColMoving);
      GetValue('goEditing',goEditing);
      GetValue('goRowSelect',goRowSelect);
      GetValue('goTabs',goTabs);
      GetValue('goAlwaysShowEditor',goAlwaysShowEditor);
      GetValue('goThumbTracking',goThumbTracking);
      GetValue('goColSpanning', goColSpanning);
      GetValue('goRelaxedRowSelect',goRelaxedRowSelect);
      GetValue('goDblClickAutoSize',goDblClickAutoSize);
      if Version>=2 then begin
        GetValue('goSmoothScroll',goSmoothScroll);
      end;

      Options:=Opt;
    end;

    CreateSaved:=Cfg.GetValue('grid/saveoptions/position', false);
    if CreateSaved then begin
      i:=Cfg.GetValue('grid/position/topleftcol',-1);
      j:=Cfg.GetValue('grid/position/topleftrow',-1);
      if CellToGridZone(i,j)=gzNormal then begin
        tryScrollto(i,j);
      end;
      i:=Cfg.GetValue('grid/position/col',-1);
      j:=Cfg.GetValue('grid/position/row',-1);
      if (i>=FFixedCols)and(i<=ColCount-1) and
         (j>=FFixedRows)and(j<=RowCount-1) then begin
        MoveExtend(false, i,j);
      end;
      if goRangeSelect in Options then begin
        FRange.left:=Cfg.getValue('grid/position/selection/left',FCol);
        FRange.Top:=Cfg.getValue('grid/position/selection/top',FRow);
        FRange.Right:=Cfg.getValue('grid/position/selection/right',FCol);
        FRange.Bottom:=Cfg.getValue('grid/position/selection/bottom',FRow);
      end;
    end;
  end;
end;

procedure TCustomGrid.Loaded;
begin
  inherited Loaded;
  VisualChange;
end;

procedure TCustomGrid.LockEditor;
begin
  inc(FEditorHidingCount);
  {$ifdef dbgGrid}DebugLn('==> LockEditor: ', dbgs(FEditorHidingCount)); {$endif}
end;

constructor TCustomGrid.Create(AOwner: TComponent);
begin
  // Inherited create Calls SetBounds->WM_SIZE->VisualChange so
  // fGrid needs to be created before that
  FCols:=TList.Create;
  FRows:=TList.Create;
  FGCache.AccumWidth:=TList.Create;
  FGCache.AccumHeight:=TList.Create;
  FGSMHBar := GetSystemMetrics(SM_CYHSCROLL) + GetSystemMetricsGapSize(SM_CYHSCROLL);
  FGSMVBar := GetSystemMetrics(SM_CXVSCROLL) + GetSystemMetricsGapSize(SM_CXVSCROLL);
  inherited Create(AOwner);

  FColumns := CreateColumns;

  FTitleFont := TFont.Create;
  FTitleFont.OnChange := @OnTitleFontChanged;
  FTitleFontIsDefault := True;

  FAutoAdvance := aaRight;
  FFocusRectVisible := True;
  FDefaultDrawing := True;
  FOptions:=
    [goFixedVertLine, goFixedHorzLine, goVertLine, goHorzLine, goRangeSelect,
     goSmoothScroll ];
  FScrollbars:=ssAutoBoth;
  fGridState:=gsNormal;
  FDefColWidth:=DEFCOLWIDTH;
  FDefRowHeight:=DEFROWHEIGHT;
  FGridLineColor:=clSilver;
  FGridLineStyle:=psSolid;
  FGridLineWidth := 1;
  fFocusColor:=clRed;
  FFixedColor:=clBtnFace;
  FSelectedColor:= clHighlight;
  FRange:=Rect(-1,-1,-1,-1);
  FDragDx:=3;
  SetBounds(0,0,200,100);
  ColCount:=5;
  RowCount:=5;
  FixedCols:=1;
  FixedRows:=1;
  Editor:=nil;
  FBorderColor := cl3DDKShadow;
  BorderStyle := bsSingle;


  ParentColor := False;
  Color:=clWindow;
  FAlternateColor := Color;
  FAltColorStartNormal := true;

  FDefaultTextStyle := Canvas.TextStyle;
  FDefaultTextStyle.Wordbreak := False;

  FButtonEditor := TButtonCellEditor.Create(nil);
  FButtonEditor.Name:='ButtonEditor';
  FButtonEditor.Caption:='...';
  FButtonEditor.Visible:=False;
  FButtonEditor.OnClick := @EditButtonClicked;

  FStringEditor := TStringCellEditor.Create(nil);
  FStringEditor.name :='StringEditor';
  FStringEditor.Text:='';
  FStringEditor.Visible:=False;
  FStringEditor.Align:=alNone;

  FPicklistEditor := TPickListCellEditor.Create(nil);
  FPickListEditor.Name := 'PickListEditor';
  FPickListEditor.Visible := False;

  FFastEditing := True;
  TabStop := True;
end;

destructor TCustomGrid.Destroy;
begin
  {$Ifdef DbgGrid}DebugLn('TCustomGrid.Destroy');{$Endif}
  FreeThenNil(FPickListEditor);
  FreeThenNil(FStringEditor);
  FreeThenNil(FButtonEditor);
  FreeThenNil(FColumns);
  FreeThenNil(FGCache.AccumWidth);
  FreeThenNil(FGCache.AccumHeight);
  FreeThenNil(FCols);
  FreeThenNil(FRows);
  FreeThenNil(FTitleFont);
  inherited Destroy;
end;

procedure TCustomGrid.SaveToFile(FileName: string);
var
  Cfg: TXMLConfig;
begin
  if FileExists(FileName) then DeleteFile(FileName);

  Cfg:=TXMLConfig.Create(nil);
  Try
    Cfg.FileName := FileName;
    SaveContent(Cfg);
  Finally
    Cfg.Flush;
    FreeThenNil(Cfg);
  end;
end;

type
  TWinCtrlAccess=class(TWinControl);

procedure TCustomGrid.SetFocus;
var
  NextControl: TWinControl;
  ParentForm: TCustomForm;
  ForwardTab: boolean;
begin
  {$IFDEF dbgGrid}
  DebugLn('TCustomGrid.SetFocus INIT.');
  {$ENDIF}
  if (Editor<>nil) and Editor.Focused and
    ([gfEditorTab,gfRevEditorTab]*GridFlags<>[]) then begin
    // Editor was doing TAB. Focus next control instead
    ForwardTab:= gfEditorTab in GridFlags;
    GridFlags:=GridFlags-[gfEditorTab,gfRevEditorTab];
    ParentForm:=GetParentForm(Self);
    if ParentForm<>nil then begin
      NextControl:=TWinCtrlAccess(Pointer(ParentForm)).FindNextControl(Self,
                                                      ForwardTab, true, false);
      if NextControl<>nil then begin
        {$IFDEF dbgGrid}
        DebugLn('   Was tabbing, will focus: ',dbgsname(NextControl));
        {$ENDIF}
        if (NextControl<>Self) and (NextControl<>Editor) then begin
          NextControl.SetFocus;
          exit;
        end;
      end;
    end;
  end;
  inherited SetFocus;
  {$IFDEF dbgGrid}
  DebugLn('TCustomGrid.SetFocus FIN');
  {$ENDIF}
end;

procedure TCustomGrid.LoadFromFile(FileName: string);
var
  Cfg: TXMLConfig;
  Version: Integer;
begin
  if not FileExists(FileName) then
    raise Exception.Create(rsGridFileDoesNotExists);

  Cfg:=TXMLConfig.Create(nil);
  Try
    Cfg.Filename := FileName;
    Version:=cfg.GetValue('grid/version',-1);
    if Version=-1 then raise Exception.Create(rsNotAValidGridFile);
    BeginUpdate;
    LoadContent(Cfg, Version);
    EndUpdate(True);
  Finally
    FreeThenNil(Cfg);
  end;
end;

procedure TCustomGrid.Clear;
var
  OldR,OldC: Integer;
begin
  // save some properties
  FGridPropBackup.ValidData := True;
  FGridPropBackup.FixedRowCount := FFixedRows;
  FGridPropBackup.FixedColCount := FFixedCols;
  
  // clear structure
  OldR:=RowCount;
  OldC:=ColCount;
  FFixedCols:=0;
  FFixedRows:=0;
  FRows.Count:=0;
  FCols.Count:=0;
  FTopLeft:=Point(-1,-1);
  FRange:=Rect(-1,-1,-1,-1);
  FGCache.TLColOff := 0;
  FGCache.TlRowOff := 0;
  VisualChange;
  SizeChanged(OldR,OldC);
end;

procedure TCustomGrid.AutoAdjustColumns;
var
  i: Integer;
begin
  For i:=0 to ColCount do
    AutoAdjustColumn(i);
end;

{ TVirtualGrid }

function TVirtualGrid.GetCells(Col, Row: Integer): PCellProps;
begin
  // todo: Check range
  Result:=nil;
  if (Col<0) or (Row<0) or (Col>=ColCount) or (Row>=RowCount) then
    raise EGridException.CreateFmt(rsIndexOutOfRange, [Col, Row]);
  Result:=FCells[Col,Row];
end;

function Tvirtualgrid.Getrows(Row: Integer): PColRowprops;
begin
  Result:= FRows[Row, 0];
end;

function Tvirtualgrid.Getcols(Col: Integer): PColRowProps;
begin
  result:=FCols[Col, 0];
end;

procedure TVirtualGrid.SetCells(Col, Row: Integer; const AValue: PCellProps);
var
   Cell: PCellProps;
begin
  // todo: Check range
  Cell:=FCells[Col,Row];
  if Cell<>nil then DisposeCell(Cell);
  Cell:=AValue;
  FCells[Col,Row]:=Cell;
end;

procedure Tvirtualgrid.Setrows(Row: Integer; const Avalue: PColRowProps);
var
   C: PColRowProps;
begin
  // todo: Check range
  C:=FRows[Row,0];
  if C<>nil then DisposeColRow(C);
  FRows[Row,0]:=AValue;
end;

procedure Tvirtualgrid.Setcolcount(const Avalue: Integer);
begin
  if FColCount=Avalue then Exit;
  {$Ifdef dbgMem}
    DebugLn('TVirtualGrid.SetColCount Value=',AValue);
  {$Endif}
  FColCount:=AValue;
  {$Ifdef dbgMem}
    DBGOut('TVirtualGrid.SetColCount->FCOLS: ');
  {$Endif}
  FCols.SetLength(FColCount, 1);
  {$Ifdef dbgMem}
    DBGOut('TVirtualGrid.SetColCount->FCELLS(',FColCount,',',FRowCount,'): ');
  {$Endif}
  FCells.SetLength(FColCount, FRowCount);
end;


procedure Tvirtualgrid.Setrowcount(const Avalue: Integer);
begin
  if FRowCount=AValue then Exit;
  {$Ifdef dbgMem}
    DebugLn('TVirtualGrid.SetRowCount Value=',AValue);
  {$Endif}
  FRowCount:=AValue;
  {$Ifdef dbgMem}
    DBGOut('TVirtualGrid.SetRowCount->FROWS: ');
  {$Endif}
  FRows.SetLength(FRowCount,1);
  {$Ifdef dbgMem}
    DBGOut('TVirtualGrid.SetRowCount->FCELLS(',FColCount,',',FRowCount,'): ');
  {$Endif}
  FCells.SetLength(FColCount, FRowCount);
end;

procedure Tvirtualgrid.Setcols(Col: Integer; const Avalue: PColRowProps);
var
   C: PColRowProps;
begin
  // todo: Check range
  C:=FCols[Col,0];
  if C<>nil then DisposeColRow(C);
  FCols[Col,0]:=AValue;
end;

procedure Tvirtualgrid.Clear;
begin
  {$Ifdef dbgMem}DBGOut('FROWS: ');{$Endif}FRows.Clear;
  {$Ifdef dbgMem}DBGOut('FCOLS: ');{$Endif}FCols.Clear;
  {$Ifdef dbgMem}DBGOut('FCELLS: ');{$Endif}FCells.Clear;
  FColCount:=0;
  FRowCount:=0;
end;

procedure Tvirtualgrid.Disposecell(var P: Pcellprops);
begin
  if P<>nil then begin
    if P^.Text<>nil then StrDispose(P^.Text);
    Dispose(P);
    P:=nil;
  end;
end;

procedure TVirtualGrid.DisposeColRow(var p: PColRowProps);
begin
  if P<>nil then begin
    Dispose(P);
    P:=nil;
  end;
end;

function TVirtualGrid.GetDefaultCell: PcellProps;
begin
  New(Result);
  Result^.Text:=nil;
  Result^.Attr:=nil;
end;

function TVirtualGrid.GetDefaultColRow: PColRowProps;
begin
  New(Result);
  Result^.FixedAttr:=nil;
  Result^.NormalAttr:=nil;
  Result^.Size:=-1;
end;

procedure Tvirtualgrid.Dodestroyitem (Sender: Tobject; Col,Row: Integer;
  var Item: Pointer);
begin
  {$Ifdef dbgMem}
    DebugLn('TVirtualGrid.doDestroyItem Col=',Col,' Row= ',
            Row,' Item=',Integer(Item));
  {$endif}
  if Item<>nil then begin
    if (Sender=FCols)or(Sender=FRows) then begin
      DisposeColRow(PColRowProps(Item));
    end else begin
      DisposeCell(PCellProps(Item));
    end;
    Item:=nil;
  end;
end;

procedure Tvirtualgrid.doNewitem(Sender: Tobject; Col,Row:Integer;
  var Item: Pointer);
begin
  {$Ifdef dbgMem}
    DebugLn('TVirtualGrid.doNewItem Col=',Col,' Row= ',
            Row,' Item=',Integer(Item));
  {$endif}
  if Sender=FCols then begin
    // Procesar Nueva Columna
    Item:=GetDefaultColRow;
  end else
  if Sender=FRows then begin
    // Procesar Nuevo Renglon
    Item:=GetDefaultColRow;
  end else begin
    // Procesar Nueva Celda
    Item:=nil;
  end;
end;

constructor TVirtualGrid.Create;
begin
  Inherited Create;
  {$Ifdef DbgGrid}DebugLn('TVirtualGrid.Create');{$Endif}
  FCells:=TArray.Create;
  FCells.OnDestroyItem:=@doDestroyItem;
  FCells.OnNewItem:=@doNewItem;
  FCols:= TArray.Create;
  FCols.OnDestroyItem:=@doDestroyItem;
  FCols.OnNewItem:=@doNewItem;
  FRows:=TArray.Create;
  FRows.OnDestroyItem:=@doDestroyItem;
  FRows.OnNewItem:=@doNewItem;
  RowCount:=4;
  ColCount:=4;
end;

destructor TVirtualGrid.Destroy;
begin
  {$Ifdef DbgGrid}DebugLn('TVirtualGrid.Destroy');{$Endif}
  Clear;
  FreeThenNil(FRows);
  FreeThenNil(FCols);
  FreeThenNil(FCells);
  inherited Destroy;
end;

procedure TVirtualGrid.DeleteColRow(IsColumn: Boolean; index: Integer);
begin
  FCells.DeleteColRow(IsColumn, index);
  if IsColumn then begin
    FCols.DeleteColRow(True, index);
    Dec(FColCount);
  end else begin
    FRows.DeleteColRow(True, index);
    Dec(fRowCount);
  end;
end;

procedure TVirtualGrid.MoveColRow(IsColumn: Boolean; FromIndex, ToIndex: Integer
  );
begin
  FCells.MoveColRow(IsColumn, FromIndex, ToIndex);
  if IsColumn then FCols.MoveColRow(True, FromIndex, ToIndex)
  else             FRows.MoveColRow(True, FromIndex, ToIndex);
end;

procedure TVirtualGrid.ExchangeColRow(IsColumn: Boolean; index,
  WithIndex: Integer);
begin
  FCells.ExchangeColRow(IsColumn, index, WithIndex);
  if IsColumn then FCols.ExchangeColRow(true, index, WithIndex)
  else             FRows.ExchangeColRow(True, index, WithIndex);
end;

procedure TVirtualGrid.InsertColRow(IsColumn: Boolean; Index: Integer);
begin
  if IsColumn then begin
    ColCount := ColCount + 1;
    MoveColRow(true, ColCount-1, Index);
  end else begin
    RowCount := RowCount + 1;
    MoveColRow(false, RowCount-1, Index);
  end;
end;

procedure TStringCellEditor.WndProc(var TheMessage: TLMessage);
begin
	{$IfDef GridTraceMsg}
	TransMsg('StrCellEditor: ', TheMessage);
	{$Endif}
  if FGrid<>nil then
    case TheMessage.Msg of
      LM_CLEARSEL,
      LM_CUTTOCLIP,
      LM_PASTEFROMCLIP:
        begin
          if FGrid.EditorIsReadOnly then
            exit;
        end;
    end;
  inherited WndProc(TheMessage);
end;

{ TStringCellEditor }

procedure TStringCellEditor.Change;
begin
  {$IfDef DbgGrid} DebugLn('TStringCellEditor.Change INIT text=',Text);{$ENDIF}
  inherited Change;
  if FGrid<>nil then begin
    FGrid.SetEditText(FCol, FRow, Text);
  end;
  {$IfDef DbgGrid} DebugLn('TStringCellEditor.Change FIN');{$ENDIF}
end;

procedure TStringCellEditor.EditingDone;
begin
  inherited EditingDone;
  if FGrid<>nil then
    FGrid.EditingDone;
end;

procedure TStringCellEditor.KeyDown(var Key: Word; Shift: TShiftState);
  function AllSelected: boolean;
  begin
    result := (SelLength>0) and (SelLength=UTF8Length(Text));
  end;
  function AtStart: Boolean;
  begin
    Result:= (SelStart=0);
  end;
  function AtEnd: Boolean;
  begin
    result := ((SelStart+1)>UTF8Length(Text)) or AllSelected;
  end;
  procedure doEditorKeyDown;
  begin
    if FGrid<>nil then
      FGrid.EditorkeyDown(Self, key, shift);
  end;
  procedure doGridKeyDown;
  begin
    if FGrid<>nil then
      FGrid.KeyDown(Key, shift);
  end;
  function GetFastEntry: boolean;
  begin
    if FGrid<>nil then
      Result := FGrid.FastEditing
    else
      Result := False;
  end;
  procedure CheckEditingKey;
  begin
    if (FGrid=nil) or FGrid.EditorIsReadOnly then
      Key := 0;
  end;
var
  IntSel: boolean;
begin
  {$IfDef dbgGrid}
  DebugLn('TStringCellEditor.KeyDown INI: Key=', Dbgs(Key),
    ' SelStart=',Dbgs(SelStart),' SelLenght=',dbgs(SelLength),
    ' Len(text)=',dbgs(Length(Text)),' Utf8Len(Text)=',dbgs(UTF8Length(Text)));
  {$Endif}
  inherited KeyDown(Key,Shift);
  case Key of
    VK_F2:
      if AllSelected then begin
        SelLength := 0;
        SelStart := Length(Text);
      end;
    VK_DELETE:
      CheckEditingKey;
    VK_UP, VK_DOWN:
      doGridKeyDown;
    VK_LEFT, VK_RIGHT:
      if GetFastEntry then begin
        IntSel:=
          ((Key=VK_LEFT) and not AtStart) or
          ((Key=VK_RIGHT) and not AtEnd);
      if not IntSel then begin
          doGridKeyDown;
      end;
    end;
    VK_END, VK_HOME:
      ;
    else
      doEditorKeyDown;
  end;
  {$IfDef dbgGrid}
  DebugLn('TStringCellEditor.KeyDown FIN: Key=', Dbgs(Key),
    ' SelStart=',Dbgs(SelStart),' SelLenght=',Dbgs(SelLength));
  {$Endif}
end;

procedure TStringCellEditor.msg_SetMask(var Msg: TGridMessage);
begin
  FCol:=Msg.Col;
  FRow:=Msg.Row;
  EditMask:=msg.Value;
end;


procedure TStringCellEditor.msg_SetValue(var Msg: TGridMessage);
begin
  FCol:=Msg.Col;
  FRow:=Msg.Row;
  Text:=Msg.Value;
  SelStart := Length(Text);
end;

procedure TStringCellEditor.msg_GetValue(var Msg: TGridMessage);
begin
  Msg.Col:=FCol;
  Msg.Row:=FRow;
  Msg.Value:=Text;
end;

procedure TStringCellEditor.msg_SetGrid(var Msg: TGridMessage);
begin
  FGrid:=Msg.Grid;
  Msg.Options:=EO_AUTOSIZE or EO_HOOKEXIT or EO_SELECTALL or EO_HOOKKEYPRESS
    or EO_HOOKKEYUP;
end;

procedure TStringCellEditor.msg_SelectAll(var Msg: TGridMessage);
begin
  SelectAll;
end;

{ TCustomDrawGrid }


procedure TCustomDrawGrid.CalcCellExtent(acol, aRow: Integer; var aRect: TRect);
begin
  //
end;

procedure TCustomDrawGrid.DrawCell(aCol,aRow: Integer; aRect: TRect;
  aState:TGridDrawState);
var
  OldDefaultDrawing: boolean;
begin
  if Assigned(OnDrawCell) and not(CsDesigning in ComponentState) then begin
    PrepareCanvas(aCol, aRow, aState);
    if DefaultDrawing then
      Canvas.FillRect(aRect);
    OnDrawCell(Self,aCol,aRow,aRect,aState)
  end else begin
    OldDefaultDrawing:=FDefaultDrawing;
    FDefaultDrawing:=True;
    try
      PrepareCanvas(aCol, aRow, aState);
    finally
      FDefaultDrawing:=OldDefaultDrawing;
    end;
    DefaultDrawCell(aCol,aRow,aRect,aState);
  end;
  DrawCellGrid(aCol,aRow,aRect,aState);
end;

procedure TCustomDrawGrid.DrawFocusRect(aCol, aRow: Integer; ARect: TRect);
var
  DCIndex: Integer;
  FOldFocusColor: TColor;
begin
  // Draw focused cell if we have the focus
  if Self.Focused or (EditorAlwaysShown and ((Feditor=nil) or not Feditor.Focused)) then
  begin
    CalcFocusRect(aRect);
    if FUseXORFeatures then begin
      DCIndex := SaveDC(Canvas.Handle);
      FOldFocusColor := FFocusColor;
      FFocusColor:= clWhite;
      Canvas.Pen.Mode := pmXOR;
    end;
    DrawRubberRect(Canvas, aRect, FFocusColor);
    if FUseXORFeatures then begin
      RestoreDC(Canvas.Handle, DCIndex);
      FFocusColor := FOldFocusColor;
    end;
  end;
end;

procedure TCustomDrawGrid.ColRowExchanged(IsColumn:Boolean; index, WithIndex: Integer);
begin
  if not IsColumn or not Columns.Enabled then
    Fgrid.ExchangeColRow(IsColumn, index, WithIndex);
  if Assigned(OnColRowExchanged) then
    OnColRowExchanged(Self, IsColumn, index, WithIndex);
end;

procedure TCustomDrawGrid.ColRowInserted(IsColumn: boolean; index: integer);
begin
  if not IsColumn or not Columns.Enabled then
    FGrid.InsertColRow(IsColumn, Index);
  NotifyColRowChange(True, IsColumn, Index, Index);
end;

procedure TCustomDrawGrid.ColRowDeleted(IsColumn: Boolean; index: Integer);
begin
  if not IsColumn or not Columns.Enabled then
    FGrid.DeleteColRow(IsColumn, index);
  NotifyColRowChange(False, IsColumn, Index, Index);
end;

procedure TCustomDrawGrid.ColRowMoved(IsColumn: Boolean; FromIndex, ToIndex: Integer);
begin
  inherited ColRowMoved(IsColumn, FromIndex, ToIndex);
  
  // now move content, if Columns.Enabled and IsColumn then
  // first row header has been already moved, what is in
  // cells[0,0]-cells[colCount-1,0] doesn't matter because
  // columns should take precedence.
  FGrid.MoveColRow(IsColumn, FromIndex, ToIndex);

  if Assigned(OnColRowMoved) then
    OnColRowMoved(Self, IsColumn, FromIndex, toIndex);
end;

procedure TCustomDrawGrid.HeaderClick(IsColumn: Boolean; index: Integer);
begin
  inherited HeaderClick(IsColumn, index);
  if Assigned(OnHeaderClick) then OnHeaderClick(Self, IsColumn, index);
end;

procedure TCustomDrawGrid.HeaderSized(IsColumn: Boolean; index: Integer);
begin
  inherited HeaderSized(IsColumn, index);
  if Assigned(OnHeaderSized) then OnHeaderSized(Self, IsColumn, index);
end;

procedure TCustomDrawGrid.GetAutoFillColumnInfo(const Index: Integer; var aMin, aMax,
  aPriority: Integer);
begin
  if Index<FixedCols then
    aPriority := 0
  else
    aPriority := 1;
end;

function TCustomDrawGrid.GetEditMask(aCol, aRow: Longint): string;
begin
  result:='';
  if assigned(OnGetEditMask) then OnGetEditMask(self, aCol, aRow, Result);
end;

function TCustomDrawGrid.GetEditText(aCol, aRow: Longint): string;
begin
  result:='';
  if assigned(OnGetEditText) then OnGetEditText(self, aCol, aRow, Result);
end;

procedure TCustomDrawGrid.NotifyColRowChange(WasInsert, IsColumn: boolean;
  FromIndex,ToIndex: Integer);
begin
  if WasInsert then begin
    if assigned(OnColRowInserted) then
      OnColRowInserted(Self, IsColumn, FromIndex, ToIndex)
  end else begin
    if assigned(OnColRowDeleted) then
      OnColRowDeleted(Self, IsColumn, FromIndex, ToIndex);
  end;
end;

procedure TCustomDrawGrid.SetEditText(ACol, ARow: Longint; const Value: string);
begin
  if Assigned(OnSetEditText) then OnSetEditText(Self, aCol, aRow, Value);
end;

procedure TCustomDrawGrid.SizeChanged(OldColCount, OldRowCount: Integer);
begin
  if OldColCount<>ColCount then begin
    fGrid.ColCount:=ColCount;
    if OldColCount>ColCount then
      NotifyColRowChange(False, True, ColCount, OldColCount-1)
    else
      NotifyColRowChange(True, True, OldColCount, ColCount-1);
  end;
  if OldRowCount<>RowCount then begin
    fGrid.RowCount:=RowCount;
    if OldRowCount>RowCount then
      NotifyColRowChange(False, False, RowCount, OldRowCount-1)
    else
      NotifyColRowChange(True, False, OldRowCount, RowCount-1);
  end;
end;

procedure TCustomDrawGrid.DrawCellAutonumbering(aCol, aRow: Integer;
  aRect: TRect; const aValue: string);
begin
  Canvas.TextRect(aRect,ARect.Left+3,ARect.Top+3, aValue);
end;

function TCustomDrawGrid.SelectCell(aCol, aRow: Integer): boolean;
begin
  Result:= (ColWidths[aCol] > 0) and (RowHeights[aRow] > 0);
  if Assigned(OnSelectCell) then OnSelectCell(Self, aCol, aRow, Result);
end;

procedure TCustomDrawGrid.SetColor(Value: TColor);
begin
  inherited SetColor(Value);
  Invalidate;
end;

function TCustomDrawGrid.CreateVirtualGrid: TVirtualGrid;
begin
  Result:=TVirtualGrid.Create;
end;

constructor TCustomDrawGrid.Create(AOwner: TComponent);
begin
  fGrid:=CreateVirtualGrid;
  inherited Create(AOwner);
end;

destructor TCustomDrawGrid.Destroy;
begin
  {$Ifdef DbgGrid}DebugLn('TCustomDrawGrid.Destroy');{$Endif}
  FreeThenNil(FGrid);
  inherited Destroy;
end;

procedure TCustomDrawGrid.DeleteColRow(IsColumn: Boolean; index: Integer);
begin
  DoOPDeleteColRow(IsColumn, Index);
end;

procedure TCustomDrawGrid.ExchangeColRow(IsColumn: Boolean; index,
  WithIndex: Integer);
begin
  DoOPExchangeColRow(IsColumn, Index, WithIndex);
end;

procedure TCustomDrawGrid.InsertColRow(IsColumn: boolean; index: integer);
begin
  doOPInsertColRow(IsColumn, Index);
end;

procedure TCustomDrawGrid.MoveColRow(IsColumn: Boolean; FromIndex,
  ToIndex: Integer);
begin
  DoOPMoveColRow(IsColumn, FromIndex, ToIndex);
end;

procedure TCustomDrawGrid.SortColRow(IsColumn: Boolean; index: Integer);
begin
  if IsColumn then Sort(IsColumn, index, FFixedRows, RowCount-1)
  else             Sort(IsColumn, index, FFixedCols, ColCount-1);
end;

procedure TCustomDrawGrid.SortColRow(IsColumn: Boolean; Index, FromIndex,
  ToIndex: Integer);
begin
  Sort(IsColumn, Index, FromIndex, ToIndex);
end;

procedure TCustomDrawGrid.DefaultDrawCell(aCol, aRow: Integer; var aRect: TRect;
  aState: TGridDrawState);
var
  C: TGridColumn;
begin
  if goColSpanning in Options then CalcCellExtent(acol, arow, aRect);
  Canvas.FillRect(aRect);

  if Columns.Enabled and (gdFixed in aState) and
    (aCol>=FixedCols) and (aRow=0) then begin
    // draw the column title if there is any
    C := ColumnFromGridColumn(aCol);
    if C<>nil then
      DrawCellText(aCol,aRow,aRect,aState,C.Title.Caption);
  end;

  if (goFixedRowNumbering in Options) and (FixedCols >= 1) and (aCol = 0) then
    DrawCellAutonumbering(aCol, aRow, aRect, IntToStr(aRow));
end;

{ TCustomStringGrid }

function TCustomStringGrid.Getcells(aCol, aRow: Integer): string;
var
   C: PCellProps;
begin
  Result:='';
  C:=FGrid.Celda[aCol,aRow];
  if C<>nil then Result:=C^ .Text;
end;

function TCustomStringGrid.GetCols(index: Integer): TStrings;
var
  i: Integer;
begin
  Result:=nil;
  if (ColCount>0)and(index>=0)and(index<ColCount) then begin
    Result:=TStringList.Create;
    for i:=0 to RowCount-1 do
      Result.AddObject(Cells[Index, i], Objects[Index, i]);
  end;
end;

function TCustomStringGrid.GetObjects(ACol, ARow: Integer): TObject;
var
  C: PCellProps;
begin
  Result:=nil;
  C:=Fgrid.Celda[aCol,aRow];
  if C<>nil then Result:=C^.Data;
end;

function TCustomStringGrid.GetRows(index: Integer): TStrings;
var
  i: Integer;
begin
  Result:=nil;
  if (RowCount>0)and(index>=0)and(index<RowCount) then begin
    Result:=TStringList.Create;
    for i:=0 to ColCount-1 do
      Result.AddObject(Cells[i, Index], Objects[i, Index]);
  end;
end;

procedure TCustomStringGrid.ReadCells(Reader: TReader);
var
  aCol,aRow: Integer;
  i, c: Integer;
begin
  with Reader do begin
    ReadListBegin;
    c := ReadInteger;
    for i:=1 to c do begin
      aCol := ReadInteger;
      aRow := ReadInteger;
      Cells[aCol,aRow]:= ReadString;
    end;
    {
    repeat
      aCol := ReadInteger;
      aRow := ReadInteger;
      Cells[aCol,aRow] := ReadString;
    until NextValue = vaNull;
    }
    ReadListEnd;
  end;
end;

procedure TCustomStringGrid.Setcells(aCol, aRow: Integer; const Avalue: string);
  procedure UpdateCell;
  begin
    if EditorMode and (aCol=FCol)and(aRow=FRow) and
      not (gfEditorUpdateLock in GridFlags) then
    begin
      EditorDoSetValue;
    end;
    InvalidateCell(aCol, aRow);
  end;
var
  C: PCellProps;
begin
  C:= FGrid.Celda[aCol,aRow];
  if C<>nil then begin
    if C^.Text<>nil then StrDispose(C^.Text);
    C^.Text:=StrNew(pchar(aValue));
    UpdateCell;
    FModified := True;
  end else begin
    if AValue<>'' then begin
      New(C);
      C^.Text:=StrNew(pchar(Avalue));
      C^.Attr:=nil;
      C^.Data:=nil;
      FGrid.Celda[aCol,aRow]:=C;
      UpdateCell;
      FModified := True;
    end;
  end;
end;

procedure TCustomStringGrid.SetCols(index: Integer; const AValue: TStrings);
var
  i: Integer;
begin
  if Avalue=nil then exit;
  for i:=0 to AValue.Count-1 do begin
    Cells[index, i]:= AValue[i];
    Objects[Index, i]:= AValue.Objects[i];
  end;
end;

procedure TCustomStringGrid.SetObjects(ACol, ARow: Integer; AValue: TObject);
var
  c: PCellProps;
begin
  C:=FGrid.Celda[aCol,aRow];
  if c<>nil then C^.Data:=AValue
  else begin
    c:=fGrid.GetDefaultCell;
    c^.Data:=Avalue;
    FGrid.Celda[aCol,aRow]:=c;
  end;
end;

procedure TCustomStringGrid.SetRows(index: Integer; const AValue: TStrings);
var
  i: Integer;
begin
  if Avalue=nil then exit;
  for i:=0 to AValue.Count-1 do begin
    Cells[i, index]:= AValue[i];
    Objects[i, Index]:= AValue.Objects[i];
  end;
end;

procedure TCustomStringGrid.WriteCells(Writer: TWriter);
var
  i,j: Integer;
  c: Integer;
begin
  with writer do begin
    WriteListBegin;
    //cell count
    c:=0;
    for i:=0 to ColCount-1 do
      for j:=0 to RowCount-1 do
        if Cells[i,j]<>'' then Inc(c);
    WriteInteger(c);

    for i:=0 to ColCount-1 do
      for j:=0 to RowCount-1 do
        if Cells[i,j]<>'' then begin
          WriteInteger(i);
          WriteInteger(j);
          WriteString(Cells[i,j]);
        end;
    WriteListEnd;
  end;
end;

procedure TCustomStringGrid.AutoAdjustColumn(aCol: Integer);
var
  i,W: Integer;
  Ts: TSize;
begin
  if (aCol<0)or(aCol>ColCount-1) then Exit;
  W:=0;
  For i:=0 to RowCount-1 do begin
    Ts:=Canvas.TextExtent(Cells[aCol, i]);
    if Ts.Cx>W then W:=Ts.Cx;
  end;
  if W=0 then W:=DefaultColWidth
  else        W:=W + 8;
  ColWidths[aCol]:=W;
end;

procedure TCustomStringGrid.CalcCellExtent(acol, aRow: Integer; var aRect: TRect);
var
  S: string;
  Ts: Tsize;
  nc: PcellProps;
  i: integer;
begin
  inherited CalcCellExtent(acol,arow, aRect);
  S:=Cells[aCol,aRow];
  if not Canvas.TextStyle.Clipping then begin
  //if not FCellAttr.TextStyle.Clipping then begin
    // Calcular el numero de celdas necesarias para contener todo
    // El Texto
    Ts:=Canvas.TextExtent(S);
    i:=aCol;
    while (Ts.Cx>(aRect.Right-aRect.Left))and(i<ColCount) do begin
      inc(i);
      Nc:=FGrid.Celda[i, aRow];
      if (nc<>nil)and(Nc^.Text<>'')then Break;
      aRect.Right:=aRect.Right + getColWidths(i);
    end;
    //fcellAttr.TextStyle.Clipping:=i<>aCol;
    Canvas.TextStyle.clipping:=i<>aCol;
  end;
end;

procedure TCustomStringGrid.DefineProperties(Filer: TFiler);
  function NeedCells: boolean;
  var
    i,j: integer;
    AntGrid: TCustomStringGrid;
  begin
    result := false;
    AntGrid := TCustomStringGrid(Filer.Ancestor);
    if (AntGrid<>nil) then begin
      result := (AntGrid.ColCount<>ColCount) or (AntGrid.RowCount<>RowCount);
      if not result then
        for i:=0 to AntGrid.ColCount-1 do
          for j:=0 to AntGrid.RowCount-1 do
            if Cells[i,j]<>AntGrid.Cells[i,j] then begin
              result := true;
              break;
            end
    end else
      for i:=0 to ColCount-1 do
        for j:=0 to RowCount-1 do
          if Cells[i,j]<>'' then begin
            result := true;
            break;
          end;
  end;
begin
  inherited DefineProperties(Filer);
  with Filer do begin
    DefineProperty('Cells',  @ReadCells,  @WriteCells,  NeedCells);
  end;
end;

function TCustomStringGrid.DoCompareCells(Acol, ARow, Bcol, BRow: Integer
  ): Integer;
begin
  if Assigned(OnCompareCells) then
    Result:=inherited DoCompareCells(Acol, ARow, Bcol, BRow)
  else
    Result:=AnsiCompareText(Cells[ACol,ARow], Cells[BCol,BRow]);
end;

procedure TCustomStringGrid.DoCopyToClipboard;
var
  SelStr: String;
  Sel: TRect;
  i: LongInt;
  j: LongInt;
begin
  SelStr := '';
  Sel := Selection;
  for i:=Sel.Top to Sel.Bottom do begin
    for j:=Sel.Left to Sel.Right do begin
      SelStr := SelStr + Cells[j,i];
      if j<>Sel.Right then
        SelStr := SelStr + #9;
    end;
    SelStr := SelStr + #13#10;
  end;
  Clipboard.AsText := SelStr;
  {
  SelStr := StringReplace(SelStr, #13#10,'|', [rfReplaceAll]);
  SelStr := StringReplace(SelStr, #9,'*', [rfReplaceAll]);
  DebugLn('Copied: ',SelStr);
  }
end;

procedure TCustomStringGrid.DoCutToClipboard;
begin
  doCopyToClipboard;
  //if not GridReadOnly then
  Clean(Selection, []);
end;

procedure TCustomStringGrid.DoPasteFromClipboard;
begin
  if Clipboard.HasFormat(CF_TEXT) then begin
    SelectionSetText(Clipboard.AsText);
  end;
end;

procedure TCustomStringGrid.DrawCell(aCol, aRow: Integer; aRect: TRect;
  aState: TGridDrawState);
begin
  inherited DrawCell(aCol, aRow, aRect, aState);
  if DefaultDrawing then begin
    if Columns.Enabled and (gdFixed in aState) and
      (aCol>=FixedCols) and (aRow=0) then
      //inherited already did
    else
      DrawCellText(aCol, aRow, aRect, aState, Cells[aCol,aRow]);
  end;
end;

procedure TCustomStringGrid.DrawCellAutonumbering(aCol, aRow: Integer;
  aRect: TRect; const aValue: string);
begin
  if Cells[aCol,aRow]='' then
    inherited DrawCellAutoNumbering(aCol,aRow,aRect,aValue);
end;

function TCustomStringGrid.GetEditText(aCol, aRow: Integer): string;
begin
  Result:=Cells[aCol, aRow];
  if Assigned(OnGetEditText) then OnGetEditText(Self, aCol, aRow, result);
end;

procedure TCustomStringGrid.SaveContent(cfg: TXMLConfig);
var
  i,j,k: Integer;
  c: PCellProps;
begin
  inherited SaveContent(cfg);
  cfg.SetValue('grid/saveoptions/content', soContent in SaveOptions);
  if soContent in SaveOptions then begin
    // Save Cell Contents
    k:=0;
    For i:=0 to ColCount-1 do
      For j:=0 to RowCount-1 do begin
        C:=fGrid.Celda[i,j];
        if (c<>nil) and (C^.Text<>'') then begin
          Inc(k);
          Cfg.SetValue('grid/content/cells/cellcount',k);
          cfg.SetValue('grid/content/cells/cell'+IntToStr(k)+'/column',i);
          cfg.SetValue('grid/content/cells/cell'+IntToStr(k)+'/row',j);
          cfg.SetValue('grid/content/cells/cell'+IntToStr(k)+'/text', c^.Text);
        end;
      end;
   end;
end;

procedure TCustomStringGrid.SelectionSetText(TheText: String);
var
  L,SubL: TStringList;
  i,j,StartCol,StartRow: Integer;
  procedure CollectCols(const S: String);
  var
    P,Ini: PChar;
    St: String;
  begin
    Subl.Clear;
    P := Pchar(S);
    if P<>nil then
      while P^<>#0 do begin
        ini := P;
        while (P^<>#0) and (P^<>#9) do
          Inc(P);
        SetLength(St, P-Ini);
        Move(Ini^,St[1],P-Ini);
        SubL.Add(St);
        if P^<>#0 then
          Inc(P);
      end;
  end;
begin
  L := TStringList.Create;
  SubL := TStringList.Create;
  StartCol := Selection.left;
  StartRow := Selection.Top;
  try
    L.Text := TheText;
    for j:=0 to L.Count-1 do begin
      CollectCols(L[j]);
      for i:=0 to SubL.Count-1 do
        Cells[i + StartCol, j + StartRow] := SubL[i];
    end;
  finally
    SubL.Free;
    L.Free;
  end;
end;

procedure TCustomStringGrid.LoadContent(Cfg: TXMLConfig; Version:Integer);
var
  ContentSaved: Boolean;
  i,j,k: Integer;
begin
  inherited LoadContent(Cfg, Version);
  if soContent in FSaveOptions then begin
    ContentSaved:=Cfg.GetValue('grid/saveoptions/content', false);
    if ContentSaved then begin
      k:=cfg.getValue('grid/content/cells/cellcount', 0);
      while k>0 do begin
        i:=cfg.GetValue('grid/content/cells/cell'+IntToStr(k)+'/column', -1);
        j:=cfg.GetValue('grid/content/cells/cell'+IntTostr(k)+'/row',-1);
        if (j>=0)and(j<=rowcount-1)and(i>=0)and(i<=Colcount-1) then
          Cells[i,j]:=cfg.GetValue('grid/content/cells/cell'+IntToStr(k)+'/text','');
        Dec(k);
      end;
    end;
  end;
end;

procedure TCustomStringGrid.Loaded;
begin
  inherited Loaded;
  FModified := False;
end;

procedure TCustomStringGrid.SetEditText(aCol, aRow: Longint; const aValue: string);
begin
  Include(GridFlags, gfEditorUpdateLock);
  try
    if Cells[aCol, aRow]<>aValue then
      Cells[aCol, aRow]:= aValue;
  finally
    Exclude(GridFlags, gfEditorUpdateLock);
  end;
  inherited SetEditText(aCol, aRow, aValue);
end;

constructor TCustomStringGrid.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  with DefaultTextStyle do begin
    Alignment := taLeftJustify;
    Layout := tlCenter;
    Clipping := True;
    //WordBreak := False
  end;
  ExtendedSelect := True;
end;

procedure TCustomStringGrid.AutoSizeColumn(aCol: Integer);
begin
  AutoAdjustColumn(aCol);
end;

procedure TCustomStringGrid.AutoSizeColumns;
var
  i: Integer;
begin
  for i:=0 to ColCount-1 do
    AutoAdjustColumn(i)
end;

procedure TCustomStringGrid.Clean;
begin
  Clean([gzNormal, gzFixedCols, gzFixedRows, gzFixedCells]);
end;

procedure TCustomStringGrid.Clean(CleanOptions: TCleanOptions);
begin
  Clean(0,0,ColCount-1,RowCount-1, CleanOptions);
end;

procedure TCustomStringGrid.Clean(aRect: TRect; CleanOptions: TCleanOptions);
begin
  with aRect do
  Clean(Left, Top, Right, Bottom, CleanOptions);
end;

procedure TCustomStringGrid.Clean(StartCol, StartRow, EndCol, EndRow: integer;
  CleanOptions: TCleanOptions);
var
  aCol: LongInt;
  aRow: LongInt;
begin
  if StartCol>EndCol then SwapInt(StartCol,EndCol);
  if StartRow>EndRow then SwapInt(StartRow,EndRow);

  if StartCol<0 then StartCol:=0;
  if EndCol>ColCount-1 then EndCol:=ColCount-1;
  if StartRow<0 then StartRow:=0;
  if EndRow>RowCount-1 then EndRow:=RowCount-1;

  BeginUpdate;
  for aCol:=StartCol to EndCol do
    for aRow:= StartRow to EndRow do
      if (CleanOptions=[]) or (CellToGridZone(aCol,aRow) in CleanOptions) then
        Cells[aCol,aRow] := '';
  EndUpdate(false);
end;


procedure Register;
begin
  RegisterComponents('Additional',[TStringGrid,TDrawGrid]);
end;


{ TGridColumnTitle }

procedure TGridColumnTitle.FontChanged(Sender: TObject);
begin
  FisDefaultTitleFont := False;
  FColumn.ColumnChanged;
end;

function TGridColumnTitle.GetAlignment: TAlignment;
begin
  if FAlignment = nil then
    result := GetDefaultAlignment
  else
    result := FAlignment^;
end;

function TGridColumnTitle.GetCaption: string;
begin
  if FCaption = nil then
    result := GetDefaultCaption
  else
    result := FCaption;
end;

function TGridColumnTitle.GetColor: TColor;
begin
  if FColor = nil then
    result := GetDefaultColor
  else
    result := FColor^;
end;

procedure TGridColumnTitle.FillTitleDefaultFont;
var
  AGrid: TCustomGrid;
begin
  AGrid :=  FColumn.Grid;
  if AGrid<>nil then
    FFont.Assign( AGrid.TitleFont )
  else
    FFont.Assign( FColumn.Font );
  FIsDefaultTitleFont := True;
end;

function TGridColumnTitle.GetFont: TFont;
begin
  Result := FFont;
end;

function TGridColumnTitle.GetLayout: TTextLayout;
begin
  if FLayout = nil then
    result := GetDefaultLayout
  else
    result := FLayout^;
end;

function TGridColumnTitle.IsAlignmentStored: boolean;
begin
  result := FAlignment <> nil;
end;

function TGridColumnTitle.IsCaptionStored: boolean;
begin
  result := FCaption <> nil;
end;

function TGridColumnTitle.IsColorStored: boolean;
begin
  result := FColor <> nil;
end;

function TGridColumnTitle.IsFontStored: boolean;
begin
  result := not IsDefaultFont;
end;

function TGridColumnTitle.IsLayoutStored: boolean;
begin
  result := FLayout <> nil;
end;

procedure TGridColumnTitle.SetAlignment(const AValue: TAlignment);
begin
  if Falignment = nil then begin
    if AValue = GetDefaultAlignment then
      exit;
    New(Falignment)
  end else if FAlignment^ = AValue then
    exit;
  FAlignment^ := AValue;
  FColumn.ColumnChanged;
end;

procedure TGridColumnTitle.SetCaption(const AValue: string);
begin
  if (FCaption=nil)or(AValue<>FCaption^) then begin
    if FCaption<>nil then
      StrDispose(FCaption)
    else if (AValue=GetDefaultCaption) then
      exit;
    FCaption := StrNew(PChar(AValue));
    FColumn.ColumnChanged;
  end;
end;

procedure TGridColumnTitle.SetColor(const AValue: TColor);
begin
  if FColor=nil then begin
    if AValue = GetDefaultColor then
      exit;
    New(FColor)
  end else if FColor^=AValue then
    exit;
  FColor^ := AValue;
  FColumn.ColumnChanged;
end;

procedure TGridColumnTitle.SetFont(const AValue: TFont);
begin
  if AValue.Handle<>FFont.Handle then begin
    FFont.Assign(AValue);
  end;
end;

procedure TGridColumnTitle.SetLayout(const AValue: TTextLayout);
begin
  if FLayout = nil then begin
    if AValue = GetDefaultLayout then
      exit;
    New(FLayout)
  end else if FLayout^ = AValue then
    exit;
  FLayout^ := AValue;
  FColumn.ColumnChanged;
end;

procedure TGridColumnTitle.Assign(Source: TPersistent);
begin
  if Source is TGridColumnTitle then begin
    Alignment := TGridColumnTitle(Source).Alignment;
    Layout := TGridColumnTitle(Source).Layout;
    Caption := TGridColumnTitle(Source).Caption;
    Color := TGridColumnTitle(Source).Color;
    Font := TGridColumnTitle(Source).Font;
  end else
    inherited Assign(Source);
end;

function TGridColumnTitle.GetDefaultCaption: string;
begin
  Result := 'Title'
end;

function TGridColumnTitle.GetDefaultAlignment: TAlignment;
begin
  result := taLeftJustify
end;

function TGridColumnTitle.GetDefaultColor: TColor;
begin
  if FColumn.Grid <> nil then
    result := FColumn.Grid.FixedColor
  else
    result := clBtnFace
end;

function TGridColumnTitle.GetDefaultLayout: TTextLayout;
begin
  result := tlCenter
end;

constructor TGridColumnTitle.Create(TheColumn: TGridColumn);
begin
  inherited Create;
  FColumn := TheColumn;
  FIsDefaultTitleFont := True;
  FFont := TFont.Create;
  FillTitleDefaultFont;
  FFont.OnChange := @FontChanged;
end;

destructor TGridColumnTitle.Destroy;
begin
  if FFont<>nil then FFont.Free;
  if FAlignment<>nil then Dispose(FAlignment);
  if FColor<>nil then Dispose(FColor);
  if FCaption<>nil then StrDispose(FCaption); //DisposeStr(FCaption);
  if FLayout<>nil then Dispose(FLayout);
  inherited Destroy;
end;

function TGridColumnTitle.IsDefault: boolean;
begin
  result :=  (FAlignment=nil) and (FColor=nil) and (FCaption=nil) and
    IsDefaultFont and (FLayout=nil);
end;

{ TGridColumn }

procedure TGridColumn.FontChanged(Sender: TObject);
begin
  FisDefaultFont := False;
  ColumnChanged;
end;

function TGridColumn.GetAlignment: TAlignment;
begin
  if FAlignment=nil then
    Result := GetDefaultAlignment
  else
    result := FAlignment^;
end;

function TGridColumn.GetColor: TColor;
begin
  if FColor=nil then
    result := GetDefaultColor
  else
    result := FColor^
end;

function TGridColumn.GetExpanded: Boolean;
begin
  result := True;
end;

function TGridColumn.GetFont: TFont;
begin
  result := FFont;
end;

function TGridColumn.GetGrid: TCustomGrid;
begin
  if Collection is TGridColumns then
    result := (Collection as TGridColumns).Grid
  else
    result := nil;
end;

function TGridColumn.GetLayout: TTextLayout;
begin
  if FLayout=nil then
    result := GetDefaultLayout
  else
    result := FLayout^;
end;

function TGridColumn.GetMaxSize: Integer;
begin
  if FMaxSize=nil then
    result := GetDefaultMaxSize
  else
    result := FMaxSize^;
end;

function TGridColumn.GetMinSize: Integer;
begin
  if FMinSize=nil then
    result := GetDefaultMinSize
  else
    result := FMinSize^;
end;

function TGridColumn.GetSizePriority: Integer;
begin
  if FSizePriority=nil then
    result := GetDefaultSizePriority
  else
    result := FSizePriority^;
end;

function TGridColumn.GetPickList: TStrings;
begin
  Result := FPickList;
end;

function TGridColumn.GetReadOnly: Boolean;
begin
  if FReadOnly=nil then
    result := GetDefaultReadOnly
  else
    result := FReadOnly^;
end;

function TGridColumn.GetVisible: Boolean;
begin
  if FVisible=nil then begin
    result := GetDefaultVisible;
  end else
    result := FVisible^;
end;

function TGridColumn.GetWidth: Integer;
begin
  if FWidth=nil then
    result := GetDefaultWidth
  else
    result := FWidth^;
end;

function TGridColumn.IsAlignmentStored: boolean;
begin
  result := FAlignment <> nil;
end;

function TGridColumn.IsColorStored: boolean;
begin
  result := FColor <> nil;
end;

function TGridColumn.IsFontStored: boolean;
begin
  result := not FisDefaultFont;
end;

function TGridColumn.IsLayoutStored: boolean;
begin
  result := FLayout <> nil;
end;

function TGridColumn.IsMinSizeStored: boolean;
begin
  result := FMinSize <> nil;
end;

function TGridColumn.IsMaxSizeStored: boolean;
begin
  result := FMaxSize <> nil;
end;

function TGridColumn.IsReadOnlyStored: boolean;
begin
  result := FReadOnly <> nil;
end;

function TGridColumn.IsSizePriorityStored: boolean;
begin
  result := FSizePriority <> nil;
end;

function TGridColumn.IsVisibleStored: boolean;
begin
  result := (FVisible<>nil) and not FVisible^;
end;

function TGridColumn.IsWidthStored: boolean;
begin
  result := FWidth <> nil;
end;

procedure TGridColumn.SetAlignment(const AValue: TAlignment);
begin
  if FAlignment = nil then begin
    if AValue=GetDefaultAlignment then
      exit;
    New(FAlignment);
  end else if FAlignment^ = AValue then
    exit;
  FAlignment^ := AValue;
  ColumnChanged;
end;

procedure TGridColumn.SetButtonStyle(const AValue: TColumnButtonStyle);
begin
  if FButtonStyle=AValue then exit;
  FButtonStyle:=AValue;
  ColumnChanged;
end;

procedure TGridColumn.SetColor(const AValue: TColor);
begin
  if FColor = nil then begin
    if AValue=GetDefaultColor then
      exit;
    New(FColor)
  end else if FColor^ = AValue then
   exit;
  FColor^ := AValue;
  ColumnChanged;
end;

procedure TGridColumn.SetExpanded(const AValue: Boolean);
begin
  //todo
end;

procedure TGridColumn.SetFont(const AValue: TFont);
begin
  if AValue.Handle<>FFont.Handle then begin
    FFont.Assign(AValue);
  end;
end;

procedure TGridColumn.SetLayout(const AValue: TTextLayout);
begin
  if FLayout = nil then begin
    if AValue=GetDefaultLayout then
      exit;
    New(FLayout)
  end else if FLayout^ = AValue then
    exit;
  FLayout^ := AValue;
  ColumnChanged;
end;

procedure TGridColumn.SetMaxSize(const AValue: Integer);
begin
  if FMaxSize = nil then begin
    if AValue = GetDefaultMaxSize then
      exit;
    New(FMaxSize)
  end else if FMaxSize^ = AVAlue then
    exit;
  FMaxSize^ := AValue;
  ColumnChanged;
end;

procedure TGridColumn.SetMinSize(const Avalue: Integer);
begin
  if FMinSize = nil then begin
    if AValue = GetDefaultMinSize then
      exit;
    New(FMinSize)
  end else if FMinSize^ = AVAlue then
    exit;
  FMinSize^ := AValue;
  ColumnChanged;
end;

procedure TGridColumn.SetPickList(const AValue: TStrings);
begin
  if AValue=nil then
    FPickList.Clear
  else
    FPickList.Assign(AValue);
end;

procedure TGridColumn.SetReadOnly(const AValue: Boolean);
begin
  if FReadOnly = nil then begin
    if AValue = GetDefaultReadOnly then
      exit;
    New(FReadOnly)
  end else if FReadOnly^ = AValue then
    exit;
  FReadOnly^ := Avalue;
  ColumnChanged;
end;

procedure TGridColumn.SetSizePriority(const AValue: Integer);
begin
  if FSizePriority = nil then begin
    if AValue = GetDefaultSizePriority then
      exit;
    New(FSizePriority)
  end else if FSizePriority^ = AVAlue then
    exit;
  FSizePriority^ := AValue;
  ColumnChanged;
end;

procedure TGridColumn.SetTitle(const AValue: TGridColumnTitle);
begin
  FTitle.Assign(AValue);
end;

procedure TGridColumn.SetVisible(const AValue: Boolean);
begin
  if FVisible = nil then begin
    if AValue=GetDefaultVisible then
      exit;
    New(FVisible)
  end else if FVisible^ = AValue then
    exit;
  FVisible^ := AValue;
  AllColumnsChange;
end;

procedure TGridColumn.SetWidth(const AValue: Integer);
begin
  if FWidth = nil then begin
    if AValue=GetDefaultWidth then
      exit;
    New(FWidth)
  end else if FWidth^ = AVAlue then
    exit;
  FWidth^ := AValue;
  FWidthChanged:=true;
  ColumnChanged;
end;

function TGridColumn.GetDefaultReadOnly: boolean;
begin
  result := false;
end;

function TGridColumn.GetDefaultLayout: TTextLayout;
begin
  result := tlCenter
end;

function TGridColumn.GetDefaultVisible: boolean;
begin
  Result := True;
end;

function TGridColumn.GetDefaultWidth: Integer;
var
  tmpGrid: TCustomGrid;
begin
  tmpGrid := Grid;
  if tmpGrid<>nil then
    result := tmpGrid.DefaultColWidth
  else
    result := DEFCOLWIDTH;
end;

function TGridColumn.GetDefaultMaxSize: Integer;
begin
  // get a better default
  Result := 200;
end;

function TGridColumn.GetDefaultMinSize: Integer;
begin
  // get a better default
  result := 10;
end;

function TGridColumn.GetDefaultColor: TColor;
var
  TmpGrid: TCustomGrid;
begin
  TmpGrid := Grid;
  if TmpGrid<>nil then
    result := TmpGrid.Color
  else
    result := clWindow
end;

function TGridColumn.GetDefaultSizePriority: Integer;
begin
  Result := 1;
end;

procedure TGridColumn.Assign(Source: TPersistent);
begin
  if Source is TGridColumn then begin
    //DebugLn('Assigning TGridColumn[',dbgs(Index),'] a TgridColumn')
    Collection.BeginUpdate;
    try
      Alignment := TGridColumn(Source).Alignment;
      ButtonStyle := TGridColumn(Source).ButtonStyle;
      Color := TGridColumn(Source).Color;
      DropDownRows := TGridColumn(Source).DropDownRows;
      //Expanded := TGridColumn(Source).Expanded; //todo
      Font := TGridColumn(Source).Font;
      Layout := TGridColumn(Source).Layout;
      MinSize := TGridColumn(Source).MinSize;
      MaxSize := TGridColumn(Source).MaxSize;
      PickList := TGridColumn(Source).PickList;
      ReadOnly := TGridColumn(Source).ReadOnly;
      SizePriority := TGridColumn(Source).SizePriority;
      Title := TGridColumn(Source).Title;
      Width := TGridCOlumn(Source).Width;
      Visible := TGridColumn(Source).Visible;
    finally
      Collection.EndUpdate;
    end;
  end else
    inherited Assign(Source);
end;

function TGridColumn.GetDisplayName: string;
begin
  if Title.Caption<>'' then
    Result := Title.Caption
  else
    Result := 'GridColumn';
end;

function TGridColumn.GetDefaultAlignment: TAlignment;
begin
  result := taLeftJustify;
end;

procedure TGridColumn.ColumnChanged;
begin
  Changed(False);
  FWidthChanged := False;
end;

procedure TGridColumn.AllColumnsChange;
begin
  Changed(True);
  FWidthChanged := False;
end;

function TGridColumn.CreateTitle: TGridColumnTitle;
begin
  result := TGridColumnTitle.Create(Self);
end;

constructor TGridColumn.Create(ACollection: TCollection);
begin
  inherited Create(ACollection);
  FTitle := CreateTitle;

  FIsDefaultFont := True;
  FFont := TFont.Create;
  FillDefaultFont;
  FFont.OnChange := @FontChanged;

  FPickList:= TStringList.Create;
  FButtonStyle := cbsAuto;
  FDropDownRows := 7;
end;

destructor TGridColumn.Destroy;
begin
  if FAlignment<>nil then Dispose(FAlignment);
  if FColor<>nil then Dispose(FColor);
  if FVisible<>nil then Dispose(FVisible);
  if FReadOnly<>nil then Dispose(FReadOnly);
  if FWidth<>nil then Dispose(FWidth);
  if FLayout<>nil then Dispose(FLayout);
  if FMaxSize<>nil then Dispose(FMaxSize);
  if FMinSize<>nil then Dispose(FMinSize);
  FreeThenNil(FPickList);
  FreeThenNil(FFont);
  FreeThenNil(FTitle);
  inherited Destroy;
end;

procedure TGridColumn.FillDefaultFont;
var
  AGrid: TCustomGrid;
begin
  AGrid := Grid;
  if (AGrid<>nil) then begin
    FFont.Assign(AGrid.Font);
    FIsDefaultFont := True;
  end;
end;

function TGridColumn.IsDefault: boolean;
begin
  result := FTitle.IsDefault and (FAlignment=nil) and (FColor=nil)
    and (FVisible=nil) and (FReadOnly=nil) and (FWidth=nil) and FIsDefaultFont
    and (FLayout=nil) and (FMaxSize=nil) and (FMinSize=nil)
    and (FSizePriority=nil);
end;

{ TGridColumns }

function TGridColumns.GetColumn(Index: Integer): TGridColumn;
begin
  result := TGridColumn( inherited Items[Index] );
end;

function TGridColumns.GetEnabled: Boolean;
begin
  result := VisibleCount > 0;
end;

procedure TGridColumns.SetColumn(Index: Integer; Value: TGridColumn
  );
begin
  Items[Index].Assign( Value );
end;

function TGridColumns.GetVisibleCount: Integer;
var
  i: Integer;
begin
  result := 0;
  for i:=0 to Count-1 do
    if Items[i].Visible then
      inc(result);
end;

procedure TGridColumns.Update(Item: TCollectionItem);
begin
  //if (FGrid<>nil) and not (csLoading in FGrid.ComponentState) then
    FGrid.ColumnsChanged(TGridColumn(Item));
end;

procedure TGridColumns.TitleFontChanged;
var
  c: TGridColumn;
  i: Integer;
begin
  for i:=0 to Count-1 do begin
    c := Items[i];
    if (c<>nil)and(c.Title.IsDefaultFont) then begin
      c.Title.FillTitleDefaultFont;
    end;
  end;
end;

procedure TGridColumns.FontChanged;
var
  c: TGridColumn;
  i: Integer;
begin
  for i:=0 to Count-1 do begin
    c := Items[i];
    if (c<>nil)and(c.IsDefaultFont) then begin
      c.FillDefaultFont;
    end;
  end;
end;

procedure TGridColumns.RemoveColumn(Index: Integer);
begin
  if HasIndex(Index) then
    Delete(Index)
  else
    raise Exception.Create('Index out of range')
end;

procedure TGridColumns.MoveColumn(FromIndex, ToIndex: Integer);
begin
  if HasIndex(FromIndex) then
    if HasIndex(ToIndex) then
      Items[FromIndex].Index := ToIndex
    else
      raise Exception.Create('ToIndex out of range')
  else
    raise Exception.Create('FromIndex out of range')
end;

procedure TGridColumns.ExchangeColumn(Index, WithIndex: Integer);
begin
  if HasIndex(Index) then
    if HasIndex(WithIndex) then begin
      BeginUpdate;
      Items[WithIndex].Index := Index;
      Items[Index+1].Index := WithIndex;
      EndUpdate;
    end else
      raise Exception.Create('WithIndex out of range')
  else
    raise Exception.Create('Index out of range')
end;

procedure TGridColumns.InsertColumn(Index: Integer);
begin
  BeginUpdate;
  Add;
  MoveColumn(Count-1, Index);
  EndUpdate;
end;

constructor TGridColumns.Create(AGrid: TCustomGrid;
  aItemClass: TCollectionItemClass);
begin
  inherited Create( aItemClass );
  FGrid := AGrid;
end;

function TGridColumns.Add: TGridColumn;
begin
  result := TGridColumn( inherited add );
end;

function TGridColumns.RealIndex(Index: Integer): Integer;
var
  i: Integer;
begin
  result := -1;
  if Index>=0 then
    for i:=0 to Count-1 do begin
      if Items[i].Visible then begin
        Dec(index);
        if Index<0 then begin
          result := i;
          exit;
        end;
      end;
    end;
end;

function TGridColumns.IndexOf(Column: TGridColumn): Integer;
var
  i: Integer;
begin
  result := -1;
  for i:=0 to Count-1 do
    if Items[i]=Column then begin
      result := i;
      break;
    end;
end;

function TGridColumns.IsDefault: boolean;
var
  i: Integer;
begin
  result := True;
  for i:=0 to Count-1 do
    result := Result and Items[i].IsDefault;
end;

function TGridColumns.HasIndex(Index: Integer): boolean;
begin
  result := (index>-1)and(index<count);
end;

{ TButtonCellEditor }

procedure TButtonCellEditor.msg_SetGrid(var Msg: TGridMessage);
begin
  FGrid:=Msg.Grid;
  Msg.Options:=EO_HOOKKEYDOWN or EO_HOOKEXIT or EO_HOOKKEYPRESS or EO_HOOKKEYUP;
end;

procedure TButtonCellEditor.msg_SetPos(var Msg: TGridMessage);
begin
  FCol:=Msg.Col;
  FRow:=Msg.Row;
  with Msg.CellRect do begin
    if Right-Left>25 then Left:=Right-25;
    SetBounds(Left, Top, Right-Left, Bottom-Top);
  End;
end;

{ TPickListCellEditor }
procedure TPickListCellEditor.WndProc(var TheMessage: TLMessage);
begin
  {$IfDef GridTraceMsg}
  TransMsg('PicklistEditor: ', TheMessage);
  {$Endif}
  if TheMessage.msg=LM_KILLFOCUS then begin
    if HWND(TheMessage.WParam) = HWND(Handle) then begin
      // lost the focus but it returns to ourselves
      // eat the message.
      TheMessage.Result := 0;
      exit;
    end;
  end;
  inherited WndProc(TheMessage);
end;

procedure TPickListCellEditor.KeyDown(var Key: Word; Shift: TShiftState);
  function AllSelected: boolean;
  begin
    result := (SelLength>0) and (SelLength=Length(Text));
  end;
  function AtStart: Boolean;
  begin
    Result:= (SelStart=0);
  end;
  function AtEnd: Boolean;
  begin
    result := ((SelStart+1)>Length(Text)) or AllSelected;
  end;
  procedure doEditorKeyDown;
  begin
    if FGrid<>nil then
      FGrid.EditorkeyDown(Self, key, shift);
  end;
  procedure doGridKeyDown;
  begin
    if FGrid<>nil then
      FGrid.KeyDown(Key, shift);
  end;
  function GetFastEntry: boolean;
  begin
    if FGrid<>nil then
      Result := FGrid.FastEditing
    else
      Result := False;
  end;
  procedure CheckEditingKey;
  begin
    // if editor is not readonly, start editing
    // else not interested
    if (FGrid=nil) or FGrid.EditorIsReadOnly then
      Key := 0;
  end;
var
  IntSel: boolean;
begin
  {$IfDef dbgGrid}
  DebugLn('TPickListCellEditor.KeyDown INI: Key=',Dbgs(Key));
  {$Endif}
  inherited KeyDown(Key,Shift);
  case Key of

    VK_F2:
      if AllSelected then begin
        SelLength := 0;
        SelStart := Length(Text);
      end;

    VK_RETURN:
      if DroppedDown then begin
        CheckEditingKey;
        DroppedDown := False;
        if Key<>0 then begin
          doEditorKeyDown;
          Key:=0;
        end;
      end else
        doEditorKeyDown;

    VK_DELETE:
      CheckEditingKey;

    VK_UP, VK_DOWN:
      if not DroppedDown then
        doGridKeyDown;

    VK_LEFT, VK_RIGHT:
      if GetFastEntry then begin
        IntSel:=
          ((Key=VK_LEFT) and not AtStart) or
          ((Key=VK_RIGHT) and not AtEnd);
        if not IntSel then begin
            doGridKeyDown;
      end;
    end;

    VK_END, VK_HOME:
      ;
    else
      doEditorKeyDown;
  end;
  {$IfDef dbgGrid}
  DebugLn('TPickListCellEditor.KeyDown FIN: Key=',Dbgs(Key));
  {$Endif}
end;

procedure TPickListCellEditor.EditingDone;
begin
  {$ifdef dbgGrid}DebugLn('TPickListCellEditor.EditingDone INIT');{$ENDIF}
  inherited EditingDone;
  if FGrid<>nil then
    FGrid.EditingDone;
  {$ifdef dbgGrid}DebugLn('TPickListCellEditor.EditingDone DONE');{$ENDIF}
end;

procedure TPickListCellEditor.DropDown;
begin
  {$ifDef dbgGrid} DebugLn('TPickListCellEditor.DropDown INIT'); {$Endif}
  inherited DropDown;
  {$ifDef dbgGrid} DebugLn('TPickListCellEditor.DropDown DONE'); {$Endif}
end;

procedure TPickListCellEditor.CloseUp;
begin
  {$ifDef dbgGrid} DebugLn('TPickListCellEditor.CloseUp INIT'); {$Endif}
  inherited CloseUp;
  {$ifDef dbgGrid} DebugLn('TPickListCellEditor.CloseUp DONE'); {$Endif}
end;

procedure TPickListCellEditor.Select;
begin
  if FGrid<>nil then begin
    if FGrid.EditorIsReadOnly then
      exit;
    FGrid.SetEditText(FCol, FRow, Text);
    FGrid.PickListItemSelected(Self);
  end;
  inherited Select;
end;

procedure TPickListCellEditor.msg_GetValue(var Msg: TGridMessage);
begin
  Msg.Col := FCol;
  Msg.Row := FRow;
  Msg.Value:=Text;
end;

procedure TPickListCellEditor.msg_SetGrid(var Msg: TGridMessage);
begin
  FGrid:=Msg.Grid;
  Msg.Options:=EO_AUTOSIZE or EO_HOOKEXIT or EO_SELECTALL or EO_HOOKKEYPRESS
    or EO_HOOKKEYUP;
end;

procedure TPickListCellEditor.msg_SetValue(var Msg: TGridMessage);
begin
  FCol := Msg.Col;
  FRow := Msg.Row;
  Text := Msg.Value;
  SelStart := Length(Text);
end;

end.
