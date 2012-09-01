{
 *****************************************************************************
 *                                                                           *
 *  See the file COPYING.modifiedLGPL.txt, included in this distribution,    *
 *  for details about the copyright.                                         *
 *                                                                           *
 *  This program is distributed in the hope that it will be useful,          *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of           *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                     *
 *                                                                           *
 *****************************************************************************

Authors: Alexander Klenin

}

unit TADrawerCanvas;

{$H+}

interface

uses
  Classes, FPCanvas, FPImage, Graphics, SysUtils, TAChartUtils, TADrawUtils;

type
  IChartTCanvasDrawer = interface
  ['{6D8E5591-6788-4D2D-9FE6-596D5157C3C2}']
    function GetCanvas: TCanvas;
    property Canvas: TCanvas read GetCanvas;
  end;

  { TCanvasDrawer }

  TCanvasDrawer = class(
    TBasicDrawer, IChartDrawer, IChartTCanvasDrawer)
  strict private
    procedure SetBrush(ABrush: TFPCustomBrush);
    procedure SetFont(AFont: TFPCustomFont);
    procedure SetPen(APen: TFPCustomPen);
  strict protected
    FCanvas: TCanvas;
    FBuffer: TBitmap;
    function GetFontAngle: Double; override;
    function SimpleTextExtent(const AText: String): TPoint; override;
    procedure SimpleTextOut(AX, AY: Integer; const AText: String); override;
  public
    procedure AddToFontOrientation(ADelta: Integer);
    procedure ClippingStart;
    procedure ClippingStart(const AClipRect: TRect);
    procedure ClippingStop;
    constructor Create(ACanvas: TCanvas);
    destructor Destroy; override;
    procedure Ellipse(AX1, AY1, AX2, AY2: Integer);
    procedure FillRect(AX1, AY1, AX2, AY2: Integer);
    function GetBrushColor: TChartColor;
    function GetCanvas: TCanvas;
    procedure Line(AX1, AY1, AX2, AY2: Integer);
    procedure Line(const AP1, AP2: TPoint);
    procedure LineTo(AX, AY: Integer); override;
    procedure MoveTo(AX, AY: Integer); override;
    procedure Polygon(
      const APoints: array of TPoint; AStartIndex, ANumPts: Integer); override;
    procedure Polyline(
      const APoints: array of TPoint; AStartIndex, ANumPts: Integer);
    procedure PrepareSimplePen(AColor: TChartColor);
    procedure RadialPie(
      AX1, AY1, AX2, AY2: Integer;
      AStartAngle16Deg, AAngleLength16Deg: Integer);
    procedure Rectangle(const ARect: TRect);
    procedure Rectangle(AX1, AY1, AX2, AY2: Integer);
    procedure SetAntialiasingMode(AValue: TChartAntialiasingMode);
    procedure SetBrushColor(AColor: TChartColor);
    procedure SetBrushParams(AStyle: TFPBrushStyle; AColor: TChartColor);
    procedure SetPenParams(AStyle: TFPPenStyle; AColor: TChartColor);
    procedure SetTransparency(ATransparency: TChartTransparency);
  end;

  function CanvasGetFontOrientationFunc(AFont: TFPCustomFont): Integer;
  function ChartColorSysToFPColor(AChartColor: TChartColor): TFPColor;

implementation

uses
  GraphType, LCLIntf, LCLType,
  TAGeometry;

function CanvasGetFontOrientationFunc(AFont: TFPCustomFont): Integer;
begin
  if AFont is TFont then
    Result := (AFont as TFont).Orientation
  else
    Result := 0;
end;

function ChartColorSysToFPColor(AChartColor: TChartColor): TFPColor;
begin
  Result := ChartColorToFPColor(ColorToRGB(AChartColor));
end;

{ TCanvasDrawer }

procedure TCanvasDrawer.AddToFontOrientation(ADelta: Integer);
begin
  with GetCanvas.Font do
    Orientation := Orientation + ADelta;
end;

procedure TCanvasDrawer.ClippingStart(const AClipRect: TRect);
begin
  GetCanvas.ClipRect := AClipRect;
  GetCanvas.Clipping := true;
end;

procedure TCanvasDrawer.ClippingStart;
begin
  GetCanvas.Clipping := true;
end;

procedure TCanvasDrawer.ClippingStop;
begin
  GetCanvas.Clipping := false;
end;

constructor TCanvasDrawer.Create(ACanvas: TCanvas);
begin
  FCanvas := ACanvas;
  FBuffer := TBitmap.Create;
  FBuffer.PixelFormat := pf32bit;
end;

destructor TCanvasDrawer.Destroy;
begin
  FreeAndNil(FBuffer);
  inherited;
end;

procedure TCanvasDrawer.Ellipse(AX1, AY1, AX2, AY2: Integer);
begin
  GetCanvas.Ellipse(AX1, AY1, AX2, AY2);
end;

procedure TCanvasDrawer.FillRect(AX1, AY1, AX2, AY2: Integer);
begin
  GetCanvas.FillRect(AX1, AY1, AX2, AY2);
end;

function TCanvasDrawer.GetBrushColor: TChartColor;
begin
  Result := GetCanvas.Brush.Color;
end;

function TCanvasDrawer.GetCanvas: TCanvas;
begin
  // When transparency is off, draw directly on canvas for better speed.
  if FTransparency > 0 then
    Result := FBuffer.Canvas
  else
    Result := FCanvas;
end;

function TCanvasDrawer.GetFontAngle: Double;
begin
  Result := OrientToRad(GetCanvas.Font.Orientation);
end;

procedure TCanvasDrawer.Line(AX1, AY1, AX2, AY2: Integer);
begin
  GetCanvas.Line(AX1, AY1, AX2, AY2);
end;

procedure TCanvasDrawer.Line(const AP1, AP2: TPoint);
begin
  GetCanvas.Line(AP1, AP2);
end;

procedure TCanvasDrawer.LineTo(AX, AY: Integer);
begin
  GetCanvas.LineTo(AX, AY);
end;

procedure TCanvasDrawer.MoveTo(AX, AY: Integer);
begin
  GetCanvas.MoveTo(AX, AY);
end;

procedure TCanvasDrawer.Polygon(
  const APoints: array of TPoint; AStartIndex, ANumPts: Integer);
begin
  GetCanvas.Polygon(APoints, false, AStartIndex, ANumPts);
end;

procedure TCanvasDrawer.Polyline(
  const APoints: array of TPoint; AStartIndex, ANumPts: Integer);
begin
  if ANumPts <= 0 then exit;
  GetCanvas.Polyline(APoints, AStartIndex, ANumPts);
  // TCanvas.Polyline does not draw the end point.
  with APoints[AStartIndex + ANumPts - 1] do
    GetCanvas.Pixels[X, Y] := GetCanvas.Pen.Color;
end;

procedure TCanvasDrawer.PrepareSimplePen(AColor: TChartColor);
begin
  with GetCanvas.Pen do begin
    if FXor then
      Color := clWhite
    else
      Color := AColor;
    Style := psSolid;
    if FXor then
      Mode := pmXor
    else
      Mode := pmCopy;
    Width := 1;
  end;
end;

procedure TCanvasDrawer.RadialPie(
  AX1, AY1, AX2, AY2: Integer;
  AStartAngle16Deg, AAngleLength16Deg: Integer);
begin
  GetCanvas.RadialPie(
    AX1, AY1, AX2, AY2, AStartAngle16Deg, AAngleLength16Deg);
end;

procedure TCanvasDrawer.Rectangle(AX1, AY1, AX2, AY2: Integer);
begin
  GetCanvas.Rectangle(AX1, AY1, AX2, AY2);
end;

procedure TCanvasDrawer.Rectangle(const ARect: TRect);
begin
  GetCanvas.Rectangle(ARect);
end;

procedure TCanvasDrawer.SetAntialiasingMode(AValue: TChartAntialiasingMode);
begin
  GetCanvas.AntialiasingMode := TAntialiasingMode(AValue);
end;

procedure TCanvasDrawer.SetBrush(ABrush: TFPCustomBrush);
begin
  GetCanvas.Brush.Assign(ABrush);
  if FXor then
    GetCanvas.Brush.Style := bsClear;
end;

procedure TCanvasDrawer.SetBrushColor(AColor: TChartColor);
begin
  GetCanvas.Brush.Color := AColor;
end;

procedure TCanvasDrawer.SetBrushParams(
  AStyle: TFPBrushStyle; AColor: TChartColor);
begin
  GetCanvas.Brush.Color := AColor;
  GetCanvas.Brush.Style := AStyle;
end;

procedure TCanvasDrawer.SetFont(AFont: TFPCustomFont);
begin
  GetCanvas.Font.Assign(AFont);
end;

procedure TCanvasDrawer.SetPen(APen: TFPCustomPen);
begin
  if FXor then
    with GetCanvas do begin
      Brush.Style := bsClear;
      if APen = nil then
        Pen.Style := psSolid
      else
        Pen.Style := APen.Style;
      Pen.Mode := pmXor;
      Pen.Color := clWhite;
      if APen = nil then
        Pen.Width := 1
      else
        Pen.Width := APen.Width;
    end
  else
    GetCanvas.Pen.Assign(APen);
end;

procedure TCanvasDrawer.SetPenParams(AStyle: TFPPenStyle; AColor: TChartColor);
begin
  GetCanvas.Pen.Style := AStyle;
  if not FXor then
    GetCanvas.Pen.Color := AColor;
end;

procedure TCanvasDrawer.SetTransparency(ATransparency: TChartTransparency);

  function FillAlpha(AAlpha: Byte): Byte;
  var
    img: TRawImage;
    p, pEnd: PCardinal;
    x: Cardinal = 0;
    r: Cardinal = 0;
  begin
    FBuffer.BeginUpdate;
    img := FBuffer.RawImage;
    p := PCardinal(img.Data);
    TRGBAQuad(x).Alpha := AAlpha;
    pEnd := PCardinal(img.Data + img.DataSize);
    // This loop is time-critical, so: avoid conditionals inside,
    // use dword-sized instead of byte-sized access.
    while p < pEnd do begin
      // On the first pass, set all alpha values to AAlpha.
      // Drawing will reset alpha of changed pixels to zero.
      // On the second pass, flip unchanged pixels back to zero alpha,
      // and changed ones to the desired alpha level.
      p^ := p^ xor x;
      r := r or p^;
      Inc(p);
    end;
    FBuffer.EndUpdate;
    Result := TRGBAQuad(r).Alpha;
  end;

begin
  if FTransparency = ATransparency then exit;
  // For each transparency change, create a buffer bitmap, draw on that,
  // then alpha-blend the bitmap to the canvas.
  // This is slow, but currently seems the only way.
  if FTransparency > 0 then begin
    // StretchMaskBlt performs alpha blending only if the image contains
    // at least one non-zero alpha value, so fully transparent image
    // becomes black box. Workround: do not call StretchMaskBlt in this case.
    if FillAlpha(255 - FTransparency) > 0 then
      StretchMaskBlt(
        FCanvas.Handle, 0, 0, FCanvas.Width, FCanvas.Height,
        FBuffer.Canvas.Handle, 0, 0, FCanvas.Width, FCanvas.Height,
        0, 0, 0, SRCCOPY);
  end;
  inherited;
  if FTransparency > 0 then begin
    FBuffer.SetSize(0, 0);
    FBuffer.SetSize(FCanvas.Width, FCanvas.Height);
    FillAlpha(255 - FTransparency);
  end;
end;

function TCanvasDrawer.SimpleTextExtent(const AText: String): TPoint;
begin
  Result := GetCanvas.TextExtent(AText);
end;

procedure TCanvasDrawer.SimpleTextOut(AX, AY: Integer; const AText: String);

  procedure DrawXorText;
  var
    bmp: TBitmap;
    p, ext, bmpSize: TPoint;
    a: Double;
  begin
    ext := GetCanvas.TextExtent(AText);
    a := OrientToRad(GetCanvas.Font.Orientation);
    bmpSize := MeasureRotatedRect(ext, a);
    p := bmpSize div 2 - RotatePoint(ext div 2, -a);

    bmp := TBitmap.Create;
    try
      bmp.SetSize(bmpSize.X, bmpSize.Y);
      bmp.Canvas.Brush.Style := bsClear;
      bmp.Canvas.Font := GetCanvas.Font;
      bmp.Canvas.Font.Color := clWhite;
      bmp.Canvas.TextOut(p.X, p.Y, AText);
      bmp.Canvas.Pen.Color := clWhite;
      BitBlt(
        GetCanvas.Handle, AX - p.X, AY - p.Y, bmpSize.X, bmpSize.Y,
        bmp.Canvas.Handle, 0, 0, SRCINVERT);
    finally
      bmp.Free;
    end;
  end;

begin
  if FXor then
    DrawXorText
  else
    GetCanvas.TextOut(AX, AY, AText);
end;

initialization
  // Suppress incorrect "TAGeometry is unused" hint
  Unused(DoublePoint(0, 0));

end.

