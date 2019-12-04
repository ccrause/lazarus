unit FpDbgRsp;

interface

uses
  Classes, SysUtils, ssockets, DbgIntfDebuggerBase;

type

  { TRspConnection }

  TRspConnection = class(TInetSocket)
  private
    FState: integer;
    fRegisterCache: TBytes;
    procedure FSetRegisterCacheSize(sz: cardinal);
    function FWaitForData: boolean;
    function FSendCommand(const cmd: string): boolean;
    function FReadReply(out retval: string): boolean;

    procedure FProcessTPacket(const packet: string);
  public
    constructor Create(const AHost: String; APort: Word; AHandler : TSocketHandler = Nil); Overload;
    destructor Destroy;
    function SendCmdWaitForReply(const cmd: string; out reply: string): boolean;
    // Wait for async signal
    function WaitForSignal(out msg: string): integer;

    function SendBreak(): boolean;
    function SendKill(): boolean;
    function MustReplyEmpty: boolean;
    function SetBreakWatchPoint(addr: PtrUInt; BreakWatchKind: TDBGWatchPointKind; watchsize: integer = 1): boolean;
    function DeleteBreakWatchPoint(addr: PtrUInt; BreakWatchKind: TDBGWatchPointKind; watchsize: integer = 1): boolean;
    // TODO: no support thread ID or different address
    function Continue(): boolean;
    function SingleStep(): boolean;
    function ReadRegisters(out regs; const sz: integer): boolean;

    // check state of target - ?
    function Init: integer;

    property State: integer read FState;
    property RegisterCacheSize: cardinal write FSetRegisterCacheSize;
    property RegisterCache: TBytes read fRegisterCache;
  end;


implementation

uses
  LazLoggerBase, StrUtils,
  {$IFNDEF WINDOWS}BaseUnix, sockets;
  {$ELSE}winsock2, windows;
  {$ENDIF}

var
  DBG_VERBOSE, DBG_WARNINGS: PLazLoggerLogGroup;

procedure TRspConnection.FSetRegisterCacheSize(sz: cardinal);
begin
  SetLength(fRegisterCache, sz);
end;

function TRspConnection.FWaitForData: boolean;
{$if defined(unix) or defined(windows)}
var
  FDS: TFDSet;
  TimeV: TTimeVal;
{$endif}
begin
  Result:=False;
{$if defined(unix) or defined(windows)}
  TimeV.tv_usec := 1 * 1000;  // 1 msec
  TimeV.tv_sec := 0;
{$endif}
{$ifdef unix}
  FDS := Default(TFDSet);
  fpFD_Zero(FDS);
  fpFD_Set(self.Handle, FDS);
  Result := fpSelect(self.Handle + 1, @FDS, nil, nil, @TimeV) > 0;
{$else}
{$ifdef windows}
  FDS := Default(TFDSet);
  FD_Zero(FDS);
  FD_Set(self.Handle, FDS);
  Result := Select(self.Handle + 1, @FDS, nil, nil, @TimeV) > 0;
{$endif}
{$endif}
end;

function TRspConnection.FSendCommand(const cmd: string): boolean;
var
  checksum: byte;
  i, totalSent, ret: integer;
  s: string;
begin
  checksum := 0;
  for i := 1 to length(cmd) do
    checksum := byte(checksum + ord(cmd[i]));

  // Start marker
  WriteByte(ord('$'));
  totalSent := 0;
  repeat
    ret := Write(cmd[1+totalSent], length(cmd));
    totalSent := totalSent + ret;
  until (totalSent = length(cmd)) or (ret < 0);
  WriteByte(ord('#'));
  s := IntToHex(checksum, 2);
  Write(s[1], length(s));

  result := (totalSent = length(cmd)) and (ret >= 0);
  if not result then
    DebugLn(DBG_WARNINGS, ['Warning: TRspConnection.FSendRspCommand error: ' + IntToStr(ret)])
end;

function TRspConnection.FReadReply(out retval: string): boolean;
var
  c: char;
  s: string;
  i, len, prevMsgEnd: integer;
  cksum, calcSum: byte;
begin
  i := 0;
  repeat
    c := chr(ReadByte);
    inc(i);
  until (c = '$') or (i = 100);  // exit loop after start or count expired

  if i > 1 then
    DebugLn(DBG_WARNINGS, ['Warning: Discarding unexpected data before start of new message']);

  c := chr(ReadByte);
  s := '';
  calcSum := 0;
  while c <> '#' do
  begin
    calcSum := byte(calcSum+byte(c));

    if c=#$7D then // escape marker, unescape data
    begin
      c := char(ReadByte);

      // Something weird happened
      if c = '#' then
        break;

      calcSum := byte(calcSum + byte(c));

      c := char(byte(c) xor $20);
    end;

    s := s + c;
    c := char(ReadByte);
  end;

  cksum := StrToInt('$' + char(ReadByte) + char(ReadByte));

  if calcSum = cksum then
  begin
    WriteByte(byte('+'));
    result := true;
    retval := s;
  end
  else
  begin
    retval := '';
    result := false;
    DebugLn(DBG_WARNINGS, ['Warning: Discarding reply packet because of invalid checksum']);
  end;
end;

procedure TRspConnection.FProcessTPacket(const packet: string);
var
  i, j, len, SigNum, regnum, regvalue: integer;
  s: string;
begin
  // Format of T packet: T05n1:r1;...
  len := length(packet);
  // grab signal number
  if len >= 3 then
  begin
    SigNum := StrToInt('$'+packet[2]+packet[3]);
    i := 4;
  end;

  {$ifdef DoFurtherProcessing}  // just get basic logic working, can precache data later
  while i < len do
  begin
    j := PosEx(':', packet, i);
    if j > i then
    begin
      s := copy(packet, i, j-1);
      regnum := StrToInt('$' + s);
      i := j+1;
    end
    else
      break;

    j := PosEx(';', packet, i);
    // in case last value is not correctly terminated
    if j = 0 then
      j := length(packet);

  end;
  {$endif}
end;

function TRspConnection.SendCmdWaitForReply(const cmd: string; out reply: string
  ): boolean;
var
  c: char;
  retryCount: integer;
begin
  result := false;
  reply := '';
  retryCount := 0;

  repeat
    if FSendCommand(cmd) then
    begin
      // now check if target returned error, resend ('-') or ACK ('+')
      // No support for ‘QStartNoAckMode’, i.e. always expect a -/+
      c := char(ReadByte);
      if c = '-' then
        inc(retryCount)
      else if c = '+' then      // cmd ACK by target
      begin
        if FReadReply(reply) then
          result := true
        else
        begin
          retryCount := 0;
          repeat
            WriteByte(ord('-'));
            inc(retryCount);
          until result or (retryCount > 5);
        end;
      end;
    end
    else // error sending command
      inc(retryCount);

  // Abort this command if no ACK after 5 attempts
  until result or (retryCount > 5);

  if retryCount > 5 then
    DebugLn(DBG_WARNINGS, ['Warning: Retries exceeded for cmd: ', cmd]);
end;

function TRspConnection.SendBreak(): boolean;
var
  c: char;
  retryCount: integer;
  reply: string;
begin
  result := false;
  reply := '';
  retryCount := 0;

  repeat
    WriteByte(3);  // Ctrl-C
    // now check if target returned error, resend ('-') or ACK ('+')
    // No support for ‘QStartNoAckMode’, i.e. always expect a -/+
    c := char(ReadByte);
    if c = '-' then
      inc(retryCount)
    else if c = '+' then
    begin
      if FReadReply(reply) then
        result := true
      else
      begin
        retryCount := 0;
        repeat
          WriteByte(ord('-'));
          inc(retryCount);
        until result or (retryCount > 5);
      end;
    end;

  // Abort this command if no ACK after 5 attempts
  until result or (retryCount > 5);

  if retryCount > 5 then
    DebugLn(DBG_WARNINGS, ['Warning: Retries exceeded for rspSendBreak']);
end;

function TRspConnection.SendKill(): boolean;
begin
  result := FSendCommand('k');
end;

constructor TRspConnection.Create(const AHost: String; APort: Word;
  AHandler: TSocketHandler);
begin
  inherited Create(AHost, APort);
  self.IOTimeout := 1000;  // socket read timeout = 1000 ms
end;

destructor TRspConnection.Destroy;
begin
end;

function TRspConnection.WaitForSignal(out msg: string): integer;
var
  res: boolean;
begin
  result := 0;
  res := false;
  try
    res := FReadReply(msg);
  except
    on E: Exception do
      DebugLn(DBG_WARNINGS, ['Warning: WaitForSignal exception: ', E.Message]);
  end;

  if res then
  begin
    if (msg[1] in ['S', 'T']) and (length(msg) > 2) then
    begin
      result := StrToInt('$' + copy(msg, 2, 2));
      FState := result;
    end;
  end;
end;

function TRspConnection.MustReplyEmpty: boolean;
var
  reply: string;
begin
  SendCmdWaitForReply('vMustReplyEmpty', reply);
  if reply <> '' then
    DebugLn(DBG_WARNINGS, ['Warning: vMustReplyEmpty command returned unexpected result: ', reply]);
end;

function TRspConnection.SetBreakWatchPoint(addr: PtrUInt;
  BreakWatchKind: TDBGWatchPointKind; watchsize: integer): boolean;
var
  cmd, reply: string;
begin
  cmd := 'Z';
  case BreakWatchKind of
    wpkWrite: cmd := cmd + '2,' + IntToHex(addr, 4) + ',' + IntToHex(watchsize, 4);
    wpkRead:  cmd := cmd + '3,' + IntToHex(addr, 4) + ',' + IntToHex(watchsize, 4);
    wpkReadWrite: cmd := cmd + '4,' + IntToHex(addr, 4) + ',' + IntToHex(watchsize, 4);
    // NOTE: Not sure whether hardware break is better than software break, depends on gdbserver implementation...
    wkpExec: cmd := cmd + '1,' + IntToHex(addr, 4) + ',00';
  end;

  result := SendCmdWaitForReply(cmd, reply);
  if result then
    result := pos('OK', reply) > 0;
end;

function TRspConnection.DeleteBreakWatchPoint(addr: PtrUInt;
  BreakWatchKind: TDBGWatchPointKind; watchsize: integer): boolean;
var
  cmd, reply: string;
begin
  cmd := 'z';
  case BreakWatchKind of
    wpkWrite: cmd := cmd + '2,' + IntToHex(addr, 4) + ',' + IntToHex(watchsize, 4);
    wpkRead:  cmd := cmd + '3,' + IntToHex(addr, 4) + ',' + IntToHex(watchsize, 4);
    wpkReadWrite: cmd := cmd + '4,' + IntToHex(addr, 4) + ',' + IntToHex(watchsize, 4);
    // NOTE: Not sure whether hardware break is better than software break, depends on gdbserver implementation...
    wkpExec: cmd := cmd + '1,' + IntToHex(addr, 4) + ',00';
  end;

  result := SendCmdWaitForReply(cmd, reply);
  if result then
    result := pos('OK', reply) > 0;
end;

function TRspConnection.Continue(): boolean;
begin
  result := FSendCommand('c');
  if not result then
    DebugLn(DBG_WARNINGS, ['Warning: Continue command failure in TRspConnection.Continue()']);
end;

function TRspConnection.SingleStep(): boolean;
begin
  result := FSendCommand('s');
  if not result then
    DebugLn(DBG_WARNINGS, ['Warning: SingleStep command failure in TRspConnection.SingleStep()']);
end;

function TRspConnection.ReadRegisters(out regs; const sz: integer): boolean;
var
  reply: string;
  b: array of byte;
  i: integer;
begin
  result := false;
  reply := '';
  setlength(b, sz);
  FillByte(b[0], sz, 0);
  // Normal receive error, or an error number of the form Exx
  if not SendCmdWaitForReply('g', reply) or ((length(reply) < 4) and (reply[1] = 'E'))
    or (length(reply) <> 2*sz) then
    DebugLn(DBG_WARNINGS, ['Warning: "g" command returned unexpected result: ', reply])
  else
  begin
    for i := 0 to sz-1 do
      b[i] := StrToInt('$'+reply[2*i+1]+reply[2*i+2]);
    result := true;
  end;
  Move(b[0], regs, sz);
end;

function TRspConnection.Init: integer;
var
  reply: string;
begin
  result := 0;
  reply := '';
  if not SendCmdWaitForReply('vMustReplyEmpty', reply) or (reply <> '') then
  begin
    DebugLn(DBG_WARNINGS, ['Warning: vMustReplyEmpty command returned unexpected result: ', reply]);
    exit;
  end;

  if FSendCommand('?') then
  begin
    result := WaitForSignal(reply);
  end
  else
    exit;

  // TODO: Check if reply includes register values
  // Perhaps defer to calling side?
  if reply[1] = 'T' then
  begin

  end;
end;

initialization
  DBG_VERBOSE := DebugLogger.FindOrRegisterLogGroup('DBG_VERBOSE' {$IFDEF DBG_VERBOSE} , True {$ENDIF} );
  DBG_WARNINGS := DebugLogger.FindOrRegisterLogGroup('DBG_WARNINGS' {$IFDEF DBG_WARNINGS} , True {$ENDIF} );
end.

