unit FpDbgRsp;

interface

uses
  Classes, SysUtils, ssockets, DbgIntfDebuggerBase, DbgIntfBaseTypes;

type

  { TRspConnection }

  TRspConnection = class(TInetSocket)
  private
    FState: integer;
    //fRegisterCache: TBytes;
    //procedure FSetRegisterCacheSize(sz: cardinal);
    // Blocking
    function FWaitForData(timeout: integer): boolean;
    function FSendCommand(const cmd: string): boolean;
    function FReadReply(out retval: string): boolean;
    procedure FProcessTPacket(const packet: string);
    function FSendCmdWaitForReply(const cmd: string; out reply: string): boolean;
  public
    constructor Create(const AHost: String; APort: Word; AHandler : TSocketHandler = Nil); Overload;
    destructor Destroy;
    // Wait for async signal - blocking
    function WaitForSignal(out msg: string): integer;

    procedure Break();
    function Kill(): boolean;
    function Detach(): boolean;
    function MustReplyEmpty: boolean;
    function SetBreakWatchPoint(addr: PtrUInt; BreakWatchKind: TDBGWatchPointKind; watchsize: integer = 1): boolean;
    function DeleteBreakWatchPoint(addr: PtrUInt; BreakWatchKind: TDBGWatchPointKind; watchsize: integer = 1): boolean;
    // TODO: no support thread ID or different address
    function Continue(): boolean;
    function SingleStep(): boolean;

    // Data exchange
    function ReadDebugReg(ind: byte; out AVal: PtrUInt): boolean;
    function WriteDebugReg(ind: byte; AVal: PtrUInt): boolean;
    function ReadRegisters(out regs; const sz: integer): boolean;  // size is not required by protocol, but is used to preallocate memory for the response
    function WriteRegisters(constref regs; const sz: integer): boolean;
    function ReadData(const AAddress: TDbgPtr; const ASize: cardinal; out AData
      ): boolean;
    function WriteData(const AAdress: TDbgPtr;
      const ASize: Cardinal; const AData): Boolean;

    // check state of target - ?
    function Init: integer;

    property State: integer read FState;
    //property RegisterCacheSize: cardinal write FSetRegisterCacheSize;
    //property RegisterCache: TBytes read fRegisterCache;
  end;


implementation

uses
  LazLoggerBase, StrUtils,
  {$IFNDEF WINDOWS}BaseUnix, sockets;
  {$ELSE}winsock2, windows;
  {$ENDIF}

var
  DBG_VERBOSE, DBG_WARNINGS: PLazLoggerLogGroup;

//procedure TRspConnection.FSetRegisterCacheSize(sz: cardinal);
//begin
//  SetLength(fRegisterCache, sz);
//end;

function TRspConnection.FWaitForData(timeout: integer): boolean;
{$if defined(unix) or defined(windows)}
var
  FDS: TFDSet;
  TimeV: TTimeVal;
{$endif}
begin
  Result:=False;
{$if defined(unix) or defined(windows)}
  TimeV.tv_usec := timeout * 1000;  // 1 msec
  TimeV.tv_sec := 0;
{$endif}
{$ifdef unix}
  FDS := Default(TFDSet);
  fpFD_Zero(FDS);
  fpFD_Set(self.Handle, FDS);
  Result := fpSelect(self.Handle + 1, @FDS, nil, nil, nil{@TimeV}) > 0;
{$else}
{$ifdef windows}
  FDS := Default(TFDSet);
  FD_Zero(FDS);
  FD_Set(self.Handle, FDS);
  Result := Select(self.Handle + 1, @FDS, nil, nil, nil{@TimeV}) > 0;
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
  s := '';
  repeat
    c := chr(ReadByte);
    inc(i);
    s := s + c;
  until (c = '$') or (i = 1000);  // exit loop after start or count expired

  if i > 1 then
    DebugLn(DBG_WARNINGS, ['Warning: Discarding unexpected data before start of new message', s]);

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
      begin
        DebugLn(DBG_WARNINGS, ['Warning: Received end of packet marker in escaped sequence: ', c]);
        break;
      end;

      calcSum := byte(calcSum + byte(c));

      c := char(byte(c) xor $20);
    end;

    s := s + c;
    c := char(ReadByte);
  end;

  cksum := StrToInt('$' + char(ReadByte) + char(ReadByte));

  // Ignore checksum for now
  WriteByte(byte('+'));
  result := true;
  retval := s;
  if not (calcSum = cksum) then
  begin
    //retval := '';
    //result := false;
    //DebugLn(DBG_WARNINGS, ['Warning: Discarding reply packet because of invalid checksum: ', s]);
    DebugLn(DBG_WARNINGS, ['Warning: Reply packet with invalid checksum: ', s]);
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
  if (len >= 3) and (packet[1] = '$') then
  begin
    SigNum := StrToInt('$'+packet[2]+packet[3]);
    i := 4;
  end
  else
    DebugLn(DBG_WARNINGS, ['Warning: Invalid break packet in TRspConnection.FProcessTPacket: ', packet]);


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

function TRspConnection.FSendCmdWaitForReply(const cmd: string; out reply: string
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
    DebugLn(DBG_WARNINGS, ['Warning: Retries exceeded in TRspConnection.FSendCmdWaitForReply for cmd: ', cmd]);
end;

procedure TRspConnection.Break();
begin
  WriteByte(3);  // Ctrl-C
end;

function TRspConnection.Kill(): boolean;
begin
  result := FSendCommand('k');
end;

function TRspConnection.Detach(): boolean;
var
  reply: string;
begin
  result := FSendCmdWaitForReply('D', reply);
  result := pos('OK', reply) = 1;
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

  FWaitForData(10);

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
      try
        result := StrToInt('$' + copy(msg, 2, 2));
        FState := result;
      except
        DebugLn(DBG_WARNINGS, ['Error converting signal number from reply: ', msg]);
      end;
    end
    else
      DebugLn(DBG_WARNINGS, ['Unexpected WaitForSignal reply: ', msg]);
  end;
end;

function TRspConnection.MustReplyEmpty: boolean;
var
  reply: string;
begin
  FSendCmdWaitForReply('vMustReplyEmpty', reply);
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

  result := FSendCmdWaitForReply(cmd, reply);
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

  result := FSendCmdWaitForReply(cmd, reply);
  if result then
    result := pos('OK', reply) > 0;
end;

function TRspConnection.Continue(): boolean;
begin
  DebugLn(DBG_VERBOSE, ['TRspConnection.Continue() called']);
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

function TRspConnection.ReadDebugReg(ind: byte; out AVal: PtrUInt): boolean;
var
  cmd, reply: string;
  err: integer;
begin
  cmd := 'p'+IntToHex(ind, 2);
  result := FSendCmdWaitForReply(cmd, reply);
  if result then
  begin
    Val('$'+reply, AVal, err);
    result := err = 0;
  end;

  if not result then
    DebugLn(DBG_WARNINGS, ['Warning: "p" command returned unexpected result: ', reply]);
end;

function TRspConnection.WriteDebugReg(ind: byte; AVal: PtrUInt): boolean;
var
  cmd, reply: string;
begin
  cmd := 'P'+IntToHex(ind, 2);
  result := FSendCmdWaitForReply(cmd, reply) and (reply = 'OK');

  if not result then
    DebugLn(DBG_WARNINGS, ['Warning: "P" command returned unexpected result: ', reply]);
end;

function TRspConnection.ReadRegisters(out regs; const sz: integer): boolean;
var
  reply: string;
  b: array of byte;
  i: integer;
begin
  reply := '';
  setlength(b, sz);
  // Normal receive error, or an error response of the form Exx
  result := FSendCmdWaitForReply('g', reply) or ((length(reply) < 4) and (reply[1] = 'E'))
    or (length(reply) <> 2*sz);
  if Result then
  begin
    for i := 0 to sz-1 do
      b[i] := StrToInt('$'+reply[2*i+1]+reply[2*i+2]);
    result := true;
  end
  else
  begin
    DebugLn(DBG_WARNINGS, ['Warning: "g" command returned unexpected result: ', reply]);
    FillByte(b[0], sz, 0);
  end;
  Move(b[0], regs, sz);
end;

function TRspConnection.WriteRegisters(constref regs; const sz: integer
  ): boolean;
var
  cmd, reply, s: string;
  i, offset: integer;
  pb: PByte;
begin
  pb := @regs;
  result := false;
  reply := '';
  cmd := format('G', []);
  offset := length(cmd);
  setlength(cmd, offset+sz*2);
  for i := 0 to sz-1 do
  begin
    s := IntToHex(pb^, 2);
    cmd[offset + 2*i + 1] := s[1];
    cmd[offset + 2*i + 2] := s[2];
  end;

  // Normal receive error, or an error number of the form Exx
  result := FSendCmdWaitForReply(cmd, reply) and (reply = 'OK');
  if not result then
    DebugLn(DBG_WARNINGS, ['Warning: "G" command returned unexpected result: ', reply]);
end;

function TRspConnection.ReadData(const AAddress: TDbgPtr;
  const ASize: cardinal; out AData): boolean;
var
  buf: pbyte;
  cmd, reply: string;
  i: integer;
begin
  result := false;
  getmem(buf, ASize);
  cmd := 'm'+IntToHex(AAddress, 2)+',' + IntToHex(ASize, 2);
  result := FSendCmdWaitForReply(cmd, reply) and (length(reply) = ASize*2);
  if result then
  begin
    for i := 0 to ASize-1 do
      buf[i] := StrToInt('$'+reply[2*i + 1]+reply[2*i + 2])
  end
  else
  begin
    DebugLn(DBG_WARNINGS, ['Warning: "m" command returned unexpected result: ', reply]);
    FillByte(buf[0], ASize, 0);
  end;

  System.Move(buf^, AData, ASize);
  Freemem(buf);
end;

function TRspConnection.WriteData(const AAdress: TDbgPtr;
  const ASize: Cardinal; const AData): Boolean;
var
  cmd, reply, s: string;
  i, offset: integer;
  pb: PByte;
begin
  result := false;
  cmd := format('M%X,%X:', [AAdress, ASize]);
  offset := length(cmd);
  setlength(cmd, offset + 2*ASize);
  pb := @AData;
  for i := 0 to ASize-1 do
  begin
    s := IntToHex(pb^, 2);
    cmd[offset + 2*i+1] := s[1];
    cmd[offset + 2*i+2] := s[2];
    inc(pb);
  end;

  result := FSendCmdWaitForReply(cmd, reply) and (reply = 'OK');
  if not result then
    DebugLn(DBG_WARNINGS, ['Warning: "M" command returned unexpected result: ', reply]);
end;

function TRspConnection.Init: integer;
var
  reply: string;
begin
  result := 0;
  reply := '';
  if not FSendCmdWaitForReply('vMustReplyEmpty', reply) or (reply <> '') then
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

