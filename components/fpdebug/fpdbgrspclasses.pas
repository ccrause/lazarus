unit FpDbgRspClasses;

// Connects to gdbserver instance and communicate over gdb's remote serial protocol (RSP)
// in principle possible to connect over any serial text capabile interface such as
// tcp/ip, RS-232, pipes etc.
// Support only tcp/ip connection for now.

{$mode objfpc}{$H+}
{$packrecords c}
{$modeswitch advancedrecords}
{off $define DebuglnLinuxDebugEvents}

interface

uses
  Classes,
  SysUtils,
  fgl,
  FpDbgClasses,
  FpDbgLoader,
  DbgIntfBaseTypes, DbgIntfDebuggerBase,
  FpDbgLinuxExtra,
  FpDbgInfo,
  FpDbgUtil,
  LazLoggerBase, Maps,
  FpDbgRsp;

const
  // Possible signal numbers that can be expected over rsp
  // for now only cater for posix like signals
  SIGHUP     = 1;
  SIGINT     = 2;
  SIGQUIT    = 3;
  SIGILL     = 4;
  SIGTRAP    = 5;
  SIGABRT    = 6;
  SIGIOT     = 6;
  SIGBUS     = 7;
  SIGFPE     = 8;
  SIGKILL    = 9;
  SIGUSR1    = 10;
  SIGSEGV    = 11;
  SIGUSR2    = 12;
  SIGPIPE    = 13;
  SIGALRM    = 14;
  SIGTERM    = 15;
  SIGSTKFLT  = 16;
  SIGCHLD    = 17;
  SIGCONT    = 18;
  SIGSTOP    = 19;
  SIGTSTP    = 20;
  SIGTTIN    = 21;
  SIGTTOU    = 22;
  SIGURG     = 23;
  SIGXCPU    = 24;
  SIGXFSZ    = 25;
  SIGVTALRM  = 26;
  SIGPROF    = 27;
  SIGWINCH   = 28;
  SIGIO      = 29;
  SIGPOLL    = SIGIO;
  SIGPWR     = 30;
  SIGUNUSED  = 31;

  // RSP commands
  Rsp_Status = '?';     // Request break reason - returns either S or T
  SREGindex = 32;
  SPLindex = 33;
  SPHindex = 34;
  PC0 = 35;
  PC1 = 36;
  PC2 = 37;
  PC3 = 38;

type
  TRegisters = packed record
    updated: boolean;
    case byte of
    0: (regs: array[0..38] of byte);
    1: (cpuRegs: array[0..31] of byte;
        SREG: byte;
        SPL, SPH: byte;
        PC: dword);
  end;

  { TDbgRspThread }

  TDbgRspThread = class(TDbgThread)
  private
    FRegs: TRegisters;
    FRegsChanged: boolean;
    FExceptionSignal: integer;
    FIsPaused, FInternalPauseRequested, FIsInInternalPause: boolean;
    FIsSteppingBreakPoint: boolean;
    FDidResetInstructionPointer: Boolean;
    FHasThreadState: boolean;
    function GetDebugRegOffset(ind: byte): pointer;
    function ReadDebugReg(ind: byte; out AVal: PtrUInt): boolean;
    function WriteDebugReg(ind: byte; AVal: PtrUInt): boolean;
  protected
    function ReadThreadState: boolean;

    function RequestInternalPause: Boolean;
    function CheckSignalForPostponing(AWaitedStatus: integer): Boolean;
    procedure ResetPauseStates;
  public
    function ResetInstructionPointerAfterBreakpoint: boolean; override;
    procedure ApplyWatchPoints(AWatchPointData: TFpWatchPointData); override;
    function DetectHardwareWatchpoint: Pointer; override;
    procedure BeforeContinue; override;
    procedure LoadRegisterValues; override;

    function GetInstructionPointerRegisterValue: TDbgPtr; override;
    function GetStackBasePointerRegisterValue: TDbgPtr; override;
    function GetStackPointerRegisterValue: TDbgPtr; override;
  end;

  { TDbgRspProcess }

  TDbgRspProcess = class(TDbgProcess)
  private
    FStatus: integer;
    FProcessStarted: boolean;
    FIsTerminating: boolean;
    FCurrentThreadId: THandle;

    // RSP protocol stuff
    FConnection: TRspConnection;

    procedure OnForkEvent(Sender : TObject);
  protected
    procedure InitializeLoaders; override;
    function CreateThread(AthreadIdentifier: THandle; out IsMainThread: boolean): TDbgThread; override;
    function AnalyseDebugEvent(AThread: TDbgThread): TFPDEvent; override;
    function CreateWatchPointData: TFpWatchPointData; override;
  public
    // Create tcp connection to target - tcp/ip address and port number in AParams
    // Optional download to target as parameter DownloadExecutable=true
    class function StartInstance(AFileName: string; AParams, AnEnvironment: TStrings;
      AWorkingDirectory, AConsoleTty: string; AFlags: TStartInstanceFlags): TDbgProcess; override;

    // Not supported, what do this mean for a remote connection?
    class function AttachToInstance(AFileName: string; APid: Integer
      ): TDbgProcess; override;
    constructor Create(const AName: string; const AProcessID, AThreadID: Integer); override;
    destructor Destroy; override;

    // FOR AVR target AAddress could be program or data (SRAM) memory (or EEPROM?)
    // Gnu tools masks data memory with $800000
    function ReadData(const AAdress: TDbgPtr; const ASize: Cardinal; out AData): Boolean; override;
    function WriteData(const AAdress: TDbgPtr; const ASize: Cardinal; const AData): Boolean; override;

    procedure TerminateProcess; override;
    function Pause: boolean; override;
    function Detach(AProcess: TDbgProcess; AThread: TDbgThread): boolean; override;

    function Continue(AProcess: TDbgProcess; AThread: TDbgThread; SingleStep: boolean): boolean; override;
    // Wait for -S or -T response from target, or if connection to target is lost
    function WaitForDebugEvent(out ProcessIdentifier, ThreadIdentifier: THandle): boolean; override;

    // Insert/Delete break points on target
    // TODO: if target doesn't support break points or have limited break points
    // then debugger needs to manage insertion/deletion of break points in target memory
    function InsertBreakInstructionCode(const ALocation: TDBGPtr; out OrigValue: Byte): Boolean; override;
    function RemoveBreakInstructionCode(const ALocation: TDBGPtr; const OrigValue: Byte): Boolean; override;
  end;

  // Lets stick with points 4 for now

  { TFpRspWatchPointData }

  TRspBreakWatchPoint = record
    Owner: Pointer;
    Address: TDBGPtr;
    Kind: TDBGWatchPointKind;
  end;

  TFpRspWatchPointData = class(TFpWatchPointData)
  private
    FData: array of TRspBreakWatchPoint;
    function FBreakWatchPoint(AnIndex: Integer): TRspBreakWatchPoint;
    function FCount: integer;
  public
    function AddOwnedWatchpoint(AnOwner: Pointer; AnAddr: TDBGPtr; ASize: Cardinal; AReadWrite: TDBGWatchPointKind): boolean; override;
    function RemoveOwnedWatchpoint(AnOwner: Pointer): boolean; override;
    property Data[AnIndex: Integer]: TRspBreakWatchPoint read FBreakWatchPoint;
    property Count: integer read FCount;
  end;

procedure RegisterDbgClasses;

implementation

var
  DBG_VERBOSE, DBG_WARNINGS: PLazLoggerLogGroup;

procedure RegisterDbgClasses;
begin
  OSDbgClasses.DbgProcessClass:=TDbgRspProcess;
  OSDbgClasses.DbgThreadClass:=TDbgRspThread;
end;

{ TFpRspWatchPointData }

function TFpRspWatchPointData.FBreakWatchPoint(AnIndex: Integer
  ): TRspBreakWatchPoint;
begin
  if AnIndex < length(FData) then
    result := FData[AnIndex];
end;

function TFpRspWatchPointData.FCount: integer;
begin
  result := length(FData);
end;

function TFpRspWatchPointData.AddOwnedWatchpoint(AnOwner: Pointer;
  AnAddr: TDBGPtr; ASize: Cardinal; AReadWrite: TDBGWatchPointKind): boolean;
var
  idx: integer;
begin
  Result := false;
  idx := length(FData);
  SetLength(FData, idx+1);
  FData[idx].Address := AnAddr;
  FData[idx].Kind := AReadWrite;
  FData[idx].Owner := AnOwner;
  Changed := true;
  Result := true;
end;

function TFpRspWatchPointData.RemoveOwnedWatchpoint(AnOwner: Pointer): boolean;
var
  i, j: integer;
begin
  Result := False;
  i := 0;
  while (i < length(FData)) and (FData[i].Owner <> AnOwner) do
    inc(i);

  if i < length(FData) then begin
    for j := i+1 to length(FData)-1 do begin
      FData[j-1] := FData[j];
      Changed := True;
      Result := True;
    end;

    SetLength(FData, length(FData)-1);
    Changed := True;
    Result := True;
  end;
end;

{ TDbgRspThread }

procedure TDbgRspProcess.OnForkEvent(Sender: TObject);
begin
end;

function TDbgRspThread.GetDebugRegOffset(ind: byte): pointer;
begin
  result := nil;
end;

function TDbgRspThread.ReadDebugReg(ind: byte; out AVal: PtrUInt): boolean;
var
  req, ret: string;
begin
  req := 'p'+IntToHex(ind, 2);
  TDbgRspProcess(Process).FConnection.SendCmdWaitForReply(req, ret);
  AVal := StrToInt('$'+ret);
  result := true;
end;

function TDbgRspThread.WriteDebugReg(ind: byte; AVal: PtrUInt): boolean;
begin
end;

function TDbgRspThread.ReadThreadState: boolean;
begin
  assert(FIsPaused, 'TDbgLinuxThread.ReadThreadState: FIsPaused');
  result := true;
  if FHasThreadState then
    exit;
end;

function TDbgRspThread.RequestInternalPause: Boolean;
begin
  Result := False;
  if FInternalPauseRequested or FIsPaused then
    exit;

  // Send SIGSTOP/break
  TDbgRspProcess(Process).FConnection.SendBreak();
  FInternalPauseRequested := true;
end;

function TDbgRspThread.CheckSignalForPostponing(AWaitedStatus: integer): Boolean;
begin
  Assert(not FIsPaused, 'Got WaitStatus while already paused');
  assert(FExceptionSignal = 0, 'TDbgLinuxThread.CheckSignalForPostponing: FExceptionSignal = 0');
  Result := FIsPaused;
  DebugLn(DBG_VERBOSE and (Result), ['Warning: Thread already paused', ID]);
  if Result then
    exit;

  FIsPaused := True;
  FIsInInternalPause := False;

  //if {FInternalPauseRequested and} (wstopsig(AWaitedStatus) = SIGSTOP) then begin
  //  DebugLn(DBG_VERBOSE and not FInternalPauseRequested, 'Received SigStop, but had not (yet) requested it. TId=', [Id]);
  //  FInternalPauseRequested := False;
  //  FIsInInternalPause := True;
  //  // no postpone
  //end
  //
  //else
  //if wstopsig(AWaitedStatus) = SIGTRAP then begin
  //  if ReadThreadState then
  //    CheckAndResetInstructionPointerAfterBreakpoint;
  //  Result := True;
  //  // TODO: main loop should search all threads for breakpoints
  //end
  //
  //else
  //if wifexited(AWaitedStatus) and (ID <> Process.ProcessID) then begin
  //  Process.RemoveThread(ID); // Done, no postpone
  //end
  //
  //else
  //begin
  //  // Handle later
  //  Result := True;
  //end;

  //TODO: Handle all signals/exceptions/...
end;

procedure TDbgRspThread.ResetPauseStates;
begin
  FIsInInternalPause := False;
  FIsPaused := False;
  FExceptionSignal := 0;
  FHasThreadState := False;
  FDidResetInstructionPointer := False;
end;

function TDbgRspThread.ResetInstructionPointerAfterBreakpoint: boolean;
begin
  if not ReadThreadState then
    exit(False);
  result := true;
  if FDidResetInstructionPointer then
    exit;
  FDidResetInstructionPointer := True;

  Dec(FRegs.PC);
  FRegsChanged:=true;
end;

procedure TDbgRspThread.ApplyWatchPoints(AWatchPointData: TFpWatchPointData);
var
  i: integer;
  r: boolean;
  addr: PtrUInt;
begin
  // Skip this for now...
  exit;

  // TODO: Derive a custom class from TFpWatchPointData to manage
  //       break/watchpoints and communicate over rsp
  r := True;
  for i := 0 to TFpRspWatchPointData(AWatchPointData).Count-1 do begin   // TODO: make size dynamic
    addr := PtrUInt(TFpRspWatchPointData(AWatchPointData).Data[i].Address);

    r := r and WriteDebugReg(i, addr);
  end;
end;

function TDbgRspThread.DetectHardwareWatchpoint: Pointer;
begin
  result := nil;
end;

procedure TDbgRspThread.BeforeContinue;
begin
  if not FIsPaused then
    exit;

  inherited;
  if Process.CurrentWatchpoint <> nil then
    WriteDebugReg(6, 0);

  if FRegsChanged then
    begin
    //io.iov_base:=@(FRegs.regs64[0]);
    //io.iov_len:= sizeof(FRegs);
    //
    //if fpPTrace(PTRACE_SETREGSET, ID, pointer(PtrUInt(NT_PRSTATUS)), @io) <> 0 then
    //  begin
    //  DebugLn(DBG_WARNINGS, 'Failed to set thread registers. Errcode: '+inttostr(fpgeterrno));
    //  end;
    //FRegsChanged:=false;
    end;
end;

procedure TDbgRspThread.LoadRegisterValues;
var
  i: integer;
begin
  if not ReadThreadState then
    exit;
  for i := low(FRegs.regs) to high(FRegs.regs) do
    FRegisterValueList.DbgRegisterAutoCreate['r'+IntToStr(i)].SetValue(FRegs.regs[i], IntToStr(FRegs.regs[i]),1, 0); // confirm dwarf index

  FRegisterValueList.DbgRegisterAutoCreate['spl'].SetValue(FRegs.SPL, IntToStr(FRegs.SPL),1,0);
  FRegisterValueList.DbgRegisterAutoCreate['sph'].SetValue(FRegs.SPH, IntToStr(FRegs.SPH),1,0);
  FRegisterValueList.DbgRegisterAutoCreate['pc'].SetValue(FRegs.PC, IntToStr(FRegs.PC),1,0);
  FRegisterValueListValid:=true;
end;

function TDbgRspThread.GetInstructionPointerRegisterValue: TDbgPtr;
var
  val: PtrUInt;
begin
  Result := 0;
  if not ReadThreadState then
    exit;

  ReadDebugReg(PC0, val);
  result := val;
  ReadDebugReg(PC1, val);
  result := result + val shl 8;
  ReadDebugReg(PC2, val);
  result := result + val shl 16;
  ReadDebugReg(PC3, val);
  result := result + val shl 24;
end;

function TDbgRspThread.GetStackBasePointerRegisterValue: TDbgPtr;
begin
  Result := 0;
  //if not ReadThreadState then
  //  exit;
  //result := FRegs.SPL + FRegs.SPH shl 8;
end;

function TDbgRspThread.GetStackPointerRegisterValue: TDbgPtr;
begin
  Result := 0;
  if not ReadThreadState then
    exit;

  result := FRegs.SPL + FRegs.SPH shl 8;
end;

{ TDbgRspProcess }

procedure TDbgRspProcess.InitializeLoaders;
begin
  TDbgImageLoader.Create(Name).AddToLoaderList(LoaderList);
end;

function TDbgRspProcess.CreateThread(AthreadIdentifier: THandle; out IsMainThread: boolean): TDbgThread;
begin
  IsMainThread:=False;
  if AthreadIdentifier>-1 then
    begin
    IsMainThread := AthreadIdentifier=ProcessID;
    result := TDbgRspThread.Create(Self, AthreadIdentifier, AthreadIdentifier)
    end
  else
    result := nil;
end;

function TDbgRspProcess.CreateWatchPointData: TFpWatchPointData;
begin
  // Replace with rsp version of TFpWatchPointData
  Result := TFpIntelWatchPointData.Create;
end;

constructor TDbgRspProcess.Create(const AName: string; const AProcessID,
  AThreadID: Integer);
begin
  inherited Create(AName, AProcessID, AThreadID);
end;

destructor TDbgRspProcess.Destroy;
begin
  inherited Destroy;
end;

class function TDbgRspProcess.StartInstance(AFileName: string; AParams,
  AnEnvironment: TStrings; AWorkingDirectory, AConsoleTty: string;
  AFlags: TStartInstanceFlags): TDbgProcess;
var
  AnExecutabeFilename: string;
  dbg: TDbgRspProcess;
begin
  result := nil;

  AnExecutabeFilename:=ExcludeTrailingPathDelimiter(AFileName);
  if DirectoryExists(AnExecutabeFilename) then
  begin
    DebugLn(DBG_WARNINGS, 'Can not debug %s, because it''s a directory',[AnExecutabeFilename]);
    Exit;
  end;

  if not FileExists(AFileName) then
  begin
    DebugLn(DBG_WARNINGS, 'Can not find  %s.',[AnExecutabeFilename]);
    Exit;
  end;

  dbg := TDbgRspProcess.Create(AFileName, 0, 0);
  try
    dbg.FConnection := TRspConnection.Create('localhost', 1234);
    dbg.FConnection.RegisterCacheSize := 38;
    result := dbg;
    dbg.FStatus := dbg.FConnection.Init;
    dbg := nil;
  except
    on E: Exception do
    begin
      if Assigned(dbg) then
        dbg.Free;
      DebugLn(DBG_WARNINGS, Format('Failed to start remote connection. Errormessage: "%s".', [E.Message]));
    end;
  end;
end;

class function TDbgRspProcess.AttachToInstance(AFileName: string;
  APid: Integer): TDbgProcess;
begin
  result := nil;
end;

function TDbgRspProcess.ReadData(const AAdress: TDbgPtr;
  const ASize: Cardinal; out AData): Boolean;
var
  AVal: TDbgPtr;
  AAdressAlign: TDBGPtr;
  BytesRead: integer;
  ReadBytes: integer;
  PB: PByte;
  buf: pbyte;
  cmd, reply: string;
  i: integer;
begin
  BytesRead := 0;
  result := false;
  getmem(buf, ASize);
  cmd := 'm'+IntToHex(AAdress, 2)+',' + IntToHex(ASize, 2);
  if FConnection.SendCmdWaitForReply(cmd, reply) and (length(reply) = ASize*2) then
  begin
    for i := 0 to ASize-1 do
    begin
      buf[i] := StrToInt('$'+reply[2*i + 1]+reply[2*i + 2]);
    end;
    System.Move(buf^, AData, ASize);
    result := true;
  end;
  Freemem(buf);

  //try
  //  WordSize:=DBGPTRSIZE[Mode];
  //  if AAdress mod WordSize <> 0 then
  //    begin
  //    AAdressAlign := ((PtrUInt(AAdress)) and not PtrUInt(WordSize - 1));
  //    if not ReadWordSize(AAdressAlign, AVal) then
  //      Exit;
  //    pb := @AVal;
  //    BytesRead:=WordSize-(AAdress-AAdressAlign);
  //    if BytesRead>=ASize then
  //      BytesRead:=ASize;
  //    move(pb[AAdress-AAdressAlign], buf[0], BytesRead);
  //    inc(AAdressAlign, WordSize);
  //    end
  //  else
  //    AAdressAlign:=AAdress;
  //
  //  while BytesRead<ASize do
  //    begin
  //    if not ReadWordSize(AAdressAlign, AVal) then
  //      exit;
  //    if WordSize<(ASize-BytesRead) then
  //      ReadBytes:=WordSize
  //    else
  //      ReadBytes:=(ASize-BytesRead);
  //    move(AVal, buf[BytesRead], ReadBytes);
  //    inc(BytesRead, ReadBytes);
  //    inc(AAdressAlign, WordSize);
  //
  //    end;
  //  System.Move(buf^, AData, BytesRead);
  //finally
  //  freemem(buf);
  //end;
  MaskBreakpointsInReadData(AAdress, ASize, AData);
  //result := true;
end;

function TDbgRspProcess.WriteData(const AAdress: TDbgPtr;
  const ASize: Cardinal; const AData): Boolean;
//var
//  e: integer;
//  pi: TDBGPtr;
//  WordSize: integer;
begin
  //result := false;
  //WordSize:=DBGPTRSIZE[Mode];
  //
  //if ASize>WordSize then
  //  DebugLn(DBG_WARNINGS, 'Can not write more then '+IntToStr(WordSize)+' bytes.')
  //else
  //  begin
  //  if ASize<WordSize then
  //    begin
  //    fpseterrno(0);
  //    pi := TDbgPtr(fpPTrace(PTRACE_PEEKDATA, FCurrentThreadId, pointer(AAdress), nil));
  //    e := fpgeterrno;
  //    if e <> 0 then
  //      begin
  //      DebugLn(DBG_WARNINGS, 'Failed to read data. Errcode: '+inttostr(e));
  //      result := false;
  //      exit;
  //      end;
  //    end;
  //  move(AData, pi, ASize);
  //
  //  fpPTrace(PTRACE_POKEDATA, FCurrentThreadId, pointer(AAdress), pointer(pi));
  //  e := fpgeterrno;
  //  if e <> 0 then
  //    begin
  //    DebugLn(DBG_WARNINGS, 'Failed to write data. Errcode: '+inttostr(e));
  //    result := false;
  //    end;
  //  end;
  //
  //result := true;
end;

procedure TDbgRspProcess.TerminateProcess;
begin
  FIsTerminating:=true;
  FConnection.SendKill();
  //if fpkill(ProcessID,SIGKILL)<>0 then
  //  begin
  //  DebugLn(DBG_WARNINGS, 'Failed to send SIGKILL to process %d. Errno: %d',[ProcessID, errno]);
  //  FIsTerminating:=false;
  //  end;
end;

function TDbgRspProcess.Pause: boolean;
begin
  // Target should automatically respond with T or S reply after processing the break
  result := FConnection.SendBreak();
  PauseRequested:=true;
  if not result then
  begin
    DebugLn(DBG_WARNINGS, 'Failed to send SIGTRAP to process %d.',[ProcessID]);
  end;
end;

function TDbgRspProcess.Detach(AProcess: TDbgProcess; AThread: TDbgThread): boolean;
var
  reply: string;
begin
  RemoveAllBreakPoints;
  result := FConnection.SendCmdWaitForReply('D', reply);
  result := pos('OK', reply) = 1;
  Result := True; // Probably not much more you can do, so say it is OK
end;

function TDbgRspProcess.Continue(AProcess: TDbgProcess; AThread: TDbgThread; SingleStep: boolean): boolean;
var
  ThreadToContinue: TDbgRspThread;
  PC: word;
  s: string;
  tempState: integer;
begin
  // Terminating process and all threads
  if FIsTerminating then
  begin
    AThread.BeforeContinue;
    // The kill command should have been issued earlier (if using fpd), calling SendKill again will lead to an exception since the connection shoul db terminated already.
    // FConnection.SendKill();

    TDbgRspThread(AThread).ResetPauseStates;
    if not FThreadMap.HasId(AThread.ID) then
      AThread.Free;
    exit;
  end;

  if TDbgRspThread(AThread).FIsPaused then  // in case of deInternal, it may not be paused and can be ignored
    AThread.NextIsSingleStep:=SingleStep;

  // check other threads if they need a singlestep
  for TDbgThread(ThreadToContinue) in FThreadMap do
    if (ThreadToContinue <> AThread) and ThreadToContinue.FIsPaused then
    begin
      PC := ThreadToContinue.GetInstructionPointerRegisterValue;
      if HasInsertedBreakInstructionAtLocation(PC) then
      begin
        TempRemoveBreakInstructionCode(PC);
        ThreadToContinue.BeforeContinue;

        while (ThreadToContinue.GetInstructionPointerRegisterValue = PC) do
        begin
          result := FConnection.Continue();
          //fpPTrace(PTRACE_SINGLESTEP, ThreadToContinue.ID, pointer(1), pointer(wstopsig(TDbgRspThread(ThreadToContinue).FExceptionSignal)));

          TDbgRspThread(ThreadToContinue).ResetPauseStates; // So BeforeContinue will not run again

          ThreadToContinue.FIsPaused := True;
          if result then
          begin
            tempState := FConnection.WaitForSignal(s);
            //PID := fpWaitPid(ThreadToContinue.ID, WaitStatus, __WALL);
            //if PID <> ThreadToContinue.ID then
            //begin
            //  DebugLn(DBG_WARNINGS, ['Error single stepping other thread ', ThreadToContinue.ID, ' waitpid got ', PID, ', ',WaitStatus, ' err ', Errno]);
            //  break;
            //end;
            if (tempState = SIGTRAP) then
              break; // if the command jumps back an itself....
          end
          else
          begin
            DebugLn(DBG_WARNINGS, ['Error single stepping other thread ', ThreadToContinue.ID]);
            break;
          end;
        end;
      end;
    end;

  if TDbgRspThread(AThread).FIsPaused then  // in case of deInternal, it may not be paused and can be ignored
  if HasInsertedBreakInstructionAtLocation(AThread.GetInstructionPointerRegisterValue) then
  begin
    TempRemoveBreakInstructionCode(AThread.GetInstructionPointerRegisterValue);
    TDbgRspThread(AThread).FIsSteppingBreakPoint := True;
    AThread.BeforeContinue;
    result := FConnection.SingleStep(); // TODO: pass thread ID once it is supported in FConnection - also signals not yet passed through
    //fpPTrace(PTRACE_SINGLESTEP, AThread.ID, pointer(1), pointer(wstopsig(TDbgRspThread(AThread).FExceptionSignal)));
    TDbgRspThread(AThread).ResetPauseStates;
    FStatus := 0; // need to call WaitForSignal to read state after single step
    exit;
  end;

  RestoreTempBreakInstructionCodes;

  ThreadsBeforeContinue;

  // start all other threads
  for TDbgThread(ThreadToContinue) in FThreadMap do
  begin
    if (ThreadToContinue <> AThread) and (ThreadToContinue.FIsPaused) then
    begin
      FConnection.Continue();
      //fpPTrace(PTRACE_CONT, ThreadToContinue.ID, pointer(1), pointer(wstopsig(ThreadToContinue.FExceptionSignal)));
      ThreadToContinue.ResetPauseStates;
    end;
  end;

  if TDbgRspThread(AThread).FIsPaused then  // in case of deInternal, it may not be paused and can be ignored
  if not FIsTerminating then
  begin
    AThread.BeforeContinue;
    if SingleStep then
      result := FConnection.SingleStep()
      //fpPTrace(PTRACE_SINGLESTEP, AThread.ID, pointer(1), pointer(wstopsig(TDbgRspThread(AThread).FExceptionSignal)))
    else
      result := FConnection.Continue();
      //fpPTrace(PTRACE_CONT, AThread.ID, pointer(1), pointer(wstopsig(TDbgRspThread(AThread).FExceptionSignal)));
    TDbgRspThread(AThread).ResetPauseStates;
    FStatus := 0;  // should update status by calling WaitForSignal
  end;

  if not FThreadMap.HasId(AThread.ID) then
    AThread.Free;
end;

function TDbgRspProcess.WaitForDebugEvent(out ProcessIdentifier, ThreadIdentifier: THandle): boolean;
var
  PID: THandle;
  ThreadWithEvent: TDbgRspThread;
  s: string;
begin
  // Currently only single process/thread
  // TODO: Query and handle process/thread states of target
  ThreadIdentifier  := self.ThreadID;
  ProcessIdentifier := Self.ProcessID;

  // Wait for S or T response from target, or if connection to target is lost
  if FStatus = 0 then
    repeat
      FStatus := FConnection.WaitForSignal(s);
    until FStatus <> 0;   // should probably wait at lower level...

  if FStatus <> 0 then
  begin
    if FStatus in [SIGINT, SIGTRAP] then
    begin
      RestoreTempBreakInstructionCodes;
    end;
  end;

  result := true;
  //result := PID<>-1;
  //if not result then
  //  DebugLn(DBG_WARNINGS, 'Failed to wait for debug event.', [])
  //else
  //begin
  //  ThreadIdentifier := self.ThreadID;
  //
  //  if not FProcessStarted and (PID <> ProcessID) then
  //    DebugLn(DBG_WARNINGS, 'ThreadID of main thread does not match the ProcessID');
  //
  //  ProcessIdentifier := ProcessID;
  //end;
end;

function TDbgRspProcess.InsertBreakInstructionCode(const ALocation: TDBGPtr;
  out OrigValue: Byte): Boolean;
begin
  result := ReadData(ALocation, SizeOf(OrigValue), OrigValue);
  if result then
  begin
  // HW break...
    result := FConnection.SetBreakWatchPoint(ALocation, wkpExec);
    if not result then
      DebugLn(DBG_WARNINGS, 'Failed to set break point.', []);
  end
  else
    DebugLn(DBG_WARNINGS, 'Failed to read memory.', []);
end;

function TDbgRspProcess.RemoveBreakInstructionCode(const ALocation: TDBGPtr;
  const OrigValue: Byte): Boolean;
begin
  result := FConnection.DeleteBreakWatchPoint(ALocation, wkpExec);
end;

function TDbgRspProcess.AnalyseDebugEvent(AThread: TDbgThread): TFPDEvent;
var
  ThreadToPause, ThreadSignaled: TDbgRspThread;
  Pid: THandle;
  WaitStatus: integer;
begin
  if FIsTerminating then begin
    result := deExitProcess;
    exit;
  end;

  if AThread = nil then begin // should not happen... / just assume the most likely safe failbacks
    result := deInternalContinue;
    exit;
  end;

  TDbgRspThread(AThread).FExceptionSignal:=0;
  TDbgRspThread(AThread).FIsPaused := True;

  if FStatus in [SIGHUP, SIGKILL] then  // not sure which signals is relevant here
  begin
    if AThread.ID=ProcessID then
    begin
      // Main thread stop -> application exited
      SetExitCode(FStatus);
      result := deExitProcess
    end
    else
    begin
      // Thread stopped, just continue
      RemoveThread(AThread.Id);
      result := deInternalContinue;
    end;
  end
  else if FStatus <> 0 then
  begin
    TDbgRspThread(AThread).ReadThreadState;

    //if FStatus = SIGTRAP then
    //begin
    //  if not FProcessStarted then
    //  begin
    //    result := deCreateProcess;
    //    FProcessStarted:=true;
    //    //if fpPTrace(PTRACE_SETOPTIONS, ProcessID, nil,  Pointer( PTRACE_O_TRACECLONE) ) <> 0 then
    //    //  writeln('Failed to set set trace options. ');
    //  end
    //  else
    //  // TODO: check it is not a real breakpoint
    //  // or end of single step
    //    if TDbgRspThread(AThread).FInternalPauseRequested then begin
    //      DebugLn(DBG_VERBOSE, ['Received late SigTrag for thread ', AThread.ID]);
    //      result := deInternalContinue; // left over signal
    //    end
    //    else
    //    begin
    //      result := deBreakpoint; // or pause requested
    //      if not TDbgRspThread(AThread).FIsSteppingBreakPoint then
    //        AThread.CheckAndResetInstructionPointerAfterBreakpoint;
    //    end;
    //end;

    if (not FProcessStarted) and (FStatus <> SIGTRAP) then
    begin
      // attached, should be SigStop, but may be out of order
      debugln(DBG_VERBOSE, ['Attached ', FStatus]);
      result := deCreateProcess;
      FProcessStarted:=true;
    end
    else
    case FStatus of
      SIGTRAP:
        begin
        if not FProcessStarted then
        begin
          result := deCreateProcess;
          FProcessStarted:=true;
        end
        else
          if TDbgRspThread(AThread).FInternalPauseRequested then begin
            DebugLn(DBG_VERBOSE, ['Received late SigTrag for thread ', AThread.ID]);
            result := deInternalContinue; // left over signal
          end
          else
          begin
            result := deBreakpoint; // or pause requested
            if not TDbgRspThread(AThread).FIsSteppingBreakPoint then
              AThread.CheckAndResetInstructionPointerAfterBreakpoint;
          end;
        end;
      SIGBUS:
        begin
          ExceptionClass:='SIGBUS';
          TDbgRspThread(AThread).FExceptionSignal:=SIGBUS;
          result := deException;
        end;
      SIGINT:
        begin
          ExceptionClass:='SIGINT';
          TDbgRspThread(AThread).FExceptionSignal:=SIGINT;
          result := deException;
        end;
      SIGSEGV:
        begin
          ExceptionClass:='SIGSEGV';
          TDbgRspThread(AThread).FExceptionSignal:=SIGSEGV;
          result := deException;
        end;
      SIGCHLD:
        begin
          TDbgRspThread(AThread).FExceptionSignal:=SIGCHLD;
          result := deInternalContinue;
        end;
      SIGKILL:
        begin
          if FIsTerminating then
            result := deInternalContinue
          else
            begin
            ExceptionClass:='SIGKILL';
            TDbgRspThread(AThread).FExceptionSignal:=SIGKILL;
            result := deException;
            end;
          end;
      SIGSTOP:
        begin
          // New thread (stopped within the new thread)
          result := deInternalContinue;
        end
      else
      begin
        ExceptionClass:='Unknown exception code ' + inttostr(FStatus);
        TDbgRspThread(AThread).FExceptionSignal := FStatus;
        result := deException;
      end;
    end; {case}
    if result=deException then
      ExceptionClass:='External: '+ExceptionClass;
  end;
  //else
  //  raise exception.CreateFmt('Received unknown status %d from process with pid=%d',[FStatus, ProcessID]);

  TDbgRspThread(AThread).FIsSteppingBreakPoint := False;

  if Result in [deException, deBreakpoint, deFinishedStep] then // deFinishedStep will not be set here
  begin
    // Signal all other threads to pause
    for TDbgThread(ThreadToPause) in FThreadMap do
    begin
      if (ThreadToPause <> AThread) then
      begin
          DebugLn(DBG_VERBOSE and (ThreadToPause.FInternalPauseRequested), ['Re-Request Internal pause for ', ThreadToPause.ID]);
          ThreadToPause.FInternalPauseRequested:=false;
          if not ThreadToPause.RequestInternalPause then // will fail, if already paused
            break;
      end;
    end;
  end;
end;

initialization
  RegisterDbgClasses;
  DBG_VERBOSE := DebugLogger.FindOrRegisterLogGroup('DBG_VERBOSE' {$IFDEF DBG_VERBOSE} , True {$ENDIF} );
  DBG_WARNINGS := DebugLogger.FindOrRegisterLogGroup('DBG_WARNINGS' {$IFDEF DBG_WARNINGS} , True {$ENDIF} );
end.
