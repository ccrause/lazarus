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
  FpDbgClasses,
  FpDbgLoader,
  DbgIntfBaseTypes, DbgIntfDebuggerBase,
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
  // Program counter register indexes
  PC0 = 35;
  PC1 = 36;
  PC2 = 37;
  PC3 = 38;

type
  TAvrRegisters = packed record
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
    FRegs: TAvrRegisters;
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

    // FOR AVR target AAddress could be program or data (SRAM) memory (or EEPROM)
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

var
  // Difficult to see how this can be encapsulated except if
  // added methods are introduced that needs to be called after .Create
  HostName: string = 'localhost';
  Port: integer = 1234;

implementation

uses
  FpDbgDisasAvr;

var
  DBG_VERBOSE, DBG_WARNINGS: PLazLoggerLogGroup;

procedure RegisterDbgClasses;
begin
  OSDbgClasses.DbgProcessClass:=TDbgRspProcess;
  OSDbgClasses.DbgThreadClass:=TDbgRspThread;
  // A large hack, should rather have a manager that loads the appropriate disassembler according to debug info
  GDisassembler := TAvrDisassembler.Create;
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
  if TDbgRspProcess(Process).FIsTerminating then
    DebugLn(DBG_WARNINGS, 'TDbgRspThread.GetDebugRegOffset called while FIsTerminating is set.');
  result := nil;
end;

function TDbgRspThread.ReadDebugReg(ind: byte; out AVal: PtrUInt): boolean;
begin
  if TDbgRspProcess(Process).FIsTerminating then
  begin
    DebugLn(DBG_WARNINGS, 'TDbgRspThread.GetDebugReg called while FIsTerminating is set.');
    Result := false;
  end
  else
  begin
    DebugLn(DBG_VERBOSE, ['TDbgRspThread.GetDebugReg requesting register: ',ind]);
    result := TDbgRspProcess(Process).FConnection.ReadDebugReg(ind, AVal);
  end;
end;

function TDbgRspThread.WriteDebugReg(ind: byte; AVal: PtrUInt): boolean;
begin
  if TDbgRspProcess(Process).FIsTerminating then
  begin
    DebugLn(DBG_WARNINGS, 'TDbgRspThread.WriteDebugReg called while FIsTerminating is set.');
    Result := false;
  end
  else
    result := TDbgRspProcess(Process).FConnection.WriteDebugReg(ind, AVal);
end;

function TDbgRspThread.ReadThreadState: boolean;
begin
  assert(FIsPaused, 'TDbgRspThread.ReadThreadState: FIsPaused');
  result := true;
  if FHasThreadState then
    exit;
  FRegisterValueListValid := false;
end;

function TDbgRspThread.RequestInternalPause: Boolean;
begin
  if TDbgRspProcess(Process).FIsTerminating then
    DebugLn(DBG_WARNINGS, 'TDbgRspThread.RequestInternalPause called while FIsTerminating is set.');

  Result := False;
  if FInternalPauseRequested or FIsPaused then
    exit;

  DebugLn(DBG_VERBOSE, 'TDbgRspThread.RequestInternalPause requesting Ctrl-C.');

  FInternalPauseRequested := true;
  // Send SIGSTOP/break
  TDbgRspProcess(Process).FConnection.Break();
end;

function TDbgRspThread.CheckSignalForPostponing(AWaitedStatus: integer): Boolean;
begin
  Assert(not FIsPaused, 'Got WaitStatus while already paused');
  assert(FExceptionSignal = 0, 'TDbgLinuxThread.CheckSignalForPostponing: FExceptionSignal = 0');
  Result := FIsPaused;
  DebugLn(DBG_VERBOSE and (Result), ['Warning: Thread already paused', ID]);

  DebugLn(DBG_VERBOSE, ['TDbgRspThread.CheckSignalForPostponing called with ', AWaitedStatus]);

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
  //if Process.CurrentWatchpoint <> nil then
  //  WriteDebugReg(6, 0);

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
  if TDbgRspProcess(Process).FIsTerminating then
  begin
    DebugLn(DBG_WARNINGS, 'TDbgRspThread.LoadRegisterValues called while FIsTerminating is set.');
    exit;
  end;

  if not ReadThreadState then
    exit;

  if TDbgRspProcess(Process).FConnection.ReadRegisters(FRegs.regs[0], length(FRegs.regs)) then
  begin
    for i := 0 to high(FRegs.cpuRegs) do
      FRegisterValueList.DbgRegisterAutoCreate['r'+IntToStr(i)].SetValue(FRegs.cpuRegs[i], IntToStr(FRegs.cpuRegs[i]),1, i); // confirm dwarf index

    FRegisterValueList.DbgRegisterAutoCreate['spl'].SetValue(FRegs.SPL, IntToStr(FRegs.SPL),1,0);
    FRegisterValueList.DbgRegisterAutoCreate['sph'].SetValue(FRegs.SPH, IntToStr(FRegs.SPH),1,0);
    FRegisterValueList.DbgRegisterAutoCreate['pc'].SetValue(FRegs.PC, IntToStr(FRegs.PC),1,0);
    FRegisterValueListValid := true;
  end;
end;

function TDbgRspThread.GetInstructionPointerRegisterValue: TDbgPtr;
var
  val: PtrUInt;
begin
  Result := 0;
  if TDbgRspProcess(Process).FIsTerminating then
  begin
    DebugLn(DBG_WARNINGS, 'TDbgRspThread.GetInstructionPointerRegisterValue called while FIsTerminating is set.');
    exit;
  end;

  if not ReadThreadState then
    exit;

  DebugLn(DBG_WARNINGS, 'TDbgRspThread.GetInstructionPointerRegisterValue requesting PC.');
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
var
  spl, sph: PtrUInt;
begin
  Result := 0;
  if TDbgRspProcess(Process).FIsTerminating then
  begin
    DebugLn(DBG_WARNINGS, 'TDbgRspThread.GetStackPointerRegisterValue called while FIsTerminating is set.');
    exit;
  end;

  if not ReadThreadState then
    exit;

  DebugLn(DBG_VERBOSE, 'TDbgRspThread.GetStackPointerRegisterValue requesting stack registers.');
  ReadDebugReg(SPLindex, spl);
  ReadDebugReg(SPHindex, sph);
  result := spl + sph shl 8;
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
  DebugLn(DBG_VERBOSE, 'TDbgRspProcess.CreateWatchPointData called.');
  Result := TFpRspWatchPointData.Create;
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
    dbg.FConnection := TRspConnection.Create(HostName, Port);
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
begin
  if FIsTerminating then
  begin
    DebugLn(DBG_WARNINGS, 'TDbgRspProcess.ReadData called while FIsTerminating is set.');
    Result := false;
    exit;
  end;

  result := FConnection.ReadData(AAdress, ASize, AData);
  MaskBreakpointsInReadData(AAdress, ASize, AData);
end;

function TDbgRspProcess.WriteData(const AAdress: TDbgPtr;
  const ASize: Cardinal; const AData): Boolean;
begin
  if FIsTerminating then
  begin
    DebugLn(DBG_WARNINGS, 'TDbgRspProcess.WriteData called while FIsTerminating is set.');
    Result := false;
    exit;
  end;

  result := FConnection.WriteData(AAdress,AAdress, AData);
end;

procedure TDbgRspProcess.TerminateProcess;
begin
  // Try to prevent access to the RSP socket after it has been closed
  if not FIsTerminating then
  begin
    FIsTerminating:=true;
    DebugLn(DBG_VERBOSE, 'Sending kill command from TDbgRspProcess.TerminateProcess');
    FConnection.Kill();
  end;
end;

function TDbgRspProcess.Pause: boolean;
begin
  if FIsTerminating then
  begin
    DebugLn(DBG_WARNINGS, 'TDbgRspProcess.Pause called while FIsTerminating is set.');
    Result := false;
    exit;
  end;

  // Target should automatically respond with T or S reply after processing the break
  result := true;
  DebugLn(DBG_VERBOSE, 'TDbgRspProcess.Pause called.');
  if not PauseRequested then
  begin
    FConnection.Break();
    PauseRequested := true;
  end
  else
  begin
    result := true;
    DebugLn(DBG_WARNINGS, 'TDbgRspProcess.Pause called while PauseRequested is set.');
  end;
end;

function TDbgRspProcess.Detach(AProcess: TDbgProcess; AThread: TDbgThread): boolean;
begin
  RemoveAllBreakPoints;
  DebugLn(DBG_VERBOSE, 'Sending detach command from TDbgRspProcess.Detach');
  Result := FConnection.Detach();
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
    DebugLn(DBG_VERBOSE, 'TDbgRspProcess.Continue called while terminating.');
    // The kill command should have been issued earlier (if using fpd), calling SendKill again will lead to an exception since the connection should be terminated already.
    // FConnection.Kill();

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
          result := FConnection.SingleStep();
          TDbgRspThread(ThreadToContinue).ResetPauseStates; // So BeforeContinue will not run again
          ThreadToContinue.FIsPaused := True;
          if result then
          begin
            tempState := FConnection.WaitForSignal(s);
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
      ThreadToContinue.ResetPauseStates;
    end;
  end;

  if TDbgRspThread(AThread).FIsPaused then  // in case of deInternal, it may not be paused and can be ignored
    if not FIsTerminating then
    begin
      AThread.BeforeContinue;
      if SingleStep then
        result := FConnection.SingleStep()
      else
        result := FConnection.Continue();
      TDbgRspThread(AThread).ResetPauseStates;
      FStatus := 0;  // should update status by calling WaitForSignal
    end;

  if not FThreadMap.HasId(AThread.ID) then
    AThread.Free;
end;

function TDbgRspProcess.WaitForDebugEvent(out ProcessIdentifier, ThreadIdentifier: THandle): boolean;
var
  s: string;
begin
  // Currently only single process/thread
  // TODO: Query and handle process/thread states of target
  ThreadIdentifier  := self.ThreadID;
  ProcessIdentifier := Self.ProcessID;

  if FIsTerminating then
  begin
    DebugLn(DBG_VERBOSE, 'TDbgRspProcess.WaitForDebugEvent called while FIsTerminating is set.');
    FStatus := SIGKILL;
  end
  else
  // Wait for S or T response from target, or if connection to target is lost
  if FStatus = 0 then
    repeat
      try
        FStatus := FConnection.WaitForSignal(s);
      except
        FStatus := 0;
      end;
    until FStatus <> 0;   // should probably wait at lower level...

  if FStatus <> 0 then
  begin
    if FStatus in [SIGINT, SIGTRAP] then
    begin
      RestoreTempBreakInstructionCodes;
    end;
  end;

  result := true;
end;

function TDbgRspProcess.InsertBreakInstructionCode(const ALocation: TDBGPtr;
  out OrigValue: Byte): Boolean;
begin
  if FIsTerminating then
    DebugLn(DBG_WARNINGS, 'TDbgRspProcess.InsertBreakInstruction called while FIsTerminating is set.');

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
  if FIsTerminating then
  begin
    DebugLn(DBG_WARNINGS, 'TDbgRspProcess.RemoveBreakInstructionCode called while FIsTerminating is set');
    result := false;
  end;

  result := FConnection.DeleteBreakWatchPoint(ALocation, wkpExec);
end;

function TDbgRspProcess.AnalyseDebugEvent(AThread: TDbgThread): TFPDEvent;
var
  ThreadToPause: TDbgRspThread;
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
          DebugLn(DBG_VERBOSE, ['Creating process - SIGTRAP received for thread: ', AThread.ID]);
        end
        else if TDbgRspThread(AThread).FInternalPauseRequested then
        begin
          DebugLn(DBG_VERBOSE, ['???Received late SigTrap for thread ', AThread.ID]);
          result := deBreakpoint;//deInternalContinue; // left over signal
        end
        else
        begin
          DebugLn(DBG_VERBOSE, ['Received SigTrap for thread ', AThread.ID,
             ' PauseRequest=', TDbgRspThread(AThread).FInternalPauseRequested]);
          result := deBreakpoint; // or pause requested
          if not TDbgRspThread(AThread).FIsSteppingBreakPoint then
            AThread.CheckAndResetInstructionPointerAfterBreakpoint;

          if PauseRequested then
            ;
        end;
      end;
      SIGINT:
        begin
          ExceptionClass:='SIGINT';
          TDbgRspThread(AThread).FExceptionSignal:=SIGINT;
          result := deException;
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
