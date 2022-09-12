using System;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using WmiSpawn.Interop;

namespace WmiSpawn.Library
{
    internal class Modules
    {
        public static bool CreateWmiProcessKerberos(
            string domain,
            string hostname,
            string username,
            string password,
            string commandLine,
            bool privileged,
            bool visible,
            uint timeout)
        {
            string server;
            ManagementScope scope;
            var options = new ConnectionOptions();

            Console.WriteLine("[*] Kerberos authentication mode.");

            if (string.IsNullOrEmpty(domain))
                domain = Helpers.GetActiveDirectoryDomainName();

            if (Helpers.IsValidIpAddress(hostname))
            {
                Console.WriteLine("[!] Use hostname, not IP address.");

                return false;
            }
            else if (Helpers.LookupIpAddressByHostname(hostname).Length == 0)
            {
                Console.WriteLine("[!] No host found.");

                return false;
            }

            if (string.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[-] This machine does not belong to active directory domain.");

                return false;
            }
            else
            {
                Console.WriteLine("    [*] Domain   : {0}", domain);
            }

            if (!string.IsNullOrEmpty(username))
            {
                options.Username = username;
                Console.WriteLine("    [*] Username : {0}", username);
            }
            else
            {
                Console.WriteLine("    [*] Username : (null)");
            }

            if (!string.IsNullOrEmpty(password))
            {
                options.Password = password;
                Console.WriteLine("    [*] Password : {0}", password);
            }
            else
            {
                Console.WriteLine("    [*] Password : (null)");
            }

            options.Authority = string.Format(
                @"kerberos:{0}\{1}",
                domain,
                hostname.Split('.')[0]);
            options.EnablePrivileges = privileged;

            server = string.Format(@"\\{0}\root\cimv2", hostname);
            scope = new ManagementScope(server, options);

            try
            {
                Console.WriteLine("[>] Trying to connect WMI server.");
                Console.WriteLine("    [*] Server : {0}", server);

                scope.Connect();
            }
            catch (COMException ex)
            {
                Console.Write("[!] {0}", ex.Message.ToString());

                return false;
            }
            catch (ManagementException ex)
            {
                Console.Write("[!] {0}", ex.Message.ToString());

                return false;
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Write("[!] {0}", ex.Message.ToString());

                return false;
            }

            if (scope.IsConnected)
            {
                Console.WriteLine("[+] Connected to the target server successfully.");
            }
            else
            {
                Console.WriteLine("[-] Failed to connect the target server.");

                return false;
            }

            return CreateWmiProcessInternal(
                scope,
                commandLine,
                visible,
                timeout);
        }


        public static bool CreateWmiProcessLocal(
            string commandLine,
            bool privileged,
            bool visible,
            uint timeout)
        {
            var server = string.Format(
                @"\\{0}\root\cimv2",
                Dns.GetHostName());
            var options = new ConnectionOptions
            {
                EnablePrivileges = privileged,
            };
            var scope = new ManagementScope(server, options);

            try
            {
                Console.WriteLine("[>] Trying to connect WMI server.");
                Console.WriteLine("    [*] Server : {0}", server);

                scope.Connect();
            }
            catch (COMException ex)
            {
                Console.Write("[!] {0}", ex.Message.ToString());

                return false;
            }
            catch (ManagementException ex)
            {
                Console.Write("[!] {0}", ex.Message.ToString());

                return false;
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Write("[!] {0}", ex.Message.ToString());

                return false;
            }

            if (scope.IsConnected)
            {
                Console.WriteLine("[+] Connected to the target server successfully.");
            }
            else
            {
                Console.WriteLine("[-] Failed to connect the target server.");

                return false;
            }

            return CreateWmiProcessInternal(
                scope,
                commandLine,
                visible,
                timeout);
        }


        public static bool CreateWmiProcessNtlm(
            string hostname,
            string username,
            string password,
            string commandLine,
            bool privileged,
            bool visible,
            uint timeout)
        {
            ManagementScope scope;
            var server = string.Format(
                @"\\{0}\root\cimv2",
                string.IsNullOrEmpty(hostname) ? Dns.GetHostName() : hostname);
            var options = new ConnectionOptions();

            Console.WriteLine("[*] NTLM authentication mode.");

            if (!string.IsNullOrEmpty(username))
            {
                options.Username = username;
                Console.WriteLine("    [*] Username : {0}", username);
            }
            else
            {
                Console.WriteLine("    [*] Username : (null)");
            }

            if (!string.IsNullOrEmpty(password))
            {
                options.Password = password;
                Console.WriteLine("    [*] Password : {0}", password);
            }
            else
            {
                Console.WriteLine("    [*] Password : (null)");
            }

            options.EnablePrivileges = privileged;
            options.Impersonation = ImpersonationLevel.Impersonate;

            try
            {
                Console.WriteLine("[>] Trying to connect WMI server.");
                Console.WriteLine("    [*] Server : {0}", server);

                scope = new ManagementScope(server, options);
                scope.Connect();
            }
            catch (COMException ex)
            {
                Console.Write("[!] {0}", ex.Message.ToString());

                return false;
            }
            catch (ManagementException ex)
            {
                Console.Write("[!] {0}", ex.Message.ToString());

                return false;
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Write("[!] {0}", ex.Message.ToString());

                return false;
            }

            if (scope.IsConnected)
            {
                Console.WriteLine("[+] Connected to the target server successfully.");
            }
            else
            {
                Console.WriteLine("[-] Failed to connect the target server.");

                return false;
            }

            return CreateWmiProcessInternal(
                scope,
                commandLine,
                visible,
                timeout);
        }


        private static bool CreateWmiProcessInternal(
            ManagementScope scope,
            string commandLine,
            bool visible,
            uint timeout) // seconds
        {
            bool status;
            uint code;
            int pid;
            ManagementBaseObject startupInfo;
            ManagementClass win32Process;
            ManagementClass win32ProcessStartup;
            ManagementBaseObject inParams;
            ManagementBaseObject outParams;

            try
            {
                using (win32Process = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions()))
                using (win32ProcessStartup = new ManagementClass(scope, new ManagementPath("Win32_ProcessStartup"), new ObjectGetOptions()))
                {
                    using (inParams = win32Process.GetMethodParameters("Create"))
                    using (startupInfo = win32ProcessStartup.CreateInstance())
                    {
                        if (visible)
                            startupInfo["ShowWindow"] = (ushort)SHOW_WINDOW_FLAGS.SW_SHOW;
                        else
                            startupInfo["ShowWindow"] = (ushort)SHOW_WINDOW_FLAGS.SW_HIDE;

                        inParams["CommandLine"] = commandLine;
                        inParams["ProcessStartupInformation"] = startupInfo;

                        Console.WriteLine("[>] Trying to execute process via WMI.");
                        Console.WriteLine("    [*] Command Line : {0}", commandLine);
                        Console.WriteLine("    [*] Visible      : {0}", visible);

                        outParams = win32Process.InvokeMethod(
                            "Create",
                            inParams,
                            new InvokeMethodOptions { Timeout = TimeSpan.FromSeconds(timeout) });
                        code = Convert.ToUInt32(outParams["returnValue"]);
                        pid = Convert.ToInt32(outParams["processId"]);
                        status = ((code == 0) || (pid > 0));

                        if (status)
                        {
                            Console.WriteLine("[+] Process will be executed from WmiPrvSE.exe.");
                            Console.WriteLine("    [*] Process ID : {0}", pid);
                        }
                        else
                        {
                            Console.WriteLine("[-] Failed to execute process.");
                            Console.WriteLine("    [*] Status : {0}", (WMI_PROCESS_STATUS)code);
                        }
                    }
                }

                Console.WriteLine("[*] Completed.");

                return status;
            }
            catch (COMException ex)
            {
                Console.Write("[!] {0}", ex.Message.ToString());

                return false;
            }
            catch (ManagementException ex)
            {
                Console.Write("[!] {0}", ex.Message.ToString());

                return false;
            }
        }
    }
}
