using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using SelfDefend.Interop;
using SelfDefend.Library;

namespace SelfDefend
{
    using SIZE_T = UIntPtr;

    internal class SelfDefend
    {
        static void Main()
        {
            int error;
            bool status;
            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy;
            int nPolicySize = Marshal.SizeOf(typeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY));
            IntPtr pPolicyInfo = Marshal.AllocHGlobal(nPolicySize);
            SIZE_T nBufferSize = new SIZE_T((uint)nPolicySize);

            Console.WriteLine();

            Console.WriteLine("[*] This PoC demonstrates self defend technique with process mitigation policy.");
            Console.WriteLine("    [*] Process Name : {0}", Process.GetCurrentProcess().ProcessName);
            Console.WriteLine("    [*] Process ID   : {0}", Process.GetCurrentProcess().Id);

            do
            {
                Console.WriteLine("[>] Trying to check current process signature policy.");

                status = NativeMethods.GetProcessMitigationPolicy(
                    Process.GetCurrentProcess().Handle,
                    PROCESS_MITIGATION_POLICY.ProcessSignaturePolicy,
                    pPolicyInfo,
                    nBufferSize);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to update process mitigation policy.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                    break;
                }
                else
                {
                    policy = (PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY)Marshal.PtrToStructure(
                        pPolicyInfo,
                        typeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY));
                    Console.WriteLine("[+] Got current process signature policy.");
                    Console.WriteLine("    [*] ProcessSignaturePolicy : {0}", policy.Flags.ToString());
                    Console.WriteLine("[*] Debug break. Hit [ENTER] to continue this program.");
                    Console.ReadLine();
                }

                policy.Flags = BINARY_SIGNATURE_POLICY_FLAGS.MicrosoftSignedOnly;
                Marshal.StructureToPtr(policy, pPolicyInfo, false);

                Console.WriteLine("[>] Trying to update process mitigation policy.");

                status = NativeMethods.SetProcessMitigationPolicy(
                    PROCESS_MITIGATION_POLICY.ProcessSignaturePolicy,
                    pPolicyInfo,
                    new SIZE_T((uint)nPolicySize));

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to update process mitigation policy.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                }
                else
                {
                    Console.WriteLine("[+] Process signature policy is updated successfully.");
                    Console.WriteLine("[*] Now this process signature policy should be MicrosoftSignedOnly.");
                    Console.WriteLine("[*] Debug break. Hit [ENTER] to exit this program.");
                    Console.ReadLine();
                }
            } while (false);

            Marshal.FreeHGlobal(pPolicyInfo);
            Console.WriteLine();
        }
    }
}
