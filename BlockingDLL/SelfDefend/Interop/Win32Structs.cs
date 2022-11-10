using System.Runtime.InteropServices;

namespace SelfDefend.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_ASLR_POLICY
    {
        public ASLR_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
    {
        public BINARY_SIGNATURE_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
    {
        public CONTROL_FLOW_GUARD_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_DEP_POLICY
    {
        public DEP_POLICY_FLAGS Flags;
        public BOOLEAN Permanent;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
    {
        public DYNAMIC_CODE_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
    {
        public EXTENSION_POINT_DISABLE_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_FONT_DISABLE_POLICY
    {
        public FONT_DISABLE_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_IMAGE_LOAD_POLICY
    {
        public IMAGE_LOAD_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_POLICY_INFORMATION
    {
        public PROCESS_MITIGATION_POLICY Policy;
        public PROCESS_MITIGATION_POLICY_INFORMATION_UNION Information;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct PROCESS_MITIGATION_POLICY_INFORMATION_UNION
    {
        [FieldOffset(0)]
        public PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;

        [FieldOffset(0)]
        public PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;

        [FieldOffset(0)]
        public PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;

        [FieldOffset(0)]
        public PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;

        [FieldOffset(0)]
        public PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;

        [FieldOffset(0)]
        public PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;

        [FieldOffset(0)]
        public PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignaturePolicy;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY
    {
        public REDIRECTION_TRUST_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY
    {
        public SIDE_CHANNEL_ISOLATION_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
    {
        public STRICT_HANDLE_CHECK_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
    {
        public SYSTEM_CALL_DISABLE_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY
    {
        public USER_SHADOW_STACK_POLICY_FLAGS Flags;
    }
}
