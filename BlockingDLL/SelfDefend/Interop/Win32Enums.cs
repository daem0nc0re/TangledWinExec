using System;

namespace SelfDefend.Interop
{
    [Flags]
    internal enum ASLR_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        EnableBottomUpRandomization = 0x00000001,
        EnableForceRelocateImages = 0x00000002,
        EnableHighEntropy = 0x00000004,
        DisallowStrippedImages = 0x00000008
    }

    [Flags]
    internal enum BINARY_SIGNATURE_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        MicrosoftSignedOnly = 0x00000001,
        StoreSignedOnly = 0x00000002,
        MitigationOptIn = 0x00000004,
        AuditMicrosoftSignedOnly = 0x00000008,
        AuditStoreSignedOnly = 0x00000010
    }

    [Flags]
    internal enum BOOLEAN : byte
    {
        FALSE,
        TRUE
    }

    [Flags]
    internal enum CONTROL_FLOW_GUARD_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        EnableControlFlowGuard = 0x00000001,
        EnableExportSuppression = 0x00000002,
        StrictMode = 0x00000004,
        EnableXfgy = 0x00000008,
        EnableXfgAuditMode = 0x00000010
    }

    [Flags]
    internal enum DEP_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        Enable = 0x00000001,
        DisableAtlThunkEmulation = 0x00000002
    }

    [Flags]
    internal enum DYNAMIC_CODE_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        ProhibitDynamicCode = 0x00000001,
        AllowThreadOptOut = 0x00000002,
        AllowRemoteDowngrade = 0x00000004,
        AuditProhibitDynamicCode = 0x00000008
    }

    [Flags]
    internal enum EXTENSION_POINT_DISABLE_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        DisableExtensionPoints = 0x00000001
    }

    [Flags]
    internal enum FONT_DISABLE_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        DisableNonSystemFonts = 0x00000001,
        AuditNonSystemFontLoading = 0x00000002
    }

    [Flags]
    internal enum FormatMessageFlags : uint
    {
        FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
        FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200,
        FORMAT_MESSAGE_FROM_STRING = 0x00000400,
        FORMAT_MESSAGE_FROM_HMODULE = 0x00000800,
        FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
        FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
    }

    [Flags]
    internal enum IMAGE_LOAD_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        NoRemoteImages = 0x00000001,
        NoLowMandatoryLabelImages = 0x00000002,
        PreferSystem32Images = 0x00000004,
        AuditNoRemoteImages = 0x00000008,
        AuditNoLowMandatoryLabelImages = 0x00000010
    }

    internal enum PROCESS_MITIGATION_POLICY : uint
    {
        ProcessDEPPolicy,
        ProcessASLRPolicy,
        ProcessDynamicCodePolicy,
        ProcessStrictHandleCheckPolicy,
        ProcessSystemCallDisablePolicy,
        ProcessMitigationOptionsMask,
        ProcessExtensionPointDisablePolicy,
        ProcessControlFlowGuardPolicy,
        ProcessSignaturePolicy,
        ProcessFontDisablePolicy,
        ProcessImageLoadPolicy,
        ProcessSystemCallFilterPolicy,
        ProcessPayloadRestrictionPolicy,
        ProcessChildProcessPolicy,
        ProcessSideChannelIsolationPolicy,
        ProcessUserShadowStackPolicy,
        ProcessRedirectionTrustPolicy,
        ProcessUserPointerAuthPolicy,
        ProcessSEHOPPolicy,
        MaxProcessMitigationPolicy
    }

    [Flags]
    internal enum REDIRECTION_TRUST_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        EnforceRedirectionTrust = 0x00000001,
        AuditRedirectionTrust = 0x00000002
    }

    [Flags]
    internal enum SIDE_CHANNEL_ISOLATION_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        SmtBranchTargetIsolation = 0x00000001,
        IsolateSecurityDomain = 0x00000002,
        DisablePageCombine = 0x00000004,
        SpeculativeStoreBypassDisable = 0x00000008,
        RestrictCoreSharing = 0x00000010
    }

    [Flags]
    internal enum STRICT_HANDLE_CHECK_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        RaiseExceptionOnInvalidHandleReference = 0x00000001,
        HandleExceptionsPermanentlyEnabled = 0x00000002
    }

    [Flags]
    internal enum SYSTEM_CALL_DISABLE_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        DisallowWin32kSystemCalls = 0x00000001,
        AuditDisallowWin32kSystemCalls = 0x00000002
    }

    [Flags]
    internal enum USER_SHADOW_STACK_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        EnableUserShadowStack = 0x00000001,
        AuditUserShadowStack = 0x00000002,
        SetContextIpValidation = 0x00000004,
        AuditSetContextIpValidation = 0x00000008,
        EnableUserShadowStackStrictMode = 0x00000010,
        BlockNonCetBinaries = 0x00000020,
        BlockNonCetBinariesNonEhcont = 0x00000040,
        AuditBlockNonCetBinaries = 0x00000080,
        CetDynamicApisOutOfProcOnly = 0x00000100,
        SetContextIpValidationRelaxedMode = 0x00000200
    }
}
