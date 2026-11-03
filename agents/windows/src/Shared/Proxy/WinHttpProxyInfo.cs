using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Patched.Shared.Proxy;

/// <summary>
/// P/Invoke wrappers over winhttp.dll for resolving the system (WinINet) proxy
/// configuration and evaluating a PAC file for a given target URL (PAT-309).
///
/// This is the Windows analogue of the macOS <c>scutil --proxy</c> read, except
/// WinHTTP can also evaluate PAC (proxy auto-config) scripts in-process — which
/// Apple's stock python could not — so PAC users get full support here.
///
/// The string members of the WinHTTP structs are <see cref="IntPtr"/> buffers
/// that WinHTTP allocates with GlobalAlloc. We read them with
/// <see cref="Marshal.PtrToStringUni(IntPtr)"/> and free them with
/// <c>GlobalFree</c> in a finally block so the session handle and these buffers
/// never leak.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WinHttpProxyInfo
{
    /// <summary>
    /// Resolved system proxy for a single target URL.
    /// <paramref name="ProxyServer"/> is the WinHTTP proxy string
    /// ("host:port" or "http=host:port;https=host:port"), empty/null for direct.
    /// <paramref name="IsPacBased"/> is true when the value came from evaluating
    /// a PAC URL (auto-config), false when it came from static IE/WinINet settings.
    /// </summary>
    public sealed record SystemProxyInfo(string? ProxyServer, string? ProxyBypass, bool IsPacBased);

    /// <summary>
    /// Resolve the system proxy for <paramref name="targetUrl"/>.
    /// Returns null only on a hard failure (caller treats null as "direct").
    ///
    /// Resolution order mirrors WinHTTP semantics:
    ///   1. If WinINet has a static proxy, use it.
    ///   2. Else if WinINet has a PAC (auto-config) URL or auto-detect, evaluate
    ///      it for the target URL via WinHttpGetProxyForUrl.
    ///   3. Else direct (null/empty proxy).
    /// </summary>
    public static SystemProxyInfo? GetSystemProxy(string targetUrl)
    {
        var ieConfig = new WINHTTP_CURRENT_USER_IE_PROXY_CONFIG();
        bool gotIeConfig = WinHttpGetIEProxyConfigForCurrentUser(ref ieConfig);

        try
        {
            if (gotIeConfig)
            {
                string? staticProxy = Marshal.PtrToStringUni(ieConfig.lpszProxy);
                string? staticBypass = Marshal.PtrToStringUni(ieConfig.lpszProxyBypass);
                string? autoConfigUrl = Marshal.PtrToStringUni(ieConfig.lpszAutoConfigUrl);

                // 1. Static proxy wins — no PAC evaluation needed.
                if (!string.IsNullOrWhiteSpace(staticProxy))
                {
                    return new SystemProxyInfo(staticProxy, staticBypass, IsPacBased: false);
                }

                // 2. Auto-detect or explicit PAC URL — evaluate the PAC.
                if (ieConfig.fAutoDetect || !string.IsNullOrWhiteSpace(autoConfigUrl))
                {
                    var pac = EvaluatePac(targetUrl, autoConfigUrl, ieConfig.fAutoDetect);
                    if (pac is not null)
                        return pac;
                }

                // 3. Nothing usable → direct.
                return new SystemProxyInfo(null, staticBypass, IsPacBased: false);
            }

            return new SystemProxyInfo(null, null, IsPacBased: false);
        }
        finally
        {
            // The IE proxy config struct strings are GlobalAlloc'd by WinHTTP.
            FreeIfNotNull(ieConfig.lpszAutoConfigUrl);
            FreeIfNotNull(ieConfig.lpszProxy);
            FreeIfNotNull(ieConfig.lpszProxyBypass);
        }
    }

    private static SystemProxyInfo? EvaluatePac(string targetUrl, string? autoConfigUrl, bool autoDetect)
    {
        IntPtr session = WinHttpOpen(
            "PatchedAgent/1.0",
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);

        if (session == IntPtr.Zero)
            return null;

        var autoProxyOptions = new WINHTTP_AUTOPROXY_OPTIONS();
        var proxyInfo = new WINHTTP_PROXY_INFO();

        try
        {
            if (!string.IsNullOrWhiteSpace(autoConfigUrl))
            {
                autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
                autoProxyOptions.lpszAutoConfigUrl = autoConfigUrl;
            }
            else if (autoDetect)
            {
                autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
                autoProxyOptions.dwAutoDetectFlags =
                    WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
            }
            else
            {
                return null;
            }

            // Auto-logon at the lowest level keeps credentials out of PAC fetches.
            autoProxyOptions.fAutoLogonIfChallenged = true;

            if (!WinHttpGetProxyForUrl(session, targetUrl, ref autoProxyOptions, ref proxyInfo))
                return null;

            string? proxy = Marshal.PtrToStringUni(proxyInfo.lpszProxy);
            string? bypass = Marshal.PtrToStringUni(proxyInfo.lpszProxyBypass);

            // dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY means the PAC said "DIRECT".
            if (proxyInfo.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY
                || string.IsNullOrWhiteSpace(proxy))
            {
                return new SystemProxyInfo(null, bypass, IsPacBased: true);
            }

            return new SystemProxyInfo(proxy, bypass, IsPacBased: true);
        }
        finally
        {
            // WINHTTP_PROXY_INFO strings are GlobalAlloc'd by WinHTTP.
            FreeIfNotNull(proxyInfo.lpszProxy);
            FreeIfNotNull(proxyInfo.lpszProxyBypass);
            WinHttpCloseHandle(session);
        }
    }

    private static void FreeIfNotNull(IntPtr p)
    {
        if (p != IntPtr.Zero)
            GlobalFree(p);
    }

    // -------------------------------------------------------------------------
    // P/Invoke — winhttp.dll
    // -------------------------------------------------------------------------

    private const int WINHTTP_ACCESS_TYPE_NO_PROXY = 1;
    private const string? WINHTTP_NO_PROXY_NAME = null;
    private const string? WINHTTP_NO_PROXY_BYPASS = null;

    private const uint WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001;
    private const uint WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002;

    private const uint WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001;
    private const uint WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002;

    // String members are native IntPtr buffers (GlobalAlloc'd by WinHTTP); read
    // via Marshal.PtrToStringUni and freed via GlobalFree. Do NOT declare these
    // as marshalled string — that would copy-and-leak the originals.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINHTTP_CURRENT_USER_IE_PROXY_CONFIG
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool fAutoDetect;
        public IntPtr lpszAutoConfigUrl;
        public IntPtr lpszProxy;
        public IntPtr lpszProxyBypass;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINHTTP_AUTOPROXY_OPTIONS
    {
        public uint dwFlags;
        public uint dwAutoDetectFlags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? lpszAutoConfigUrl;
        public IntPtr lpvReserved;
        public uint dwReserved;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fAutoLogonIfChallenged;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINHTTP_PROXY_INFO
    {
        public uint dwAccessType;
        public IntPtr lpszProxy;
        public IntPtr lpszProxyBypass;
    }

    [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WinHttpGetIEProxyConfigForCurrentUser(
        ref WINHTTP_CURRENT_USER_IE_PROXY_CONFIG config);

    [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr WinHttpOpen(
        string? pszAgentW,
        int dwAccessType,
        string? pszProxyW,
        string? pszProxyBypassW,
        int dwFlags);

    [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WinHttpGetProxyForUrl(
        IntPtr hSession,
        string lpcwszUrl,
        ref WINHTTP_AUTOPROXY_OPTIONS pAutoProxyOptions,
        ref WINHTTP_PROXY_INFO pProxyInfo);

    [DllImport("winhttp.dll", SetLastError = true)]
    private static extern bool WinHttpCloseHandle(IntPtr hInternet);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalFree(IntPtr hMem);
}
