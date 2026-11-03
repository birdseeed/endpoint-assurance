[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$Sha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^\\/\r\n]+$')]
    [string]$Artifact,

    [Parameter()]
    [string]$OutputPath = 'SHA256SUMS'
)

# SHA256SUMS is consumed on macOS with `shasum -a 256 -c`. Write its bytes
# directly: PowerShell's text writers use the Windows newline convention even
# with utf8NoBOM, which leaves the filename suffixed with a carriage return.
$manifest = "$($Sha256.ToLowerInvariant())  $Artifact`n"
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllBytes($OutputPath, $utf8NoBom.GetBytes($manifest))
