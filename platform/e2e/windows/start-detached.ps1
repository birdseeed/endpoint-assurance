<#
.SYNOPSIS
  Start a long-running E2E process that outlives the workflow step that
  started it. Returns the PID of the started executable.

.DESCRIPTION
  PAT-1744: processes launched with Start-Process from a GitHub Actions step
  on windows-latest are gone by the next step. patched-api passed its /health
  check inside its own start step, then refused connections from the next one
  with a clean log and nothing on stderr, with and without -NoNewWindow. The
  runner tears down the step's process tree when the step ends.

  Win32_Process.Create starts the process from the WMI provider host, outside
  the step's process tree, so it survives. That process does not inherit the
  step's environment: it gets the user and Machine-scope environment only.
  Anything the process needs beyond that (including Machine-scope variables
  written earlier in the same job, which provision.ps1 relies on) must be
  passed in -Environment.

  The executable runs under a cmd.exe wrapper written to RUNNER_TEMP (never to
  artifacts/, which is uploaded), with stdout and stderr redirected to
  <LogDir>\<Name>.log and <LogDir>\<Name>-err.log. When the executable exits
  the wrapper appends its exit code to the -err log, so a crash can be told
  apart from a kill.

.PARAMETER Name
  Log and wrapper base name, e.g. patched-api.

.PARAMETER FilePath
  Executable to run.

.PARAMETER Environment
  Variables to set for the process. Names must be identifiers; values must
  not contain characters cmd.exe would interpret (" % ^ & | < > or newlines).
  The script throws rather than escaping them.

.PARAMETER LogDir
  Existing directory for the stdout/stderr logs.
#>
param(
    [Parameter(Mandatory)] [string]    $Name,
    [Parameter(Mandatory)] [string]    $FilePath,
    [Parameter(Mandatory)] [hashtable] $Environment,
    [Parameter(Mandatory)] [string]    $LogDir
)

$ErrorActionPreference = 'Stop'

$exe    = (Resolve-Path $FilePath).Path
$logDir = (Resolve-Path $LogDir).Path
$log    = Join-Path $logDir "$Name.log"
$errLog = Join-Path $logDir "$Name-err.log"

$lines = @('@echo off')
foreach ($key in $Environment.Keys) {
    $value = [string]$Environment[$key]
    if ($key -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
        throw "start-detached: invalid environment variable name '$key' for $Name"
    }
    if ($value -match '["%^&|<>\r\n]') {
        throw "start-detached: value of $key for $Name contains a character cmd.exe would interpret"
    }
    $lines += "set `"$key=$value`""
}
$lines += "`"$exe`" > `"$log`" 2> `"$errLog`""
$lines += "echo exited with code %ERRORLEVEL%>> `"$errLog`""

$wrapper = Join-Path $env:RUNNER_TEMP "start-$Name.cmd"
Set-Content -Path $wrapper -Value $lines -Encoding ascii

$result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine      = "cmd.exe /d /c `"$wrapper`""
    CurrentDirectory = (Get-Location).Path
}
if ($result.ReturnValue -ne 0) {
    throw "start-detached: Win32_Process.Create failed for $Name (ReturnValue $($result.ReturnValue))"
}

$exeName = [System.IO.Path]::GetFileName($exe)
$child = $null
for ($i = 0; $i -lt 40 -and -not $child; $i++) {
    $child = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($result.ProcessId) AND Name='$exeName'" |
        Select-Object -First 1
    if (-not $child) { Start-Sleep -Milliseconds 250 }
}
if (-not $child) {
    Get-Content $errLog -ErrorAction SilentlyContinue | Select-Object -Last 20 | Write-Host
    throw "start-detached: $Name did not start (wrapper PID $($result.ProcessId))"
}

return [int]$child.ProcessId
