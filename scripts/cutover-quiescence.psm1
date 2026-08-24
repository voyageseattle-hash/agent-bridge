Set-StrictMode -Version Latest

function ConvertTo-AgentBridgeCutoverProcess {
    param(
        [Parameter(Mandatory = $true)]$Process
    )

    return [pscustomobject][ordered]@{
        pid = [int]$Process.ProcessId
        parentPid = [int]$Process.ParentProcessId
        name = [string]$Process.Name
        executablePath = if ($Process.ExecutablePath) { [string]$Process.ExecutablePath } else { $null }
        # Command lines can contain arbitrary provider arguments or secrets.
        # Process identity is enough to prove refusal, so none is projected.
        commandLine = $null
    }
}

function Get-AgentBridgeCutoverProcessSample {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    # Fully qualify the built-in cmdlet. A function from a profile, plugin, or
    # calling test scope must never be able to manufacture an empty inventory.
    $all = @(CimCmdlets\Get-CimInstance Win32_Process -ErrorAction Stop)
    foreach ($process in $all) {
        if ($null -eq $process.ProcessId -or $null -eq $process.ParentProcessId -or [string]::IsNullOrWhiteSpace([string]$process.Name)) {
            throw 'cutover process inventory returned an incomplete process record'
        }
    }

    $children = @{}
    foreach ($process in $all) {
        $key = [string]$process.ParentProcessId
        if (-not $children.ContainsKey($key)) { $children[$key] = @() }
        $children[$key] += $process
    }

    $root = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\', '/')
    $forwardRoot = $root.Replace('\', '/')
    $bridge = @($all | Where-Object {
        if ($_.Name -notmatch '^(?i:node\.exe)$' -or -not $_.CommandLine) { return $false }
        $forwardCommand = $_.CommandLine.Replace('\', '/')
        return $_.CommandLine.IndexOf($root, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $forwardCommand.IndexOf($forwardRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0
    })

    $seen = @{}
    $queue = [Collections.Generic.Queue[object]]::new()
    foreach ($process in @($all | Where-Object { $_.Name -match '^(?i:codex(?:\.exe)?|claude(?:\.exe)?)$' })) {
        $queue.Enqueue($process)
    }
    while ($queue.Count) {
        $process = $queue.Dequeue()
        $key = [string]$process.ProcessId
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $process
        if ($children.ContainsKey($key)) {
            foreach ($child in $children[$key]) { $queue.Enqueue($child) }
        }
    }

    $projectedBridge = @($bridge | Sort-Object ProcessId | Select-Object -First 64 | ForEach-Object {
        ConvertTo-AgentBridgeCutoverProcess -Process $_
    })
    $projectedHosts = @($seen.Values | Sort-Object ProcessId | Select-Object -First 64 | ForEach-Object {
        ConvertTo-AgentBridgeCutoverProcess -Process $_
    })
    return [pscustomobject][ordered]@{
        sampledAt = (Get-Date).ToUniversalTime().ToString('o')
        bridgeProcessCount = $bridge.Count
        hostProcessCount = $seen.Count
        processListTruncated = $bridge.Count -gt $projectedBridge.Count -or $seen.Count -gt $projectedHosts.Count
        bridgeProcesses = $projectedBridge
        hostProcesses = $projectedHosts
    }
}

function Assert-AgentBridgeOperationalQuiescence {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [ValidateRange(1, 10)][int]$Samples = 2,
        [ValidateRange(0, 30000)][int]$IntervalMilliseconds = 1500
    )

    $captured = @()
    try {
        for ($index = 0; $index -lt $Samples; $index++) {
            $captured += Get-AgentBridgeCutoverProcessSample -InstallRoot $InstallRoot
            if ($index + 1 -lt $Samples -and $IntervalMilliseconds -gt 0) {
                Start-Sleep -Milliseconds $IntervalMilliseconds
            }
        }
    } catch {
        throw 'cutover operational-quiescence capture failed; no mutation was authorized'
    }

    $bridgeCount = [int](($captured | Measure-Object -Property bridgeProcessCount -Sum).Sum)
    $hostCount = [int](($captured | Measure-Object -Property hostProcessCount -Sum).Sum)
    if ($bridgeCount -gt 0 -or $hostCount -gt 0) {
        throw "cutover operational quiescence failed: observed $bridgeCount bridge process record(s) and $hostCount Codex/Claude host-family record(s); no mutation was authorized"
    }
    return @($captured)
}

Export-ModuleMember -Function Get-AgentBridgeCutoverProcessSample, Assert-AgentBridgeOperationalQuiescence
