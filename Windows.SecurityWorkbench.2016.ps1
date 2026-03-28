# itinfra7 on GitHub
[CmdletBinding()]
param(
    [switch]$NoGui,
    [switch]$ScanOnly,
    [switch]$PreviewOnly,
    [switch]$Apply,
    [switch]$IncludeDetails,
    [string]$Code,
    [string]$OptionsJson,
    [string]$ConfigPath,
    [string]$ExceptionPath,
    [ValidateSet('None', 'Set', 'Clear', 'Toggle')]
    [string]$ExceptionAction = 'None',
    [string]$OutputPath,
    [switch]$FullCatalogAudit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-WorkbenchDisplayName {
    return 'Windows Security Workbench 2016'
}

function Get-WorkbenchScriptStem {
    $scriptPath = $PSCommandPath
    if (-not $scriptPath -and $MyInvocation.MyCommand.Path) {
        $scriptPath = $MyInvocation.MyCommand.Path
    }

    if ($scriptPath) {
        return [System.IO.Path]::GetFileNameWithoutExtension($scriptPath)
    }

    return 'Windows.SecurityWorkbench.2016'
}

function Test-IsWindows {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return $IsWindows
    }

    return $env:OS -eq 'Windows_NT'
}

function Assert-Windows {
    if (-not (Test-IsWindows)) {
        throw '이 스크립트는 Windows에서만 실행할 수 있습니다.'
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-IsAdministrator)) {
        throw '관리자 권한 PowerShell로 실행해야 합니다.'
    }
}

function Get-StartupLogPath {
    $logName = '{0}.startup.log' -f (Get-WorkbenchScriptStem)
    if ($PSScriptRoot) {
        return (Join-Path -Path $PSScriptRoot -ChildPath $logName)
    }

    return (Join-Path -Path $env:TEMP -ChildPath $logName)
}

function Write-StartupFailure {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [switch]$GuiExpected
    )

    $logPath = Get-StartupLogPath
    $lines = @(
        ('Timestamp: {0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss K'))
        ('PowerShell: {0}' -f $PSVersionTable.PSVersion)
        ('UserInteractive: {0}' -f [Environment]::UserInteractive)
        ('CurrentDirectory: {0}' -f (Get-Location).Path)
        ('ScriptRoot: {0}' -f $PSScriptRoot)
        ('Message: {0}' -f $ErrorRecord.Exception.Message)
        ('Category: {0}' -f $ErrorRecord.CategoryInfo)
        ('Position:')
        ($ErrorRecord.InvocationInfo.PositionMessage | Out-String).TrimEnd()
        ('ScriptStackTrace:')
        ($ErrorRecord.ScriptStackTrace | Out-String).TrimEnd()
        ('ErrorRecord:')
        ($ErrorRecord | Out-String).TrimEnd()
    )

    try {
        $utf8Encoding = New-Object System.Text.UTF8Encoding($true)
        [System.IO.File]::WriteAllLines($logPath, $lines, $utf8Encoding)
    } catch {
    }

    if ($GuiExpected -and [Environment]::UserInteractive) {
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            $message = @(
                'GUI 실행 중 오류가 발생했습니다.'
                ''
                ('로그 파일: {0}' -f $logPath)
                ''
                ('오류: {0}' -f $ErrorRecord.Exception.Message)
            ) -join [Environment]::NewLine
            [void][System.Windows.Forms.MessageBox]::Show(
                $message,
                (Get-WorkbenchDisplayName),
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        } catch {
        }
    }

    try {
        [Console]::Error.WriteLine('실행 실패. 로그 파일: {0}' -f $logPath)
        [Console]::Error.WriteLine($ErrorRecord.Exception.Message)
    } catch {
    }
}

function Test-CommandSafe {
    param([string]$Name)
    return ($null -ne (Get-Command $Name -ErrorAction SilentlyContinue))
}

function Get-PropertyValueSafe {
    param(
        $InputObject,
        [string]$Name,
        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return $InputObject[$Name]
        }

        return $Default
    }

    if ($null -ne $InputObject.PSObject) {
        $property = $InputObject.PSObject.Properties[$Name]
        if ($property) {
            return $property.Value
        }
    }

    return $Default
}

function Get-ResultDataValue {
    param(
        $Result,
        [string]$Name,
        $Default = $null
    )

    $data = Get-PropertyValueSafe -InputObject $Result -Name 'Data' -Default $null
    return (Get-PropertyValueSafe -InputObject $data -Name $Name -Default $Default)
}

function Resolve-ResultDataValue {
    param(
        [hashtable]$Definition,
        $Result,
        [hashtable]$Options,
        [string]$Name,
        $Default = $null
    )

    $value = Get-ResultDataValue -Result $Result -Name $Name -Default $null
    if ($null -ne $value) {
        return $value
    }

    if ($Definition -and $Definition.Detect) {
        try {
            $refreshed = & $Definition.Detect $Definition $Options
            if ($refreshed -and $refreshed.PSObject.Properties['Data']) {
                $Result.Data = ConvertTo-PropertyObject $refreshed.Data
                $value = Get-ResultDataValue -Result $Result -Name $Name -Default $null
                if ($null -ne $value) {
                    return $value
                }
            }
        } catch {
        }
    }

    return $Default
}

function Resolve-ResultDataArray {
    param(
        [hashtable]$Definition,
        $Result,
        [hashtable]$Options,
        [string]$Name
    )

    $value = Resolve-ResultDataValue -Definition $Definition -Result $Result -Options $Options -Name $Name -Default @()
    $items = @()
    foreach ($item in @($value)) {
        $items += ,$item
    }
    return ,$items
}

function Get-RequiredResultDataValue {
    param(
        [hashtable]$Definition,
        $Result,
        [hashtable]$Options,
        [string]$Name
    )

    $sentinel = '__MISSING_RESULT_DATA__'
    $value = Resolve-ResultDataValue -Definition $Definition -Result $Result -Options $Options -Name $Name -Default $sentinel
    if ($value -eq $sentinel) {
        throw ('{0} 처리에 필요한 데이터({1})를 다시 구성하지 못했습니다.' -f $Definition.Code, $Name)
    }

    return $value
}

function Get-RequiredResultDataArray {
    param(
        [hashtable]$Definition,
        $Result,
        [hashtable]$Options,
        [string]$Name
    )

    $items = @()
    foreach ($item in @(Get-RequiredResultDataValue -Definition $Definition -Result $Result -Options $Options -Name $Name)) {
        $items += ,$item
    }
    return ,$items
}

function ConvertFrom-DmtfDateTimeSafe {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    try {
        return [System.Management.ManagementDateTimeConverter]::ToDateTime($Value)
    } catch {
        return $null
    }
}

function Get-Win32ClassInstancesSafe {
    param(
        [string]$ClassName,
        [string]$Filter = ''
    )

    if (Test-CommandSafe -Name 'Get-CimInstance') {
        if ([string]::IsNullOrWhiteSpace($Filter)) {
            return @(Get-CimInstance -ClassName $ClassName -ErrorAction Stop)
        }

        return @(Get-CimInstance -ClassName $ClassName -Filter $Filter -ErrorAction Stop)
    }

    if (Test-CommandSafe -Name 'Get-WmiObject') {
        if ([string]::IsNullOrWhiteSpace($Filter)) {
            return @(Get-WmiObject -Class $ClassName -ErrorAction Stop)
        }

        return @(Get-WmiObject -Class $ClassName -Filter $Filter -ErrorAction Stop)
    }

    throw ('CIM/WMI 클래스를 조회할 수 없습니다: {0}' -f $ClassName)
}

function Get-Win32ClassInstanceSafe {
    param(
        [string]$ClassName,
        [string]$Filter = ''
    )

    return @(Get-Win32ClassInstancesSafe -ClassName $ClassName -Filter $Filter) | Select-Object -First 1
}

function Get-WindowsServerLifecycleMap {
    return @(
        [pscustomobject]@{
            Release            = '2016'
            Label              = 'Windows Server 2016'
            ProductPatterns    = @('Windows Server 2016')
            MinimumBuild       = 14393
            MainstreamEndDate  = [datetime]'2022-01-11'
            SupportEndDate     = [datetime]'2027-01-12'
        }
    )
}

function Resolve-WindowsServerLifecycle {
    param(
        [string]$ProductName,
        [string]$Caption,
        [int]$BuildNumber,
        [string]$InstallationType
    )

    $isServerCandidate = (
        ($ProductName -match 'Server') -or
        ($Caption -match 'Server') -or
        ($InstallationType -match 'Server')
    )

    $entry = $null
    $matchSource = ''
    foreach ($candidate in Get-WindowsServerLifecycleMap) {
        foreach ($pattern in $candidate.ProductPatterns) {
            if ($ProductName -like "*$pattern*") {
                $entry = $candidate
                $matchSource = 'ProductName'
                break
            }

            if ($Caption -like "*$pattern*") {
                $entry = $candidate
                $matchSource = 'Caption'
                break
            }
        }

        if ($entry) {
            break
        }
    }

    if (-not $entry -and $isServerCandidate) {
        foreach ($candidate in Get-WindowsServerLifecycleMap) {
            if ($BuildNumber -eq [int]$candidate.MinimumBuild) {
                $entry = $candidate
                $matchSource = 'BuildNumber'
                break
            }
        }
    }

    return [pscustomobject]@{
        IsServerCandidate = $isServerCandidate
        Entry             = $entry
        MatchSource       = $matchSource
    }
}

function Get-OsContext {
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $operatingSystem = $null
    try {
        $operatingSystem = Get-Win32ClassInstanceSafe -ClassName 'Win32_OperatingSystem'
    } catch {
        $operatingSystem = $null
    }

    $productName = [string](Get-PropertyValueSafe -InputObject $currentVersion -Name 'ProductName' -Default '')
    $caption = [string](Get-PropertyValueSafe -InputObject $operatingSystem -Name 'Caption' -Default $productName)
    $buildText = [string](Get-PropertyValueSafe -InputObject $currentVersion -Name 'CurrentBuildNumber' -Default (Get-PropertyValueSafe -InputObject $operatingSystem -Name 'BuildNumber' -Default '0'))
    $ubrText = [string](Get-PropertyValueSafe -InputObject $currentVersion -Name 'UBR' -Default '0')
    $buildNumber = 0
    $ubr = 0
    [void][int]::TryParse($buildText, [ref]$buildNumber)
    [void][int]::TryParse($ubrText, [ref]$ubr)
    $installationType = [string](Get-PropertyValueSafe -InputObject $currentVersion -Name 'InstallationType' -Default '')
    $displayVersion = [string](Get-PropertyValueSafe -InputObject $currentVersion -Name 'DisplayVersion' -Default '')
    if (-not $displayVersion) {
        $displayVersion = [string](Get-PropertyValueSafe -InputObject $currentVersion -Name 'ReleaseId' -Default '')
    }

    $resolved = Resolve-WindowsServerLifecycle -ProductName $productName -Caption $caption -BuildNumber $buildNumber -InstallationType $installationType
    $entry = $resolved.Entry

    return [pscustomobject]@{
        ProductName       = $productName
        Caption           = $caption
        Version           = [string](Get-PropertyValueSafe -InputObject $operatingSystem -Name 'Version' -Default (Get-PropertyValueSafe -InputObject $currentVersion -Name 'CurrentVersion' -Default ''))
        BuildNumber       = $buildNumber
        UBR               = $ubr
        BuildLabEx        = [string](Get-PropertyValueSafe -InputObject $currentVersion -Name 'BuildLabEx' -Default '')
        DisplayVersion    = $displayVersion
        EditionId         = [string](Get-PropertyValueSafe -InputObject $currentVersion -Name 'EditionID' -Default '')
        InstallationType  = $installationType
        OSArchitecture    = [string](Get-PropertyValueSafe -InputObject $operatingSystem -Name 'OSArchitecture' -Default '')
        InstallDate       = ConvertFrom-DmtfDateTimeSafe -Value ([string](Get-PropertyValueSafe -InputObject $operatingSystem -Name 'InstallDate' -Default ''))
        ComputerName      = $env:COMPUTERNAME
        IsServer          = [bool]$resolved.IsServerCandidate
        Supported         = ($null -ne $entry)
        Release           = if ($entry) { $entry.Release } else { '' }
        ReleaseLabel      = if ($entry) { $entry.Label } else { '' }
        MatchSource       = if ($entry) { $resolved.MatchSource } else { '' }
        MainstreamEndDate = if ($entry) { $entry.MainstreamEndDate } else { $null }
        SupportEndDate    = if ($entry) { $entry.SupportEndDate } else { $null }
        SupportedRange    = 'Windows Server 2016'
        Capabilities      = [ordered]@{
            GetCimInstance      = Test-CommandSafe -Name 'Get-CimInstance'
            GetWmiObject        = Test-CommandSafe -Name 'Get-WmiObject'
            GetLocalUser        = Test-CommandSafe -Name 'Get-LocalUser'
            GetLocalGroupMember = Test-CommandSafe -Name 'Get-LocalGroupMember'
            RenameLocalUser     = Test-CommandSafe -Name 'Rename-LocalUser'
            GetSmbShare         = Test-CommandSafe -Name 'Get-SmbShare'
            GetSmbShareAccess   = Test-CommandSafe -Name 'Get-SmbShareAccess'
            GetMpComputerStatus = Test-CommandSafe -Name 'Get-MpComputerStatus'
            UpdateMpSignature   = Test-CommandSafe -Name 'Update-MpSignature'
            GetWindowsFeature   = Test-CommandSafe -Name 'Get-WindowsFeature'
        }
    }
}

function Format-OsContextDisplayText {
    param($OsContext)

    if ($null -eq $OsContext) {
        return 'OS 감지 정보 없음'
    }

    $releaseText = if ($OsContext.ReleaseLabel) { $OsContext.ReleaseLabel } else { '지원 범위 외 OS' }
    $buildText = if ($OsContext.UBR -gt 0) {
        '{0}.{1}' -f $OsContext.BuildNumber, $OsContext.UBR
    } else {
        [string]$OsContext.BuildNumber
    }
    $supportText = if ($OsContext.Supported) { '지원 대상' } else { '지원 범위 외' }
    return ('OS={0} | 릴리스={1} | 빌드={2} | {3}' -f $OsContext.ProductName, $releaseText, $buildText, $supportText)
}

function Initialize-EnvironmentContext {
    $osContext = Get-OsContext
    $script:State.Environment = @{
        OsContext = $osContext
    }

    Write-ToolLog -Message ('실행 환경 감지: {0}' -f (Format-OsContextDisplayText -OsContext $osContext))
}

function Assert-SupportedServerRelease {
    $osContext = Get-PropertyValueSafe -InputObject $script:State.Environment -Name 'OsContext'
    if ($null -eq $osContext) {
        throw '실행 환경 정보를 확인하지 못했습니다.'
    }

    if (-not $osContext.IsServer) {
        throw ('이 스크립트는 Windows Server에서만 지원합니다. 감지된 OS: {0}' -f $osContext.ProductName)
    }

    if (-not $osContext.Supported) {
        throw ('지원 대상 OS가 아닙니다. 감지된 OS: {0} (빌드 {1}). 지원 범위: {2}' -f $osContext.ProductName, $osContext.BuildNumber, $osContext.SupportedRange)
    }
}

function New-OrderedDictionary {
    return New-Object System.Collections.Specialized.OrderedDictionary
}

function New-ToolState {
    $state = [ordered]@{
        StartedAt            = Get-Date
        ScriptRoot           = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        BackupRoot           = $null
        ReportRoot           = $null
        ExceptionPath        = $null
        Environment          = @{}
        LogLines             = New-Object System.Collections.Generic.List[string]
        Results              = @{}
        Catalog              = @()
        Config               = @{}
        Exceptions           = @{}
        SecurityPolicyCache  = $null
        OptionTextByCode     = @{}
        Gui                  = @{}
    }

    $state.BackupRoot = Join-Path $state.ScriptRoot 'backups'
    $state.ReportRoot = Join-Path $state.ScriptRoot 'reports'
    New-Item -ItemType Directory -Path $state.BackupRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $state.ReportRoot -Force | Out-Null
    return $state
}

$script:State = New-ToolState

function Test-GuiKey {
    param([string]$Key)
    return ($script:State.Gui -is [hashtable] -and $script:State.Gui.ContainsKey($Key) -and $null -ne $script:State.Gui[$Key])
}

function Write-ToolLog {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = '[{0}] [{1}] {2}' -f $timestamp, $Level.ToUpperInvariant(), $Message
    $script:State.LogLines.Add($line) | Out-Null

    if (Test-GuiKey -Key 'LogTextBox') {
        $script:State.Gui['LogTextBox'].AppendText($line + [Environment]::NewLine)
    }

    Write-Verbose $line
}

function ConvertTo-PlainHashtable {
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [hashtable]) {
        $result = @{}
        foreach ($key in $InputObject.Keys) {
            $result[$key] = ConvertTo-PlainHashtable $InputObject[$key]
        }
        return $result
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($key in $InputObject.Keys) {
            $result[$key] = ConvertTo-PlainHashtable $InputObject[$key]
        }
        return $result
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ,(ConvertTo-PlainHashtable $item)
        }
        return ,$items
    }

    $properties = @()
    if ($null -ne $InputObject.PSObject) {
        $properties = @($InputObject.PSObject.Properties)
    }

    if ($properties.Count -gt 0 -and
        $InputObject -isnot [string] -and
        $InputObject -isnot [int] -and
        $InputObject -isnot [long] -and
        $InputObject -isnot [double] -and
        $InputObject -isnot [datetime] -and
        $InputObject -isnot [bool]) {
        $result = @{}
        foreach ($property in $properties) {
            $result[$property.Name] = ConvertTo-PlainHashtable $property.Value
        }
        return $result
    }

    return $InputObject
}

function ConvertTo-PropertyObject {
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [hashtable] -or $InputObject -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            $result[$key] = ConvertTo-PropertyObject $InputObject[$key]
        }
        return [pscustomobject]$result
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ,(ConvertTo-PropertyObject $item)
        }
        return ,$items
    }

    if (
        $null -ne $InputObject.PSObject -and
        $InputObject.PSObject.TypeNames -contains 'System.Management.Automation.PSCustomObject'
    ) {
        $result = [ordered]@{}
        foreach ($property in @($InputObject.PSObject.Properties)) {
            $result[$property.Name] = ConvertTo-PropertyObject $property.Value
        }
        return [pscustomobject]$result
    }

    return $InputObject
}

function Merge-Hashtable {
    param(
        [hashtable]$Base,
        [hashtable]$Override
    )

    $merged = @{}
    if ($Base) {
        foreach ($key in $Base.Keys) {
            $merged[$key] = ConvertTo-PlainHashtable $Base[$key]
        }
    }

    if (-not $Override) {
        return $merged
    }

    foreach ($key in $Override.Keys) {
        if ($merged.ContainsKey($key) -and $merged[$key] -is [hashtable] -and $Override[$key] -is [hashtable]) {
            $merged[$key] = Merge-Hashtable -Base $merged[$key] -Override $Override[$key]
        } else {
            $merged[$key] = ConvertTo-PlainHashtable $Override[$key]
        }
    }

    return $merged
}

function ConvertTo-PrettyJson {
    param($InputObject)
    return (ConvertTo-Json -InputObject $InputObject -Depth 8)
}

function Save-JsonFile {
    param(
        $InputObject,
        [string]$Path
    )

    $json = ConvertTo-PrettyJson $InputObject
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

function Get-DefaultExceptionPath {
    return Join-Path $script:State.ScriptRoot ((Get-WorkbenchScriptStem) + '.exceptions.json')
}

function Initialize-ExceptionState {
    $script:State.ExceptionPath = if ($ExceptionPath) { $ExceptionPath } else { Get-DefaultExceptionPath }
    $script:State.Exceptions = @{}

    if (-not (Test-Path -LiteralPath $script:State.ExceptionPath)) {
        return
    }

    try {
        $raw = Get-Content -LiteralPath $script:State.ExceptionPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return
        }

        $parsed = ConvertTo-PlainHashtable (ConvertFrom-Json -InputObject $raw)
        $items = if ($parsed -is [hashtable] -and $parsed.ContainsKey('Items')) {
            ConvertTo-PlainHashtable $parsed.Items
        } else {
            $parsed
        }

        if ($items -isnot [hashtable]) {
            return
        }

        foreach ($code in $items.Keys) {
            $entry = ConvertTo-PlainHashtable $items[$code]
            if ($entry -isnot [hashtable]) {
                $entry = @{}
            }
            if (-not $entry.ContainsKey('Enabled')) {
                $entry.Enabled = $true
            }
            if ([bool]$entry.Enabled) {
                $script:State.Exceptions[$code] = $entry
            }
        }

        Write-ToolLog -Message ('예외 상태 로드: {0}' -f $script:State.ExceptionPath)
    } catch {
        Write-ToolLog -Level 'WARN' -Message ('예외 상태 파일을 읽지 못했습니다: {0}' -f $_.Exception.Message)
    }
}

function Save-ExceptionState {
    $directory = Split-Path -Path $script:State.ExceptionPath -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    Save-JsonFile -InputObject @{ Items = $script:State.Exceptions } -Path $script:State.ExceptionPath
    Write-ToolLog -Message ('예외 상태 저장: {0}' -f $script:State.ExceptionPath)
}

function New-BackupSession {
    param([string]$Code)

    $name = '{0}_{1:yyyyMMdd_HHmmss}' -f $Code, (Get-Date)
    $path = Join-Path $script:State.BackupRoot $name
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return $path
}

function ConvertTo-RegExePath {
    param([string]$Path)

    if ($Path -like 'Registry::HKEY_LOCAL_MACHINE\*') {
        return $Path -replace '^Registry::HKEY_LOCAL_MACHINE\\', 'HKLM\'
    }

    if ($Path -like 'Registry::HKEY_CURRENT_USER\*') {
        return $Path -replace '^Registry::HKEY_CURRENT_USER\\', 'HKCU\'
    }

    if ($Path -like 'Registry::HKEY_USERS\*') {
        return $Path -replace '^Registry::HKEY_USERS\\', 'HKU\'
    }

    if ($Path -like 'HKLM:\*') {
        return $Path -replace '^HKLM:\\', 'HKLM\'
    }

    if ($Path -like 'HKCU:\*') {
        return $Path -replace '^HKCU:\\', 'HKCU\'
    }

    if ($Path -like 'HKU:\*') {
        return $Path -replace '^HKU:\\', 'HKU\'
    }

    return $Path
}

function Expand-EnvironmentPathSafe {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $Path
    }

    try {
        return [Environment]::ExpandEnvironmentVariables($Path)
    } catch {
        return $Path
    }
}

function Backup-RegistryPath {
    param(
        [string]$Path,
        [string]$BackupDirectory
    )

    $regPath = ConvertTo-RegExePath $Path
    $fileName = ($regPath -replace '[\\/:*?"<>|]', '_') + '.reg'
    $target = Join-Path $BackupDirectory $fileName
    try {
        $exitCode = Invoke-ExternalQuiet -FilePath 'reg.exe' -ArgumentList @('export', $regPath, $target, '/y')
        if ($exitCode -ne 0) {
            Write-ToolLog -Level 'WARN' -Message ('레지스트리 백업 실패: {0} (exit={1})' -f $regPath, $exitCode)
        }
    } catch {
        Write-ToolLog -Level 'WARN' -Message ('레지스트리 백업 실패: {0} ({1})' -f $regPath, $_.Exception.Message)
    }
}

function Backup-FileAcl {
    param(
        [string]$Path,
        [string]$BackupDirectory
    )

    try {
        $acl = Get-Acl -LiteralPath $Path
        $target = Join-Path $BackupDirectory ((Split-Path -Leaf $Path) + '.acl.txt')
        $acl | Format-List * | Out-String | Set-Content -LiteralPath $target -Encoding UTF8
    } catch {
        Write-ToolLog -Level 'WARN' -Message ('ACL 백업 실패: {0} ({1})' -f $Path, $_.Exception.Message)
    }
}

function Backup-CommandOutput {
    param(
        [string]$FileName,
        [scriptblock]$ScriptBlock,
        [string]$BackupDirectory
    )

    try {
        $content = & $ScriptBlock | Out-String
        Set-Content -LiteralPath (Join-Path $BackupDirectory $FileName) -Value $content -Encoding UTF8
    } catch {
        Write-ToolLog -Level 'WARN' -Message ('명령 출력 백업 실패: {0} ({1})' -f $FileName, $_.Exception.Message)
    }
}

function Invoke-ExternalQuiet {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList
    )

    $stdout = Join-Path $env:TEMP ('Windows.SecurityWorkbench_stdout_{0}.log' -f ([guid]::NewGuid().Guid))
    $stderr = Join-Path $env:TEMP ('Windows.SecurityWorkbench_stderr_{0}.log' -f ([guid]::NewGuid().Guid))
    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        return $process.ExitCode
    } finally {
        Remove-Item -LiteralPath $stdout -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stderr -Force -ErrorAction SilentlyContinue
    }
}

function Get-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        if ($item.PSObject.Properties.Name -contains $Name) {
            return $item.$Name
        }
        return $null
    } catch {
        return $null
    }
}

function Ensure-RegistryKeyExists {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path) {
        return
    }

    $regPath = ConvertTo-RegExePath $Path
    if ($regPath -match '^(HKLM|HKCU|HKU)\\.+$') {
        $exitCode = Invoke-ExternalQuiet -FilePath 'reg.exe' -ArgumentList @('add', $regPath, '/f')
        if ($exitCode -eq 0) {
            return
        }
    }

    New-Item -Path $Path -ItemType Key -Force | Out-Null
}

function Ensure-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [ValidateSet('String', 'ExpandString', 'MultiString', 'Binary', 'DWord', 'QWord')]
        [string]$Type,
        $Value
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Ensure-RegistryKeyExists -Path $Path
    }

    $existing = Get-RegistryValueSafe -Path $Path -Name $Name
    if ($null -eq $existing) {
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    } else {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    }
}

function Remove-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        if ((Get-ItemProperty -LiteralPath $Path -ErrorAction Stop).PSObject.Properties.Name -contains $Name) {
            Remove-ItemProperty -LiteralPath $Path -Name $Name -Force
        }
    } catch {
        Write-ToolLog -Level 'WARN' -Message ('레지스트리 값 삭제 실패: {0}\{1} ({2})' -f $Path, $Name, $_.Exception.Message)
    }
}

function Get-LocalUsersSafe {
    if (Test-CommandSafe -Name 'Get-LocalUser') {
        return Get-LocalUser | Sort-Object Name | ForEach-Object {
            [pscustomobject]@{
                Name             = $_.Name
                FullName         = [string](Get-PropertyValueSafe -InputObject $_ -Name 'FullName' -Default '')
                Enabled          = $_.Enabled
                Description      = $_.Description
                PasswordRequired = $_.PasswordRequired
                PasswordExpires  = [bool](Get-PropertyValueSafe -InputObject $_ -Name 'PasswordExpires' -Default $true)
                PasswordLastSet  = $_.PasswordLastSet
                LastLogon        = $_.LastLogon
                SID              = $_.SID.Value
                PrincipalSource  = if ($_.PrincipalSource) { $_.PrincipalSource.ToString() } else { '' }
            }
        }
    }

    Write-ToolLog -Level 'WARN' -Message 'Get-LocalUser 미지원. CIM/WMI fallback으로 로컬 계정을 조회합니다.'
    $accounts = @{}
    $usedAdsiFallback = $false
    try {
        foreach ($account in @(Get-Win32ClassInstancesSafe -ClassName 'Win32_UserAccount' -Filter 'LocalAccount=True')) {
            $name = [string](Get-PropertyValueSafe -InputObject $account -Name 'Name' -Default '')
            if (-not $name) {
                continue
            }

            $accounts[$name] = [ordered]@{
                Name             = $name
                FullName         = [string](Get-PropertyValueSafe -InputObject $account -Name 'FullName' -Default '')
                Enabled          = (-not [bool](Get-PropertyValueSafe -InputObject $account -Name 'Disabled' -Default $false))
                Description      = [string](Get-PropertyValueSafe -InputObject $account -Name 'Description' -Default '')
                PasswordRequired = [bool](Get-PropertyValueSafe -InputObject $account -Name 'PasswordRequired' -Default $false)
                PasswordExpires  = [bool](Get-PropertyValueSafe -InputObject $account -Name 'PasswordExpires' -Default $true)
                PasswordLastSet  = $null
                LastLogon        = $null
                SID              = [string](Get-PropertyValueSafe -InputObject $account -Name 'SID' -Default '')
                PrincipalSource  = 'Local'
            }
        }
    } catch {
        $usedAdsiFallback = $true
        Write-ToolLog -Level 'WARN' -Message ('Win32_UserAccount 조회 실패. ADSI fallback으로 로컬 계정을 조회합니다: {0}' -f $_.Exception.Message)
    }

    if ($accounts.Count -eq 0) {
        $usedAdsiFallback = $true
        try {
            $container = [ADSI]("WinNT://{0}" -f $env:COMPUTERNAME)
            foreach ($child in @($container.psbase.Children)) {
                try {
                    if ([string]$child.SchemaClassName -ne 'User') {
                        continue
                    }
                } catch {
                    continue
                }

                $name = [string](Get-PropertyValueSafe -InputObject $child -Name 'Name' -Default '')
                if (-not $name) {
                    continue
                }

                $flags = 0
                try {
                    $flags = [int](Get-PropertyValueSafe -InputObject $child -Name 'UserFlags' -Default 0)
                } catch {
                    $flags = 0
                }

                $sid = ''
                try {
                    $sidBytes = $child.psbase.InvokeGet('ObjectSID')
                    if ($sidBytes) {
                        $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                    }
                } catch {
                    $sid = ''
                }

                $accounts[$name] = [ordered]@{
                    Name             = $name
                    FullName         = [string](Get-PropertyValueSafe -InputObject $child -Name 'FullName' -Default '')
                    Enabled          = (-not [bool]($flags -band 0x2))
                    Description      = [string](Get-PropertyValueSafe -InputObject $child -Name 'Description' -Default '')
                    PasswordRequired = (-not [bool]($flags -band 0x20))
                    PasswordExpires  = (-not [bool]($flags -band 0x10000))
                    PasswordLastSet  = $null
                    LastLogon        = $null
                    SID              = $sid
                    PrincipalSource  = 'Local'
                }
            }
        } catch {
            throw ('로컬 계정 ADSI 조회 실패: {0}' -f $_.Exception.Message)
        }
    }

    try {
        foreach ($profile in @(Get-Win32ClassInstancesSafe -ClassName 'Win32_NetworkLoginProfile')) {
            $name = [string](Get-PropertyValueSafe -InputObject $profile -Name 'Name' -Default '')
            if (-not $name) {
                continue
            }

            $accountKey = $name
            if (-not $accounts.ContainsKey($accountKey)) {
                $accountLeaf = ($name -split '\\')[-1]
                if ($accounts.ContainsKey($accountLeaf)) {
                    $accountKey = $accountLeaf
                } else {
                    continue
                }
            }

            $passwordAgeValue = Get-PropertyValueSafe -InputObject $profile -Name 'PasswordAge' -Default $null
            $passwordAgeSeconds = $null
            if ($passwordAgeValue -is [TimeSpan]) {
                $passwordAgeSeconds = [double]$passwordAgeValue.TotalSeconds
            } else {
                $passwordAgeText = [string]$passwordAgeValue
                $parsedSeconds = 0.0
                if ([double]::TryParse($passwordAgeText, [ref]$parsedSeconds)) {
                    $passwordAgeSeconds = $parsedSeconds
                } elseif (-not [string]::IsNullOrWhiteSpace($passwordAgeText)) {
                    try {
                        $passwordAgeSeconds = [System.Management.ManagementDateTimeConverter]::ToTimeSpan($passwordAgeText).TotalSeconds
                    } catch {
                        $passwordAgeSeconds = $null
                    }
                }
            }

            if ($null -ne $passwordAgeSeconds -and $passwordAgeSeconds -ge 0) {
                $accounts[$accountKey].PasswordLastSet = (Get-Date).AddSeconds(-1 * [double]$passwordAgeSeconds)
            }

            $accounts[$accountKey].LastLogon = ConvertFrom-DmtfDateTimeSafe -Value ([string](Get-PropertyValueSafe -InputObject $profile -Name 'LastLogon' -Default ''))
        }
    } catch {
        if (-not $usedAdsiFallback) {
            Write-ToolLog -Level 'WARN' -Message ('Win32_NetworkLoginProfile 조회 실패: {0}' -f $_.Exception.Message)
        }
    }

    return @($accounts.Values | Sort-Object Name | ForEach-Object { [pscustomobject]$_ })
}

function Get-LocalGroupMembersSafe {
    param([string]$Group = 'Administrators')

    if (Test-CommandSafe -Name 'Get-LocalGroupMember') {
        return Get-LocalGroupMember -Group $Group | Sort-Object Name | ForEach-Object {
            [pscustomobject]@{
                Name            = $_.Name
                ObjectClass     = $_.ObjectClass.ToString()
                PrincipalSource = if ($_.PrincipalSource) { $_.PrincipalSource.ToString() } else { '' }
                SID             = $_.SID.Value
            }
        }
    }

    Write-ToolLog -Level 'WARN' -Message ('Get-LocalGroupMember 미지원. ADSI fallback으로 그룹 멤버를 조회합니다: {0}' -f $Group)
    $members = @()
    $groupEntry = [ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME, $Group)
    foreach ($member in @($groupEntry.psbase.Invoke('Members'))) {
        $memberType = $member.GetType()
        $adsPath = [string]$memberType.InvokeMember('ADsPath', 'GetProperty', $null, $member, $null)
        $name = [string]$memberType.InvokeMember('Name', 'GetProperty', $null, $member, $null)
        $objectClass = [string]$memberType.InvokeMember('Class', 'GetProperty', $null, $member, $null)
        $domain = ''
        if ($adsPath -match '^WinNT://([^/]+)/') {
            $domain = $Matches[1]
        }

        $fullName = if ($domain) { '{0}\{1}' -f $domain, $name } else { $name }
        $sid = $null
        try {
            $sidBytes = $memberType.InvokeMember('ObjectSID', 'GetProperty', $null, $member, $null)
            if ($sidBytes) {
                $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            }
        } catch {
            $sid = $null
        }

        if (-not $sid) {
            $sid = Resolve-AccountToSid -Account $fullName
        }

        $members += [pscustomobject]@{
            Name            = $fullName
            ObjectClass     = $objectClass
            PrincipalSource = if ($domain -and $domain.ToUpperInvariant() -ne $env:COMPUTERNAME.ToUpperInvariant()) { 'Domain' } else { 'Local' }
            SID             = $sid
        }
    }

    return @($members | Sort-Object Name)
}

function Get-BuiltinAdministratorUser {
    $users = Get-LocalUsersSafe
    foreach ($user in $users) {
        if ($user.SID -match '-500$') {
            return $user
        }
    }

    return $null
}

function Get-RemoteDesktopServiceState {
    $service = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
    if (-not $service) {
        return [pscustomobject]@{
            Exists    = $false
            Running   = $false
            Status    = 'NotInstalled'
            StartMode = 'Unknown'
        }
    }

    $serviceCim = Get-Win32ClassInstanceSafe -ClassName 'Win32_Service' -Filter "Name='TermService'"
    return [pscustomobject]@{
        Exists    = $true
        Running   = ($service.Status -eq 'Running')
        Status    = [string]$service.Status
        StartMode = if ($serviceCim) { [string]$serviceCim.StartMode } else { 'Unknown' }
    }
}

function Get-LocalUserByLeafName {
    param(
        [array]$Users,
        [string]$Name
    )

    foreach ($user in @($Users)) {
        if ($user.Name -ieq $Name) {
            return $user
        }
    }

    return $null
}

function Get-LocalUserBySid {
    param(
        [array]$Users,
        [string]$Sid
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) {
        return $null
    }

    foreach ($user in @($Users)) {
        if ($user.SID -eq $Sid) {
            return $user
        }
    }

    return $null
}

function Test-StringMatchesPatternList {
    param(
        [string]$Value,
        [string[]]$Patterns
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or @($Patterns).Count -eq 0) {
        return $false
    }

    $leaf = ($Value -split '\\')[-1]
    foreach ($pattern in @($Patterns)) {
        if ([string]::IsNullOrWhiteSpace($pattern)) {
            continue
        }

        if ($Value -like $pattern -or $leaf -like $pattern) {
            return $true
        }
    }

    return $false
}

function Get-EffectiveAllowedAdministratorNames {
    param(
        [hashtable]$Options,
        $BuiltinAdmin = $null
    )

    $allowed = @($Options.AllowedAdministrators)
    if ($BuiltinAdmin) {
        $allowed += $BuiltinAdmin.Name
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Options.RenameBuiltinAdministratorTo)) {
        $allowed += [string]$Options.RenameBuiltinAdministratorTo
    }

    return @($allowed | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
}

function Get-AdministratorMemberStates {
    param(
        [array]$Administrators,
        [array]$Users,
        [hashtable]$Options
    )

    $states = @()
    foreach ($member in @($Administrators)) {
        $localUser = Get-LocalUserBySid -Users $Users -Sid $member.SID
        if (-not $localUser) {
            $localUser = Get-LocalUserByLeafName -Users $Users -Name (($member.Name -split '\\')[-1])
        }

        $displayName = [string]$member.Name
        if ($localUser) {
            if ($member.Name -match '^(.*)\\') {
                $displayName = '{0}\{1}' -f $Matches[1], $localUser.Name
            } else {
                $displayName = [string]$localUser.Name
            }
        }

        $leaf = ($displayName -split '\\')[-1]
        if (Test-StringMatchesPatternList -Value $leaf -Patterns @($Options.ExcludeUsers)) {
            continue
        }

        $enabled = $true
        $fullName = ''
        $description = ''
        if ($localUser) {
            $enabled = [bool]$localUser.Enabled
            $fullName = [string]$localUser.FullName
            $description = [string]$localUser.Description
        }

        $states += [pscustomobject]@{
            Name            = $displayName
            LeafName        = $leaf
            SID             = $member.SID
            PrincipalSource = $member.PrincipalSource
            Enabled         = $enabled
            FullName        = $fullName
            Description     = $description
        }
    }

    return $states
}

function Disable-LocalUserSafe {
    param([string]$Name)
    if (Get-Command Disable-LocalUser -ErrorAction SilentlyContinue) {
        Disable-LocalUser -Name $Name
    } else {
        & net.exe user $Name /active:no | Out-Null
    }
}

function Rename-LocalUserSafe {
    param(
        [string]$OldName,
        [string]$NewName
    )

    if ($OldName -eq $NewName) {
        return
    }

    if (Test-CommandSafe -Name 'Rename-LocalUser') {
        Rename-LocalUser -Name $OldName -NewName $NewName
        return
    }

    $wmicCommand = Get-Command wmic.exe -ErrorAction SilentlyContinue
    if ($wmicCommand) {
        $wmicPath = if ($wmicCommand.Path) { $wmicCommand.Path } else { $wmicCommand.Definition }
        $escapedOldName = $OldName.Replace("'", "''")
        $escapedComputer = $env:COMPUTERNAME.Replace("'", "''")
        foreach ($filter in @(
            ("name='{0}' and localaccount='true'" -f $escapedOldName),
            ("name='{0}' and domain='{1}'" -f $escapedOldName, $escapedComputer)
        )) {
            & $wmicPath useraccount where $filter rename $NewName | Out-Null
            if ($LASTEXITCODE -eq 0) {
                return
            }
        }
    }

    try {
        $container = [ADSI]("WinNT://{0}" -f $env:COMPUTERNAME)
        $user = [ADSI]("WinNT://{0}/{1},user" -f $env:COMPUTERNAME, $OldName)
        [void]$container.psbase.MoveHere($user.psbase.Path, $NewName)
    } catch {
        throw ('Rename-LocalUser fallback 실패: {0}' -f $_.Exception.Message)
    }
}

function Remove-LocalAdminMemberSafe {
    param([string]$Member)

    if (Get-Command Remove-LocalGroupMember -ErrorAction SilentlyContinue) {
        Remove-LocalGroupMember -Group 'Administrators' -Member $Member -ErrorAction Stop
    } else {
        & net.exe localgroup Administrators $Member /delete | Out-Null
    }
}

function Add-LocalAdminMemberSafe {
    param([string]$Member)

    if (Get-Command Add-LocalGroupMember -ErrorAction SilentlyContinue) {
        Add-LocalGroupMember -Group 'Administrators' -Member $Member -ErrorAction Stop
    } else {
        & net.exe localgroup Administrators $Member /add | Out-Null
    }
}

function Clear-SecurityPolicyCache {
    $script:State.SecurityPolicyCache = $null
}

function Get-SecurityPolicySnapshot {
    if ($script:State.SecurityPolicyCache) {
        return $script:State.SecurityPolicyCache
    }

    $cfg = Join-Path $env:TEMP ('Windows.SecurityWorkbench_secpol_{0}.inf' -f ([guid]::NewGuid().Guid))
    & secedit /export /cfg $cfg /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'secedit /export 실행에 실패했습니다.'
    }

    $sections = @{}
    $currentSection = $null
    foreach ($line in Get-Content -LiteralPath $cfg) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith(';')) {
            continue
        }

        if ($trimmed -match '^\[(.+)\]$') {
            $currentSection = $Matches[1]
            if (-not $sections.ContainsKey($currentSection)) {
                $sections[$currentSection] = @{}
            }
            continue
        }

        if ($currentSection -and $trimmed -match '^(.*?)\s*=\s*(.*)$') {
            $name = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            $sections[$currentSection][$name] = $value
        }
    }

    Remove-Item -LiteralPath $cfg -Force -ErrorAction SilentlyContinue
    $script:State.SecurityPolicyCache = $sections
    return $sections
}

function Get-SecurityPolicyValue {
    param(
        [string]$Section,
        [string]$Name,
        $Default = $null
    )

    $snapshot = Get-SecurityPolicySnapshot
    if ($snapshot.ContainsKey($Section) -and $snapshot[$Section].ContainsKey($Name)) {
        return $snapshot[$Section][$Name]
    }

    return $Default
}

function Get-W0504DefaultNotice {
    return @{
        Caption = '경고: 인가된 사용자만 접근할 수 있습니다'
        Text    = '이 시스템은 인가된 사용자만 사용할 수 있습니다. 허가되지 않은 접근 및 사용은 금지되며, 접속 및 작업 내역은 기록 및 모니터링될 수 있습니다. 계속 진행하면 관련 보안정책에 동의한 것으로 간주됩니다.'
    }
}

function Import-SecurityPolicyTemplate {
    param(
        [hashtable]$Sections,
        [string]$Area = 'SECURITYPOLICY'
    )

    $templatePath = Join-Path $env:TEMP ('Windows.SecurityWorkbench_apply_{0}.inf' -f ([guid]::NewGuid().Guid))
    $dbPath = Join-Path $env:TEMP ('Windows.SecurityWorkbench_apply_{0}.sdb' -f ([guid]::NewGuid().Guid))
    $lines = @(
        '[Unicode]',
        'Unicode=yes',
        '',
        '[Version]',
        'signature="$CHICAGO$"',
        'Revision=1',
        ''
    )

    foreach ($sectionName in $Sections.Keys) {
        $lines += "[{0}]" -f $sectionName
        foreach ($key in $Sections[$sectionName].Keys) {
            $lines += '{0} = {1}' -f $key, $Sections[$sectionName][$key]
        }
        $lines += ''
    }

    Set-Content -LiteralPath $templatePath -Value $lines -Encoding Unicode
    & secedit /configure /db $dbPath /cfg $templatePath /areas $Area /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw ('secedit /configure 실패: area={0}' -f $Area)
    }

    Remove-Item -LiteralPath $templatePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $dbPath -Force -ErrorAction SilentlyContinue
    Clear-SecurityPolicyCache
}

function Get-RegistryRuleStates {
    param([array]$Rules)

    $states = @()
    foreach ($rule in $Rules) {
        $current = Get-RegistryValueSafe -Path $rule.Path -Name $rule.Name
        $compliant = $false
        switch ($rule.Comparison) {
            'eq' { $compliant = ($current -eq $rule.Expected) }
            'ge' {
                $currentNumber = if ($null -eq $current) { $null } else { [double]$current }
                $compliant = ($null -ne $currentNumber -and $currentNumber -ge [double]$rule.Expected)
            }
            'le' {
                $currentNumber = if ($null -eq $current) { $null } else { [double]$current }
                $compliant = ($null -ne $currentNumber -and $currentNumber -le [double]$rule.Expected)
            }
            'absent' { $compliant = ($null -eq $current) }
            'nonempty' { $compliant = (-not [string]::IsNullOrWhiteSpace([string]$current)) }
            default { throw ('지원하지 않는 비교 방식: {0}' -f $rule.Comparison) }
        }

        $states += [pscustomobject]@{
            Path        = $rule.Path
            Name        = $rule.Name
            Description = $rule.Description
            Current     = $current
            Expected    = $rule.Expected
            Type        = $rule.Type
            Compliant   = $compliant
            Comparison  = $rule.Comparison
        }
    }

    return $states
}

function Invoke-RegistryRemediation {
    param(
        [array]$Rules,
        [string]$BackupDirectory
    )

    $backedUpPaths = @{}
    foreach ($rule in $Rules) {
        if (-not $backedUpPaths.ContainsKey($rule.Path)) {
            Backup-RegistryPath -Path $rule.Path -BackupDirectory $BackupDirectory
            $backedUpPaths[$rule.Path] = $true
        }

        switch ($rule.Comparison) {
            'absent' {
                Remove-RegistryValueSafe -Path $rule.Path -Name $rule.Name
            }
            default {
                Ensure-RegistryValue -Path $rule.Path -Name $rule.Name -Type $rule.Type -Value $rule.Expected
            }
        }
    }
}

function New-CheckResult {
    param(
        [hashtable]$Definition,
        [string]$Status,
        [string]$Summary,
        [string]$Details,
        [object]$Data = $null,
        [bool]$CanAutoRemediate = $false
    )

    return [pscustomobject]@{
        Code              = $Definition.Code
        Title             = $Definition.Title
        Category          = $Definition.Category
        Severity          = $Definition.Severity
        Status            = $Status
        Summary           = $Summary
        Details           = $Details
        Data              = (ConvertTo-PropertyObject $Data)
        CanAutoRemediate  = $CanAutoRemediate
        CheckedAt         = Get-Date
        OriginalStatus    = $Status
        OriginalSummary   = $Summary
        IsException       = $false
        ExceptionReason   = ''
        ExceptionAt       = $null
    }
}

function New-PlanResult {
    param(
        [hashtable]$Definition,
        [bool]$AutoSupported,
        [string[]]$Changes,
        [string]$Impact,
        [string]$ExpectedStatus,
        [bool]$RequiresRestart = $false,
        [string]$Notes = ''
    )

    return [pscustomobject]@{
        Code            = $Definition.Code
        Title           = $Definition.Title
        AutoSupported   = $AutoSupported
        Changes         = $Changes
        Impact          = $Impact
        ExpectedStatus  = $ExpectedStatus
        RequiresRestart = $RequiresRestart
        Notes           = $Notes
    }
}

function Resolve-AccountToSid {
    param([string]$Account)

    try {
        $nt = New-Object System.Security.Principal.NTAccount($Account)
        return $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}

function Get-WellKnownSidValue {
    param(
        [ValidateSet('WorldSid')]
        [string]$Name
    )

    switch ($Name) {
        'WorldSid' {
            return (New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)).Value
        }
    }
}

function Get-IdentityReferenceSidValue {
    param($IdentityReference)

    if ($null -eq $IdentityReference) {
        return $null
    }

    try {
        if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
            return $IdentityReference.Value
        }

        return $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        try {
            return (Resolve-AccountToSid -Account ([string]$IdentityReference))
        } catch {
            return $null
        }
    }
}

function ConvertTo-RegistryRightsValue {
    param([string]$Value)
    return [System.Security.AccessControl.RegistryRights]$Value
}

function ConvertTo-AuditFlagsValue {
    param([string[]]$Values)

    $combined = [System.Security.AccessControl.AuditFlags]::None
    foreach ($value in @($Values)) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $combined = $combined -bor ([System.Security.AccessControl.AuditFlags]$value)
        }
    }

    return $combined
}

function ConvertTo-InheritanceFlagsValue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return [System.Security.AccessControl.InheritanceFlags]::None
    }

    return [System.Security.AccessControl.InheritanceFlags]$Value
}

function ConvertTo-PropagationFlagsValue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return [System.Security.AccessControl.PropagationFlags]::None
    }

    return [System.Security.AccessControl.PropagationFlags]$Value
}

function Get-RegistryAuditRulesSafe {
    param([string]$Path)

    $acl = Get-Acl -Path $Path -Audit -ErrorAction Stop
    return [pscustomobject]@{
        Path  = $Path
        Acl   = $acl
        Rules = @($acl.Audit)
    }
}

function Format-RegistryAuditRuleDetails {
    param([array]$Rules)

    if (@($Rules).Count -eq 0) {
        return '감사 규칙 없음'
    }

    $lines = @()
    foreach ($rule in @($Rules)) {
        $lines += '- {0} / Rights={1} / Flags={2} / Inheritance={3} / Propagation={4}' -f `
            $rule.IdentityReference, $rule.RegistryRights, $rule.AuditFlags, $rule.InheritanceFlags, $rule.PropagationFlags
    }

    return ($lines -join [Environment]::NewLine)
}

function New-RegistryAuditRuleSafe {
    param(
        [string]$Identity,
        [string]$Rights,
        [string[]]$AuditFlags,
        [string]$InheritanceFlags,
        [string]$PropagationFlags
    )

    $identityReference = switch ($Identity) {
        'Everyone' {
            New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        }
        default {
            New-Object System.Security.Principal.NTAccount($Identity)
        }
    }

    return New-Object System.Security.AccessControl.RegistryAuditRule(
        $identityReference,
        (ConvertTo-RegistryRightsValue -Value $Rights),
        (ConvertTo-InheritanceFlagsValue -Value $InheritanceFlags),
        (ConvertTo-PropagationFlagsValue -Value $PropagationFlags),
        (ConvertTo-AuditFlagsValue -Values $AuditFlags)
    )
}

function Test-RegistryAuditRuleMatch {
    param(
        $Rule,
        [string]$IdentitySid,
        [string]$Rights,
        [string[]]$AuditFlags
    )

    $ruleSid = Get-IdentityReferenceSidValue -IdentityReference $Rule.IdentityReference
    $requiredRights = ConvertTo-RegistryRightsValue -Value $Rights
    $requiredFlags = ConvertTo-AuditFlagsValue -Values $AuditFlags
    $flagsOk = (($Rule.AuditFlags -band $requiredFlags) -eq $requiredFlags)
    $rightsOk = (($Rule.RegistryRights -band $requiredRights) -eq $requiredRights)
    return ($ruleSid -eq $IdentitySid -and $flagsOk -and $rightsOk)
}

function Convert-SidListToPolicyString {
    param([string[]]$Sids)
    return (($Sids | Where-Object { $_ } | ForEach-Object { '*{0}' -f $_ }) -join ',')
}

function Split-PolicySidString {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }

    return $Value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { $_ -replace '^\*', '' }
}

function Get-ProfileHiveTargets {
    param(
        [switch]$IncludeDefaultProfile
    )

    $targets = @()
    $profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $defaultProfile = Join-Path $env:SystemDrive 'Users\Default\NTUSER.DAT'
    $disabledLocalSids = @(
        Get-LocalUsersSafe |
        Where-Object { -not $_.Enabled } |
        ForEach-Object { $_.SID }
    )

    foreach ($key in Get-ChildItem -LiteralPath $profileListPath -ErrorAction SilentlyContinue) {
        $sid = Split-Path -Leaf $key.PSChildName
        if ($sid -notmatch '^S-1-5-21-') {
            continue
        }

        if ($disabledLocalSids -contains $sid) {
            continue
        }

        $profilePathRaw = [string](Get-ItemProperty -LiteralPath $key.PSPath).ProfileImagePath
        if ([string]::IsNullOrWhiteSpace($profilePathRaw)) {
            continue
        }

        $profilePath = Expand-EnvironmentPathSafe -Path $profilePathRaw
        $userHive = Join-Path $profilePath 'NTUSER.DAT'
        $loaded = $false
        $hiveName = $sid
        $existingHiveLoaded = Test-Path -LiteralPath ("Registry::HKEY_USERS\{0}" -f $sid)

        if (-not $existingHiveLoaded -and -not (Test-Path -LiteralPath $userHive)) {
            Write-ToolLog -Level 'WARN' -Message ('프로필 하이브를 찾지 못해 대상에서 제외합니다: SID={0}, ProfileImagePath={1}, ExpandedPath={2}' -f $sid, $profilePathRaw, $profilePath)
            continue
        }

        if (-not $existingHiveLoaded) {
            $tempHive = 'Windows.SecurityWorkbench_{0}' -f ([guid]::NewGuid().ToString('N'))
            $exitCode = Invoke-ExternalQuiet -FilePath 'reg.exe' -ArgumentList @('load', ("HKU\{0}" -f $tempHive), $userHive)
            if ($exitCode -eq 0) {
                $loaded = $true
                $hiveName = $tempHive
            } else {
                Write-ToolLog -Level 'WARN' -Message ('프로필 하이브 로드 실패로 대상에서 제외합니다: SID={0}, Hive={1}, exit={2}' -f $sid, $userHive, $exitCode)
                continue
            }
        }

        $targets += [pscustomobject]@{
            Sid         = $sid
            ProfilePath = $profilePath
            ProfilePathRaw = $profilePathRaw
            HiveName    = $hiveName
            HivePath    = "Registry::HKEY_USERS\{0}" -f $hiveName
            Loaded      = $loaded
            UserHive    = $userHive
        }
    }

    if ($IncludeDefaultProfile -and (Test-Path -LiteralPath $defaultProfile)) {
        $tempHive = 'Windows.SecurityWorkbench_Default_{0}' -f ([guid]::NewGuid().ToString('N'))
        $exitCode = Invoke-ExternalQuiet -FilePath 'reg.exe' -ArgumentList @('load', ("HKU\{0}" -f $tempHive), $defaultProfile)
        if ($exitCode -eq 0) {
            $targets += [pscustomobject]@{
                Sid         = '.DEFAULTPROFILE'
                ProfilePath = (Split-Path -Parent $defaultProfile)
                HiveName    = $tempHive
                HivePath    = "Registry::HKEY_USERS\{0}" -f $tempHive
                Loaded      = $true
                UserHive    = $defaultProfile
            }
        }
    }

    return $targets
}

function Normalize-W0502TargetOptions {
    param([hashtable]$Options)

    $normalized = @{}
    foreach ($key in $Options.Keys) {
        $normalized[$key] = $Options[$key]
    }

    if (-not $normalized.ContainsKey('CheckCurrentUser')) {
        $normalized.CheckCurrentUser = $false
    }
    if (-not $normalized.ContainsKey('CheckAllActiveUsers')) {
        $normalized.CheckAllActiveUsers = $false
    }
    if (-not $normalized.ContainsKey('CheckAdministratorsOnly')) {
        $normalized.CheckAdministratorsOnly = $false
    }
    if (-not $normalized.ContainsKey('IncludeUsers') -or $null -eq $normalized.IncludeUsers) {
        $normalized.IncludeUsers = @()
    }
    if (-not $normalized.ContainsKey('ApplyToDefaultProfile')) {
        $normalized.ApplyToDefaultProfile = $false
    }

    $includeUsers = @($normalized.IncludeUsers | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $normalized.IncludeUsers = $includeUsers

    if ($normalized.CheckCurrentUser) {
        $normalized.CheckAllActiveUsers = $false
        $normalized.CheckAdministratorsOnly = $false
        return $normalized
    }

    if ($includeUsers.Count -gt 0) {
        $normalized.CheckAllActiveUsers = $false
        $normalized.CheckAdministratorsOnly = $false
        return $normalized
    }

    if ($normalized.CheckAllActiveUsers) {
        $normalized.CheckAdministratorsOnly = $false
        return $normalized
    }

    if (-not $normalized.CheckAdministratorsOnly) {
        $normalized.CheckAllActiveUsers = $true
    }

    return $normalized
}

function Get-W0502TargetProfileHives {
    param([hashtable]$Options)

    $Options = Normalize-W0502TargetOptions -Options $Options
    $targets = @(Get-ProfileHiveTargets -IncludeDefaultProfile:([bool]$Options.ApplyToDefaultProfile))
    $users = @(Get-LocalUsersSafe | Where-Object { $_.Enabled })
    $adminLeafNames = @((Get-LocalGroupMembersSafe -Group 'Administrators') | ForEach-Object { ($_.Name -split '\\')[-1] } | Sort-Object -Unique)
    $targetUsers = @($users | Where-Object {
        if ($Options.CheckCurrentUser) {
            return ($_.Name -ieq $env:USERNAME)
        }

        if (@($Options.IncludeUsers).Count -gt 0) {
            return ($Options.IncludeUsers -contains $_.Name)
        }

        if ($Options.CheckAllActiveUsers) {
            return $true
        }

        if ($Options.CheckAdministratorsOnly) {
            return ($adminLeafNames -contains $_.Name)
        }

        return $true
    })

    $targetSids = @($targetUsers | ForEach-Object { $_.SID })
    return @($targets | Where-Object { $_.Sid -in $targetSids })
}

function Get-W0502ScopeDescription {
    param([hashtable]$Options)

    $Options = Normalize-W0502TargetOptions -Options $Options
    $suffix = if ([bool]$Options.ApplyToDefaultProfile) { ' + 신규 계정 기본 프로필' } else { '' }
    if ($Options.CheckCurrentUser) {
        return ('현재 사용자만 적용{0}' -f $suffix)
    }

    if (@($Options.IncludeUsers).Count -gt 0) {
        return ('특정 계정만 적용: {0}{1}' -f (Format-StringList $Options.IncludeUsers), $suffix)
    }

    if ($Options.CheckAllActiveUsers) {
        return ('모든 활성 계정 적용{0}' -f $suffix)
    }

    if ($Options.CheckAdministratorsOnly) {
        return ('활성 관리자 계정만 적용{0}' -f $suffix)
    }

    return ('모든 활성 계정 적용{0}' -f $suffix)
}

function Close-ProfileHiveTargets {
    param([array]$Targets)

    foreach ($target in $Targets) {
        if ($target.Loaded -and $target.HiveName -like 'Windows.SecurityWorkbench_*') {
            $unloaded = $false
            for ($attempt = 1; $attempt -le 10; $attempt++) {
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
                $exitCode = Invoke-ExternalQuiet -FilePath 'reg.exe' -ArgumentList @('unload', ("HKU\{0}" -f $target.HiveName))
                if ($exitCode -eq 0 -or -not (Test-Path -LiteralPath ("Registry::HKEY_USERS\{0}" -f $target.HiveName))) {
                    $unloaded = $true
                    break
                }

                Start-Sleep -Milliseconds 200
            }

            if (-not $unloaded) {
                Write-ToolLog -Level 'WARN' -Message ('프로필 하이브 언로드 실패: {0} ({1})' -f $target.HiveName, $target.UserHive)
            }
        }
    }
}

function Get-SmbSharesSafe {
    if (Test-CommandSafe -Name 'Get-SmbShare') {
        return Get-SmbShare | Sort-Object Name
    }

    Write-ToolLog -Level 'WARN' -Message 'Get-SmbShare 미지원. Win32_Share fallback으로 공유 목록을 조회합니다.'
    return @(Get-Win32ClassInstancesSafe -ClassName 'Win32_Share' | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{
            Name        = $_.Name
            Path        = $_.Path
            ShareType   = $_.Type
            Description = $_.Description
        }
    })
}

function Get-SmbShareAccessSafe {
    param([string]$Name)

    if (Get-Command Get-SmbShareAccess -ErrorAction SilentlyContinue) {
        return Get-SmbShareAccess -Name $Name
    }

    return @()
}

function Get-AccessRuleSummary {
    param([string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    return $acl.Access | ForEach-Object {
        [pscustomobject]@{
            Identity  = $_.IdentityReference.Value
            Rights    = $_.FileSystemRights.ToString()
            Type      = $_.AccessControlType.ToString()
            Inherited = $_.IsInherited
        }
    }
}

function Get-WorldWritableAccessRules {
    param([string]$Path)

    $suspects = @('Everyone', 'BUILTIN\Users', 'Users', 'Authenticated Users')
    return Get-AccessRuleSummary -Path $Path | Where-Object {
        $_.Type -eq 'Allow' -and
        ($suspects -contains $_.Identity) -and
        ($_.Rights -match 'FullControl|Modify|Write')
    }
}

function Reset-PathAclToAdministrativeOnly {
    param(
        [string]$Path,
        [switch]$IncludeCurrentUser
    )

    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        $acl.RemoveAccessRule($rule) | Out-Null
    }

    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propFlags = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    $rules = @(
        New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM', 'FullControl', $inheritFlags, $propFlags, $allow),
        New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators', 'FullControl', $inheritFlags, $propFlags, $allow)
    )

    if ($IncludeCurrentUser) {
        $currentUser = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
        $rules += New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, 'FullControl', $inheritFlags, $propFlags, $allow)
    }

    foreach ($rule in $rules) {
        $acl.AddAccessRule($rule) | Out-Null
    }

    Set-Acl -LiteralPath $Path -AclObject $acl
}

function ConvertTo-ResultExportObject {
    param(
        [array]$Results,
        [switch]$IncludeDetails
    )

    $sorted = $Results | Sort-Object Code
    if ($IncludeDetails) {
        $export = @()
        foreach ($item in $sorted) {
            $safeData = if ($null -eq $item.Data) {
                $null
            } else {
                try {
                    ($item.Data | Out-String).TrimEnd()
                } catch {
                    [string]$item.Data
                }
            }
            $export += [pscustomobject]@{
                Code             = $item.Code
                Title            = $item.Title
                Category         = $item.Category
                Severity         = $item.Severity
                Status           = $item.Status
                OriginalStatus   = $item.OriginalStatus
                IsException      = $item.IsException
                ExceptionReason  = $item.ExceptionReason
                ExceptionAt      = $item.ExceptionAt
                Summary          = $item.Summary
                Details          = $item.Details
                Data             = $safeData
                CanAutoRemediate = $item.CanAutoRemediate
                CheckedAt        = (Get-Date -Date $item.CheckedAt -Format 'yyyy-MM-dd HH:mm:ss')
            }
        }
        return $export
    }

    return $sorted | ForEach-Object {
        [pscustomobject]@{
            Code           = $_.Code
            Title          = $_.Title
            Category       = $_.Category
            Severity       = $_.Severity
            Status         = $_.Status
            OriginalStatus = $_.OriginalStatus
            IsException    = $_.IsException
            Summary        = $_.Summary
            CheckedAt      = (Get-Date -Date $_.CheckedAt -Format 'yyyy-MM-dd HH:mm:ss')
        }
    }
}

function Export-ScanResults {
    param(
        [array]$Results,
        [switch]$IncludeDetails,
        [string]$OutputPath
    )

    $target = $OutputPath
    if (-not $target) {
        $target = Join-Path $script:State.ReportRoot ('scan_{0:yyyyMMdd_HHmmss}.json' -f (Get-Date))
    }

    Save-JsonFile -InputObject (ConvertTo-ResultExportObject -Results $Results -IncludeDetails:$IncludeDetails) -Path $target
    Write-ToolLog -Message ('진단 결과 저장: {0}' -f $target)
    return $target
}

function Get-DefaultConfiguration {
    return @{
        Global = @{
            ScreenSaverTimeoutSeconds = 300
            ScreenSaverExecutable     = (Join-Path $env:WINDIR 'System32\scrnsave.scr')
            EventLogMinimumSizeBytes  = 20971520
            WindowsUpdateSearchFilter = "IsInstalled=0 and Type='Software' and IsHidden=0"
        }
        Items  = @{
            W0101 = @{
                DisableGuest                      = $true
                RequireBuiltinAdministratorRename = $true
                DisableBuiltinAdministratorIfSafe = $false
                RenameBuiltinAdministratorTo      = ''
                MaxActiveAdministrators           = 1
                CheckEnabledUserMetadata          = $true
                RemoveUnexpectedAdministrators    = $false
                AllowRemovingCurrentUser          = $false
                ExcludeUsers                      = @()
                AllowedAdministrators             = @('Administrator', 'Domain Admins', 'Enterprise Admins', "$env:USERNAME")
            }
            W0102 = @{
                LockoutThreshold = 5
                LockoutDuration  = 30
                ResetWindow      = 30
            }
            W0103 = @{
                MinimumPasswordLength = 8
                MaximumPasswordAge    = 90
                MinimumPasswordAge    = 7
                PasswordHistorySize   = 12
                PasswordComplexity    = 1
                UsePerUserPasswordExpireCheck = $true
                CheckAdministratorsOnly       = $true
                ExcludeUsers                  = @()
            }
            W0104 = @{
                ManualOnly = $true
            }
            W0105 = @{
                ConsentPromptBehaviorAdmin = 5
                PromptOnSecureDesktop      = 1
                EnableLUA                  = 1
                CheckFilterAdministratorToken = $false
                FilterAdministratorToken      = 1
            }
            W0106 = @{
                LSAAnonymousNameLookup = 0
            }
            W0107 = @{
                LimitBlankPasswordUse = 1
            }
            W0201 = @{
                RemoveBroadWriteAccess = $true
                IncludeCurrentUser     = $true
            }
            W0202 = @{
                RemoveEveryoneAccess         = $true
                RemoveGuestAccess            = $true
                DisableAdministrativeShares  = $true
                AdministrativeShares         = @('ADMIN$', 'C$', 'D$', 'E$')
                ShareAllowList               = @('IPC$')
                ForceGuest                   = 0
            }
            W0203 = @{
                IncludeCurrentUser = $false
            }
            W0204 = @{
                ManualOnly = $true
            }
            W0301 = @{
                ServiceAction = 'Disable'
                TargetServices = @('RemoteRegistry', 'TlntSvr', 'SNMP', 'SSDPSRV', 'upnphost')
                IgnoreServices = @()
            }
            W0302 = @{
                MinEncryptionLevel = 2
                DisableDriveRedirection = 1
            }
            W0303 = @{
                NetbiosOption = 2
            }
            W0304 = @{
                MaxIdleTimeMinutes = 5
            }
            W0401 = @{
                DisableService = $true
                UninstallFeature = $false
            }
            W0402 = @{
                ManualOnly = $true
            }
            W0403 = @{
                DisableIfPresent = $true
                AllowedManagers  = @()
                ReadOnlyCommunity = ''
            }
            W0501 = @{
                IncludeCurrentUser = $false
            }
            W0502 = @{
                ScreenSaveActive    = '1'
                ScreenSaverIsSecure = '1'
                ScreenSaveTimeOut   = '300'
                ScreenSaverExe      = ''
                CheckCurrentUser    = $false
                CheckAllActiveUsers = $true
                CheckAdministratorsOnly = $false
                IncludeUsers        = @()
                ApplyToDefaultProfile = $false
            }
            W0503 = @{
                Application = 20971520
                Security    = 20971520
                System      = 20971520
            }
            W0504 = Get-W0504DefaultNotice
            W0505 = @{
                DontDisplayLastUserName = 1
            }
            W0506 = @{
                ShutdownWithoutLogon = 0
            }
            W0507 = @{
                AuditSystemEvents = 0
                AuditLogonEvents  = 3
                AuditPolicyChange = 0
                AuditAccountLogon = 3
                AuditAccountManage = 3
                AuditObjectAccess = 3
                AuditPrivilegeUse = 3
            }
            W0508 = @{
                ClearPageFileAtShutdown = 1
            }
            W0509 = @{
                LmCompatibilityLevel = 3
            }
            W0510 = @{
                EveryoneIncludesAnonymous = 0
            }
            W0511 = @{
                AddPrinterDrivers = 1
            }
            W0512 = @{
                AutoDisconnectMinutes = 15
            }
            W0513 = @{
                ManualOnly = $true
                SuspiciousPathPatterns = @('\AppData\Local\Temp\', '\Users\Public\', '\Downloads\', '\Desktop\')
                DisableTaskNames = @()
            }
            W0514 = @{
                AllowedAccounts = @('Administrators')
            }
            W0515 = @{
                CrashOnAuditFail = 0
            }
            W0516 = @{
                RequireSignOrSeal = 1
                RequireStrongKey  = 1
                SealSecureChannel = 1
                SignSecureChannel = 1
            }
            W0517 = @{
                AddPrinterDrivers = 1
            }
            W0601 = @{
                PreferDefender = $true
                AntivirusServicePatterns = @(
                    'V3', 'AHNLAB', 'ALYAC', 'SYMANTEC', 'SEP', 'KLNAGENT', 'KASPERSKY',
                    'Microsoft Antimalware Service', 'Windows Defender', 'Windows Essentials',
                    'MCAFEE', 'VIROBOT', 'Virus Chaser', 'CHASER', 'Trend Micro', 'AVAST'
                )
                AntivirusDisplayPatterns = @(
                    'AhnLab', 'V3', 'Alyac', 'Symantec', 'Endpoint Protection', 'Kaspersky',
                    'Microsoft Antimalware', 'Windows Defender', 'Windows Essentials',
                    'McAfee', 'Virobot', 'Virus Chaser', 'Trend Micro', 'Avast',
                    'CrowdStrike', 'SentinelOne'
                )
            }
            W0602 = @{
                MaxSignatureAgeDays = 7
            }
            W0701 = @{
                RegistryPath      = 'Registry::HKEY_LOCAL_MACHINE\SAM'
                Identity          = 'Everyone'
                Rights            = 'FullControl'
                AuditFlags        = @('Success', 'Failure')
                InheritanceFlags  = 'ContainerInherit'
                PropagationFlags  = 'None'
            }
            W0702 = @{
                RestrictAnonymous       = 2
                CheckNullSessionLists   = $false
            }
            W0703 = @{
                StartupType = 'Disabled'
                StopService = $true
            }
            W0704 = @{
                AutoAdminLogon = 0
                RemoveStoredCredentials = $true
            }
            W0705 = @{
                SynAttackProtect      = 2
                EnablePMTUDiscovery   = 0
                NoNameReleaseOnDemand = 1
                EnableDeadGWDetect    = 0
                KeepAliveTime         = 300000
            }
            W0801 = @{
                ManualOnly = $true
            }
            W0802 = @{
                WarningDaysBeforeEol = 365
            }
            W0803 = @{
                InstallUpdates = $true
            }
        }
    }
}

function Initialize-Configuration {
    $script:State.Config = Get-DefaultConfiguration
    if ($ConfigPath) {
        $raw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
        $userConfig = ConvertTo-PlainHashtable (ConvertFrom-Json -InputObject $raw)
        $script:State.Config = Merge-Hashtable -Base $script:State.Config -Override $userConfig
    }
}

function Convert-OptionValueToTemplateType {
    param(
        $Value,
        $TemplateValue
    )

    if ($TemplateValue -is [bool]) {
        if ($Value -is [string]) {
            switch -Regex ($Value.Trim().ToLowerInvariant()) {
                '^(1|true|yes|on)$' { return $true }
                '^(0|false|no|off)$' { return $false }
                default { return [bool]$TemplateValue }
            }
        }

        return [bool]$Value
    }

    if ($TemplateValue -is [byte] -or $TemplateValue -is [int16] -or $TemplateValue -is [int32] -or $TemplateValue -is [int64]) {
        if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
            return [int64]$TemplateValue
        }

        return [int64]$Value
    }

    if ($TemplateValue -is [System.Collections.IEnumerable] -and $TemplateValue -isnot [string]) {
        if ($null -eq $Value) {
            return ,@()
        }

        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            return ,@($Value | ForEach-Object { [string]$_ })
        }

        return ,@([string]$Value)
    }

    if ($null -eq $Value) {
        return ''
    }

    return [string]$Value
}

function Normalize-OptionHashtable {
    param(
        [System.Collections.IDictionary]$Template,
        [hashtable]$Values
    )

    $normalized = @{}
    foreach ($key in $Template.Keys) {
        if ($Values.ContainsKey($key)) {
            $normalized[$key] = Convert-OptionValueToTemplateType -Value $Values[$key] -TemplateValue $Template[$key]
        } else {
            $normalized[$key] = Convert-OptionValueToTemplateType -Value $Template[$key] -TemplateValue $Template[$key]
        }
    }

    foreach ($key in $Values.Keys) {
        if (-not $normalized.ContainsKey($key)) {
            $normalized[$key] = ConvertTo-PlainHashtable $Values[$key]
        }
    }

    return $normalized
}

function Get-ItemOptions {
    param(
        [string]$Code,
        [hashtable]$InlineOverride = $null
    )

    $rawTemplateOptions = @{}
    $templateOptions = @{}
    if ($script:State.Config.Items.ContainsKey($Code)) {
        $rawTemplateOptions = $script:State.Config.Items[$Code]
        $templateOptions = ConvertTo-PlainHashtable $script:State.Config.Items[$Code]
    }

    $merged = Merge-Hashtable -Base $templateOptions -Override $InlineOverride
    $normalized = Normalize-OptionHashtable -Template $rawTemplateOptions -Values $merged

    switch ($Code) {
        'W0504' {
            $defaultNotice = Get-W0504DefaultNotice
            if ([string]::IsNullOrWhiteSpace([string]$normalized.Caption)) {
                $normalized.Caption = [string]$defaultNotice.Caption
            }
            if ([string]::IsNullOrWhiteSpace([string]$normalized.Text)) {
                $normalized.Text = [string]$defaultNotice.Text
            }
        }
    }

    return $normalized
}

function Convert-OptionTextToHashtable {
    param(
        [string]$Code,
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return Get-ItemOptions -Code $Code
    }

    $parsed = ConvertFrom-Json -InputObject $Text
    return Get-ItemOptions -Code $Code -InlineOverride (ConvertTo-PlainHashtable $parsed)
}

function Format-StringList {
    param([object[]]$Items)
    if (-not $Items -or $Items.Count -eq 0) {
        return '(없음)'
    }

    return ($Items | ForEach-Object { [string]$_ }) -join ', '
}

function Format-RegistryStateDetails {
    param([array]$States)
    $lines = @()
    foreach ($state in $States) {
        $lines += '- {0}: 현재={1} / 기대={2} / 준수={3}' -f $state.Description, $state.Current, $state.Expected, $state.Compliant
    }
    return ($lines -join [Environment]::NewLine)
}

function Test-DefinitionAllowsException {
    param([hashtable]$Definition)

    return ($Definition -is [hashtable] -and $Definition.ContainsKey('AllowException') -and [bool]$Definition.AllowException)
}

function Get-ExceptionEntry {
    param([string]$Code)

    if ($script:State.Exceptions.ContainsKey($Code)) {
        return $script:State.Exceptions[$Code]
    }

    return $null
}

function Test-ExceptionEnabled {
    param([string]$Code)

    $entry = Get-ExceptionEntry -Code $Code
    return ($entry -is [hashtable] -and $entry.ContainsKey('Enabled') -and [bool]$entry.Enabled)
}

function Set-ExceptionEnabled {
    param(
        [string]$Code,
        [bool]$Enabled,
        [string]$Reason = '사용자 예외 처리'
    )

    $definition = Get-CatalogDefinition -Code $Code
    if (-not (Test-DefinitionAllowsException -Definition $definition)) {
        throw ('{0}은 예외 처리를 지원하지 않습니다.' -f $Code)
    }

    if ($Enabled) {
        $script:State.Exceptions[$Code] = @{
            Enabled = $true
            Title   = $definition.Title
            Reason  = if ([string]::IsNullOrWhiteSpace($Reason)) { '사용자 예외 처리' } else { $Reason }
            SetAt   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        }
        Write-ToolLog -Message ('{0} 예외 처리' -f $Code)
    } else {
        if ($script:State.Exceptions.ContainsKey($Code)) {
            $script:State.Exceptions.Remove($Code)
        }
        Write-ToolLog -Message ('{0} 예외 해제' -f $Code)
    }

    Save-ExceptionState
}

function Convert-ToExceptionResult {
    param(
        [hashtable]$Definition,
        [pscustomobject]$Result
    )

    if ($null -eq $Result -or $Result.Status -eq '오류') {
        return $Result
    }

    if (-not (Test-DefinitionAllowsException -Definition $Definition)) {
        return $Result
    }

    $entry = Get-ExceptionEntry -Code $Definition.Code
    if ($entry -isnot [hashtable] -or -not [bool]$entry.Enabled) {
        return $Result
    }

    $exceptionReason = if ($entry.ContainsKey('Reason')) { [string]$entry.Reason } else { '사용자 예외 처리' }
    $exceptionAt = if ($entry.ContainsKey('SetAt')) { [string]$entry.SetAt } else { '' }
    $originalStatus = if ($Result.PSObject.Properties['OriginalStatus']) { [string]$Result.OriginalStatus } else { [string]$Result.Status }
    $originalSummary = if ($Result.PSObject.Properties['OriginalSummary']) { [string]$Result.OriginalSummary } else { [string]$Result.Summary }

    $displayExceptionAt = if ($exceptionAt) { $exceptionAt } else { '(기록 없음)' }
    $detailLines = @(
        '예외 처리: 예'
        ('예외 사유: {0}' -f $exceptionReason)
        ('예외 시각: {0}' -f $displayExceptionAt)
        ('원래 상태: {0}' -f $originalStatus)
        ('원래 요약: {0}' -f $originalSummary)
    )
    if ($Result.Details) {
        $detailLines += ''
        $detailLines += $Result.Details
    }

    return [pscustomobject]@{
        Code             = $Result.Code
        Title            = $Result.Title
        Category         = $Result.Category
        Severity         = $Result.Severity
        Status           = '예외'
        Summary          = ('예외 처리됨 (원래 상태: {0})' -f $originalStatus)
        Details          = ($detailLines -join [Environment]::NewLine)
        Data             = $Result.Data
        CanAutoRemediate = $false
        CheckedAt        = $Result.CheckedAt
        OriginalStatus   = $originalStatus
        OriginalSummary  = $originalSummary
        IsException      = $true
        ExceptionReason  = $exceptionReason
        ExceptionAt      = $exceptionAt
    }
}

function Get-CatalogDefinition {
    param([string]$Code)

    foreach ($definition in $script:State.Catalog) {
        if ($definition.Code -eq $Code) {
            return $definition
        }
    }

    throw ('알 수 없는 코드입니다: {0}' -f $Code)
}

function Invoke-Detect {
    param(
        [hashtable]$Definition,
        [hashtable]$Options
    )

    try {
        $result = & $Definition.Detect $Definition $Options
        $result = Convert-ToExceptionResult -Definition $Definition -Result $result
        $script:State.Results[$Definition.Code] = $result
        return $result
    } catch {
        $message = $_.Exception.Message
        Write-ToolLog -Level 'ERROR' -Message ('{0} 탐지 실패: {1}' -f $Definition.Code, $message)
        $failure = New-CheckResult -Definition $Definition -Status '오류' -Summary $message -Details $message -CanAutoRemediate:$false
        $script:State.Results[$Definition.Code] = $failure
        return $failure
    }
}

function Invoke-Plan {
    param(
        [hashtable]$Definition,
        [pscustomobject]$Result,
        [hashtable]$Options
    )

    if ($Result.PSObject.Properties['Data']) {
        $Result.Data = ConvertTo-PropertyObject $Result.Data
    }

    if ($Definition.Plan) {
        return & $Definition.Plan $Definition $Result $Options
    }

    return New-PlanResult -Definition $Definition -AutoSupported:$false -Changes @() -Impact '' -ExpectedStatus $Result.Status
}

function Invoke-ApplyDefinition {
    param(
        [hashtable]$Definition,
        [pscustomobject]$Result,
        [hashtable]$Options
    )

    if (-not $Definition.Apply) {
        throw ('{0}은 자동 적용을 지원하지 않습니다.' -f $Definition.Code)
    }

    if ($Result.PSObject.Properties['Data']) {
        $Result.Data = ConvertTo-PropertyObject $Result.Data
    }

    $backupDirectory = New-BackupSession -Code $Definition.Code
    Write-ToolLog -Message ('{0} 적용 시작. 백업 위치: {1}' -f $Definition.Code, $backupDirectory)
    & $Definition.Apply $Definition $Result $Options $backupDirectory
    Write-ToolLog -Message ('{0} 적용 완료' -f $Definition.Code)
    return $backupDirectory
}

function New-ManualOnlyPlan {
    param(
        [hashtable]$Definition,
        [string]$Reason,
        [string[]]$Changes
    )

    return New-PlanResult -Definition $Definition -AutoSupported:$false -Changes $Changes -Impact $Reason -ExpectedStatus '수동 확인 필요' -Notes $Reason
}

function Get-SecurityPolicyInt {
    param(
        [string]$Section,
        [string]$Name,
        [int]$Default = -2147483648
    )

    $value = Get-SecurityPolicyValue -Section $Section -Name $Name
    if ($null -eq $value -or $value -eq '') {
        return $Default
    }

    try {
        return [int]$value
    } catch {
        return $Default
    }
}

function Test-NameAllowed {
    param(
        [string]$Name,
        [string[]]$AllowedNames
    )

    $leaf = ($Name -split '\\')[-1]
    foreach ($allowed in $AllowedNames) {
        $allowedLeaf = ($allowed -split '\\')[-1]
        if ($Name -ieq $allowed -or $leaf -ieq $allowedLeaf) {
            return $true
        }
    }

    return $false
}

function Get-ProfileScreenSaverState {
    param([pscustomobject]$Target)

    $policyPath = Join-Path $Target.HivePath 'Software\Policies\Microsoft\Windows\Control Panel\Desktop'
    $controlPath = Join-Path $Target.HivePath 'Control Panel\Desktop'

    [pscustomobject]@{
        HivePath            = $Target.HivePath
        ProfilePath         = $Target.ProfilePath
        ScreenSaveActive    = Get-RegistryValueSafe -Path $policyPath -Name 'ScreenSaveActive'
        ScreenSaverIsSecure = Get-RegistryValueSafe -Path $policyPath -Name 'ScreenSaverIsSecure'
        ScreenSaveTimeOut   = Get-RegistryValueSafe -Path $policyPath -Name 'ScreenSaveTimeOut'
        ScreenSaverExe      = (Get-RegistryValueSafe -Path $policyPath -Name 'SCRNSAVE.EXE')
        CurrentActive       = Get-RegistryValueSafe -Path $controlPath -Name 'ScreenSaveActive'
        CurrentSecure       = Get-RegistryValueSafe -Path $controlPath -Name 'ScreenSaverIsSecure'
        CurrentTimeout      = Get-RegistryValueSafe -Path $controlPath -Name 'ScreenSaveTimeOut'
    }
}

function Invoke-W0101Detect {
    param($Definition, $Options)

    $users = Get-LocalUsersSafe
    $admins = Get-LocalGroupMembersSafe -Group 'Administrators'
    $guest = $users | Where-Object { $_.Name -eq 'Guest' } | Select-Object -First 1
    $builtinAdmin = Get-BuiltinAdministratorUser
    $allowed = Get-EffectiveAllowedAdministratorNames -Options $Options -BuiltinAdmin $builtinAdmin
    $adminStates = @(Get-AdministratorMemberStates -Administrators $admins -Users $users -Options $Options)
    $enabledAdmins = @($adminStates | Where-Object { $_.Enabled })
    $unexpectedAdmins = @($adminStates | Where-Object {
        -not (Test-NameAllowed -Name $_.Name -AllowedNames $allowed)
    } | ForEach-Object { $_.Name })
    $renameTarget = [string]$Options.RenameBuiltinAdministratorTo

    $issues = @()
    if ($guest -and $guest.Enabled) {
        $issues += 'Guest 계정이 활성화되어 있습니다.'
    }

    if ($Options.RequireBuiltinAdministratorRename -and $builtinAdmin -and $builtinAdmin.Enabled -and $builtinAdmin.Name -ieq 'Administrator') {
        $issues += '기본 Administrator 계정이 활성 상태이며 이름이 변경되지 않았습니다.'
    }

    if ([int]$Options.MaxActiveAdministrators -gt 0 -and $enabledAdmins.Count -gt [int]$Options.MaxActiveAdministrators) {
        $issues += ('활성 관리자 계정 수가 기준을 초과합니다. 현재={0} / 기대<={1}' -f $enabledAdmins.Count, $Options.MaxActiveAdministrators)
    }

    if ($unexpectedAdmins.Count -gt 0) {
        $issues += ('허용되지 않은 관리자 계정: {0}' -f (Format-StringList $unexpectedAdmins))
    }

    $metadataIssues = @()
    if ($Options.CheckEnabledUserMetadata) {
        foreach ($user in @($users | Where-Object { $_.Enabled })) {
            if (Test-StringMatchesPatternList -Value $user.Name -Patterns @($Options.ExcludeUsers)) {
                continue
            }

            if ([string]::IsNullOrWhiteSpace([string]$user.FullName) -and [string]::IsNullOrWhiteSpace([string]$user.Description)) {
                $metadataIssues += $user.Name
            }
        }

        if ($metadataIssues.Count -gt 0) {
            $issues += ('전체이름/설명이 비어 있는 활성 계정: {0}' -f (Format-StringList $metadataIssues))
        }
    }

    $details = @(
        ('활성 관리자: {0}' -f (Format-StringList ($enabledAdmins.Name)))
        ('활성 관리자 수: {0} / 기준<={1}' -f $enabledAdmins.Count, $Options.MaxActiveAdministrators)
        ('허용 관리자: {0}' -f (Format-StringList $allowed))
        ('예외 계정: {0}' -f (Format-StringList $Options.ExcludeUsers))
        ('Guest 활성화: {0}' -f ([bool]($guest -and $guest.Enabled)))
        ('Built-in Administrator: {0} / Enabled={1} / RenameTarget={2}' -f ($builtinAdmin.Name), ([bool]($builtinAdmin -and $builtinAdmin.Enabled)), $(if ([string]::IsNullOrWhiteSpace($renameTarget)) { '(미설정)' } else { $renameTarget }))
        ('전체이름/설명 미기입 활성 계정: {0}' -f (Format-StringList $metadataIssues))
    )
    if ($builtinAdmin -and -not [string]::IsNullOrWhiteSpace($renameTarget) -and $builtinAdmin.Name -ine $renameTarget) {
        $details += ('이름 변경 예정: {0} -> {1}' -f $builtinAdmin.Name, $renameTarget)
    }
    if ($issues.Count -gt 0) {
        $details += ''
        $details += '문제점:'
        $details += ($issues | ForEach-Object { '- ' + $_ })
    }

    $status = if ($issues.Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($issues.Count -gt 0) { $issues[0] } else { 'Guest 비활성화, 관리자 그룹 상태 양호' }
    $data = @{
        Users            = $users
        Administrators   = $admins
        AdministratorStates = $adminStates
        EnabledAdministrators = $enabledAdmins
        ActiveAdminCount = $enabledAdmins.Count
        UnexpectedAdmins = $unexpectedAdmins
        Guest            = $guest
        BuiltinAdmin     = $builtinAdmin
        EffectiveAllowedAdministrators = $allowed
        MetadataIssues   = $metadataIssues
    }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data $data -CanAutoRemediate:$true
}

function Invoke-W0101Plan {
    param($Definition, $Result, $Options)

    $changes = @()
    $residual = @()
    $autoSupported = $true
    $builtinAdmin = Resolve-ResultDataValue -Definition $Definition -Result $Result -Options $Options -Name 'BuiltinAdmin' -Default $null
    $users = Resolve-ResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Users'
    $guest = Resolve-ResultDataValue -Definition $Definition -Result $Result -Options $Options -Name 'Guest' -Default $null
    $activeAdminCount = [int](Resolve-ResultDataValue -Definition $Definition -Result $Result -Options $Options -Name 'ActiveAdminCount' -Default 0)
    $unexpectedAdmins = Resolve-ResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'UnexpectedAdmins'
    $metadataIssues = Resolve-ResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'MetadataIssues'
    $renameTarget = [string]$Options.RenameBuiltinAdministratorTo

    if ($Options.DisableGuest -and $guest -and $guest.Enabled) {
        $changes += 'Guest 계정을 비활성화합니다.'
    } elseif ($guest -and $guest.Enabled) {
        $residual += 'Guest 계정이 계속 활성 상태로 남습니다.'
    }

    $renameConflict = $null
    if ($builtinAdmin -and -not [string]::IsNullOrWhiteSpace($renameTarget)) {
        $renameConflict = @($users | Where-Object {
            $_.Name -ieq $renameTarget -and $_.SID -ne $builtinAdmin.SID
        } | Select-Object -First 1)
        if (-not $renameConflict -and $builtinAdmin.Name -ine $renameTarget) {
            $changes += ('Built-in Administrator 이름을 "{0}"에서 "{1}"(으)로 변경합니다.' -f $builtinAdmin.Name, $renameTarget)
        } elseif ($renameConflict) {
            $residual += ('변경 대상 이름이 이미 존재합니다: {0}' -f $renameTarget)
            $autoSupported = $false
        }
    } elseif ($Options.RequireBuiltinAdministratorRename -and $builtinAdmin -and $builtinAdmin.Enabled -and $builtinAdmin.Name -ieq 'Administrator') {
        $residual += 'Built-in Administrator 새 이름이 지정되지 않았습니다.'
        $autoSupported = $false
    }

    if ($Options.DisableBuiltinAdministratorIfSafe -and $builtinAdmin -and $builtinAdmin.Enabled) {
        $changes += '다른 관리자 계정이 존재하면 Built-in Administrator를 비활성화합니다.'
    } elseif ($builtinAdmin -and $builtinAdmin.Enabled -and $activeAdminCount -gt [int]$Options.MaxActiveAdministrators) {
        $residual += '활성 관리자 수를 줄이기 위한 비활성화/제거 옵션이 꺼져 있습니다.'
    }
    if ($Options.RemoveUnexpectedAdministrators -and @($unexpectedAdmins).Count -gt 0) {
        $changes += ('허용 목록 외 관리자 계정을 Administrators 그룹에서 제거합니다. 허용 목록: {0}' -f (Format-StringList $Options.AllowedAdministrators))
    } elseif (@($unexpectedAdmins).Count -gt 0) {
        $residual += ('허용되지 않은 관리자 계정이 남습니다: {0}' -f (Format-StringList $unexpectedAdmins))
    }
    if (@($metadataIssues).Count -gt 0) {
        $residual += ('전체이름/설명이 비어 있는 활성 계정은 수동으로 보완해야 합니다: {0}' -f (Format-StringList $metadataIssues))
    }

    if ($changes.Count -eq 0) {
        $changes += '현재 옵션으로 자동 수정되는 항목이 없습니다.'
    }

    $expectedStatus = if ($residual.Count -eq 0) { '양호' } else { '취약' }
    $notes = if ($residual.Count -gt 0) {
        '잔여 이슈: {0}' -f ((@($residual) | Sort-Object -Unique) -join '; ')
    } else {
        ''
    }

    return New-PlanResult -Definition $Definition -AutoSupported:$autoSupported -Changes $changes -Impact '관리자 계정 제거/비활성화/이름 변경은 원격 접속 경로에 직접 영향을 줄 수 있습니다.' -ExpectedStatus $expectedStatus -Notes $notes
}

function Invoke-W0101Apply {
    param($Definition, $Result, $Options, $BackupDirectory)

    Backup-CommandOutput -FileName 'local_users_before.txt' -BackupDirectory $BackupDirectory -ScriptBlock {
        Get-LocalUsersSafe | Format-Table -AutoSize | Out-String
    }
    Backup-CommandOutput -FileName 'administrators_before.txt' -BackupDirectory $BackupDirectory -ScriptBlock {
        Get-LocalGroupMembersSafe -Group 'Administrators' | Format-Table -AutoSize | Out-String
    }

    $users = Get-LocalUsersSafe
    $guest = $users | Where-Object { $_.Name -eq 'Guest' } | Select-Object -First 1
    if ($Options.DisableGuest -and $guest -and $guest.Enabled) {
        Disable-LocalUserSafe -Name $guest.Name
    }

    $builtinAdmin = Get-BuiltinAdministratorUser
    $renameTarget = [string]$Options.RenameBuiltinAdministratorTo
    if ($builtinAdmin -and -not [string]::IsNullOrWhiteSpace($renameTarget)) {
        $existingTarget = @($users | Where-Object {
            $_.Name -ieq $renameTarget -and $_.SID -ne $builtinAdmin.SID
        } | Select-Object -First 1)
        if ($existingTarget) {
            throw ('이미 존재하는 계정명으로 Built-in Administrator를 변경할 수 없습니다: {0}' -f $renameTarget)
        }

        if ($builtinAdmin.Name -ine $renameTarget) {
            Rename-LocalUserSafe -OldName $builtinAdmin.Name -NewName $renameTarget
        }
        $users = Get-LocalUsersSafe
        $builtinAdmin = Get-BuiltinAdministratorUser
    }

    $effectiveAllowed = Get-EffectiveAllowedAdministratorNames -Options $Options -BuiltinAdmin $builtinAdmin

    if ($Options.DisableBuiltinAdministratorIfSafe -and $builtinAdmin -and $builtinAdmin.Enabled) {
        $admins = Get-LocalGroupMembersSafe -Group 'Administrators'
        $states = @(Get-AdministratorMemberStates -Administrators $admins -Users $users -Options $Options)
        $otherAdmins = @($states | Where-Object { $_.Enabled -and $_.SID -ne $builtinAdmin.SID })
        if ($otherAdmins.Count -gt 0) {
            Disable-LocalUserSafe -Name $builtinAdmin.Name
        }
    }

    if ($Options.RemoveUnexpectedAdministrators) {
        $admins = Get-LocalGroupMembersSafe -Group 'Administrators'
        foreach ($member in $admins) {
            $leaf = ($member.Name -split '\\')[-1]
            if (Test-StringMatchesPatternList -Value $leaf -Patterns @($Options.ExcludeUsers)) {
                continue
            }

            if (-not (Test-NameAllowed -Name $member.Name -AllowedNames $effectiveAllowed)) {
                if (-not $Options.AllowRemovingCurrentUser) {
                    if ($leaf -ieq $env:USERNAME) {
                        Write-ToolLog -Level 'WARN' -Message ('현재 로그인 계정은 제거하지 않음: {0}' -f $member.Name)
                        continue
                    }
                }
                Remove-LocalAdminMemberSafe -Member $member.Name
            }
        }
    }
}

function Invoke-W0102Detect {
    param($Definition, $Options)

    $threshold = Get-SecurityPolicyInt -Section 'System Access' -Name 'LockoutBadCount' -Default -1
    $duration = Get-SecurityPolicyInt -Section 'System Access' -Name 'LockoutDuration' -Default -1
    $window = Get-SecurityPolicyInt -Section 'System Access' -Name 'ResetLockoutCount' -Default -1

    $issues = @()
    if ($threshold -lt 1 -or $threshold -gt [int]$Options.LockoutThreshold) {
        $issues += ('계정 잠금 임계값이 기준과 다릅니다. 현재={0} / 기대=1~{1}' -f $threshold, $Options.LockoutThreshold)
    }
    if ($duration -lt [int]$Options.LockoutDuration) {
        $issues += ('계정 잠금 기간이 너무 짧습니다. 현재={0} / 기대>={1}' -f $duration, $Options.LockoutDuration)
    }
    if ($window -lt [int]$Options.ResetWindow) {
        $issues += ('잠금 수 초기화 시간이 너무 짧습니다. 현재={0} / 기대>={1}' -f $window, $Options.ResetWindow)
    }

    $details = @(
        ('LockoutBadCount={0}' -f $threshold)
        ('LockoutDuration={0}' -f $duration)
        ('ResetLockoutCount={0}' -f $window)
    )
    if ($issues.Count -gt 0) {
        $details += ''
        $details += '문제점:'
        $details += ($issues | ForEach-Object { '- ' + $_ })
    }

    $status = if ($issues.Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($issues.Count -gt 0) { $issues[0] } else { '계정 잠금 정책이 기준을 충족합니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{
        LockoutBadCount = $threshold
        LockoutDuration = $duration
        ResetLockoutCount = $window
    } -CanAutoRemediate:$true
}

function Invoke-W0102Plan {
    param($Definition, $Result, $Options)

    $changes = @(
        ('계정 잠금 임계값을 {0}(으)로 설정' -f $Options.LockoutThreshold)
        ('계정 잠금 기간을 {0}분으로 설정' -f $Options.LockoutDuration)
        ('잠금 수 초기화 시간을 {0}분으로 설정' -f $Options.ResetWindow)
    )
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes $changes -Impact '로그인 실패 횟수 정책이 강화되므로 자동화 계정의 로그인 실패 누적에 주의해야 합니다.' -ExpectedStatus '양호'
}

function Invoke-W0102Apply {
    param($Definition, $Result, $Options, $BackupDirectory)

    Backup-CommandOutput -FileName 'secpol_before.inf' -BackupDirectory $BackupDirectory -ScriptBlock {
        $p = Join-Path $env:TEMP 'Windows.SecurityWorkbench_backup.inf'
        secedit /export /cfg $p /quiet | Out-Null
        Get-Content $p
    }

    & net.exe accounts "/lockoutthreshold:$($Options.LockoutThreshold)" "/lockoutduration:$($Options.LockoutDuration)" "/lockoutwindow:$($Options.ResetWindow)" | Out-Null
    Clear-SecurityPolicyCache
}

function Invoke-W0103Detect {
    param($Definition, $Options)

    $values = @{
        MinimumPasswordLength = Get-SecurityPolicyInt -Section 'System Access' -Name 'MinimumPasswordLength' -Default -1
        MaximumPasswordAge    = Get-SecurityPolicyInt -Section 'System Access' -Name 'MaximumPasswordAge' -Default -1
        MinimumPasswordAge    = Get-SecurityPolicyInt -Section 'System Access' -Name 'MinimumPasswordAge' -Default -1
        PasswordHistorySize   = Get-SecurityPolicyInt -Section 'System Access' -Name 'PasswordHistorySize' -Default -1
        PasswordComplexity    = Get-SecurityPolicyInt -Section 'System Access' -Name 'PasswordComplexity' -Default -1
        ClearTextPassword     = Get-SecurityPolicyInt -Section 'System Access' -Name 'ClearTextPassword' -Default -1
    }

    $issues = @()
    if ($values.MinimumPasswordLength -lt [int]$Options.MinimumPasswordLength) {
        $issues += ('최소 암호 길이가 짧습니다. 현재={0} / 기대>={1}' -f $values.MinimumPasswordLength, $Options.MinimumPasswordLength)
    }
    if ($values.MaximumPasswordAge -lt 1 -or $values.MaximumPasswordAge -gt [int]$Options.MaximumPasswordAge) {
        $issues += ('최대 암호 사용 기간이 기준 범위를 벗어납니다. 현재={0} / 기대=1~{1}' -f $values.MaximumPasswordAge, $Options.MaximumPasswordAge)
    }
    if ($values.MinimumPasswordAge -lt [int]$Options.MinimumPasswordAge) {
        $issues += ('최소 암호 사용 기간이 짧습니다. 현재={0} / 기대>={1}' -f $values.MinimumPasswordAge, $Options.MinimumPasswordAge)
    }
    if ($values.PasswordHistorySize -lt [int]$Options.PasswordHistorySize) {
        $issues += ('암호 이력 개수가 부족합니다. 현재={0} / 기대>={1}' -f $values.PasswordHistorySize, $Options.PasswordHistorySize)
    }
    if ($values.PasswordComplexity -ne [int]$Options.PasswordComplexity) {
        $issues += ('복잡성 정책이 비활성화되어 있습니다.')
    }
    if ($values.ClearTextPassword -ne 0) {
        $issues += ('가역적 암호화 저장이 비활성화되어 있지 않습니다.')
    }

    $scopedUsers = @()
    $userFindings = @()
    if ($Options.UsePerUserPasswordExpireCheck) {
        $users = @(Get-LocalUsersSafe | Where-Object { $_.Enabled })
        if ($Options.CheckAdministratorsOnly) {
            $adminLeafNames = @((Get-LocalGroupMembersSafe -Group 'Administrators') | ForEach-Object { ($_.Name -split '\\')[-1] } | Sort-Object -Unique)
            $users = @($users | Where-Object { $adminLeafNames -contains $_.Name })
        }

        $scopedUsers = @($users | Where-Object {
            -not (Test-StringMatchesPatternList -Value $_.Name -Patterns @($Options.ExcludeUsers))
        })

        foreach ($user in $scopedUsers) {
            $ageDays = if ($user.PasswordLastSet) {
                [math]::Round((New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).TotalDays, 1)
            } else {
                $null
            }

            if (-not $user.PasswordExpires) {
                $userFindings += [pscustomobject]@{
                    Name            = $user.Name
                    Issue           = '암호 만료 기간 없음'
                    PasswordAgeDays = $ageDays
                    PasswordLastSet = $user.PasswordLastSet
                }
                $issues += ('암호 만료 기간이 없는 활성 계정이 있습니다: {0}' -f $user.Name)
                continue
            }

            if ($null -ne $ageDays -and $ageDays -gt [double]$values.MaximumPasswordAge) {
                $userFindings += [pscustomobject]@{
                    Name            = $user.Name
                    Issue           = '최대 암호 사용 기간 초과'
                    PasswordAgeDays = $ageDays
                    PasswordLastSet = $user.PasswordLastSet
                }
                $issues += ('최대 암호 사용 기간을 초과한 활성 계정이 있습니다: {0} ({1}일)' -f $user.Name, $ageDays)
            }
        }
    }

    $details = @()
    foreach ($pair in $values.GetEnumerator() | Sort-Object Name) {
        $details += ('{0}={1}' -f $pair.Name, $pair.Value)
    }
    if ($Options.UsePerUserPasswordExpireCheck) {
        $details += ''
        $details += ('계정별 암호 만료 점검 범위: {0}' -f $(if ($Options.CheckAdministratorsOnly) { '활성 로컬 Administrators 그룹 계정' } else { '모든 활성 로컬 계정' }))
        $details += ('예외 계정: {0}' -f (Format-StringList $Options.ExcludeUsers))
        if ($scopedUsers.Count -gt 0) {
            $details += ('점검 대상 계정: {0}' -f (Format-StringList ($scopedUsers.Name)))
        }
        foreach ($finding in $userFindings) {
            $details += ('계정 이슈: {0} / {1} / PasswordAgeDays={2}' -f $finding.Name, $finding.Issue, $(if ($null -eq $finding.PasswordAgeDays) { 'N/A' } else { $finding.PasswordAgeDays }))
        }
    }
    if ($issues.Count -gt 0) {
        $details += ''
        $details += '문제점:'
        $details += ($issues | ForEach-Object { '- ' + $_ })
    }

    $status = if ($issues.Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($issues.Count -gt 0) { $issues[0] } else { '암호 정책이 기준을 충족합니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{
        PolicyValues = $values
        ScopedUsers  = $scopedUsers
        UserFindings = $userFindings
    } -CanAutoRemediate:$true
}

function Invoke-W0103Plan {
    param($Definition, $Result, $Options)

    $values = Get-RequiredResultDataValue -Definition $Definition -Result $Result -Options $Options -Name 'PolicyValues'
    $changes = @()
    $policyChanges = 0

    if ($values.MinimumPasswordLength -lt [int]$Options.MinimumPasswordLength) {
        $changes += ('최소 암호 길이를 {0}(으)로 설정' -f $Options.MinimumPasswordLength)
        $policyChanges += 1
    }
    if ($values.MaximumPasswordAge -lt 1 -or $values.MaximumPasswordAge -gt [int]$Options.MaximumPasswordAge) {
        $changes += ('최대 암호 사용 기간을 1~{0}일 범위로 조정' -f $Options.MaximumPasswordAge)
        $policyChanges += 1
    }
    if ($values.MinimumPasswordAge -lt [int]$Options.MinimumPasswordAge) {
        $changes += ('최소 암호 사용 기간을 {0}일로 설정' -f $Options.MinimumPasswordAge)
        $policyChanges += 1
    }
    if ($values.PasswordHistorySize -lt [int]$Options.PasswordHistorySize) {
        $changes += ('암호 이력을 {0}개로 설정' -f $Options.PasswordHistorySize)
        $policyChanges += 1
    }
    if ($values.PasswordComplexity -ne [int]$Options.PasswordComplexity) {
        $changes += '암호 복잡성을 사용으로 설정'
        $policyChanges += 1
    }
    if ($values.ClearTextPassword -ne 0) {
        $changes += '해독 가능한 암호화를 사용한 암호 저장을 사용 안 함으로 설정'
        $policyChanges += 1
    }

    $userFindings = Resolve-ResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'UserFindings'
    if ($userFindings.Count -gt 0) {
        $changes += ('계정별 암호 만료 수동 조치 필요: {0}' -f ((@($userFindings | ForEach-Object { $_.Name }) | Sort-Object -Unique) -join ', '))
    }

    if ($changes.Count -eq 0) {
        $changes += '현재 옵션으로 자동 수정되는 항목이 없습니다.'
    }

    if ($policyChanges -eq 0 -and $userFindings.Count -gt 0) {
        return New-ManualOnlyPlan -Definition $Definition -Reason '계정별 암호 만료 없음/초과 상태는 사용자별 정책과 서비스 영향이 있어 수동 조치가 필요합니다.' -Changes $changes
    }

    $expectedStatus = if ($userFindings.Count -eq 0) { '양호' } else { '취약' }
    $notes = if ($userFindings.Count -gt 0) {
        '정책값 적용 후에도 계정별 암호 만료 없음/초과 계정은 수동 조치가 필요합니다.'
    } else {
        ''
    }
    return New-PlanResult -Definition $Definition -AutoSupported:($policyChanges -gt 0) -Changes $changes -Impact '서비스 계정의 암호 갱신 주기와 충돌할 수 있습니다.' -ExpectedStatus $expectedStatus -Notes $notes
}

function Invoke-W0103Apply {
    param($Definition, $Result, $Options, $BackupDirectory)

    Backup-CommandOutput -FileName 'secpol_before.inf' -BackupDirectory $BackupDirectory -ScriptBlock {
        $p = Join-Path $env:TEMP 'Windows.SecurityWorkbench_backup.inf'
        secedit /export /cfg $p /quiet | Out-Null
        Get-Content $p
    }

    & net.exe accounts "/minpwlen:$($Options.MinimumPasswordLength)" "/maxpwage:$($Options.MaximumPasswordAge)" "/minpwage:$($Options.MinimumPasswordAge)" "/uniquepw:$($Options.PasswordHistorySize)" | Out-Null
    Import-SecurityPolicyTemplate -Area 'SECURITYPOLICY' -Sections @{
        'System Access' = @{
            PasswordComplexity = [int]$Options.PasswordComplexity
            ClearTextPassword  = 0
        }
    }
    Clear-SecurityPolicyCache
}

function Invoke-W0104Detect {
    param($Definition, $Options)

    $users = Get-LocalUsersSafe
    $suspicious = @($users | Where-Object { $_.Enabled -and ($_.PasswordRequired -eq $false -or -not $_.PasswordLastSet) })
    $suspiciousNames = @($suspicious | ForEach-Object { $_.Name })
    $details = @(
        '이 항목은 실제 비밀번호 강도 자체를 자동으로 판별하지 않습니다.',
        ('활성 로컬 계정 수: {0}' -f (@($users | Where-Object { $_.Enabled }).Count)),
        ('비밀번호 미설정/점검 필요 계정: {0}' -f (Format-StringList $suspiciousNames))
    )

    if ($suspicious.Count -gt 0) {
        return New-CheckResult -Definition $Definition -Status '취약' -Summary '비밀번호 미설정 또는 수동 점검이 필요한 계정이 존재합니다.' -Details ($details -join [Environment]::NewLine) -Data @{ SuspiciousUsers = $suspicious } -CanAutoRemediate:$false
    }

    return New-CheckResult -Definition $Definition -Status '수동점검' -Summary '정책상 문제는 없지만 실제 약한 비밀번호 여부는 자동 판별하지 않습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ SuspiciousUsers = $suspicious } -CanAutoRemediate:$false
}

function Invoke-W0104Plan {
    param($Definition, $Result, $Options)

    return New-ManualOnlyPlan -Definition $Definition -Reason '실제 비밀번호 변경은 계정/서비스 영향이 커서 자동 적용을 제공하지 않습니다.' -Changes @(
        '점검 대상 계정의 비밀번호를 강한 조합으로 수동 변경',
        '서비스 계정은 서비스 재시작 및 연동 점검 후 반영',
        '필요 시 비밀번호 만료 및 다음 로그온 시 변경 강제'
    )
}

function Invoke-W0105Detect {
    param($Definition, $Options)

    $rules = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorAdmin'; Expected = [int]$Options.ConsentPromptBehaviorAdmin; Type = 'DWord'; Comparison = 'eq'; Description = '관리자 상승 프롬프트 동작' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'PromptOnSecureDesktop'; Expected = [int]$Options.PromptOnSecureDesktop; Type = 'DWord'; Comparison = 'eq'; Description = '보안 데스크톱 사용' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Expected = [int]$Options.EnableLUA; Type = 'DWord'; Comparison = 'eq'; Description = 'UAC 사용' }
    )
    if ($Options.CheckFilterAdministratorToken) {
        $rules += @{
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Name = 'FilterAdministratorToken'
            Expected = [int]$Options.FilterAdministratorToken
            Type = 'DWord'
            Comparison = 'eq'
            Description = 'Administrator 승인 모드'
        }
    }
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if (@($states | Where-Object { -not $_.Compliant }).Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($status -eq '취약') { 'UAC 관련 정책이 기준과 다릅니다.' } else { 'UAC 정책이 기준을 충족합니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0105Plan {
    param($Definition, $Result, $Options)

    $changes = @(
        'UAC 활성화'
        '보안 데스크톱에서 관리자 승인을 요구'
    )
    if ($Options.CheckFilterAdministratorToken) {
        $changes += 'Built-in Administrator에도 승인 모드를 적용'
    }
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes $changes -Impact 'EnableLUA 변경 시 일부 응용프로그램 동작과 재부팅에 영향이 있을 수 있습니다.' -ExpectedStatus '양호' -RequiresRestart:$true
}

function Invoke-W0105Apply {
    param($Definition, $Result, $Options, $BackupDirectory)

    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0106Detect {
    param($Definition, $Options)

    $value = Get-SecurityPolicyInt -Section 'System Access' -Name 'LSAAnonymousNameLookup' -Default -1
    $status = if ($value -eq [int]$Options.LSAAnonymousNameLookup) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { '익명 SID/이름 변환 허용 정책이 비활성화되어 있습니다.' } else { '익명 SID/이름 변환 허용 정책이 활성화되어 있습니다.' }
    $details = 'LSAAnonymousNameLookup={0}' -f $value
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details $details -Data @{ LSAAnonymousNameLookup = $value } -CanAutoRemediate:$true
}

function Invoke-W0106Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('익명 SID/이름 변환 허용 정책을 사용 안 함으로 설정') -Impact '일부 구형 익명 열거 스크립트가 실패할 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0106Apply {
    param($Definition, $Result, $Options, $BackupDirectory)

    Backup-CommandOutput -FileName 'secpol_before.inf' -BackupDirectory $BackupDirectory -ScriptBlock {
        $p = Join-Path $env:TEMP 'Windows.SecurityWorkbench_backup.inf'
        secedit /export /cfg $p /quiet | Out-Null
        Get-Content $p
    }

    Import-SecurityPolicyTemplate -Area 'SECURITYPOLICY' -Sections @{
        'System Access' = @{
            LSAAnonymousNameLookup = [int]$Options.LSAAnonymousNameLookup
        }
    }
}

function Invoke-W0107Detect {
    param($Definition, $Options)

    $rules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LimitBlankPasswordUse'; Expected = [int]$Options.LimitBlankPasswordUse; Type = 'DWord'; Comparison = 'eq'; Description = '콘솔 로그온 시 빈 암호 사용 제한' }
    )
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if (@($states | Where-Object { -not $_.Compliant }).Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($status -eq '양호') { '빈 암호 사용 제한 정책이 활성화되어 있습니다.' } else { '빈 암호 사용 제한 정책이 비활성화되어 있습니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0107Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('빈 암호 로컬 계정의 콘솔 로그온을 제한합니다.') -Impact '자동화용 빈 암호 계정이 있다면 로그인 실패가 발생합니다.' -ExpectedStatus '양호'
}

function Invoke-W0107Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0201Detect {
    param($Definition, $Options)

    $findings = @()
    foreach ($user in Get-LocalUsersSafe | Where-Object { $_.Enabled }) {
        $profile = Join-Path $env:SystemDrive ('Users\{0}' -f $user.Name)
        if (-not (Test-Path -LiteralPath $profile)) {
            continue
        }

        $rules = @(Get-WorldWritableAccessRules -Path $profile)
        if ($rules.Count -gt 0) {
            $findings += [pscustomobject]@{
                User  = $user.Name
                Path  = $profile
                Rules = $rules
            }
        }
    }

    $details = @()
    if ($findings.Count -eq 0) {
        $details += '활성 사용자 프로필에서 Everyone/Users의 광범위 쓰기 권한을 발견하지 못했습니다.'
        return New-CheckResult -Definition $Definition -Status '양호' -Summary '사용자 홈 디렉터리에 광범위 쓰기 권한이 없습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Findings = $findings } -CanAutoRemediate:$true
    }

    foreach ($finding in $findings) {
        $details += ('- {0}: {1}' -f $finding.User, $finding.Path)
        foreach ($rule in $finding.Rules) {
            $details += ('  * {0} / {1}' -f $rule.Identity, $rule.Rights)
        }
    }

    return New-CheckResult -Definition $Definition -Status '취약' -Summary '하나 이상의 사용자 홈 디렉터리에 광범위 쓰기 권한이 있습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Findings = $findings } -CanAutoRemediate:$true
}

function Invoke-W0201Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('사용자 프로필 디렉터리에서 Everyone/Users 광범위 쓰기 권한을 제거하고 관리 계정만 유지합니다.') -Impact '프로필 경로에 수동으로 부여한 권한이 제거될 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0201Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    foreach ($finding in (Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Findings')) {
        Backup-FileAcl -Path $finding.Path -BackupDirectory $BackupDirectory
        Reset-PathAclToAdministrativeOnly -Path $finding.Path -IncludeCurrentUser:$Options.IncludeCurrentUser
    }
}

function Invoke-W0202Detect {
    param($Definition, $Options)

    $shares = Get-SmbSharesSafe
    $issues = @()
    $forceGuest = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'forceguest'
    foreach ($share in $shares) {
        if ($Options.ShareAllowList -contains $share.Name) {
            continue
        }

        $access = @(Get-SmbShareAccessSafe -Name $share.Name)
        $riskyAccess = @($access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            ($_.AccountName -match 'Everyone|Guest')
        } | Select-Object AccountName, AccessControlType, AccessRight)

        $isAdministrative = ($share.Name -in $Options.AdministrativeShares) -or ($share.Name -match '^[A-Z]\$$|^ADMIN\$$')
        if (@($riskyAccess).Count -gt 0 -or $isAdministrative) {
            $issues += [pscustomobject]@{
                Name           = $share.Name
                Path           = $share.Path
                Administrative = $isAdministrative
                RiskyAccess    = $riskyAccess
            }
        }
    }

    $details = @()
    foreach ($issue in $issues) {
        $details += ('- {0} ({1})' -f $issue.Name, $issue.Path)
        if ($issue.Administrative) {
            $details += '  * 관리 공유'
        }
        foreach ($access in $issue.RiskyAccess) {
            $details += ('  * {0}: {1}' -f $access.AccountName, $access.AccessRight)
        }
    }
    $sharingProtected = ([string]$forceGuest -eq [string]$Options.ForceGuest)
    $details += ('암호 보호 공유(ForceGuest)={0} / 기대={1} / 준수={2}' -f $forceGuest, $Options.ForceGuest, $sharingProtected)

    if ((@($issues).Count -eq 0) -and $sharingProtected) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary '위험한 공유 또는 Everyone/Guest 권한을 발견하지 못했고 암호 보호 공유가 유지됩니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Issues = $issues; ForceGuest = $forceGuest } -CanAutoRemediate:$true
    }

    return New-CheckResult -Definition $Definition -Status '취약' -Summary '위험한 공유 설정이 발견되었거나 암호 보호 공유가 꺼져 있습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Issues = $issues; ForceGuest = $forceGuest } -CanAutoRemediate:$true
}

function Invoke-W0202Plan {
    param($Definition, $Result, $Options)

    $resultData = $Result.Data
    if (
        $null -eq (Get-PropertyValueSafe -InputObject $resultData -Name 'Issues' -Default $null) -or
        $null -eq (Get-PropertyValueSafe -InputObject $resultData -Name 'ForceGuest' -Default $null)
    ) {
        $Result = Invoke-W0202Detect -Definition $Definition -Options $Options
        $resultData = $Result.Data
    }

    $issues = @(Get-PropertyValueSafe -InputObject $resultData -Name 'Issues' -Default @())
    $forceGuestCurrent = Get-PropertyValueSafe -InputObject $resultData -Name 'ForceGuest' -Default (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'forceguest')

    $changes = @()
    $residual = @()
    if ($Options.RemoveEveryoneAccess) {
        $changes += '공유 권한에서 Everyone 계정을 제거합니다.'
    }
    if ($Options.RemoveGuestAccess) {
        $changes += '공유 권한에서 Guest 계정을 제거합니다.'
    }
    if ($Options.DisableAdministrativeShares) {
        $changes += '지정된 관리 공유를 삭제하고 자동 재생성을 차단합니다.'
    }
    if ([string]$forceGuestCurrent -ne [string]$Options.ForceGuest) {
        $changes += '암호 보호 공유(ForceGuest)를 사용으로 설정합니다.'
    }

    foreach ($issue in $issues) {
        if ($issue.Administrative -and -not $Options.DisableAdministrativeShares) {
            $residual += ('관리 공유 유지: {0}' -f $issue.Name)
        }

        foreach ($access in @($issue.RiskyAccess)) {
            if ($access.AccountName -match 'Everyone' -and -not $Options.RemoveEveryoneAccess) {
                $residual += ('Everyone 권한 유지: {0}' -f $issue.Name)
            }
            if ($access.AccountName -match 'Guest' -and -not $Options.RemoveGuestAccess) {
                $residual += ('Guest 권한 유지: {0}' -f $issue.Name)
            }
        }
    }

    if ($changes.Count -eq 0) {
        $changes += '현재 옵션으로 자동 수정되는 공유 권한이 없습니다.'
    }

    $expectedStatus = if ($residual.Count -eq 0) { '양호' } else { '취약' }
    $notes = if ($residual.Count -eq 0) {
        ''
    } else {
        '잔여 이슈: {0}. 옵션 JSON에서 RemoveEveryoneAccess/RemoveGuestAccess/DisableAdministrativeShares 값을 조정하십시오.' -f ((@($residual) | Sort-Object -Unique) -join '; ')
    }

    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes $changes -Impact '파일 공유 또는 원격 관리 절차가 중단될 수 있습니다.' -ExpectedStatus $expectedStatus -Notes $notes
}

function Invoke-W0202Apply {
    param($Definition, $Result, $Options, $BackupDirectory)

    $resultData = $Result.Data
    if (
        $null -eq (Get-PropertyValueSafe -InputObject $resultData -Name 'Issues' -Default $null) -or
        $null -eq (Get-PropertyValueSafe -InputObject $resultData -Name 'ForceGuest' -Default $null)
    ) {
        $Result = Invoke-W0202Detect -Definition $Definition -Options $Options
        $resultData = $Result.Data
    }

    $issues = @(Get-PropertyValueSafe -InputObject $resultData -Name 'Issues' -Default @())
    $forceGuestCurrent = Get-PropertyValueSafe -InputObject $resultData -Name 'ForceGuest' -Default (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'forceguest')

    Backup-CommandOutput -FileName 'shares_before.txt' -BackupDirectory $BackupDirectory -ScriptBlock {
        Get-SmbSharesSafe | Format-Table Name, Path, ShareType, Description -AutoSize | Out-String
    }

    $adminShareRules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareServer'; Expected = 0; Type = 'DWord'; Comparison = 'eq'; Description = '서버 기본 관리 공유 자동 생성' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareWks'; Expected = 0; Type = 'DWord'; Comparison = 'eq'; Description = '워크스테이션 기본 관리 공유 자동 생성' }
    )
    $passwordProtectedSharingRules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'forceguest'; Expected = [int]$Options.ForceGuest; Type = 'DWord'; Comparison = 'eq'; Description = '암호 보호 공유(ForceGuest)' }
    )

    foreach ($issue in $issues) {
        $access = @(Get-SmbShareAccessSafe -Name $issue.Name)
        foreach ($entry in $access) {
            if ($Options.RemoveEveryoneAccess -and $entry.AccountName -match 'Everyone') {
                Revoke-SmbShareAccess -Name $issue.Name -AccountName $entry.AccountName -Force | Out-Null
            }
            if ($Options.RemoveGuestAccess -and $entry.AccountName -match 'Guest') {
                Revoke-SmbShareAccess -Name $issue.Name -AccountName $entry.AccountName -Force | Out-Null
            }
        }

        $isAdministrativeTarget = ($issue.Name -in $Options.AdministrativeShares) -or ($issue.Name -match '^[A-Z]\$$|^ADMIN\$$')
        if ($Options.DisableAdministrativeShares -and $isAdministrativeTarget) {
            $exitCode = Invoke-ExternalQuiet -FilePath 'net.exe' -ArgumentList @('share', $issue.Name, '/delete', '/y')
            if ($exitCode -ne 0) {
                Write-ToolLog -Level 'WARN' -Message ('관리 공유 삭제 실패: {0} (exit={1})' -f $issue.Name, $exitCode)
            }
        }
    }

    if ($Options.DisableAdministrativeShares) {
        Invoke-RegistryRemediation -Rules $adminShareRules -BackupDirectory $BackupDirectory
    }
    if ([string]$forceGuestCurrent -ne [string]$Options.ForceGuest) {
        Invoke-RegistryRemediation -Rules $passwordProtectedSharingRules -BackupDirectory $BackupDirectory
    }
}

function Invoke-W0203Detect {
    param($Definition, $Options)

    $path = Join-Path $env:WINDIR 'System32\config\SAM'
    $rules = @(Get-AccessRuleSummary -Path $path)
    $bad = @($rules | Where-Object {
        $_.Type -eq 'Allow' -and
        $_.Identity -notmatch 'SYSTEM|Administrators' -and
        $_.Rights -match 'Read|Write|Modify|FullControl'
    })

    $details = @('대상 경로: ' + $path)
    foreach ($rule in $rules) {
        $details += ('- {0} / {1} / {2}' -f $rule.Identity, $rule.Rights, $rule.Type)
    }

    if (@($bad).Count -gt 0) {
        return New-CheckResult -Definition $Definition -Status '취약' -Summary 'SAM 파일에 관리 계정 외 접근 권한이 존재합니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Path = $path; BadRules = $bad } -CanAutoRemediate:$true
    }

    return New-CheckResult -Definition $Definition -Status '양호' -Summary 'SAM 파일 권한이 제한되어 있습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Path = $path; BadRules = $bad } -CanAutoRemediate:$true
}

function Invoke-W0203Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('SAM 파일 ACL을 SYSTEM/Administrators 전용으로 재설정합니다.') -Impact '수동으로 추가된 보안 제품 계정 권한이 제거될 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0203Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $path = Get-RequiredResultDataValue -Definition $Definition -Result $Result -Options $Options -Name 'Path'
    Backup-FileAcl -Path $path -BackupDirectory $BackupDirectory
    Reset-PathAclToAdministrativeOnly -Path $path -IncludeCurrentUser:$Options.IncludeCurrentUser
}

function Invoke-W0204Detect {
    param($Definition, $Options)
    return New-CheckResult -Definition $Definition -Status '수동점검' -Summary '중요 파일/디렉터리 범위가 서버별로 달라 자동 판정을 제한합니다.' -Details '서버별 업무 경로와 애플리케이션 데이터 경로가 다르므로 경로 목록 합의 후 적용하는 것이 안전합니다.' -Data @{} -CanAutoRemediate:$false
}

function Invoke-W0204Plan {
    param($Definition, $Result, $Options)
    return New-ManualOnlyPlan -Definition $Definition -Reason '애플리케이션 데이터 경로를 모른 상태에서 일괄 권한 수정은 서비스 장애 위험이 큽니다.' -Changes @(
        '보호 대상 디렉터리 목록 확정'
        'Everyone/Users 광범위 쓰기 권한 제거'
        '서비스 계정과 운영 계정 권한 재정의'
    )
}

function Invoke-W0301Detect {
    param($Definition, $Options)

    $findings = @()
    foreach ($serviceName in $Options.TargetServices) {
        if ($Options.IgnoreServices -contains $serviceName) {
            continue
        }

        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (-not $service) {
            continue
        }

        $cim = Get-Win32ClassInstanceSafe -ClassName 'Win32_Service' -Filter ("Name='{0}'" -f $serviceName)
        if ($cim -and ($cim.StartMode -ne 'Disabled' -or $service.Status -eq 'Running')) {
            $findings += [pscustomobject]@{
                Name        = $serviceName
                DisplayName = $service.DisplayName
                Status      = $service.Status.ToString()
                StartMode   = $cim.StartMode
            }
        }
    }

    $details = @()
    foreach ($item in $findings) {
        $details += ('- {0} ({1}) / 상태={2} / 시작유형={3}' -f $item.Name, $item.DisplayName, $item.Status, $item.StartMode)
    }

    if ($findings.Count -eq 0) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary '지정한 불필요 서비스가 발견되지 않았습니다.' -Details '대상 서비스가 없거나 모두 비활성화되어 있습니다.' -Data @{ Findings = $findings } -CanAutoRemediate:$true
    }

    return New-CheckResult -Definition $Definition -Status '취약' -Summary '불필요 서비스가 실행 중이거나 비활성화되어 있지 않습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Findings = $findings } -CanAutoRemediate:$true
}

function Invoke-W0301Plan {
    param($Definition, $Result, $Options)

    $findings = Get-PropertyValueSafe -InputObject $Result.Data -Name 'Findings' -Default $null
    if ($null -eq $findings) {
        $Result = Invoke-W0301Detect -Definition $Definition -Options $Options
        $findings = Get-PropertyValueSafe -InputObject $Result.Data -Name 'Findings' -Default @()
    }

    $findings = @($findings)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(
        ('대상 서비스: {0}' -f (Format-StringList ($findings | ForEach-Object { $_.Name })))
        ('서비스 시작 유형을 {0}(으)로 변경' -f $Options.ServiceAction)
    ) -Impact '서비스 역할이 남아 있는 서버에서 기능 중단이 발생할 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0301Apply {
    param($Definition, $Result, $Options, $BackupDirectory)

    $findings = Get-PropertyValueSafe -InputObject $Result.Data -Name 'Findings' -Default $null
    if ($null -eq $findings) {
        $Result = Invoke-W0301Detect -Definition $Definition -Options $Options
        $findings = Get-PropertyValueSafe -InputObject $Result.Data -Name 'Findings' -Default @()
    }

    $findings = @($findings)
    Backup-CommandOutput -FileName 'services_before.txt' -BackupDirectory $BackupDirectory -ScriptBlock {
        Get-Service | Sort-Object Name | Format-Table Name, Status, StartType -AutoSize | Out-String
    }

    foreach ($service in $findings) {
        if ($service.Status -eq 'Running') {
            Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
        }
        Set-Service -Name $service.Name -StartupType Disabled
    }
}

function ConvertTo-NullableIntSafe {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    $parsed = 0
    if ([int]::TryParse($text, [ref]$parsed)) {
        return [int]$parsed
    }

    try {
        return [int]$Value
    } catch {
        return $null
    }
}

function Format-NullableValueForDisplay {
    param($Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return '(미설정)'
    }

    return [string]$Value
}

function Get-TerminalServicesPaths {
    return [pscustomobject]@{
        PolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        RdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    }
}

function Get-W0302RemediationRules {
    param([hashtable]$Options)

    $paths = Get-TerminalServicesPaths
    return @(
        @{ Path = $paths.PolicyPath; Name = 'MinEncryptionLevel'; Expected = [int]$Options.MinEncryptionLevel; Type = 'DWord'; Comparison = 'ge'; Description = '정책 MinEncryptionLevel' },
        @{ Path = $paths.PolicyPath; Name = 'fDisableCdm'; Expected = [int]$Options.DisableDriveRedirection; Type = 'DWord'; Comparison = 'eq'; Description = '정책 fDisableCdm' },
        @{ Path = $paths.RdpTcpPath; Name = 'MinEncryptionLevel'; Expected = [int]$Options.MinEncryptionLevel; Type = 'DWord'; Comparison = 'ge'; Description = 'RDP-Tcp MinEncryptionLevel' },
        @{ Path = $paths.RdpTcpPath; Name = 'fDisableCdm'; Expected = [int]$Options.DisableDriveRedirection; Type = 'DWord'; Comparison = 'eq'; Description = 'RDP-Tcp fDisableCdm' }
    )
}

function Get-W0304RemediationRules {
    param([hashtable]$Options)

    $expected = [int]$Options.MaxIdleTimeMinutes * 60000
    $paths = Get-TerminalServicesPaths
    return @(
        @{ Path = $paths.PolicyPath; Name = 'MaxIdleTime'; Expected = $expected; Type = 'DWord'; Comparison = 'le'; Description = '정책 MaxIdleTime(ms)' },
        @{ Path = $paths.RdpTcpPath; Name = 'MaxIdleTime'; Expected = $expected; Type = 'DWord'; Comparison = 'le'; Description = 'RDP-Tcp MaxIdleTime(ms)' }
    )
}

function Invoke-W0302Detect {
    param($Definition, $Options)

    $termService = Get-RemoteDesktopServiceState
    if (-not $termService.Exists -or -not $termService.Running) {
        $details = @(
            ('TermService.Exists={0}' -f $termService.Exists)
            ('TermService.Status={0}' -f $termService.Status)
            ('TermService.StartMode={0}' -f $termService.StartMode)
            '터미널 서비스가 구동 중이지 않아 문서 기준상 양호로 판단합니다.'
        )
        return New-CheckResult -Definition $Definition -Status '양호' -Summary '터미널 서비스가 구동 중이지 않습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Rules = @(); States = @(); TermService = $termService } -CanAutoRemediate:$true
    }

    $paths = Get-TerminalServicesPaths
    $policyMin = ConvertTo-NullableIntSafe (Get-RegistryValueSafe -Path $paths.PolicyPath -Name 'MinEncryptionLevel')
    $policyDisableCdm = ConvertTo-NullableIntSafe (Get-RegistryValueSafe -Path $paths.PolicyPath -Name 'fDisableCdm')
    $rdpTcpMin = ConvertTo-NullableIntSafe (Get-RegistryValueSafe -Path $paths.RdpTcpPath -Name 'MinEncryptionLevel')
    $rdpTcpDisableCdm = ConvertTo-NullableIntSafe (Get-RegistryValueSafe -Path $paths.RdpTcpPath -Name 'fDisableCdm')

    $expectedMin = [int]$Options.MinEncryptionLevel
    $expectedDisableCdm = [int]$Options.DisableDriveRedirection
    $policyMinOk = ($null -eq $policyMin) -or ($policyMin -ge $expectedMin)
    $policyDisableCdmOk = ($null -eq $policyDisableCdm) -or ($policyDisableCdm -eq $expectedDisableCdm)
    $rdpTcpMinOk = ($null -ne $rdpTcpMin) -and ($rdpTcpMin -ge $expectedMin)
    $rdpTcpDisableCdmOk = ($null -ne $rdpTcpDisableCdm) -and ($rdpTcpDisableCdm -eq $expectedDisableCdm)

    $states = @(
        [pscustomobject]@{ Description = '정책 MinEncryptionLevel'; Current = $policyMin; Expected = $expectedMin; Compliant = $policyMinOk },
        [pscustomobject]@{ Description = '정책 fDisableCdm'; Current = $policyDisableCdm; Expected = $expectedDisableCdm; Compliant = $policyDisableCdmOk },
        [pscustomobject]@{ Description = 'RDP-Tcp MinEncryptionLevel'; Current = $rdpTcpMin; Expected = $expectedMin; Compliant = $rdpTcpMinOk },
        [pscustomobject]@{ Description = 'RDP-Tcp fDisableCdm'; Current = $rdpTcpDisableCdm; Expected = $expectedDisableCdm; Compliant = $rdpTcpDisableCdmOk }
    )
    $status = if ($rdpTcpMinOk -and $rdpTcpDisableCdmOk -and $policyMinOk -and $policyDisableCdmOk) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { '터미널 서비스 암호화와 리디렉션 설정이 기준을 충족합니다.' } else { '터미널 서비스 암호화/리디렉션 설정이 기준과 다릅니다.' }
    $details = @(
        ('TermService.Status={0}' -f $termService.Status)
        ('TermService.StartMode={0}' -f $termService.StartMode)
        ('검사 기준: 암호화 수준 >= {0}, 드라이브 리디렉션 차단 = {1}' -f $expectedMin, $expectedDisableCdm)
        '판정 방식: RDP-Tcp 실효값은 반드시 기준 충족, 정책값이 존재하면 정책값도 기준 충족'
        ('정책 MinEncryptionLevel={0}' -f (Format-NullableValueForDisplay $policyMin))
        ('정책 fDisableCdm={0}' -f (Format-NullableValueForDisplay $policyDisableCdm))
        ('RDP-Tcp MinEncryptionLevel={0}' -f (Format-NullableValueForDisplay $rdpTcpMin))
        ('RDP-Tcp fDisableCdm={0}' -f (Format-NullableValueForDisplay $rdpTcpDisableCdm))
        (Format-RegistryStateDetails -States $states)
    )
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{
        Rules = Get-W0302RemediationRules -Options $Options
        States = $states
        TermService = $termService
        PolicyMinEncryptionLevel = $policyMin
        PolicyDisableCdm = $policyDisableCdm
        RdpTcpMinEncryptionLevel = $rdpTcpMin
        RdpTcpDisableCdm = $rdpTcpDisableCdm
        EffectiveMinEncryptionLevel = $rdpTcpMin
        EffectiveDisableCdm = $rdpTcpDisableCdm
    } -CanAutoRemediate:$true
}

function Invoke-W0302Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(
        ('RDP 최소 암호화 수준을 {0}(으)로 설정' -f $Options.MinEncryptionLevel)
        '드라이브 리디렉션을 차단'
        '정책 레지스트리와 RDP-Tcp 실효 레지스트리를 함께 설정'
    ) -Impact 'RDP 클라이언트의 드라이브 매핑 기능이 비활성화됩니다.' -ExpectedStatus '양호'
}

function Invoke-W0302Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = @(Get-W0302RemediationRules -Options $Options)
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0303Detect {
    param($Definition, $Options)

    $configs = @(Get-Win32ClassInstancesSafe -ClassName 'Win32_NetworkAdapterConfiguration') | Where-Object { $_.IPEnabled }
    $issues = @()
    foreach ($config in $configs) {
        if ($config.TcpipNetbiosOptions -ne [int]$Options.NetbiosOption) {
            $issues += [pscustomobject]@{
                Description = $config.Description
                Index       = $config.InterfaceIndex
                Current     = $config.TcpipNetbiosOptions
            }
        }
    }

    $details = @()
    foreach ($issue in $issues) {
        $details += ('- {0} / InterfaceIndex={1} / NetBIOS 옵션={2}' -f $issue.Description, $issue.Index, $issue.Current)
    }

    if ($issues.Count -eq 0) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary '모든 활성 NIC에서 NetBIOS가 비활성화되어 있습니다.' -Details '모든 IPEnabled 어댑터가 기준 충족' -Data @{ Issues = $issues } -CanAutoRemediate:$true
    }

    return New-CheckResult -Definition $Definition -Status '취약' -Summary '일부 NIC에서 NetBIOS over TCP/IP가 비활성화되어 있지 않습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Issues = $issues } -CanAutoRemediate:$true
}

function Invoke-W0303Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('현재 활성(IPEnabled) NIC 전체의 NetBIOS over TCP/IP 옵션을 "사용 안 함(2)"으로 설정') -Impact '구형 NetBIOS 기반 이름 확인이 필요한 환경에서는 영향이 있을 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0303Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    Backup-CommandOutput -FileName 'netbios_before.txt' -BackupDirectory $BackupDirectory -ScriptBlock {
        Get-Win32ClassInstancesSafe -ClassName 'Win32_NetworkAdapterConfiguration' | Where-Object { $_.IPEnabled } | Select-Object Description, InterfaceIndex, TcpipNetbiosOptions | Format-Table -AutoSize | Out-String
    }
    foreach ($adapterInfo in @(Get-Win32ClassInstancesSafe -ClassName 'Win32_NetworkAdapterConfiguration') | Where-Object { $_.IPEnabled }) {
        $adapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter ("InterfaceIndex={0}" -f $adapterInfo.InterfaceIndex)
        if ($adapter) {
            [void]$adapter.SetTcpipNetbios([int]$Options.NetbiosOption)
        }
    }
}

function Invoke-W0304Detect {
    param($Definition, $Options)

    $termService = Get-RemoteDesktopServiceState
    if (-not $termService.Exists -or -not $termService.Running) {
        $details = @(
            ('TermService.Exists={0}' -f $termService.Exists)
            ('TermService.Status={0}' -f $termService.Status)
            ('TermService.StartMode={0}' -f $termService.StartMode)
            '터미널 서비스가 구동 중이지 않아 문서 기준상 양호로 판단합니다.'
        )
        return New-CheckResult -Definition $Definition -Status '양호' -Summary '터미널 서비스가 구동 중이지 않습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Rules = @(); States = @(); TermService = $termService } -CanAutoRemediate:$true
    }

    $paths = Get-TerminalServicesPaths
    $expectedMaxIdleTime = [int]$Options.MaxIdleTimeMinutes * 60000
    $policyMaxIdleTime = ConvertTo-NullableIntSafe (Get-RegistryValueSafe -Path $paths.PolicyPath -Name 'MaxIdleTime')
    $rdpTcpMaxIdleTime = ConvertTo-NullableIntSafe (Get-RegistryValueSafe -Path $paths.RdpTcpPath -Name 'MaxIdleTime')
    $policyMaxIdleTimeOk = ($null -eq $policyMaxIdleTime) -or ($policyMaxIdleTime -gt 0 -and $policyMaxIdleTime -le $expectedMaxIdleTime)
    $rdpTcpMaxIdleTimeOk = ($null -ne $rdpTcpMaxIdleTime) -and ($rdpTcpMaxIdleTime -gt 0 -and $rdpTcpMaxIdleTime -le $expectedMaxIdleTime)

    $states = @(
        [pscustomobject]@{ Description = '정책 MaxIdleTime(ms)'; Current = $policyMaxIdleTime; Expected = $expectedMaxIdleTime; Compliant = $policyMaxIdleTimeOk },
        [pscustomobject]@{ Description = 'RDP-Tcp MaxIdleTime(ms)'; Current = $rdpTcpMaxIdleTime; Expected = $expectedMaxIdleTime; Compliant = $rdpTcpMaxIdleTimeOk }
    )
    $status = if ($rdpTcpMaxIdleTimeOk -and $policyMaxIdleTimeOk) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { 'RDP 유휴 세션 제한이 기준 이내입니다.' } else { 'RDP 유휴 세션 제한이 없거나 기준보다 깁니다.' }
    $details = @(
        ('TermService.Status={0}' -f $termService.Status)
        ('TermService.StartMode={0}' -f $termService.StartMode)
        ('검사 기준: MaxIdleTime <= {0}ms' -f $expectedMaxIdleTime)
        '판정 방식: RDP-Tcp 실효값은 반드시 기준 충족, 정책값이 존재하면 정책값도 기준 충족'
        ('정책 MaxIdleTime={0}' -f (Format-NullableValueForDisplay $policyMaxIdleTime))
        ('RDP-Tcp MaxIdleTime={0}' -f (Format-NullableValueForDisplay $rdpTcpMaxIdleTime))
        (Format-RegistryStateDetails -States $states)
    )
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{
        Rules = Get-W0304RemediationRules -Options $Options
        States = $states
        TermService = $termService
        PolicyMaxIdleTime = $policyMaxIdleTime
        RdpTcpMaxIdleTime = $rdpTcpMaxIdleTime
        EffectiveMaxIdleTime = $rdpTcpMaxIdleTime
    } -CanAutoRemediate:$true
}

function Invoke-W0304Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(
        ('RDP 유휴 세션 종료 시간을 {0}분으로 설정' -f $Options.MaxIdleTimeMinutes)
        '정책 레지스트리와 RDP-Tcp 실효 레지스트리를 함께 설정'
    ) -Impact '오래 열어둔 RDP 세션이 자동 종료됩니다.' -ExpectedStatus '양호'
}

function Invoke-W0304Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = @(Get-W0304RemediationRules -Options $Options)
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0401Detect {
    param($Definition, $Options)
    $service = Get-Service -Name 'TlntSvr' -ErrorAction SilentlyContinue
    if (-not $service) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary 'Telnet 서비스가 설치되어 있지 않습니다.' -Details 'TlntSvr 서비스를 찾지 못했습니다.' -Data @{} -CanAutoRemediate:$true
    }

    $cim = Get-Win32ClassInstanceSafe -ClassName 'Win32_Service' -Filter "Name='TlntSvr'"
    $details = '상태={0}, 시작유형={1}' -f $service.Status, $cim.StartMode
    $status = if ($cim.StartMode -eq 'Disabled' -and $service.Status -ne 'Running') { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { 'Telnet 서비스가 비활성화되어 있습니다.' } else { 'Telnet 서비스가 설치되어 있거나 실행 중입니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details $details -Data @{ Installed = $true } -CanAutoRemediate:$true
}

function Invoke-W0401Plan {
    param($Definition, $Result, $Options)
    $changes = @('Telnet 서비스를 중지하고 비활성화')
    if ($Options.UninstallFeature) {
        $changes += '가능하면 Telnet 기능을 제거'
    }
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes $changes -Impact 'Telnet 기반 관리 경로가 더 이상 동작하지 않습니다.' -ExpectedStatus '양호'
}

function Invoke-W0401Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    Backup-CommandOutput -FileName 'telnet_before.txt' -BackupDirectory $BackupDirectory -ScriptBlock {
        Get-Service -Name TlntSvr -ErrorAction SilentlyContinue | Format-Table Status, Name, DisplayName -AutoSize | Out-String
    }

    $service = Get-Service -Name 'TlntSvr' -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq 'Running') {
            Stop-Service -Name 'TlntSvr' -Force -ErrorAction SilentlyContinue
        }
        Set-Service -Name 'TlntSvr' -StartupType Disabled
    }

    if ($Options.UninstallFeature -and (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        $feature = Get-WindowsFeature -Name Telnet-Server -ErrorAction SilentlyContinue
        if ($feature -and $feature.Installed) {
            Uninstall-WindowsFeature -Name Telnet-Server -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

function Invoke-W0402Detect {
    param($Definition, $Options)
    $dnsService = Get-Service -Name 'DNS' -ErrorAction SilentlyContinue
    if (-not $dnsService) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary 'DNS 서버 역할이 설치되어 있지 않습니다.' -Details 'DNS 서비스 미설치' -Data @{} -CanAutoRemediate:$false
    }

    if ($dnsService.Status -ne 'Running') {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary 'DNS 서비스가 실행 중이지 않습니다.' -Details ('DNS 서비스 상태={0}' -f $dnsService.Status) -Data @{} -CanAutoRemediate:$false
    }

    $details = 'DNS 서비스가 설치 및 실행 중입니다. 영역 전송 정책은 서버 구조에 따라 달라 자동 적용을 제한합니다.'
    return New-CheckResult -Definition $Definition -Status '수동점검' -Summary 'DNS 보안 정책은 영역 구성 검토가 필요합니다.' -Details $details -Data @{} -CanAutoRemediate:$false
}

function Invoke-W0402Plan {
    param($Definition, $Result, $Options)
    return New-ManualOnlyPlan -Definition $Definition -Reason '보조 DNS, 포워더, 영역 전송 구조를 모르면 자동 변경이 위험합니다.' -Changes @(
        'DNS 영역 전송 허용 대상 검토'
        '불필요한 영역 전송 차단'
        '캐시 오염, 재귀 허용 범위 점검'
    )
}

function Invoke-W0403Detect {
    param($Definition, $Options)
    $service = Get-Service -Name 'SNMP' -ErrorAction SilentlyContinue
    if (-not $service) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary 'SNMP 서비스가 설치되어 있지 않습니다.' -Details 'SNMP 서비스 미설치' -Data @{} -CanAutoRemediate:$true
    }

    $details = @('SNMP 서비스가 설치되어 있습니다.')
    $details += ('상태={0}' -f $service.Status)
    $details += '커뮤니티 문자열과 허용 관리자 설정은 서버 역할에 따라 달라집니다.'

    $status = if ($service.Status -eq 'Running') { '취약' } else { '수동점검' }
    $summary = if ($status -eq '취약') { 'SNMP 서비스가 실행 중입니다.' } else { 'SNMP 서비스가 설치되어 있으나 실행 중은 아닙니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{ Installed = $true } -CanAutoRemediate:$true
}

function Invoke-W0403Plan {
    param($Definition, $Result, $Options)
    $changes = @('SNMP 서비스를 중지 및 비활성화')
    if ($Options.ReadOnlyCommunity) {
        $changes += '필요 시 읽기 전용 커뮤니티와 허용 관리자만 남기도록 별도 조정'
    }
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes $changes -Impact 'SNMP 모니터링 연동이 중단될 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0403Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    Backup-CommandOutput -FileName 'snmp_before.txt' -BackupDirectory $BackupDirectory -ScriptBlock {
        Get-Service -Name SNMP -ErrorAction SilentlyContinue | Format-Table Status, Name, DisplayName -AutoSize | Out-String
    }
    $service = Get-Service -Name 'SNMP' -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq 'Running') {
            Stop-Service -Name 'SNMP' -Force -ErrorAction SilentlyContinue
        }
        if ($Options.DisableIfPresent) {
            Set-Service -Name 'SNMP' -StartupType Disabled
        }
    }
}

function Invoke-W0501Detect {
    param($Definition, $Options)

    $path = Join-Path $env:WINDIR 'System32\LogFiles'
    $rules = @(Get-WorldWritableAccessRules -Path $path)
    $details = @('대상 경로: ' + $path)
    foreach ($rule in $rules) {
        $details += ('- {0} / {1}' -f $rule.Identity, $rule.Rights)
    }

    if (@($rules).Count -gt 0) {
        return New-CheckResult -Definition $Definition -Status '취약' -Summary '원격 로그파일 경로에 광범위 쓰기 권한이 있습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Path = $path; Rules = $rules } -CanAutoRemediate:$true
    }

    return New-CheckResult -Definition $Definition -Status '양호' -Summary '로그파일 경로에 광범위 쓰기 권한이 없습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Path = $path; Rules = $rules } -CanAutoRemediate:$true
}

function Invoke-W0501Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('로그파일 디렉터리 ACL을 관리 계정 중심으로 재설정') -Impact '로그 수집 에이전트가 별도 계정을 쓰는 경우 권한 재부여가 필요할 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0501Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $path = Get-RequiredResultDataValue -Definition $Definition -Result $Result -Options $Options -Name 'Path'
    Backup-FileAcl -Path $path -BackupDirectory $BackupDirectory
    Reset-PathAclToAdministrativeOnly -Path $path -IncludeCurrentUser:$Options.IncludeCurrentUser
}

function Invoke-W0502Detect {
    param($Definition, $Options)

    $Options = Normalize-W0502TargetOptions -Options $Options
    $targets = Get-W0502TargetProfileHives -Options $Options
    $scopeDescription = Get-W0502ScopeDescription -Options $Options
    try {
        $states = @()
        foreach ($target in $targets) {
            $state = Get-ProfileScreenSaverState -Target $target
            $activeValue = if ($state.ScreenSaveActive) { $state.ScreenSaveActive } else { $state.CurrentActive }
            $secureValue = if ($state.ScreenSaverIsSecure) { $state.ScreenSaverIsSecure } else { $state.CurrentSecure }
            $timeoutValue = if ($state.ScreenSaveTimeOut) { [int]$state.ScreenSaveTimeOut } else { [int]($state.CurrentTimeout | ForEach-Object { if ($_){$_} else {0} }) }
            $exeValue = if ($state.ScreenSaverExe) { [string]$state.ScreenSaverExe } else { [string](Get-RegistryValueSafe -Path (Join-Path $target.HivePath 'Control Panel\Desktop') -Name 'SCRNSAVE.EXE') }
            $compliant = ($activeValue -eq [string]$Options.ScreenSaveActive) -and ($secureValue -eq [string]$Options.ScreenSaverIsSecure) -and ($timeoutValue -gt 0 -and $timeoutValue -le [int]$Options.ScreenSaveTimeOut)
            $states += [pscustomobject]@{
                ProfilePath = $target.ProfilePath
                HivePath    = $target.HivePath
                Active      = $activeValue
                Secure      = $secureValue
                Timeout     = $timeoutValue
                ScreenSaverExe = $exeValue
                Compliant   = $compliant
            }
        }
    } finally {
        Close-ProfileHiveTargets -Targets $targets
    }

    if ($states.Count -eq 0) {
        return New-CheckResult -Definition $Definition -Status '수동점검' -Summary '적용 대상 사용자 프로필을 찾지 못했습니다.' -Details ('적용 대상 프로필을 찾지 못해 수동 확인이 필요합니다. 범위: {0}' -f $scopeDescription) -Data @{ States = $states; Scope = $scopeDescription } -CanAutoRemediate:$true
    }

    $details = @(
        ('적용 대상 범위: {0}' -f $scopeDescription)
    )
    foreach ($state in $states) {
        $details += ('- {0} / Active={1} / Secure={2} / Timeout={3} / SCRNSAVE.EXE={4} / 준수={5}' -f $state.ProfilePath, $state.Active, $state.Secure, $state.Timeout, $state.ScreenSaverExe, $state.Compliant)
    }

    if (@($states | Where-Object { -not $_.Compliant }).Count -gt 0) {
        return New-CheckResult -Definition $Definition -Status '취약' -Summary '하나 이상의 적용 대상 프로필에 화면 보호기 잠금 정책이 적용되지 않았습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ States = $states; Scope = $scopeDescription } -CanAutoRemediate:$true
    }

    return New-CheckResult -Definition $Definition -Status '양호' -Summary '모든 적용 대상 프로필이 화면 보호기 잠금 정책을 충족합니다.' -Details ($details -join [Environment]::NewLine) -Data @{ States = $states; Scope = $scopeDescription } -CanAutoRemediate:$true
}

function Invoke-W0502Plan {
    param($Definition, $Result, $Options)
    $Options = Normalize-W0502TargetOptions -Options $Options
    $scopeDescription = Get-W0502ScopeDescription -Options $Options
    $states = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'States'
    if (@($states).Count -eq 0) {
        return New-ManualOnlyPlan -Definition $Definition -Reason ('적용 대상 사용자 프로필을 찾지 못했습니다. 범위: {0}' -f $scopeDescription) -Changes @(
            '대상 사용자가 한 번 이상 정상 로그인해 프로필이 생성되었는지 확인'
            '손상된 사용자 프로필 또는 잠긴 NTUSER.DAT 여부 확인'
        )
    }
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(
        ('적용 대상 범위: {0}' -f $scopeDescription)
        ('화면 보호기 유휴시간을 {0}초로 설정' -f $Options.ScreenSaveTimeOut)
        '화면 보호기 재개 시 암호 요구'
        '기본 화면 보호기 실행 파일 지정'
    ) -Impact '사용자 세션이 짧은 시간에 잠길 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0502Apply {
    param($Definition, $Result, $Options, $BackupDirectory)

    $Options = Normalize-W0502TargetOptions -Options $Options
    $targets = Get-W0502TargetProfileHives -Options $Options
    if (@($targets).Count -eq 0) {
        throw '적용 대상 사용자 프로필 하이브를 찾지 못했습니다. 사용자가 한 번 이상 로그인해 프로필이 생성되었는지 확인하십시오.'
    }
    try {
        foreach ($target in $targets) {
            $policyPath = Join-Path $target.HivePath 'Software\Policies\Microsoft\Windows\Control Panel\Desktop'
            Backup-RegistryPath -Path $policyPath -BackupDirectory $BackupDirectory
            Ensure-RegistryValue -Path $policyPath -Name 'ScreenSaveActive' -Type String -Value ([string]$Options.ScreenSaveActive)
            Ensure-RegistryValue -Path $policyPath -Name 'ScreenSaverIsSecure' -Type String -Value ([string]$Options.ScreenSaverIsSecure)
            Ensure-RegistryValue -Path $policyPath -Name 'ScreenSaveTimeOut' -Type String -Value ([string]$Options.ScreenSaveTimeOut)
            $exe = if ([string]::IsNullOrWhiteSpace($Options.ScreenSaverExe)) { $script:State.Config.Global.ScreenSaverExecutable } else { $Options.ScreenSaverExe }
            Ensure-RegistryValue -Path $policyPath -Name 'SCRNSAVE.EXE' -Type String -Value $exe
        }
    } finally {
        Close-ProfileHiveTargets -Targets $targets
    }
}

function Invoke-W0503Detect {
    param($Definition, $Options)

    $logs = @('Application', 'Security', 'System')
    $states = @()
    foreach ($logName in $logs) {
        $log = Get-WinEvent -ListLog $logName
        $expected = [int]$Options[$logName]
        $states += [pscustomobject]@{
            Name       = $logName
            Current    = [int64]$log.MaximumSizeInBytes
            Expected   = [int64]$expected
            Compliant  = ([int64]$log.MaximumSizeInBytes -ge [int64]$expected)
        }
    }

    $details = $states | ForEach-Object {
        '- {0}: 현재={1} / 기대>={2} / 준수={3}' -f $_.Name, $_.Current, $_.Expected, $_.Compliant
    }
    $status = if (@($states | Where-Object { -not $_.Compliant }).Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($status -eq '양호') { '주요 이벤트 로그 크기가 기준 이상입니다.' } else { '주요 이벤트 로그 크기가 기준보다 작습니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{ States = $states } -CanAutoRemediate:$true
}

function Invoke-W0503Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(
        'Application/Security/System 로그 최대 크기 확장'
    ) -Impact '로그 보관량이 늘어 디스크 사용량이 증가합니다.' -ExpectedStatus '양호'
}

function Invoke-W0503Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    Backup-CommandOutput -FileName 'eventlogs_before.txt' -BackupDirectory $BackupDirectory -ScriptBlock {
        Get-WinEvent -ListLog Application, Security, System | Select-Object LogName, MaximumSizeInBytes | Format-Table -AutoSize | Out-String
    }
    foreach ($state in (Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'States')) {
        & wevtutil.exe sl $state.Name /ms:$($state.Expected) | Out-Null
    }
}

function Invoke-W0504Detect {
    param($Definition, $Options)

    $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $winlogonCaption = Get-RegistryValueSafe -Path $winlogonPath -Name 'LegalNoticeCaption'
    $winlogonText = Get-RegistryValueSafe -Path $winlogonPath -Name 'LegalNoticeText'
    $policyCaption = Get-RegistryValueSafe -Path $policyPath -Name 'LegalNoticeCaption'
    $policyText = Get-RegistryValueSafe -Path $policyPath -Name 'LegalNoticeText'
    $caption = if ([string]::IsNullOrWhiteSpace([string]$winlogonCaption)) { $policyCaption } else { $winlogonCaption }
    $text = if ([string]::IsNullOrWhiteSpace([string]$winlogonText)) { $policyText } else { $winlogonText }
    $issues = @()
    if ([string]::IsNullOrWhiteSpace([string]$caption)) { $issues += '로그인 경고 제목이 비어 있습니다.' }
    if ([string]::IsNullOrWhiteSpace([string]$text)) { $issues += '로그인 경고 본문이 비어 있습니다.' }
    $details = @(
        ('Winlogon.LegalNoticeCaption={0}' -f $winlogonCaption)
        ('Winlogon.LegalNoticeText={0}' -f $winlogonText)
        ('PoliciesSystem.LegalNoticeCaption={0}' -f $policyCaption)
        ('PoliciesSystem.LegalNoticeText={0}' -f $policyText)
    )
    if ($issues.Count -gt 0) {
        $details += ''
        $details += '문제점:'
        $details += ($issues | ForEach-Object { '- ' + $_ })
    }
    $status = if ($issues.Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($status -eq '양호') { '로그인 경고 메시지가 설정되어 있습니다.' } else { '로그인 경고 메시지가 미설정입니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{ Caption = $caption; Text = $text; WinlogonPath = $winlogonPath; PolicyPath = $policyPath } -CanAutoRemediate:$true
}

function Invoke-W0504Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(
        ('로그인 경고 제목 설정: {0}' -f $Options.Caption)
        '로그인 경고 본문 설정'
    ) -Impact '로그온 시 배너가 표시됩니다.' -ExpectedStatus '양호'
}

function Invoke-W0504Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'LegalNoticeCaption'; Expected = [string]$Options.Caption; Type = 'String'; Comparison = 'eq'; Description = 'Winlogon 로그인 경고 제목' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'LegalNoticeText'; Expected = [string]$Options.Text; Type = 'String'; Comparison = 'eq'; Description = 'Winlogon 로그인 경고 본문' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'LegalNoticeCaption'; Expected = [string]$Options.Caption; Type = 'String'; Comparison = 'eq'; Description = 'Policies 로그인 경고 제목' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'LegalNoticeText'; Expected = [string]$Options.Text; Type = 'String'; Comparison = 'eq'; Description = 'Policies 로그인 경고 본문' }
    )
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0505Detect {
    param($Definition, $Options)
    $rules = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'DontDisplayLastUserName'; Expected = [int]$Options.DontDisplayLastUserName; Type = 'DWord'; Comparison = 'eq'; Description = '마지막 로그인 사용자 숨김' }
    )
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if ($states[0].Compliant) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { '마지막 로그인 사용자명이 숨겨집니다.' } else { '마지막 로그인 사용자명이 노출됩니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0505Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('마지막 로그인 사용자명을 숨김') -Impact '로그온 화면에서 마지막 사용자명이 자동 채워지지 않습니다.' -ExpectedStatus '양호'
}

function Invoke-W0505Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0506Detect {
    param($Definition, $Options)
    $rules = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ShutdownWithoutLogon'; Expected = [int]$Options.ShutdownWithoutLogon; Type = 'DWord'; Comparison = 'eq'; Description = '로그온 전 시스템 종료 허용' }
    )
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if ($states[0].Compliant) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { '로그온 전 시스템 종료가 차단됩니다.' } else { '로그온 전 시스템 종료가 허용됩니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0506Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('로그온 전 시스템 종료 허용을 차단') -Impact '로그온 없이 전원 끄기 메뉴를 사용하던 절차가 막힙니다.' -ExpectedStatus '양호'
}

function Invoke-W0506Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0507Detect {
    param($Definition, $Options)

    $states = @()
    foreach ($name in @('AuditObjectAccess', 'AuditAccountManage', 'AuditAccountLogon', 'AuditPrivilegeUse', 'AuditLogonEvents', 'AuditSystemEvents', 'AuditPolicyChange')) {
        $current = Get-SecurityPolicyInt -Section 'Event Audit' -Name $name -Default -1
        $expected = [int]$Options[$name]
        $states += [pscustomobject]@{
            Name      = $name
            Current   = $current
            Expected  = $expected
            Compliant = ($current -eq $expected)
        }
    }
    $details = $states | ForEach-Object { '- {0}: 현재={1} / 기대={2} / 준수={3}' -f $_.Name, $_.Current, $_.Expected, $_.Compliant }
    $status = if (@($states | Where-Object { -not $_.Compliant }).Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($status -eq '양호') { '기본 로컬 감사 정책이 기준을 충족합니다.' } else { '로컬 감사 정책이 일부 누락되어 있습니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{ States = $states } -CanAutoRemediate:$true
}

function Invoke-W0507Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(
        '개체 액세스/계정 관리/계정 로그온/권한 사용/로그온 이벤트 감사 성공+실패 설정'
        '시스템 이벤트/정책 변경 감사는 문서 기준값으로 설정'
    ) -Impact '보안 이벤트 로그 증가로 디스크 사용량이 늘어납니다.' -ExpectedStatus '양호'
}

function Invoke-W0507Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    Backup-CommandOutput -FileName 'secpol_before.inf' -BackupDirectory $BackupDirectory -ScriptBlock {
        $p = Join-Path $env:TEMP 'Windows.SecurityWorkbench_backup.inf'
        secedit /export /cfg $p /quiet | Out-Null
        Get-Content $p
    }

    Import-SecurityPolicyTemplate -Area 'SECURITYPOLICY' -Sections @{
        'Event Audit' = @{
            AuditObjectAccess = [int]$Options.AuditObjectAccess
            AuditAccountManage = [int]$Options.AuditAccountManage
            AuditAccountLogon = [int]$Options.AuditAccountLogon
            AuditPrivilegeUse = [int]$Options.AuditPrivilegeUse
            AuditLogonEvents  = [int]$Options.AuditLogonEvents
            AuditSystemEvents = [int]$Options.AuditSystemEvents
            AuditPolicyChange = [int]$Options.AuditPolicyChange
        }
    }
}

function Invoke-W0508Detect {
    param($Definition, $Options)
    $rules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; Name = 'ClearPageFileAtShutdown'; Expected = [int]$Options.ClearPageFileAtShutdown; Type = 'DWord'; Comparison = 'eq'; Description = '종료 시 페이지파일 지움' }
    )
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if ($states[0].Compliant) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { '종료 시 페이지파일 삭제가 활성화되어 있습니다.' } else { '종료 시 페이지파일 삭제가 비활성화되어 있습니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0508Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('시스템 종료 시 페이지파일 자동 삭제 활성화') -Impact '종료 시간이 길어질 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0508Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0509Detect {
    param($Definition, $Options)
    if ($script:State.Environment.OsContext.Release -eq '2012R2') {
        return New-CheckResult -Definition $Definition -Status '수동점검' -Summary 'Windows.xlsm 기준상 2012 R2에서는 N/A 처리되는 항목입니다.' -Details '엑셀의 exclude_check_version 설정에 2012_R2가 포함되어 있어 전용판 목록에서 제외했습니다.' -Data @{} -CanAutoRemediate:$false
    }
    $rules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Expected = [int]$Options.LmCompatibilityLevel; Type = 'DWord'; Comparison = 'ge'; Description = 'Lan Manager 인증 수준' }
    )
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if ($states[0].Compliant) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { 'Lan Manager 인증 수준이 기준 이상입니다.' } else { 'Lan Manager 인증 수준이 낮습니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0509Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(('LmCompatibilityLevel을 {0}(으)로 설정' -f $Options.LmCompatibilityLevel)) -Impact '구형 NTLMv1 클라이언트와의 호환성이 저하될 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0509Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0510Detect {
    param($Definition, $Options)
    $rules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'EveryoneIncludesAnonymous'; Expected = [int]$Options.EveryoneIncludesAnonymous; Type = 'DWord'; Comparison = 'eq'; Description = 'Everyone에 익명 사용자 포함' }
    )
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if ($states[0].Compliant) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { '익명 사용자에게 Everyone 권한이 적용되지 않습니다.' } else { '익명 사용자에게 Everyone 권한이 적용됩니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0510Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('익명 사용자에게 Everyone 권한이 적용되지 않도록 설정') -Impact '일부 익명 접근 리소스가 제한될 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0510Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0511Detect {
    param($Definition, $Options)
    $rules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'; Name = 'AddPrinterDrivers'; Expected = [int]$Options.AddPrinterDrivers; Type = 'DWord'; Comparison = 'eq'; Description = '프린터 드라이버 설치 제한' }
    )
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if ($states[0].Compliant) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { '프린터 드라이버 설치 제한이 활성화되어 있습니다.' } else { '프린터 드라이버 설치 제한이 비활성화되어 있습니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0511Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('일반 사용자 프린터 드라이버 설치 제한 활성화') -Impact '비관리자 사용자의 프린터 드라이버 설치가 제한됩니다.' -ExpectedStatus '양호'
}

function Invoke-W0511Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0512Detect {
    param($Definition, $Options)
    $rules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoDisconnect'; Expected = [int]$Options.AutoDisconnectMinutes; Type = 'DWord'; Comparison = 'le'; Description = '유휴 SMB 세션 자동 끊기(분)' }
    )
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if ($states[0].Compliant) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { '유휴 SMB 세션 제한이 기준 이내입니다.' } else { '유휴 SMB 세션 제한이 기준보다 깁니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0512Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(('유휴 SMB 세션 자동 끊기 시간을 {0}분 이하로 설정' -f $Options.AutoDisconnectMinutes)) -Impact '오래 열어둔 파일 공유 세션이 끊어질 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0512Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0513Detect {
    param($Definition, $Options)
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    $suspects = @()
    foreach ($task in @($tasks)) {
        foreach ($action in @($task.Actions)) {
            $execute = if ($action.PSObject.Properties['Execute']) { $action.Execute } else { $null }
            $arguments = if ($action.PSObject.Properties['Arguments']) { $action.Arguments } else { '' }
            if ([string]::IsNullOrWhiteSpace([string]$execute)) {
                continue
            }
            $command = '{0} {1}' -f $execute, $arguments
            foreach ($pattern in $Options.SuspiciousPathPatterns) {
                if ($command -like ('*{0}*' -f $pattern)) {
                    $suspects += [pscustomobject]@{
                        TaskName  = $task.TaskName
                        TaskPath  = $task.TaskPath
                        Command   = $command
                        Pattern   = $pattern
                    }
                    break
                }
            }
        }
    }

    if (@($suspects).Count -eq 0) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary '의심스러운 예약 작업 경로를 발견하지 못했습니다.' -Details '점검 패턴 기준 문제 없음' -Data @{ Suspects = $suspects } -CanAutoRemediate:$false
    }

    $details = $suspects | ForEach-Object { '- {0}{1} -> {2}' -f $_.TaskPath, $_.TaskName, $_.Command }
    return New-CheckResult -Definition $Definition -Status '수동점검' -Summary '의심스러운 예약 작업 후보가 있습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Suspects = $suspects } -CanAutoRemediate:$false
}

function Invoke-W0513Plan {
    param($Definition, $Result, $Options)
    return New-ManualOnlyPlan -Definition $Definition -Reason '작업 비활성화 전에 업무 배치 여부 확인이 필요합니다.' -Changes @(
        '의심 작업 확인'
        '업무 불필요 시 작업 비활성화 또는 삭제'
        '실행 파일 무결성 검증'
    )
}

function Invoke-W0514Detect {
    param($Definition, $Options)
    $currentSids = Split-PolicySidString (Get-SecurityPolicyValue -Section 'Privilege Rights' -Name 'SeRemoteShutdownPrivilege' -Default '')
    $expectedSids = @()
    foreach ($account in $Options.AllowedAccounts) {
        $sid = Resolve-AccountToSid -Account $account
        if ($sid) {
            $expectedSids += $sid
        }
    }
    $currentSorted = @($currentSids | Sort-Object -Unique)
    $expectedSorted = @($expectedSids | Sort-Object -Unique)
    $isSame = (@(Compare-Object -ReferenceObject $expectedSorted -DifferenceObject $currentSorted).Count -eq 0)
    $details = @(
        ('현재 SID: {0}' -f (Format-StringList $currentSorted)),
        ('기대 SID: {0}' -f (Format-StringList $expectedSorted))
    )
    $status = if ($isSame) { '양호' } else { '취약' }
    $summary = if ($isSame) { '원격 시스템 종료 권한이 허용 계정으로 제한되어 있습니다.' } else { '원격 시스템 종료 권한에 추가 계정이 포함되어 있습니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{ CurrentSids = $currentSorted; ExpectedSids = $expectedSorted } -CanAutoRemediate:$true
}

function Invoke-W0514Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(('SeRemoteShutdownPrivilege 권한을 다음 계정으로 제한: {0}' -f (Format-StringList $Options.AllowedAccounts))) -Impact '운영툴이 원격 종료 권한에 의존하면 영향이 있을 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0514Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    Backup-CommandOutput -FileName 'secpol_before.inf' -BackupDirectory $BackupDirectory -ScriptBlock {
        $p = Join-Path $env:TEMP 'Windows.SecurityWorkbench_backup.inf'
        secedit /export /cfg $p /quiet | Out-Null
        Get-Content $p
    }
    Import-SecurityPolicyTemplate -Area 'USER_RIGHTS' -Sections @{
        'Privilege Rights' = @{
            SeRemoteShutdownPrivilege = (Convert-SidListToPolicyString -Sids (Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'ExpectedSids'))
        }
    }
}

function Invoke-W0515Detect {
    param($Definition, $Options)
    $rules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'CrashOnAuditFail'; Expected = [int]$Options.CrashOnAuditFail; Type = 'DWord'; Comparison = 'eq'; Description = '감사 로그 실패 시 즉시 종료' }
    )
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if ($states[0].Compliant) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { '감사 로그 실패 시 즉시 종료가 비활성화되어 있습니다.' } else { '감사 로그 실패 시 즉시 종료가 활성화되어 있습니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0515Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('감사 로그 실패 시 즉시 종료 정책 비활성화') -Impact '없음' -ExpectedStatus '양호'
}

function Invoke-W0515Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0516Detect {
    param($Definition, $Options)

    $rules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireSignOrSeal'; Expected = [int]$Options.RequireSignOrSeal; Type = 'DWord'; Comparison = 'eq'; Description = '보안 채널 서명/암호화 요구' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireStrongKey'; Expected = [int]$Options.RequireStrongKey; Type = 'DWord'; Comparison = 'eq'; Description = '보안 채널 강한 키 요구' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SealSecureChannel'; Expected = [int]$Options.SealSecureChannel; Type = 'DWord'; Comparison = 'eq'; Description = '보안 채널 암호화' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SignSecureChannel'; Expected = [int]$Options.SignSecureChannel; Type = 'DWord'; Comparison = 'eq'; Description = '보안 채널 서명' }
    )
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if (@($states | Where-Object { -not $_.Compliant }).Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($status -eq '양호') { 'Netlogon 보안 채널 정책이 기준을 충족합니다.' } else { 'Netlogon 보안 채널 정책이 기준과 다릅니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0516Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('Netlogon 보안 채널 서명/암호화를 강제') -Impact '매우 오래된 도메인/시스템과의 신뢰 관계에 영향이 있을 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0516Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0517Detect {
    param($Definition, $Options)
    return Invoke-W0511Detect $Definition $Options
}

function Invoke-W0517Plan {
    param($Definition, $Result, $Options)
    return Invoke-W0511Plan $Definition $Result $Options
}

function Invoke-W0517Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    Invoke-W0511Apply $Definition $Result $Options $BackupDirectory
}

function Get-UninstallDisplayNames {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $names = @()
    foreach ($root in $roots) {
        foreach ($item in Get-ItemProperty -Path $root -ErrorAction SilentlyContinue) {
            $displayNameProperty = $item.PSObject.Properties['DisplayName']
            if ($displayNameProperty -and $displayNameProperty.Value) {
                $names += [pscustomobject]@{
                    DisplayName    = $displayNameProperty.Value
                    DisplayVersion = if ($item.PSObject.Properties['DisplayVersion']) { $item.PSObject.Properties['DisplayVersion'].Value } else { $null }
                    Publisher      = if ($item.PSObject.Properties['Publisher']) { $item.PSObject.Properties['Publisher'].Value } else { $null }
                }
            }
        }
    }
    return $names
}

function Get-PendingWindowsUpdates {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search($script:State.Config.Global.WindowsUpdateSearchFilter)
    $updates = @()
    for ($i = 0; $i -lt $result.Updates.Count; $i++) {
        $update = $result.Updates.Item($i)
        $kbs = @()
        foreach ($kb in $update.KBArticleIDs) {
            $kbs += ('KB{0}' -f $kb)
        }
        $updates += [pscustomobject]@{
            Title               = $update.Title
            KBs                 = $kbs
            RebootRequired      = $update.RebootRequired
            IsDownloaded        = $update.IsDownloaded
            Severity            = $update.MsrcSeverity
            Categories          = @($update.Categories | ForEach-Object { $_.Name })
        }
    }
    return $updates
}

function Install-PendingWindowsUpdates {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $searchResult = $searcher.Search($script:State.Config.Global.WindowsUpdateSearchFilter)
    if ($searchResult.Updates.Count -eq 0) {
        return [pscustomobject]@{
            Count          = 0
            ResultCode     = 'NotApplicable'
            RebootRequired = $false
            Titles         = @()
        }
    }

    $updatesToProcess = New-Object -ComObject Microsoft.Update.UpdateColl
    for ($i = 0; $i -lt $searchResult.Updates.Count; $i++) {
        [void]$updatesToProcess.Add($searchResult.Updates.Item($i))
    }

    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $updatesToProcess
    [void]$downloader.Download()

    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $updatesToProcess
    $result = $installer.Install()

    return [pscustomobject]@{
        Count          = $updatesToProcess.Count
        ResultCode     = $result.ResultCode.ToString()
        RebootRequired = [bool]$result.RebootRequired
        Titles         = @($updatesToProcess | ForEach-Object { $_.Title })
    }
}

function Get-WindowsFeatureCandidateSafe {
    param(
        [string[]]$Names,
        [string[]]$NamePatterns = @()
    )

    if (-not (Test-CommandSafe -Name 'Get-WindowsFeature')) {
        return $null
    }

    foreach ($name in @($Names)) {
        if (-not $name) {
            continue
        }

        $feature = Get-WindowsFeature -Name $name -ErrorAction SilentlyContinue
        if ($feature) {
            return $feature
        }
    }

    if (@($NamePatterns).Count -eq 0) {
        return $null
    }

    foreach ($feature in @(Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        foreach ($pattern in $NamePatterns) {
            if ($feature.Name -like $pattern -or $feature.DisplayName -like $pattern) {
                return $feature
            }
        }
    }

    return $null
}

function Get-DefenderFeatureCandidateSafe {
    return Get-WindowsFeatureCandidateSafe -Names @(
        'Windows-Defender'
        'Windows-Defender-Features'
        'Microsoft-Defender'
    ) -NamePatterns @('*Defender*')
}

function Get-DefenderMpCmdRunPath {
    $candidates = @(
        (Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Defender\MpCmdRun.exe')
    )

    if (Get-ChildItem Env:ProgramFiles(x86) -ErrorAction SilentlyContinue) {
        $programFilesX86 = (Get-Item Env:ProgramFiles(x86)).Value
        $candidates += @(
            (Join-Path $programFilesX86 'Windows Defender\MpCmdRun.exe'),
            (Join-Path $programFilesX86 'Microsoft Defender\MpCmdRun.exe')
        )
    }

    if ($env:ProgramData) {
        $platformRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
        foreach ($item in @(Get-ChildItem -Path (Join-Path $platformRoot '*\MpCmdRun.exe') -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
            $candidates += $item.FullName
        }
    }

    foreach ($candidate in @($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

function Get-DefenderStatusSafe {
    if (Test-CommandSafe -Name 'Get-MpComputerStatus') {
        try {
            $status = Get-MpComputerStatus -ErrorAction Stop
            $snapshot = [pscustomobject]@{
                AMProductVersion          = $status.AMProductVersion
                AntivirusSignatureVersion = $status.AntivirusSignatureVersion
                NISSignatureVersion       = $status.NISSignatureVersion
                QuickScanAge              = $status.QuickScanAge
                FullScanAge               = $status.FullScanAge
                RebootRequired            = $status.RebootRequired
            }
            return [pscustomobject]@{
                Source                        = 'Get-MpComputerStatus'
                AntivirusEnabled              = [bool]$status.AntivirusEnabled
                AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
                RealTimeProtectionEnabled     = [bool]$status.RealTimeProtectionEnabled
                Raw                           = $snapshot
            }
        } catch {
            Write-ToolLog -Level 'WARN' -Message ('Get-MpComputerStatus 조회 실패: {0}' -f $_.Exception.Message)
        }
    }

    $defenderService = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
    $signatureInfo = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates' -ErrorAction SilentlyContinue
    if (-not $defenderService -and -not $signatureInfo) {
        return $null
    }

    $signatureUpdated = $null
    foreach ($propertyName in @('SignaturesLastUpdated', 'AVSignatureApplied', 'ASSignatureApplied')) {
        $value = Get-PropertyValueSafe -InputObject $signatureInfo -Name $propertyName
        if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
            continue
        }

        try {
            $signatureUpdated = [datetime]$value
            break
        } catch {
            continue
        }
    }

    $disableRealtime = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableRealtimeMonitoring'
    return [pscustomobject]@{
        Source                        = 'RegistryFallback'
        AntivirusEnabled              = [bool]($defenderService -and $defenderService.StartType -ne 'Disabled')
        AntivirusSignatureLastUpdated = $signatureUpdated
        RealTimeProtectionEnabled     = ($disableRealtime -ne 1)
        Raw                           = [pscustomobject]@{
            ServiceStatus      = if ($defenderService) { $defenderService.Status } else { $null }
            ServiceStartType   = if ($defenderService) { $defenderService.StartType } else { $null }
            SignatureAvailable = [bool]$signatureInfo
        }
    }
}

function Update-DefenderSignaturesSafe {
    if (Test-CommandSafe -Name 'Update-MpSignature') {
        Update-MpSignature -ErrorAction Stop | Out-Null
        return
    }

    $mpCmdRun = Get-DefenderMpCmdRunPath
    if ($mpCmdRun) {
        $exitCode = Invoke-ExternalQuiet -FilePath $mpCmdRun -ArgumentList @('-SignatureUpdate')
        if ($exitCode -eq 0) {
            return
        }

        throw ('MpCmdRun.exe 서명 업데이트 실패: exit={0}' -f $exitCode)
    }

    throw 'Update-MpSignature 또는 MpCmdRun.exe를 사용할 수 없습니다.'
}

function Invoke-W0601Detect {
    param($Definition, $Options)
    $servicePattern = (@($Options.AntivirusServicePatterns) | ForEach-Object { [regex]::Escape([string]$_) }) -join '|'
    $displayPattern = (@($Options.AntivirusDisplayPatterns) | ForEach-Object { [regex]::Escape([string]$_) }) -join '|'
    $services = @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $servicePattern -or $_.DisplayName -match $servicePattern
    })
    $installed = @(Get-UninstallDisplayNames | Where-Object {
        $_.DisplayName -match $displayPattern
    })

    $details = @()
    foreach ($service in @($services | Sort-Object Name -Unique)) {
        $details += ('- 서비스: {0} / 상태={1}' -f $service.Name, $service.Status)
    }
    foreach ($product in $installed | Select-Object -Unique DisplayName, DisplayVersion) {
        $details += ('- 제품: {0} {1}' -f $product.DisplayName, $product.DisplayVersion)
    }

    if ($services.Count -gt 0 -or $installed.Count -gt 0) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary '백신/엔드포인트 보안 제품이 감지되었습니다.' -Details (($details | Sort-Object -Unique) -join [Environment]::NewLine) -Data @{ Services = $services; Products = $installed } -CanAutoRemediate:$false
    }

    return New-CheckResult -Definition $Definition -Status '취약' -Summary '백신 또는 EDR 제품을 감지하지 못했습니다.' -Details 'Defender 또는 주요 보안 제품 서비스/설치 항목을 찾지 못했습니다.' -Data @{ Services = $services; Products = $installed } -CanAutoRemediate:$false
}

function Invoke-W0601Plan {
    param($Definition, $Result, $Options)
    return New-ManualOnlyPlan -Definition $Definition -Reason '이 전용판에서는 백신/EDR 설치를 자동 배포하지 않습니다. 서버별 제품 표준과 운영 절차에 따라 수동으로 진행해야 합니다.' -Changes @(
        '도입할 백신 또는 EDR 제품 선정'
        '설치 패키지 및 정책 준비'
        '설치 후 실시간 보호 및 업데이트 상태 확인'
    )
}

function Invoke-W0602Detect {
    param($Definition, $Options)

    $status = Get-DefenderStatusSafe
    if (-not $status) {
        return New-CheckResult -Definition $Definition -Status '수동점검' -Summary 'Defender 상태를 자동으로 확인할 수 없어 수동 확인이 필요합니다.' -Details 'Get-MpComputerStatus/MpCmdRun/레지스트리 정보 미감지' -Data @{} -CanAutoRemediate:$false
    }

    $lastUpdated = $status.AntivirusSignatureLastUpdated
    $ageDays = if ($lastUpdated) { [math]::Round(((Get-Date) - $lastUpdated).TotalDays, 2) } else { $null }
    $details = @(
        ('Source={0}' -f $status.Source)
        ('AntivirusEnabled={0}' -f $status.AntivirusEnabled)
        ('AntivirusSignatureLastUpdated={0}' -f $lastUpdated)
        ('SignatureAgeDays={0}' -f $ageDays)
        ('RealTimeProtectionEnabled={0}' -f $status.RealTimeProtectionEnabled)
    )

    if ($status.AntivirusEnabled -and $null -ne $ageDays -and $ageDays -le [int]$Options.MaxSignatureAgeDays) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary '백신 엔진 서명이 최신 기준 이내입니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Status = $status; SignatureAgeDays = $ageDays } -CanAutoRemediate:$true
    }

    if ($null -eq $ageDays) {
        return New-CheckResult -Definition $Definition -Status '수동점검' -Summary 'Defender 서명 갱신 시각을 자동 확인할 수 없어 수동 확인이 필요합니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Status = $status; SignatureAgeDays = $ageDays } -CanAutoRemediate:$false
    }

    return New-CheckResult -Definition $Definition -Status '취약' -Summary '백신 엔진 서명이 오래되었거나 Defender가 비활성화되어 있습니다.' -Details ($details -join [Environment]::NewLine) -Data @{ Status = $status; SignatureAgeDays = $ageDays } -CanAutoRemediate:$true
}

function Invoke-W0602Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('Microsoft Defender 엔진 및 시그니처 업데이트 실행') -Impact '업데이트 중 네트워크 사용량이 증가할 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0602Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    Update-DefenderSignaturesSafe
}

function Invoke-W0701Detect {
    param($Definition, $Options)
    $auditInfo = Get-RegistryAuditRulesSafe -Path $Options.RegistryPath
    $targetSid = if ($Options.Identity -eq 'Everyone') {
        Get-WellKnownSidValue -Name 'WorldSid'
    } else {
        Resolve-AccountToSid -Account $Options.Identity
    }

    if (-not $targetSid) {
        return New-CheckResult -Definition $Definition -Status '오류' -Summary '감사 대상 계정 SID를 확인하지 못했습니다.' -Details ('Identity={0}' -f $Options.Identity) -Data @{ Path = $Options.RegistryPath; Identity = $Options.Identity } -CanAutoRemediate:$false
    }

    $matchingRules = @($auditInfo.Rules | Where-Object {
        Test-RegistryAuditRuleMatch -Rule $_ -IdentitySid $targetSid -Rights $Options.Rights -AuditFlags $Options.AuditFlags
    })

    $status = if ($matchingRules.Count -gt 0) { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') {
        'SAM 키에 Everyone 성공/실패 감사 규칙이 설정되어 있습니다.'
    } else {
        'SAM 키에 Everyone 성공/실패 감사 규칙이 없습니다.'
    }

    $details = @(
        ('Path={0}' -f $Options.RegistryPath)
        ('Identity={0}' -f $Options.Identity)
        ('RequiredRights={0}' -f $Options.Rights)
        ('RequiredAuditFlags={0}' -f (Format-StringList $Options.AuditFlags))
        ''
        '현재 감사 규칙:'
        (Format-RegistryAuditRuleDetails -Rules $auditInfo.Rules)
    )

    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{
        Path          = $Options.RegistryPath
        TargetSid     = $targetSid
        Rules         = $auditInfo.Rules
        MatchingRules = $matchingRules
        Options       = $Options
    } -CanAutoRemediate:$true
}

function Invoke-W0701Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(
        ('{0} 키 감사 규칙에 {1} 성공/실패 감사를 추가 또는 재정의' -f $Options.RegistryPath, $Options.Identity)
    ) -Impact 'SAM 접근 감사 이벤트가 증가할 수 있습니다.' -ExpectedStatus '양호' -Notes '객체 액세스 감사 정책과 이벤트 로그 용량을 함께 검토하십시오.'
}

function Invoke-W0701Apply {
    param($Definition, $Result, $Options, $BackupDirectory)

    Backup-CommandOutput -FileName 'sam_audit_before.txt' -BackupDirectory $BackupDirectory -ScriptBlock {
        Get-Acl -Path $Options.RegistryPath -Audit -ErrorAction Stop | Format-List * | Out-String
    }

    $acl = Get-Acl -Path $Options.RegistryPath -Audit -ErrorAction Stop
    $targetSid = Get-RequiredResultDataValue -Definition $Definition -Result $Result -Options $Options -Name 'TargetSid'
    foreach ($rule in @($acl.Audit)) {
        if ((Get-IdentityReferenceSidValue -IdentityReference $rule.IdentityReference) -eq $targetSid) {
            [void]$acl.RemoveAuditRuleAll($rule)
        }
    }

    $newRule = New-RegistryAuditRuleSafe -Identity $Options.Identity -Rights $Options.Rights -AuditFlags $Options.AuditFlags -InheritanceFlags $Options.InheritanceFlags -PropagationFlags $Options.PropagationFlags
    [void]$acl.AddAuditRule($newRule)
    Set-Acl -Path $Options.RegistryPath -AclObject $acl
}

function Invoke-W0702Detect {
    param($Definition, $Options)

    $restrictAnonymous = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous'
    $shares = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'NullSessionShares'
    $pipes = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'NullSessionPipes'

    if ($shares -isnot [array] -and $shares) { $shares = @($shares) }
    if ($pipes -isnot [array] -and $pipes) { $pipes = @($pipes) }

    $issues = @()
    if ([int]$restrictAnonymous -ne [int]$Options.RestrictAnonymous) { $issues += ('RestrictAnonymous 값이 기준과 다릅니다. 현재={0} / 기대={1}' -f $restrictAnonymous, $Options.RestrictAnonymous) }
    if ($Options.CheckNullSessionLists -and @($shares).Count -gt 0) { $issues += ('NullSessionShares가 설정되어 있습니다: {0}' -f (Format-StringList $shares)) }
    if ($Options.CheckNullSessionLists -and @($pipes).Count -gt 0) { $issues += ('NullSessionPipes가 설정되어 있습니다: {0}' -f (Format-StringList $pipes)) }

    $details = @(
        ('RestrictAnonymous={0}' -f $restrictAnonymous)
        ('NullSessionShares={0}' -f (Format-StringList $shares))
        ('NullSessionPipes={0}' -f (Format-StringList $pipes))
    )
    if ($issues.Count -gt 0) {
        $details += ''
        $details += '문제점:'
        $details += ($issues | ForEach-Object { '- ' + $_ })
    }

    $status = if ($issues.Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($status -eq '양호') { 'Null Session 관련 설정이 제한되어 있습니다.' } else { 'Null Session 관련 설정이 완전히 제한되지 않았습니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{ RestrictAnonymous = $restrictAnonymous; NullSessionShares = $shares; NullSessionPipes = $pipes } -CanAutoRemediate:$true
}

function Invoke-W0702Plan {
    param($Definition, $Result, $Options)
    $changes = @(
        ('RestrictAnonymous 값을 {0}(으)로 설정' -f $Options.RestrictAnonymous)
    )
    if ($Options.CheckNullSessionLists) {
        $changes += 'NullSessionShares / NullSessionPipes 비우기'
    }
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes $changes -Impact '익명 공유/파이프 접근이 차단됩니다.' -ExpectedStatus '양호'
}

function Invoke-W0702Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Expected = [int]$Options.RestrictAnonymous; Type = 'DWord'; Comparison = 'eq'; Description = 'RestrictAnonymous' }
    )
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
    if ($Options.CheckNullSessionLists) {
        $lanmanPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Backup-RegistryPath -Path $lanmanPath -BackupDirectory $BackupDirectory
        Ensure-RegistryValue -Path $lanmanPath -Name 'NullSessionShares' -Type MultiString -Value @()
        Ensure-RegistryValue -Path $lanmanPath -Name 'NullSessionPipes' -Type MultiString -Value @()
    }
}

function Invoke-W0703Detect {
    param($Definition, $Options)
    $service = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
    if (-not $service) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary 'Remote Registry 서비스가 없습니다.' -Details 'RemoteRegistry 서비스 미설치' -Data @{} -CanAutoRemediate:$true
    }
    $cim = Get-Win32ClassInstanceSafe -ClassName 'Win32_Service' -Filter "Name='RemoteRegistry'"
    $status = if ($service.Status -ne 'Running') { '양호' } else { '취약' }
    $summary = if ($status -eq '양호') { 'Remote Registry 서비스가 중지되어 있습니다.' } else { 'Remote Registry 서비스가 실행 중입니다.' }
    $details = '상태={0}, 시작유형={1}' -f $service.Status, $cim.StartMode
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details $details -Data @{ Service = $service; StartMode = $cim.StartMode } -CanAutoRemediate:$true
}

function Invoke-W0703Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @('Remote Registry 서비스 중지 및 시작유형 Disabled 설정') -Impact '원격 레지스트리 기반 관리가 불가능해집니다.' -ExpectedStatus '양호'
}

function Invoke-W0703Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    Backup-CommandOutput -FileName 'remote_registry_before.txt' -BackupDirectory $BackupDirectory -ScriptBlock {
        Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue | Format-Table Status, Name, DisplayName -AutoSize | Out-String
    }
    $service = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
    if ($service) {
        if ($Options.StopService -and $service.Status -eq 'Running') {
            Stop-Service -Name 'RemoteRegistry' -Force -ErrorAction SilentlyContinue
        }
        Set-Service -Name 'RemoteRegistry' -StartupType $Options.StartupType
    }
}

function Invoke-W0704Detect {
    param($Definition, $Options)
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $auto = Get-RegistryValueSafe -Path $path -Name 'AutoAdminLogon'
    $defaultUser = Get-RegistryValueSafe -Path $path -Name 'DefaultUserName'
    $defaultDomain = Get-RegistryValueSafe -Path $path -Name 'DefaultDomainName'
    $defaultPassword = Get-RegistryValueSafe -Path $path -Name 'DefaultPassword'
    $issues = @()
    if ([string]$auto -ne [string]$Options.AutoAdminLogon) { $issues += 'AutoAdminLogon 값이 비활성화 상태가 아닙니다.' }
    if ($Options.RemoveStoredCredentials -and (-not [string]::IsNullOrWhiteSpace([string]$defaultPassword))) { $issues += 'DefaultPassword 값이 저장되어 있습니다.' }
    $details = @(
        ('AutoAdminLogon={0}' -f $auto)
        ('DefaultUserName={0}' -f $defaultUser)
        ('DefaultDomainName={0}' -f $defaultDomain)
        ('DefaultPassword={0}' -f $(if ($defaultPassword) { '[설정됨]' } else { '[없음]' }))
    )
    if ($issues.Count -gt 0) { $details += ''; $details += ($issues | ForEach-Object { '- ' + $_ }) }
    $status = if ($issues.Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($status -eq '양호') { 'AutoLogon 구성이 비활성화되어 있습니다.' } else { 'AutoLogon 또는 저장된 자격 증명이 발견되었습니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{ Path = $path } -CanAutoRemediate:$true
}

function Invoke-W0704Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(
        'AutoAdminLogon 비활성화'
        'DefaultPassword 등 저장된 AutoLogon 자격 증명 제거'
    ) -Impact '자동 로그온 기반 운영 절차가 있다면 중단됩니다.' -ExpectedStatus '양호'
}

function Invoke-W0704Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $path = Get-RequiredResultDataValue -Definition $Definition -Result $Result -Options $Options -Name 'Path'
    Backup-RegistryPath -Path $path -BackupDirectory $BackupDirectory
    Ensure-RegistryValue -Path $path -Name 'AutoAdminLogon' -Type String -Value ([string]$Options.AutoAdminLogon)
    if ($Options.RemoveStoredCredentials) {
        foreach ($name in @('DefaultPassword', 'AltDefaultPassword')) {
            Remove-RegistryValueSafe -Path $path -Name $name
        }
    }
}

function Invoke-W0705Detect {
    param($Definition, $Options)
    if ($script:State.Environment.OsContext.Release -eq '2012R2') {
        return New-CheckResult -Definition $Definition -Status '수동점검' -Summary 'Windows.xlsm 기준상 2012 R2에서는 N/A 처리되는 항목입니다.' -Details '엑셀의 exclude_check_version 설정에 2012_R2가 포함되어 있어 전용판 목록에서 제외했습니다.' -Data @{} -CanAutoRemediate:$false
    }
    $rules = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'SynAttackProtect'; Expected = [int]$Options.SynAttackProtect; Type = 'DWord'; Comparison = 'eq'; Description = 'SYN 공격 보호' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'EnablePMTUDiscovery'; Expected = [int]$Options.EnablePMTUDiscovery; Type = 'DWord'; Comparison = 'eq'; Description = 'PMTU Discovery' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'NoNameReleaseOnDemand'; Expected = [int]$Options.NoNameReleaseOnDemand; Type = 'DWord'; Comparison = 'eq'; Description = 'Name Release On Demand 차단' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'EnableDeadGWDetect'; Expected = [int]$Options.EnableDeadGWDetect; Type = 'DWord'; Comparison = 'eq'; Description = 'Dead Gateway Detect' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'KeepAliveTime'; Expected = [int]$Options.KeepAliveTime; Type = 'DWord'; Comparison = 'eq'; Description = 'KeepAliveTime(ms)' }
    )
    $states = Get-RegistryRuleStates -Rules $rules
    $status = if (@($states | Where-Object { -not $_.Compliant }).Count -gt 0) { '취약' } else { '양호' }
    $summary = if ($status -eq '양호') { '기본 DoS 방어 레지스트리 값이 기준을 충족합니다.' } else { '기본 DoS 방어 레지스트리 값이 기준과 다릅니다.' }
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details (Format-RegistryStateDetails -States $states) -Data @{ Rules = $rules; States = $states } -CanAutoRemediate:$true
}

function Invoke-W0705Plan {
    param($Definition, $Result, $Options)
    return New-PlanResult -Definition $Definition -AutoSupported:$true -Changes @(
        ('SynAttackProtect={0} 설정' -f $Options.SynAttackProtect)
        ('EnablePMTUDiscovery={0} 설정' -f $Options.EnablePMTUDiscovery)
        ('NoNameReleaseOnDemand={0} 설정' -f $Options.NoNameReleaseOnDemand)
        ('EnableDeadGWDetect={0} 설정' -f $Options.EnableDeadGWDetect)
        ('KeepAliveTime={0}ms 설정' -f $Options.KeepAliveTime)
    ) -Impact 'TCP/IP 스택 보안 레지스트리가 강화됩니다. 특수 네트워크 장비나 구형 호스트가 있는 환경은 사전 확인이 필요할 수 있습니다.' -ExpectedStatus '양호'
}

function Invoke-W0705Apply {
    param($Definition, $Result, $Options, $BackupDirectory)
    $rules = Get-RequiredResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Rules'
    Invoke-RegistryRemediation -Rules $rules -BackupDirectory $BackupDirectory
}

function Invoke-W0801Detect {
    param($Definition, $Options)
    $products = @(Get-UninstallDisplayNames | Where-Object { $_.DisplayName -match '^OpenSSL' })
    $commands = @(Get-Command openssl.exe -ErrorAction SilentlyContinue)
    $details = @()
    foreach ($product in $products) {
        $details += ('- 설치 제품: {0} {1}' -f $product.DisplayName, $product.DisplayVersion)
    }
    foreach ($command in $commands) {
        $details += ('- 실행 파일: {0}' -f $command.Source)
    }
    if ($products.Count -eq 0 -and $commands.Count -eq 0) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary 'OpenSSL 설치 흔적을 찾지 못했습니다.' -Details '설치 제품/실행 파일 미감지' -Data @{ Products = $products; Commands = $commands } -CanAutoRemediate:$false
    }
    return New-CheckResult -Definition $Definition -Status '수동점검' -Summary 'OpenSSL이 설치되어 있어 버전별 취약점 확인이 필요합니다.' -Details (($details | Sort-Object -Unique) -join [Environment]::NewLine) -Data @{ Products = $products; Commands = $commands } -CanAutoRemediate:$false
}

function Invoke-W0801Plan {
    param($Definition, $Result, $Options)
    return New-ManualOnlyPlan -Definition $Definition -Reason 'OpenSSL 설치 경로와 배포 주체가 제각각이라 자동 업그레이드는 제공하지 않습니다.' -Changes @(
        '설치 위치 및 버전 확인'
        '벤더 제공 최신 버전으로 교체'
        '의존 애플리케이션 호환성 검증'
    )
}

function Invoke-W0802Detect {
    param($Definition, $Options)
    $osContext = $script:State.Environment.OsContext
    if (-not $osContext -or -not $osContext.Supported -or -not $osContext.SupportEndDate) {
        $details = if ($osContext) {
            Format-OsContextDisplayText -OsContext $osContext
        } else {
            'OS 컨텍스트를 확인하지 못했습니다.'
        }
        return New-CheckResult -Definition $Definition -Status '수동점검' -Summary '지원 종료 날짜 매핑이 없는 OS입니다.' -Details $details -Data @{ OsContext = $osContext } -CanAutoRemediate:$false
    }

    $eol = $osContext.SupportEndDate
    $daysRemaining = [int](New-TimeSpan -Start (Get-Date) -End $eol).TotalDays
    $status = if ($daysRemaining -le [int]$Options.WarningDaysBeforeEol) { '취약' } else { '양호' }
    $summary = if ($status -eq '양호') { 'OS 지원 종료일까지 충분한 기간이 남아 있습니다.' } else { 'OS 지원 종료일이 임박했거나 지났습니다.' }
    $details = @(
        ('ProductName={0}' -f $osContext.ProductName)
        ('Release={0}' -f $osContext.ReleaseLabel)
        ('BuildNumber={0}' -f $osContext.BuildNumber)
        ('MatchSource={0}' -f $osContext.MatchSource)
        ('MainstreamEndDate={0:yyyy-MM-dd}' -f $osContext.MainstreamEndDate)
        ('SupportEndDate={0:yyyy-MM-dd}' -f $eol)
        ('DaysRemaining={0}' -f $daysRemaining)
    )
    return New-CheckResult -Definition $Definition -Status $status -Summary $summary -Details ($details -join [Environment]::NewLine) -Data @{ ProductName = $osContext.ProductName; Release = $osContext.Release; SupportEndDate = $eol; DaysRemaining = $daysRemaining } -CanAutoRemediate:$false
}

function Invoke-W0802Plan {
    param($Definition, $Result, $Options)
    return New-ManualOnlyPlan -Definition $Definition -Reason 'OS 업그레이드 또는 마이그레이션은 서비스 단위의 변경 계획이 필요합니다.' -Changes @(
        '지원 종료 일정 검토'
        '차기 OS 또는 신규 서버로 마이그레이션 계획 수립'
        '사전 호환성 검증 및 점검 창 확보'
    )
}

function Invoke-W0803Detect {
    param($Definition, $Options)
    $updates = @(Get-PendingWindowsUpdates)
    if ($updates.Count -eq 0) {
        return New-CheckResult -Definition $Definition -Status '양호' -Summary '현재 설치 대기 중인 Windows 업데이트가 없습니다.' -Details '대기 업데이트 없음' -Data @{ Updates = $updates } -CanAutoRemediate:$false
    }

    $details = $updates | ForEach-Object {
        '- {0} / {1} / 재부팅={2}' -f $_.Title, (Format-StringList $_.KBs), $_.RebootRequired
    }
    return New-CheckResult -Definition $Definition -Status '취약' -Summary ('설치 대기 중인 Windows 업데이트가 {0}건 있습니다.' -f $updates.Count) -Details ($details -join [Environment]::NewLine) -Data @{ Updates = $updates } -CanAutoRemediate:$false
}

function Invoke-W0803Plan {
    param($Definition, $Result, $Options)

    $updates = Resolve-ResultDataArray -Definition $Definition -Result $Result -Options $Options -Name 'Updates'
    $requiresRestart = @($updates | Where-Object { $_.RebootRequired }).Count -gt 0
    $notes = if ($requiresRestart) {
        '대기 업데이트 중 재부팅이 필요한 항목이 포함되어 있습니다.'
    } else {
        '현재 감지된 대기 업데이트는 재부팅 플래그가 없습니다. 설치 결과에 따라 재부팅이 추가로 필요해질 수 있습니다.'
    }

    return New-ManualOnlyPlan -Definition $Definition -Reason '최신 HotFix 적용은 서비스 영향과 재부팅 가능성이 있어 이 전용판에서는 확인만 제공합니다.' -Changes @(
        ('Windows Update 대기 항목 {0}건 검토' -f @($updates).Count)
        '점검 창 확보'
        '재부팅 필요 여부 사전 검토'
    )
}

function Get-MinimalCatalogDefinitions {
    return @(
        @{ Code = 'W0101'; Category = '계정관리'; Severity = '상'; Title = '로컬 계정 사용 설정'; Detect = 'Invoke-W0101Detect'; Plan = 'Invoke-W0101Plan'; Apply = 'Invoke-W0101Apply' },
        @{ Code = 'W0102'; Category = '계정관리'; Severity = '상'; Title = '계정 잠금 정책 설정'; Detect = 'Invoke-W0102Detect'; Plan = 'Invoke-W0102Plan'; Apply = 'Invoke-W0102Apply' },
        @{ Code = 'W0103'; Category = '계정관리'; Severity = '상'; Title = '암호 정책 설정'; Detect = 'Invoke-W0103Detect'; Plan = 'Invoke-W0103Plan'; Apply = 'Invoke-W0103Apply' },
        @{ Code = 'W0202'; Category = '파일시스템'; Severity = '상'; Title = '공유 폴더 설정'; Detect = 'Invoke-W0202Detect'; Plan = 'Invoke-W0202Plan'; Apply = 'Invoke-W0202Apply' },
        @{ Code = 'W0301'; Category = '네트워크서비스'; Severity = '상'; Title = '불필요한 서비스 제거'; Detect = 'Invoke-W0301Detect'; Plan = 'Invoke-W0301Plan'; Apply = 'Invoke-W0301Apply' },
        @{ Code = 'W0302'; Category = '네트워크서비스'; Severity = '중'; Title = '터미널 서비스 암호화 수준 및 리디렉션 설정'; Detect = 'Invoke-W0302Detect'; Plan = 'Invoke-W0302Plan'; Apply = 'Invoke-W0302Apply' },
        @{ Code = 'W0303'; Category = '네트워크서비스'; Severity = '상'; Title = 'NetBIOS 서비스 보안 설정'; Detect = 'Invoke-W0303Detect'; Plan = 'Invoke-W0303Plan'; Apply = 'Invoke-W0303Apply' },
        @{ Code = 'W0304'; Category = '네트워크서비스'; Severity = '중'; Title = '터미널 서비스 Time Out 설정'; Detect = 'Invoke-W0304Detect'; Plan = 'Invoke-W0304Plan'; Apply = 'Invoke-W0304Apply' },
        @{ Code = 'W0502'; Category = '시스템보안설정'; Severity = '하'; Title = '화면 보호기 설정'; Detect = 'Invoke-W0502Detect'; Plan = 'Invoke-W0502Plan'; Apply = 'Invoke-W0502Apply' },
        @{ Code = 'W0504'; Category = '시스템보안설정'; Severity = '상'; Title = '로그인 시 경고 메시지 표시 설정'; Detect = 'Invoke-W0504Detect'; Plan = 'Invoke-W0504Plan'; Apply = 'Invoke-W0504Apply' },
        @{ Code = 'W0505'; Category = '시스템보안설정'; Severity = '중'; Title = '마지막 로그온 사용자 계정 숨김'; Detect = 'Invoke-W0505Detect'; Plan = 'Invoke-W0505Plan'; Apply = 'Invoke-W0505Apply' },
        @{ Code = 'W0507'; Category = '시스템보안설정'; Severity = '상'; Title = '로컬 감사정책 설정'; Detect = 'Invoke-W0507Detect'; Plan = 'Invoke-W0507Plan'; Apply = 'Invoke-W0507Apply' },
        @{ Code = 'W0508'; Category = '시스템보안설정'; Severity = '하'; Title = '가상 메모리 페이지 파일 삭제 설정'; Detect = 'Invoke-W0508Detect'; Plan = 'Invoke-W0508Plan'; Apply = 'Invoke-W0508Apply' },
        @{ Code = 'W0509'; Category = '시스템보안설정'; Severity = '하'; Title = 'Lan Manager 인증 수준'; Detect = 'Invoke-W0509Detect'; Plan = 'Invoke-W0509Plan'; Apply = 'Invoke-W0509Apply' },
        @{ Code = 'W0601'; Category = '바이러스진단'; Severity = '중'; Title = '백신 프로그램 설치'; Detect = 'Invoke-W0601Detect'; Plan = 'Invoke-W0601Plan'; Apply = $null; AllowException = $true },
        @{ Code = 'W0701'; Category = '레지스트리보안설정'; Severity = '하'; Title = 'SAM(Security Account Manager) 보안 감사 설정'; Detect = 'Invoke-W0701Detect'; Plan = 'Invoke-W0701Plan'; Apply = 'Invoke-W0701Apply' },
        @{ Code = 'W0702'; Category = '레지스트리보안설정'; Severity = '상'; Title = 'Null Session 설정'; Detect = 'Invoke-W0702Detect'; Plan = 'Invoke-W0702Plan'; Apply = 'Invoke-W0702Apply' },
        @{ Code = 'W0703'; Category = '레지스트리보안설정'; Severity = '상'; Title = 'Remote Registry Service 설정'; Detect = 'Invoke-W0703Detect'; Plan = 'Invoke-W0703Plan'; Apply = 'Invoke-W0703Apply' },
        @{ Code = 'W0704'; Category = '레지스트리보안설정'; Severity = '중'; Title = 'AutoLogon 제한 설정'; Detect = 'Invoke-W0704Detect'; Plan = 'Invoke-W0704Plan'; Apply = 'Invoke-W0704Apply' },
        @{ Code = 'W0705'; Category = '레지스트리보안설정'; Severity = '중'; Title = 'DoS 공격에 대한 방어 레지스트리 설정'; Detect = 'Invoke-W0705Detect'; Plan = 'Invoke-W0705Plan'; Apply = 'Invoke-W0705Apply' },
        @{ Code = 'W0802'; Category = '보안패치'; Severity = '상'; Title = '최신 서비스 팩 적용'; Detect = 'Invoke-W0802Detect'; Plan = 'Invoke-W0802Plan'; Apply = $null; AllowException = $true },
        @{ Code = 'W0803'; Category = '보안패치'; Severity = '상'; Title = '최신 HotFix 적용'; Detect = 'Invoke-W0803Detect'; Plan = 'Invoke-W0803Plan'; Apply = $null; AllowException = $true }
    )
}

function Get-FullCatalogDefinitions {
    return @(
        @{ Code = 'W0101'; Category = '계정관리'; Severity = '상'; Title = '로컬 계정 사용 설정'; Detect = 'Invoke-W0101Detect'; Plan = 'Invoke-W0101Plan'; Apply = 'Invoke-W0101Apply' },
        @{ Code = 'W0102'; Category = '계정관리'; Severity = '상'; Title = '계정 잠금 정책 설정'; Detect = 'Invoke-W0102Detect'; Plan = 'Invoke-W0102Plan'; Apply = 'Invoke-W0102Apply' },
        @{ Code = 'W0103'; Category = '계정관리'; Severity = '상'; Title = '암호 정책 설정'; Detect = 'Invoke-W0103Detect'; Plan = 'Invoke-W0103Plan'; Apply = 'Invoke-W0103Apply' },
        @{ Code = 'W0104'; Category = '계정관리'; Severity = '상'; Title = '취약한 패스워드 점검'; Detect = 'Invoke-W0104Detect'; Plan = 'Invoke-W0104Plan'; Apply = $null; AllowException = $true },
        @{ Code = 'W0105'; Category = '계정관리'; Severity = '하'; Title = '사용자 계정 컨트롤(User Account Control) 설정'; Detect = 'Invoke-W0105Detect'; Plan = 'Invoke-W0105Plan'; Apply = 'Invoke-W0105Apply' },
        @{ Code = 'W0106'; Category = '계정관리'; Severity = '중'; Title = '익명 SID/이름 변환 허용 정책'; Detect = 'Invoke-W0106Detect'; Plan = 'Invoke-W0106Plan'; Apply = 'Invoke-W0106Apply' },
        @{ Code = 'W0107'; Category = '계정관리'; Severity = '중'; Title = '콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 정책 점검'; Detect = 'Invoke-W0107Detect'; Plan = 'Invoke-W0107Plan'; Apply = 'Invoke-W0107Apply' },
        @{ Code = 'W0201'; Category = '파일시스템'; Severity = '중'; Title = '사용자 홈 디렉터리 접근제한'; Detect = 'Invoke-W0201Detect'; Plan = 'Invoke-W0201Plan'; Apply = 'Invoke-W0201Apply' },
        @{ Code = 'W0202'; Category = '파일시스템'; Severity = '상'; Title = '공유 폴더 설정'; Detect = 'Invoke-W0202Detect'; Plan = 'Invoke-W0202Plan'; Apply = 'Invoke-W0202Apply' },
        @{ Code = 'W0203'; Category = '파일시스템'; Severity = '상'; Title = 'SAM(Security Account Manager) 파일 권한 설정'; Detect = 'Invoke-W0203Detect'; Plan = 'Invoke-W0203Plan'; Apply = 'Invoke-W0203Apply' },
        @{ Code = 'W0204'; Category = '파일시스템'; Severity = '하'; Title = '파일 및 디렉터리 보호'; Detect = 'Invoke-W0204Detect'; Plan = 'Invoke-W0204Plan'; Apply = $null },
        @{ Code = 'W0301'; Category = '네트워크서비스'; Severity = '상'; Title = '불필요한 서비스 제거'; Detect = 'Invoke-W0301Detect'; Plan = 'Invoke-W0301Plan'; Apply = 'Invoke-W0301Apply' },
        @{ Code = 'W0302'; Category = '네트워크서비스'; Severity = '중'; Title = '터미널 서비스 암호화 수준 및 리디렉션 설정'; Detect = 'Invoke-W0302Detect'; Plan = 'Invoke-W0302Plan'; Apply = 'Invoke-W0302Apply' },
        @{ Code = 'W0303'; Category = '네트워크서비스'; Severity = '상'; Title = 'NetBIOS 서비스 보안 설정'; Detect = 'Invoke-W0303Detect'; Plan = 'Invoke-W0303Plan'; Apply = 'Invoke-W0303Apply' },
        @{ Code = 'W0304'; Category = '네트워크서비스'; Severity = '중'; Title = '터미널 서비스 Time Out 설정'; Detect = 'Invoke-W0304Detect'; Plan = 'Invoke-W0304Plan'; Apply = 'Invoke-W0304Apply' },
        @{ Code = 'W0401'; Category = '주요응용설정'; Severity = '중'; Title = 'Telnet 서비스 보안 설정'; Detect = 'Invoke-W0401Detect'; Plan = 'Invoke-W0401Plan'; Apply = 'Invoke-W0401Apply' },
        @{ Code = 'W0402'; Category = '주요응용설정'; Severity = '상'; Title = 'DNS(Domain Name Service) 보안 설정'; Detect = 'Invoke-W0402Detect'; Plan = 'Invoke-W0402Plan'; Apply = $null },
        @{ Code = 'W0403'; Category = '주요응용설정'; Severity = '상'; Title = 'SNMP(Simple Network Management Protocol) 서비스 보안 설정'; Detect = 'Invoke-W0403Detect'; Plan = 'Invoke-W0403Plan'; Apply = 'Invoke-W0403Apply' },
        @{ Code = 'W0501'; Category = '시스템보안설정'; Severity = '하'; Title = '원격 로그파일 접근 진단'; Detect = 'Invoke-W0501Detect'; Plan = 'Invoke-W0501Plan'; Apply = 'Invoke-W0501Apply' },
        @{ Code = 'W0502'; Category = '시스템보안설정'; Severity = '하'; Title = '화면 보호기 설정'; Detect = 'Invoke-W0502Detect'; Plan = 'Invoke-W0502Plan'; Apply = 'Invoke-W0502Apply' },
        @{ Code = 'W0503'; Category = '시스템보안설정'; Severity = '상'; Title = '이벤트 뷰어 설정'; Detect = 'Invoke-W0503Detect'; Plan = 'Invoke-W0503Plan'; Apply = 'Invoke-W0503Apply' },
        @{ Code = 'W0504'; Category = '시스템보안설정'; Severity = '상'; Title = '로그인 시 경고 메시지 표시 설정'; Detect = 'Invoke-W0504Detect'; Plan = 'Invoke-W0504Plan'; Apply = 'Invoke-W0504Apply' },
        @{ Code = 'W0505'; Category = '시스템보안설정'; Severity = '중'; Title = '마지막 로그온 사용자 계정 숨김'; Detect = 'Invoke-W0505Detect'; Plan = 'Invoke-W0505Plan'; Apply = 'Invoke-W0505Apply' },
        @{ Code = 'W0506'; Category = '시스템보안설정'; Severity = '중'; Title = '로그온 하지 않은 사용자 시스템 종료 방지'; Detect = 'Invoke-W0506Detect'; Plan = 'Invoke-W0506Plan'; Apply = 'Invoke-W0506Apply' },
        @{ Code = 'W0507'; Category = '시스템보안설정'; Severity = '상'; Title = '로컬 감사정책 설정'; Detect = 'Invoke-W0507Detect'; Plan = 'Invoke-W0507Plan'; Apply = 'Invoke-W0507Apply' },
        @{ Code = 'W0508'; Category = '시스템보안설정'; Severity = '하'; Title = '가상 메모리 페이지 파일 삭제 설정'; Detect = 'Invoke-W0508Detect'; Plan = 'Invoke-W0508Plan'; Apply = 'Invoke-W0508Apply' },
        @{ Code = 'W0509'; Category = '시스템보안설정'; Severity = '하'; Title = 'Lan Manager 인증 수준'; Detect = 'Invoke-W0509Detect'; Plan = 'Invoke-W0509Plan'; Apply = 'Invoke-W0509Apply' },
        @{ Code = 'W0510'; Category = '시스템보안설정'; Severity = '하'; Title = 'Everyone 사용 권한을 익명 사용자에게 적용 안함'; Detect = 'Invoke-W0510Detect'; Plan = 'Invoke-W0510Plan'; Apply = 'Invoke-W0510Apply' },
        @{ Code = 'W0511'; Category = '시스템보안설정'; Severity = '하'; Title = '이동식 미디어 포맷 및 꺼내기 admin만 허용'; Detect = 'Invoke-W0511Detect'; Plan = 'Invoke-W0511Plan'; Apply = 'Invoke-W0511Apply' },
        @{ Code = 'W0512'; Category = '시스템보안설정'; Severity = '하'; Title = '세션 연결 끊기 전 유휴시간 설정'; Detect = 'Invoke-W0512Detect'; Plan = 'Invoke-W0512Plan'; Apply = 'Invoke-W0512Apply' },
        @{ Code = 'W0513'; Category = '시스템보안설정'; Severity = '중'; Title = '예약된 작업 의심스런 명령어나 파일 점검'; Detect = 'Invoke-W0513Detect'; Plan = 'Invoke-W0513Plan'; Apply = $null },
        @{ Code = 'W0514'; Category = '시스템보안설정'; Severity = '상'; Title = '원격 시스템 종료 권한 설정'; Detect = 'Invoke-W0514Detect'; Plan = 'Invoke-W0514Plan'; Apply = 'Invoke-W0514Apply' },
        @{ Code = 'W0515'; Category = '시스템보안설정'; Severity = '상'; Title = '보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 방지'; Detect = 'Invoke-W0515Detect'; Plan = 'Invoke-W0515Plan'; Apply = 'Invoke-W0515Apply' },
        @{ Code = 'W0516'; Category = '시스템보안설정'; Severity = '중'; Title = '보안 채널 데이터 디지털 암호화 또는 서명 설정'; Detect = 'Invoke-W0516Detect'; Plan = 'Invoke-W0516Plan'; Apply = 'Invoke-W0516Apply' },
        @{ Code = 'W0517'; Category = '시스템 보안 설정'; Severity = '하'; Title = '프린터 드라이버 설치 제한 설정'; Detect = 'Invoke-W0517Detect'; Plan = 'Invoke-W0517Plan'; Apply = 'Invoke-W0517Apply' },
        @{ Code = 'W0601'; Category = '바이러스진단'; Severity = '중'; Title = '백신 프로그램 설치'; Detect = 'Invoke-W0601Detect'; Plan = 'Invoke-W0601Plan'; Apply = $null; AllowException = $true },
        @{ Code = 'W0602'; Category = '바이러스진단'; Severity = '상'; Title = '최신 엔진 업데이트'; Detect = 'Invoke-W0602Detect'; Plan = 'Invoke-W0602Plan'; Apply = $null; AllowException = $true },
        @{ Code = 'W0701'; Category = '레지스트리보안설정'; Severity = '하'; Title = 'SAM(Security Account Manager) 보안 감사 설정'; Detect = 'Invoke-W0701Detect'; Plan = 'Invoke-W0701Plan'; Apply = 'Invoke-W0701Apply' },
        @{ Code = 'W0702'; Category = '레지스트리보안설정'; Severity = '상'; Title = 'Null Session 설정'; Detect = 'Invoke-W0702Detect'; Plan = 'Invoke-W0702Plan'; Apply = 'Invoke-W0702Apply' },
        @{ Code = 'W0703'; Category = '레지스트리보안설정'; Severity = '상'; Title = 'Remote Registry Service 설정'; Detect = 'Invoke-W0703Detect'; Plan = 'Invoke-W0703Plan'; Apply = 'Invoke-W0703Apply' },
        @{ Code = 'W0704'; Category = '레지스트리보안설정'; Severity = '중'; Title = 'AutoLogon 제한 설정'; Detect = 'Invoke-W0704Detect'; Plan = 'Invoke-W0704Plan'; Apply = 'Invoke-W0704Apply' },
        @{ Code = 'W0705'; Category = '레지스트리보안설정'; Severity = '중'; Title = 'DoS 공격에 대한 방어 레지스트리 설정'; Detect = 'Invoke-W0705Detect'; Plan = 'Invoke-W0705Plan'; Apply = 'Invoke-W0705Apply' },
        @{ Code = 'W0801'; Category = '보안패치'; Severity = '상'; Title = 'OpenSSL 취약점 패치적용'; Detect = 'Invoke-W0801Detect'; Plan = 'Invoke-W0801Plan'; Apply = $null },
        @{ Code = 'W0802'; Category = '보안패치'; Severity = '상'; Title = '최신 서비스 팩 적용'; Detect = 'Invoke-W0802Detect'; Plan = 'Invoke-W0802Plan'; Apply = $null; AllowException = $true },
        @{ Code = 'W0803'; Category = '보안패치'; Severity = '상'; Title = '최신 HotFix 적용'; Detect = 'Invoke-W0803Detect'; Plan = 'Invoke-W0803Plan'; Apply = $null; AllowException = $true }
    )
}

function Initialize-Catalog {
    if ($FullCatalogAudit) {
        $script:State.Catalog = @(Get-FullCatalogDefinitions)
    } else {
        $script:State.Catalog = @(Get-MinimalCatalogDefinitions)
    }
}

function Get-DefaultOptionText {
    param([string]$Code)
    return ConvertTo-PrettyJson (Get-ItemOptions -Code $Code)
}

function Get-CurrentOptionText {
    param([string]$Code)
    if ($script:State.OptionTextByCode.ContainsKey($Code)) {
        return $script:State.OptionTextByCode[$Code]
    }

    $text = Get-DefaultOptionText -Code $Code
    $script:State.OptionTextByCode[$Code] = $text
    return $text
}

function Set-CurrentOptionText {
    param(
        [string]$Code,
        [string]$Text
    )
    $script:State.OptionTextByCode[$Code] = $Text
}

function Get-ParsedOptionsForCode {
    param(
        [string]$Code,
        [string]$Text = $null
    )
    $effectiveText = if ($null -ne $Text) { $Text } else { Get-CurrentOptionText -Code $Code }
    return Convert-OptionTextToHashtable -Code $Code -Text $effectiveText
}

function Get-OptionEditorKind {
    param($Value)

    if ($Value -is [bool]) {
        return 'Boolean'
    }

    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64]) {
        return 'Integer'
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return 'Array'
    }

    return 'String'
}

function Format-OptionArrayValue {
    param($Value)

    if ($null -eq $Value) {
        return ''
    }

    return (@($Value) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
}

function Get-GuiOptionEditorValues {
    if (-not (Test-GuiKey -Key 'OptionEditors')) {
        return $null
    }

    $values = @{}
    foreach ($entry in @($script:State.Gui.OptionEditors)) {
        switch ($entry.Kind) {
            'Boolean' {
                $values[$entry.Name] = [bool]$entry.Control.Checked
            }
            'Integer' {
                $values[$entry.Name] = [int64]$entry.Control.Value
            }
            'Array' {
                $items = @($entry.Control.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                $values[$entry.Name] = $items
            }
            default {
                $values[$entry.Name] = [string]$entry.Control.Text
            }
        }
    }

    if ($values.ContainsKey('CheckAllActiveUsers') -or $values.ContainsKey('CheckAdministratorsOnly')) {
        $values = Normalize-W0502TargetOptions -Options $values
    }

    return $values
}

function Update-GuiOptionJsonMirror {
    if (-not (Test-GuiKey -Key 'CurrentCode') -or -not $script:State.Gui.CurrentCode) {
        return
    }

    if ($script:State.Gui.ContainsKey('SuppressOptionSync') -and $script:State.Gui.SuppressOptionSync) {
        return
    }

    $values = Get-GuiOptionEditorValues
    if ($null -eq $values) {
        return
    }

    $json = ConvertTo-PrettyJson $values
    Set-CurrentOptionText -Code $script:State.Gui.CurrentCode -Text $json
    if (Test-GuiKey -Key 'OptionsTextBox') {
        $script:State.Gui.OptionsTextBox.Text = $json
    }
}

function Add-GuiOptionEditorChangedHandler {
    param(
        $Control,
        [string]$Kind
    )

    switch ($Kind) {
        'Boolean' {
            $Control.Add_CheckedChanged({ Update-GuiOptionJsonMirror })
        }
        'Integer' {
            $Control.Add_ValueChanged({ Update-GuiOptionJsonMirror })
        }
        default {
            $Control.Add_TextChanged({ Update-GuiOptionJsonMirror })
        }
    }
}

function Get-GuiOptionEditorLabelText {
    param(
        [string]$Code,
        [string]$Name
    )

    switch ($Code) {
        'W0105' {
            switch ($Name) {
                'ConsentPromptBehaviorAdmin' { return '관리자 상승 프롬프트 동작' }
                'PromptOnSecureDesktop' { return '보안 데스크톱 사용' }
                'EnableLUA' { return 'UAC 사용' }
                'CheckFilterAdministratorToken' { return 'Built-in Administrator 승인 모드도 함께 점검' }
                'FilterAdministratorToken' { return 'Built-in Administrator 승인 모드 기대값' }
            }
        }
        'W0202' {
            switch ($Name) {
                'RemoveEveryoneAccess' { return 'Everyone 공유 권한 제거' }
                'RemoveGuestAccess' { return 'Guest 공유 권한 제거' }
                'DisableAdministrativeShares' { return '기본 관리 공유 삭제' }
                'AdministrativeShares' { return '관리 공유 이름 목록' }
                'ShareAllowList' { return '점검 제외 공유 목록' }
                'ForceGuest' { return '암호 보호 공유 ForceGuest 값' }
            }
        }
        'W0101' {
            switch ($Name) {
                'DisableGuest' { return 'Guest 계정 비활성화' }
                'RequireBuiltinAdministratorRename' { return 'Administrator 이름 변경 필수' }
                'RenameBuiltinAdministratorTo' { return 'Administrator 새 이름' }
                'MaxActiveAdministrators' { return '활성 관리자 최대 허용 수' }
                'CheckEnabledUserMetadata' { return '활성 계정 전체이름/설명 점검' }
                'DisableBuiltinAdministratorIfSafe' { return '다른 관리자 있으면 Built-in Administrator 비활성화' }
                'RemoveUnexpectedAdministrators' { return '허용 목록 외 관리자 제거' }
                'AllowRemovingCurrentUser' { return '현재 로그인 계정 제거 허용' }
                'ExcludeUsers' { return '예외 계정 목록' }
                'AllowedAdministrators' { return '허용 관리자 목록' }
            }
        }
        'W0103' {
            switch ($Name) {
                'MinimumPasswordLength' { return '최소 암호 길이' }
                'MaximumPasswordAge' { return '최대 암호 사용 기간(일)' }
                'MinimumPasswordAge' { return '최소 암호 사용 기간(일)' }
                'PasswordHistorySize' { return '최근 암호 기억 개수' }
                'PasswordComplexity' { return '암호 복잡성 사용(1/0)' }
                'UsePerUserPasswordExpireCheck' { return '계정별 암호 만료 점검' }
                'CheckAdministratorsOnly' { return 'Administrators만 계정별 점검' }
                'ExcludeUsers' { return '예외 계정 목록' }
            }
        }
        'W0504' {
            switch ($Name) {
                'Caption' { return '경고 제목 (Caption)' }
                'Text' { return '경고 본문 (Text)' }
            }
        }
        'W0502' {
            switch ($Name) {
                'ScreenSaveActive' { return '화면 보호기 사용' }
                'ScreenSaverIsSecure' { return '재개 시 암호 요구' }
                'ScreenSaveTimeOut' { return '대기 시간(초)' }
                'ScreenSaverExe' { return '화면 보호기 실행 파일' }
                'CheckCurrentUser' { return '현재 사용자만 적용' }
                'CheckAllActiveUsers' { return '모든 활성 계정 적용' }
                'CheckAdministratorsOnly' { return '활성 관리자 계정만 적용' }
                'IncludeUsers' { return '특정 계정만 적용' }
                'ApplyToDefaultProfile' { return '신규 계정 기본 프로필에도 적용' }
            }
        }
        'W0507' {
            switch ($Name) {
                'AuditObjectAccess' { return '개체 액세스 감사' }
                'AuditAccountManage' { return '계정 관리 감사' }
                'AuditAccountLogon' { return '계정 로그온 이벤트 감사' }
                'AuditPrivilegeUse' { return '권한 사용 감사' }
                'AuditLogonEvents' { return '로그온 이벤트 감사' }
                'AuditSystemEvents' { return '시스템 이벤트 감사' }
                'AuditPolicyChange' { return '정책 변경 감사' }
            }
        }
        'W0601' {
            switch ($Name) {
                'PreferDefender' { return 'Defender 우선 표기' }
                'AntivirusServicePatterns' { return '백신 서비스 탐지 문자열' }
                'AntivirusDisplayPatterns' { return '설치 제품 탐지 문자열' }
            }
        }
        'W0702' {
            switch ($Name) {
                'RestrictAnonymous' { return 'RestrictAnonymous 기준값' }
                'CheckNullSessionLists' { return 'NullSessionShares/Pipes 함께 점검' }
            }
        }
        'W0705' {
            switch ($Name) {
                'SynAttackProtect' { return 'SynAttackProtect' }
                'EnablePMTUDiscovery' { return 'EnablePMTUDiscovery' }
                'NoNameReleaseOnDemand' { return 'NoNameReleaseOnDemand' }
                'EnableDeadGWDetect' { return 'EnableDeadGWDetect' }
                'KeepAliveTime' { return 'KeepAliveTime(ms)' }
            }
        }
    }

    return $Name
}

function Get-GuiOptionGuideText {
    param([string]$Code)

    switch ($Code) {
        'W0101' {
            return '문서 기준에 맞춰 Guest 비활성화, Administrator 이름 변경, 활성 관리자 수 제한, 활성 계정의 전체이름/설명 기입 여부를 함께 점검합니다. 계정 메타데이터 보완은 자동 적용 대상이 아니라 미리보기에서 잔여 이슈로 남깁니다.'
        }
        'W0105' {
            return '엑셀 기준에 맞춰 UAC 사용(EnableLUA=1)과 기본 알림 수준(ConsentPromptBehaviorAdmin=5, PromptOnSecureDesktop=1)을 점검합니다. Built-in Administrator 승인 모드는 기본값으로는 강제하지 않습니다.'
        }
        'W0202' {
            return '엑셀 기준에 맞춰 기본 관리 공유, Everyone/Guest 공유 권한, AutoShareServer/AutoShareWks, 그리고 암호 보호 공유(ForceGuest=0)까지 함께 점검합니다. 기본값은 관리 공유 삭제를 포함하고, `IPC$`는 예외 목록으로 남겨 둡니다.'
        }
        'W0502' {
            return '문서 기준에 맞춰 화면 보호기, 암호 사용, 대기시간 5분 이하를 적용합니다. 기본값은 모든 활성 계정 적용이며, 신규 계정 기본 프로필은 기본으로 건드리지 않습니다. 필요할 때만 활성 관리자 계정만 적용, 특정 계정만 적용, 신규 계정 기본 프로필 적용을 선택할 수 있습니다.'
        }
        'W0103' {
            return '문서 기준에 맞춰 최소 길이 8, 최대 90일, 최소 사용 기간 7일, 최근 암호 기억 12개, 복잡성 사용, 가역 저장 금지, 그리고 계정별 암호 만료 없음/초과 여부까지 함께 점검합니다.'
        }
        'W0504' {
            return '문서 기준에 맞춰 로그인 경고 배너를 점검합니다. Winlogon과 Policies\\System 두 경로 중 하나라도 실제 배너가 잡히면 양호로 보고, 적용 시 두 경로를 함께 맞춥니다.'
        }
        'W0507' {
            return '문서 기준에 맞춰 개체 액세스, 계정 관리, 계정 로그온, 권한 사용, 로그온 이벤트는 성공/실패(3), 시스템 이벤트와 정책 변경은 0으로 점검합니다.'
        }
        'W0601' {
            return '이 항목은 설치 여부만 점검합니다. 엑셀의 서비스 문자열 목록을 기준으로 탐지하고, 목록에 없는 다른 백신/EDR을 쓰는 서버라면 우측 버튼으로 예외 처리해 취약 카운트에서 제외할 수 있습니다.'
        }
        'W0702' {
            return '엑셀 기준에 맞춰 RestrictAnonymous 값을 정확히 2로 점검합니다. NullSessionShares/Pipes는 기본적으로 정보만 보여주고, 필요할 때만 함께 점검하도록 할 수 있습니다.'
        }
        'W0705' {
            return '엑셀 기준에 맞춰 SynAttackProtect=2, EnablePMTUDiscovery=0, NoNameReleaseOnDemand=1, EnableDeadGWDetect=0, KeepAliveTime=300000ms를 함께 점검합니다.'
        }
        'W0802' {
            return '이 항목은 지원 종료 여부만 점검합니다. 업그레이드 계획이 별도로 잡혀 있으면 우측 버튼으로 예외 처리할 수 있습니다.'
        }
        'W0803' {
            return '이 항목은 대기 중인 Windows 업데이트만 점검합니다. 운영 일정상 별도 패치 절차를 쓰면 우측 버튼으로 예외 처리할 수 있습니다.'
        }
    }

    return '체크박스/숫자/문자열/배열 입력으로 옵션을 수정합니다. 배열 값은 한 줄에 하나씩 입력합니다.'
}

function Build-GuiOptionEditor {
    param([string]$Code)

    if (-not (Test-GuiKey -Key 'OptionTable')) {
        return
    }

    $table = $script:State.Gui.OptionTable
    $script:State.Gui.SuppressOptionSync = $true
    $table.SuspendLayout()
    try {
        $table.Controls.Clear()
        $table.RowStyles.Clear()
        $table.RowCount = 0
        $script:State.Gui.OptionEditors = @()

        $options = Get-ParsedOptionsForCode -Code $Code
        foreach ($name in ($options.Keys | Sort-Object)) {
            $value = $options[$name]
            $kind = Get-OptionEditorKind -Value $value

            $label = New-Object System.Windows.Forms.Label
            $label.Text = Get-GuiOptionEditorLabelText -Code $Code -Name $name
            $label.AutoSize = $true
            $label.Margin = '3,8,6,0'

            $editor = $null
            switch ($kind) {
                'Boolean' {
                    $editor = New-Object System.Windows.Forms.CheckBox
                    $editor.AutoSize = $true
                    $editor.Text = '사용'
                    $editor.Checked = [bool]$value
                    $editor.Margin = '3,6,3,6'
                }
                'Integer' {
                    $editor = New-Object System.Windows.Forms.NumericUpDown
                    $editor.Width = 180
                    $editor.Minimum = [decimal]-2147483648
                    $editor.Maximum = [decimal]2147483647
                    $editor.Value = [decimal]([int64]$value)
                    $editor.Margin = '3,4,3,4'
                    $editor.Anchor = 'Left,Right'
                }
                'Array' {
                    $editor = New-Object System.Windows.Forms.TextBox
                    $editor.Multiline = $true
                    $editor.ScrollBars = 'Vertical'
                    $editor.AcceptsReturn = $true
                    $editor.WordWrap = $false
                    $editor.Height = 72
                    $editor.Text = Format-OptionArrayValue -Value $value
                    $editor.Margin = '3,4,3,8'
                    $editor.Dock = 'Fill'
                }
                default {
                    $editor = New-Object System.Windows.Forms.TextBox
                    $editor.Text = if ($null -eq $value) { '' } else { [string]$value }
                    $editor.Margin = '3,4,3,4'
                    $editor.Anchor = 'Left,Right'
                    if ($name -match 'Text|Patterns|Managers|Accounts|Executable|Exe|Path' -or [string]$value -match '\r|\n' -or ([string]$value).Length -gt 80) {
                        $editor.Multiline = $true
                        $editor.ScrollBars = 'Vertical'
                        $editor.AcceptsReturn = $true
                        $editor.WordWrap = $false
                        $editor.Height = 72
                        $editor.Dock = 'Fill'
                    }
                }
            }

            $rowIndex = $table.RowCount
            $table.RowCount += 1
            [void]$table.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
            [void]$table.Controls.Add($label, 0, $rowIndex)
            [void]$table.Controls.Add($editor, 1, $rowIndex)
            $script:State.Gui.OptionEditors += [pscustomobject]@{
                Name    = $name
                Kind    = $kind
                Control = $editor
            }
            Add-GuiOptionEditorChangedHandler -Control $editor -Kind $kind
        }

        if (Test-GuiKey -Key 'OptionGuideLabel') {
            $script:State.Gui.OptionGuideLabel.Text = Get-GuiOptionGuideText -Code $Code
        }
    } finally {
        $table.ResumeLayout()
        $script:State.Gui.SuppressOptionSync = $false
    }

    Update-GuiOptionJsonMirror
}

function Invoke-ScanCode {
    param(
        [string]$Code,
        [string]$OptionText = $null
    )

    $definition = Get-CatalogDefinition -Code $Code
    $options = Get-ParsedOptionsForCode -Code $Code -Text $OptionText
    return Invoke-Detect -Definition $definition -Options $options
}

function Invoke-ScanAll {
    $results = @()
    foreach ($definition in $script:State.Catalog) {
        Write-ToolLog -Message ('진단 중: {0} {1}' -f $definition.Code, $definition.Title)
        $result = Invoke-ScanCode -Code $definition.Code
        $results += $result
        if (Test-GuiKey -Key 'Form') {
            Update-GuiRowFromResult -Result $result
            [System.Windows.Forms.Application]::DoEvents()
        }
    }

    return $results
}

function Format-PlanText {
    param([pscustomobject]$Plan)

    $lines = @(
        ('코드: {0}' -f $Plan.Code)
        ('자동 적용 지원: {0}' -f $Plan.AutoSupported)
        ('예상 상태: {0}' -f $Plan.ExpectedStatus)
        ('재부팅 필요 가능성: {0}' -f $Plan.RequiresRestart)
        ('영향: {0}' -f $Plan.Impact)
    )

    if ($Plan.Notes) {
        $lines += ('메모: {0}' -f $Plan.Notes)
    }

    if ($Plan.Changes.Count -gt 0) {
        $lines += ''
        $lines += '예정 변경:'
        $lines += ($Plan.Changes | ForEach-Object { '- ' + $_ })
    }

    return ($lines -join [Environment]::NewLine)
}

function Format-ResultText {
    param([pscustomobject]$Result)

    $lines = @(
        ('코드: {0}' -f $Result.Code)
        ('항목: {0}' -f $Result.Title)
        ('상태: {0}' -f $Result.Status)
        ('요약: {0}' -f $Result.Summary)
        ('점검 시각: {0:yyyy-MM-dd HH:mm:ss}' -f $Result.CheckedAt)
    )

    if ($Result.PSObject.Properties['IsException'] -and $Result.IsException) {
        $lines += ('원래 상태: {0}' -f $Result.OriginalStatus)
        if ($Result.ExceptionAt) {
            $lines += ('예외 시각: {0}' -f $Result.ExceptionAt)
        }
        if ($Result.ExceptionReason) {
            $lines += ('예외 사유: {0}' -f $Result.ExceptionReason)
        }
    }

    $lines += ''
    $lines += $Result.Details
    return ($lines -join [Environment]::NewLine)
}

function Invoke-PreviewCode {
    param(
        [string]$Code,
        [string]$OptionText = $null
    )

    $definition = Get-CatalogDefinition -Code $Code
    $result = Invoke-ScanCode -Code $Code -OptionText $OptionText
    $options = Get-ParsedOptionsForCode -Code $Code -Text $OptionText
    return [pscustomobject]@{
        Result = $result
        Plan   = (Invoke-Plan -Definition $definition -Result $result -Options $options)
    }
}

function Invoke-ApplyCode {
    param(
        [string]$Code,
        [string]$OptionText = $null
    )

    $definition = Get-CatalogDefinition -Code $Code
    $preview = Invoke-PreviewCode -Code $Code -OptionText $OptionText
    if (-not $preview.Plan.AutoSupported) {
        $reason = if ([string]::IsNullOrWhiteSpace([string]$preview.Plan.Notes)) {
            '미리보기 결과를 확인하세요.'
        } else {
            [string]$preview.Plan.Notes
        }
        throw ('{0}은 자동 적용을 지원하지 않습니다. {1}' -f $Code, $reason)
    }

    $backupDirectory = Invoke-ApplyDefinition -Definition $definition -Result $preview.Result -Options (Get-ParsedOptionsForCode -Code $Code -Text $OptionText)
    $after = Invoke-ScanCode -Code $Code -OptionText $OptionText
    return [pscustomobject]@{
        Before          = $preview.Result
        Plan            = $preview.Plan
        BackupDirectory = $backupDirectory
        After           = $after
    }
}

function Invoke-ExceptionActionForCode {
    param(
        [string]$Code,
        [ValidateSet('Set', 'Clear', 'Toggle')]
        [string]$Action,
        [string]$OptionText = $null
    )

    $definition = Get-CatalogDefinition -Code $Code
    if (-not (Test-DefinitionAllowsException -Definition $definition)) {
        throw ('{0}은 예외 처리를 지원하지 않습니다.' -f $Code)
    }

    $enabled = Test-ExceptionEnabled -Code $Code
    switch ($Action) {
        'Set' {
            if (-not $enabled) {
                Set-ExceptionEnabled -Code $Code -Enabled:$true
            }
        }
        'Clear' {
            if ($enabled) {
                Set-ExceptionEnabled -Code $Code -Enabled:$false
            }
        }
        'Toggle' {
            Set-ExceptionEnabled -Code $Code -Enabled:(-not $enabled)
        }
    }

    $result = Invoke-ScanCode -Code $Code -OptionText $OptionText
    return [pscustomobject]@{
        Code             = $Code
        ExceptionEnabled = (Test-ExceptionEnabled -Code $Code)
        ExceptionPath    = $script:State.ExceptionPath
        Result           = $result
    }
}

function Ensure-GuiAssemblies {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
}

function Get-StatusColor {
    param([string]$Status)
    switch ($Status) {
        '양호' { return [System.Drawing.Color]::FromArgb(227, 246, 227) }
        '취약' { return [System.Drawing.Color]::FromArgb(253, 228, 228) }
        '수동점검' { return [System.Drawing.Color]::FromArgb(255, 247, 221) }
        '예외' { return [System.Drawing.Color]::FromArgb(227, 239, 255) }
        '오류' { return [System.Drawing.Color]::FromArgb(255, 209, 209) }
        default { return [System.Drawing.Color]::White }
    }
}

function Update-GuiSummary {
    if (-not (Test-GuiKey -Key 'CountLabels')) {
        return
    }

    $results = @($script:State.Results.Values)
    $total = $script:State.Catalog.Count
    $checked = $results.Count
    $safe = @($results | Where-Object { $_.Status -eq '양호' }).Count
    $vuln = @($results | Where-Object { $_.Status -eq '취약' }).Count
    $manual = @($results | Where-Object { $_.Status -eq '수동점검' }).Count
    $except = @($results | Where-Object { $_.Status -eq '예외' }).Count
    $errorCount = @($results | Where-Object { $_.Status -eq '오류' }).Count

    $script:State.Gui.CountLabels.Total.Text = ('전체 {0}' -f $total)
    $script:State.Gui.CountLabels.Checked.Text = ('점검 {0}' -f $checked)
    $script:State.Gui.CountLabels.Safe.Text = ('양호 {0}' -f $safe)
    $script:State.Gui.CountLabels.Vuln.Text = ('취약 {0}' -f $vuln)
    $script:State.Gui.CountLabels.Manual.Text = ('수동 {0}' -f $manual)
    $script:State.Gui.CountLabels.Except.Text = ('예외 {0}' -f $except)
    $script:State.Gui.CountLabels.Error.Text = ('오류 {0}' -f $errorCount)
}

function Update-GuiRowFromResult {
    param([pscustomobject]$Result)

    $grid = $script:State.Gui.Grid
    if (-not $grid) {
        return
    }

    $rowIndex = $script:State.Gui.RowIndexByCode[$Result.Code]
    $row = $grid.Rows[$rowIndex]
    $row.Cells['Status'].Value = $Result.Status
    $row.Cells['Summary'].Value = $Result.Summary
    $row.Cells['CheckedAt'].Value = (Get-Date -Date $Result.CheckedAt -Format 'HH:mm:ss')
    $row.DefaultCellStyle.BackColor = Get-StatusColor -Status $Result.Status
    Update-GuiSummary
}

function Get-GuiSelectedCode {
    $grid = $script:State.Gui.Grid
    if (-not $grid -or $grid.SelectedRows.Count -eq 0) {
        return $null
    }
    return [string]$grid.SelectedRows[0].Cells['Code'].Value
}

function Save-CurrentOptionEditor {
    $code = $script:State.Gui.CurrentCode
    if (-not $code) {
        return $null
    }

    if (Test-GuiKey -Key 'OptionEditors') {
        $values = Get-GuiOptionEditorValues
        if ($null -ne $values) {
            $json = ConvertTo-PrettyJson $values
            Set-CurrentOptionText -Code $code -Text $json
            if (Test-GuiKey -Key 'OptionsTextBox') {
                $script:State.Gui.OptionsTextBox.Text = $json
            }
            return $json
        }
    }

    if (Test-GuiKey -Key 'OptionsTextBox') {
        Set-CurrentOptionText -Code $code -Text $script:State.Gui.OptionsTextBox.Text
        return $script:State.Gui.OptionsTextBox.Text
    }

    return Get-CurrentOptionText -Code $code
}

function Update-GuiPrimaryActionButton {
    if (-not (Test-GuiKey -Key 'ApplyButton')) {
        return
    }

    $button = $script:State.Gui.ApplyButton
    $code = $script:State.Gui.CurrentCode
    if (-not $code) {
        $button.Enabled = $false
        $button.Text = '적용'
        return
    }

    $definition = Get-CatalogDefinition -Code $code
    if (Test-DefinitionAllowsException -Definition $definition) {
        $button.Enabled = $true
        $button.Text = if (Test-ExceptionEnabled -Code $code) { '예외 해제' } else { '예외 처리' }
        return
    }

    if ($definition.Apply) {
        $button.Enabled = $true
        $button.Text = '적용'
        return
    }

    $button.Enabled = $false
    $button.Text = '적용 불가'
}

function Set-GuiButtonPanelLayout {
    param(
        [switch]$Compact,
        [int]$CompactColumns = 2
    )

    if (-not (Test-GuiKey -Key 'ButtonPanel') -or -not (Test-GuiKey -Key 'Buttons')) {
        return
    }

    $panel = $script:State.Gui.ButtonPanel
    $buttons = @($script:State.Gui.Buttons)
    if ($buttons.Count -eq 0) {
        return
    }

    $panel.SuspendLayout()
    try {
        $panel.Controls.Clear()
        $panel.RowStyles.Clear()
        $panel.ColumnStyles.Clear()

        if ($Compact) {
            $columnCount = [Math]::Max(2, $CompactColumns)
            $panel.ColumnCount = $columnCount
            $panel.RowCount = [int][Math]::Ceiling($buttons.Count / [double]$columnCount)
            $panel.Padding = '0,0,0,4'
            for ($i = 0; $i -lt $columnCount; $i++) {
                [void]$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, (100 / $columnCount))))
            }

            for ($index = 0; $index -lt $buttons.Count; $index++) {
                $button = $buttons[$index]
                $button.Dock = 'Fill'
                $button.Width = 0
                $button.Height = 32
                $button.Margin = '0,0,6,6'
                $row = [int][Math]::Floor($index / [double]$columnCount)
                $column = $index % $columnCount
                [void]$panel.Controls.Add($button, $column, $row)
            }
        } else {
            $panel.ColumnCount = 1
            $panel.RowCount = $buttons.Count
            $panel.Padding = '0,0,0,6'
            [void]$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
            for ($index = 0; $index -lt $buttons.Count; $index++) {
                $button = $buttons[$index]
                $button.Dock = 'None'
                $button.Width = 130
                $button.Height = 30
                $button.Margin = '0,0,0,6'
                [void]$panel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
                [void]$panel.Controls.Add($button, 0, $index)
            }
        }
    } finally {
        $panel.ResumeLayout()
    }
}

function Refresh-GuiSelectionDetails {
    $code = Get-GuiSelectedCode
    if (-not $code) {
        return
    }

    if ($script:State.Gui.CurrentCode -and $script:State.Gui.CurrentCode -ne $code) {
        Save-CurrentOptionEditor
    }

    $script:State.Gui.CurrentCode = $code
    $definition = Get-CatalogDefinition -Code $code
    $result = if ($script:State.Results.ContainsKey($code)) { $script:State.Results[$code] } else { $null }

    $script:State.Gui.MetaLabel.Text = '{0} | {1} | 위험도 {2}' -f $definition.Code, $definition.Category, $definition.Severity
    $script:State.Gui.TitleLabel.Text = $definition.Title
    Build-GuiOptionEditor -Code $code
    Update-GuiPrimaryActionButton
    $script:State.Gui.CurrentTextBox.Text = if ($result) { Format-ResultText -Result $result } else { '아직 점검하지 않았습니다.' }
    $script:State.Gui.PreviewTextBox.Text = ''
}

function Invoke-GuiScanAll {
    $form = $script:State.Gui.Form
    Save-CurrentOptionEditor
    $form.UseWaitCursor = $true
    try {
        Invoke-ScanAll | Out-Null
        Refresh-GuiSelectionDetails
    } finally {
        $form.UseWaitCursor = $false
    }
}

function Invoke-GuiScanSelected {
    $code = Get-GuiSelectedCode
    if (-not $code) {
        return
    }

    $optionText = Save-CurrentOptionEditor
    $script:State.Gui.Form.UseWaitCursor = $true
    try {
        $result = Invoke-ScanCode -Code $code -OptionText $optionText
        Update-GuiRowFromResult -Result $result
        Refresh-GuiSelectionDetails
    } finally {
        $script:State.Gui.Form.UseWaitCursor = $false
    }
}

function Invoke-GuiPreviewSelected {
    $code = Get-GuiSelectedCode
    if (-not $code) {
        return
    }

    $optionText = Save-CurrentOptionEditor
    $script:State.Gui.Form.UseWaitCursor = $true
    try {
        $preview = Invoke-PreviewCode -Code $code -OptionText $optionText
        Update-GuiRowFromResult -Result $preview.Result
        $script:State.Gui.CurrentTextBox.Text = Format-ResultText -Result $preview.Result
        $script:State.Gui.PreviewTextBox.Text = Format-PlanText -Plan $preview.Plan
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, '미리보기 실패', 'OK', 'Error') | Out-Null
    } finally {
        $script:State.Gui.Form.UseWaitCursor = $false
    }
}

function Invoke-GuiApplySelected {
    $code = Get-GuiSelectedCode
    if (-not $code) {
        return
    }

    $optionText = Save-CurrentOptionEditor
    try {
        $definition = Get-CatalogDefinition -Code $code
        if (Test-DefinitionAllowsException -Definition $definition) {
            $currentlyEnabled = Test-ExceptionEnabled -Code $code
            $message = if ($currentlyEnabled) {
                '예외를 해제하면 다음 점검부터 실제 상태가 다시 취약/양호 집계에 반영됩니다. 계속하시겠습니까?'
            } else {
                '이 항목을 예외 처리하면 취약 카운트에서 제외합니다. 계속하시겠습니까?'
            }
            $confirmTitle = if ($currentlyEnabled) { ('{0} 예외 해제' -f $code) } else { ('{0} 예외 처리' -f $code) }
            $confirmException = [System.Windows.Forms.MessageBox]::Show(
                $message,
                $confirmTitle,
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($confirmException -ne [System.Windows.Forms.DialogResult]::Yes) {
                return
            }

            $script:State.Gui.Form.UseWaitCursor = $true
            $exceptionResult = Invoke-ExceptionActionForCode -Code $code -Action 'Toggle'
            Update-GuiRowFromResult -Result $exceptionResult.Result
            Refresh-GuiSelectionDetails
            $script:State.Gui.PreviewTextBox.Text = if ($exceptionResult.ExceptionEnabled) {
                "예외 처리 완료`r`n예외 파일: $($exceptionResult.ExceptionPath)"
            } else {
                "예외 해제 완료`r`n예외 파일: $($exceptionResult.ExceptionPath)"
            }
            return
        }

        $preview = Invoke-PreviewCode -Code $code -OptionText $optionText
        $planText = Format-PlanText -Plan $preview.Plan
        $script:State.Gui.PreviewTextBox.Text = $planText
        if (-not $preview.Plan.AutoSupported) {
            $message = if ([string]::IsNullOrWhiteSpace([string]$preview.Plan.Notes)) {
                '이 항목은 자동 적용을 지원하지 않습니다. 우측 미리보기와 현황을 참고해 수동 적용하세요.'
            } else {
                "이 항목은 자동 적용을 지원하지 않습니다.`r`n`r`n$($preview.Plan.Notes)"
            }
            [System.Windows.Forms.MessageBox]::Show($message, '자동 적용 미지원', 'OK', 'Information') | Out-Null
            return
        }

        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "아래 변경을 적용합니다.`r`n`r`n$planText",
            ('{0} 적용 확인' -f $code),
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
            return
        }

        $script:State.Gui.Form.UseWaitCursor = $true
        $applyResult = Invoke-ApplyCode -Code $code -OptionText $optionText
        Update-GuiRowFromResult -Result $applyResult.After
        $script:State.Gui.CurrentTextBox.Text = Format-ResultText -Result $applyResult.After
        $script:State.Gui.PreviewTextBox.Text = @(
            '적용 전',
            '----------------',
            (Format-ResultText -Result $applyResult.Before),
            '',
            '적용 계획',
            '----------------',
            (Format-PlanText -Plan $applyResult.Plan),
            '',
            '적용 후',
            '----------------',
            (Format-ResultText -Result $applyResult.After),
            '',
            ('백업 위치: {0}' -f $applyResult.BackupDirectory)
        ) -join [Environment]::NewLine
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, '적용 실패', 'OK', 'Error') | Out-Null
    } finally {
        $script:State.Gui.Form.UseWaitCursor = $false
    }
}

function Invoke-GuiExportResults {
    Save-CurrentOptionEditor
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'JSON files (*.json)|*.json'
    $dialog.FileName = 'scan_results.json'
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Export-ScanResults -Results @($script:State.Results.Values) -OutputPath $dialog.FileName | Out-Null
    }
}

function Invoke-GuiResetSelectedOptions {
    $code = Get-GuiSelectedCode
    if (-not $code) {
        return
    }

    Set-CurrentOptionText -Code $code -Text (Get-DefaultOptionText -Code $code)
    Build-GuiOptionEditor -Code $code
    $script:State.Gui.PreviewTextBox.Text = '선택 항목 옵션을 기본값으로 복원했습니다.'
}

function Apply-GuiResponsiveLayout {
    if (-not (Test-GuiKey -Key 'Form') -or -not (Test-GuiKey -Key 'Split') -or -not (Test-GuiKey -Key 'Grid')) {
        return
    }

    $form = $script:State.Gui.Form
    $split = $script:State.Gui.Split
    $grid = $script:State.Gui.Grid
    $topPanel = $script:State.Gui.TopPanel
    $tabs = $script:State.Gui.Tabs
    $optionTable = $script:State.Gui.OptionTable
    $clientWidth = $form.ClientSize.Width
    $clientHeight = $form.ClientSize.Height
    $compact = ($clientWidth -lt 1280 -or $clientHeight -lt 820)
    $veryCompact = ($clientWidth -lt 1080 -or $clientHeight -lt 700)

    if ($compact) {
        $split.Orientation = [System.Windows.Forms.Orientation]::Vertical
        $split.SplitterDistance = [Math]::Max(360, [Math]::Min([int]($clientWidth * 0.42), $clientWidth - 430))
        $topPanel.WrapContents = $true
        $topPanel.AutoSize = $true
        $tabs.Multiline = $true
        Set-GuiButtonPanelLayout -Compact -CompactColumns $(if ($clientWidth -lt 1120) { 2 } else { 3 })
        if ($optionTable) {
            $optionTable.ColumnStyles[0].Width = 180
        }
        $grid.Columns['Summary'].Visible = $false
        $grid.Columns['CheckedAt'].Visible = $false
        $grid.Columns['Category'].Visible = (-not $veryCompact)
        $grid.Columns['Severity'].Visible = (-not $veryCompact)
        $grid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
        $grid.Columns['Code'].FillWeight = 15
        $grid.Columns['Title'].FillWeight = if ($veryCompact) { 60 } else { 45 }
        $grid.Columns['Status'].FillWeight = 20
        if (-not $veryCompact) {
            $grid.Columns['Category'].FillWeight = 20
            $grid.Columns['Severity'].FillWeight = 10
        }
    } else {
        $split.Orientation = [System.Windows.Forms.Orientation]::Vertical
        $split.SplitterDistance = [Math]::Max(600, [Math]::Min(820, $clientWidth - 520))
        $topPanel.WrapContents = $false
        $topPanel.AutoSize = $false
        $topPanel.Height = 42
        $tabs.Multiline = $false
        Set-GuiButtonPanelLayout
        if ($optionTable) {
            $optionTable.ColumnStyles[0].Width = 250
        }
        $grid.Columns['Summary'].Visible = $true
        $grid.Columns['CheckedAt'].Visible = $true
        $grid.Columns['Category'].Visible = $true
        $grid.Columns['Severity'].Visible = $true
        $grid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
        $grid.Columns['Code'].FillWeight = 12
        $grid.Columns['Title'].FillWeight = 28
        $grid.Columns['Category'].FillWeight = 16
        $grid.Columns['Severity'].FillWeight = 10
        $grid.Columns['Status'].FillWeight = 12
        $grid.Columns['CheckedAt'].FillWeight = 12
        $grid.Columns['Summary'].FillWeight = 35
    }
}

function Show-MainForm {
    Ensure-GuiAssemblies
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form
    $form.Text = if ($script:State.Environment.OsContext.ReleaseLabel) {
        '{0} - {1}' -f (Get-WorkbenchDisplayName), $script:State.Environment.OsContext.ReleaseLabel
    } else {
        Get-WorkbenchDisplayName
    }
    $form.Width = 1560
    $form.Height = 920
    $form.StartPosition = 'CenterScreen'

    $topPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $topPanel.Dock = 'Top'
    $topPanel.Height = 42
    $topPanel.Padding = '8,8,8,4'
    $topPanel.AutoSize = $false

    $summaryLabels = [ordered]@{
        Total   = New-Object System.Windows.Forms.Label
        Checked = New-Object System.Windows.Forms.Label
        Safe    = New-Object System.Windows.Forms.Label
        Vuln    = New-Object System.Windows.Forms.Label
        Manual  = New-Object System.Windows.Forms.Label
        Except  = New-Object System.Windows.Forms.Label
        Error   = New-Object System.Windows.Forms.Label
    }
    foreach ($label in $summaryLabels.Values) {
        $label.AutoSize = $true
        $label.Margin = '0,4,16,0'
        [void]$topPanel.Controls.Add($label)
    }

    $environmentLabel = New-Object System.Windows.Forms.Label
    $environmentLabel.AutoSize = $true
    $environmentLabel.Margin = '16,4,0,0'
    $environmentLabel.Text = Format-OsContextDisplayText -OsContext $script:State.Environment.OsContext
    [void]$topPanel.Controls.Add($environmentLabel)

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'
    $split.SplitterDistance = 820

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.ReadOnly = $true
    $grid.SelectionMode = 'FullRowSelect'
    $grid.MultiSelect = $false
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.RowHeadersVisible = $false
    $grid.AutoSizeColumnsMode = 'Fill'
    $grid.RowTemplate.Height = 24
    $grid.Font = New-Object System.Drawing.Font('Consolas', 9)
    [void]$grid.Columns.Add('Code', 'Code')
    [void]$grid.Columns.Add('Title', '제목')
    [void]$grid.Columns.Add('Category', '분류')
    [void]$grid.Columns.Add('Severity', '위험도')
    [void]$grid.Columns.Add('Status', '상태')
    [void]$grid.Columns.Add('CheckedAt', '점검')
    [void]$grid.Columns.Add('Summary', '요약')

    $script:State.Gui.RowIndexByCode = @{}
    foreach ($definition in $script:State.Catalog) {
        $index = $grid.Rows.Add($definition.Code, $definition.Title, $definition.Category, $definition.Severity, '미점검', '', '')
        $script:State.Gui.RowIndexByCode[$definition.Code] = $index
    }
    [void]$split.Panel1.Controls.Add($grid)

    $rightLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $rightLayout.Dock = 'Fill'
    $rightLayout.RowCount = 4
    $rightLayout.ColumnCount = 1
    [void]$rightLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
    [void]$rightLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 28)))
    [void]$rightLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$rightLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $metaLabel = New-Object System.Windows.Forms.Label
    $metaLabel.Dock = 'Fill'
    $metaLabel.TextAlign = 'MiddleLeft'
    $metaLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    [void]$rightLayout.Controls.Add($metaLabel, 0, 0)

    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Dock = 'Fill'
    $titleLabel.TextAlign = 'MiddleLeft'
    $titleLabel.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 11, [System.Drawing.FontStyle]::Bold)
    [void]$rightLayout.Controls.Add($titleLabel, 0, 1)

    $buttonPanel = New-Object System.Windows.Forms.TableLayoutPanel
    $buttonPanel.Dock = 'Top'
    $buttonPanel.AutoSize = $true
    $buttonPanel.AutoSizeMode = 'GrowAndShrink'
    $buttonPanel.ColumnCount = 1
    $buttonPanel.RowCount = 6
    $buttonPanel.Padding = '0,0,0,6'
    [void]$buttonPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))

    $scanAllButton = New-Object System.Windows.Forms.Button
    $scanAllButton.Text = '전체 진단'
    $scanAllButton.Width = 130
    $scanButton = New-Object System.Windows.Forms.Button
    $scanButton.Text = '선택 재진단'
    $scanButton.Width = 130
    $previewButton = New-Object System.Windows.Forms.Button
    $previewButton.Text = '미리보기'
    $previewButton.Width = 130
    $resetOptionsButton = New-Object System.Windows.Forms.Button
    $resetOptionsButton.Text = '기본값 복원'
    $resetOptionsButton.Width = 130
    $applyButton = New-Object System.Windows.Forms.Button
    $applyButton.Text = '적용'
    $applyButton.Width = 130
    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Text = '결과 내보내기'
    $exportButton.Width = 130
    $buttonSet = @($scanAllButton, $scanButton, $previewButton, $resetOptionsButton, $applyButton, $exportButton)
    foreach ($button in $buttonSet) {
        $button.AutoSize = $false
        $button.Height = 32
        $button.Margin = '0,0,0,6'
    }
    $script:State.Gui.Buttons = $buttonSet
    Set-GuiButtonPanelLayout
    [void]$rightLayout.Controls.Add($buttonPanel, 0, 2)

    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = 'Fill'
    $currentTab = New-Object System.Windows.Forms.TabPage
    $currentTab.Text = '현황'
    $previewTab = New-Object System.Windows.Forms.TabPage
    $previewTab.Text = '미리보기'
    $optionsTab = New-Object System.Windows.Forms.TabPage
    $optionsTab.Text = '옵션'
    $jsonTab = New-Object System.Windows.Forms.TabPage
    $jsonTab.Text = '고급 JSON'
    $logTab = New-Object System.Windows.Forms.TabPage
    $logTab.Text = '로그'

    $currentTextBox = New-Object System.Windows.Forms.TextBox
    $currentTextBox.Dock = 'Fill'
    $currentTextBox.Multiline = $true
    $currentTextBox.ReadOnly = $true
    $currentTextBox.ScrollBars = 'Both'
    $currentTextBox.Font = New-Object System.Drawing.Font('Consolas', 9)
    [void]$currentTab.Controls.Add($currentTextBox)

    $previewTextBox = New-Object System.Windows.Forms.TextBox
    $previewTextBox.Dock = 'Fill'
    $previewTextBox.Multiline = $true
    $previewTextBox.ReadOnly = $true
    $previewTextBox.ScrollBars = 'Both'
    $previewTextBox.Font = New-Object System.Drawing.Font('Consolas', 9)
    [void]$previewTab.Controls.Add($previewTextBox)

    $optionsLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $optionsLayout.Dock = 'Fill'
    $optionsLayout.RowCount = 2
    $optionsLayout.ColumnCount = 1
    [void]$optionsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))
    [void]$optionsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $optionGuideLabel = New-Object System.Windows.Forms.Label
    $optionGuideLabel.Dock = 'Fill'
    $optionGuideLabel.Padding = '6,8,6,0'
    $optionGuideLabel.Text = '선택 항목의 옵션을 여기서 직접 조정합니다.'
    [void]$optionsLayout.Controls.Add($optionGuideLabel, 0, 0)

    $optionScrollPanel = New-Object System.Windows.Forms.Panel
    $optionScrollPanel.Dock = 'Fill'
    $optionScrollPanel.AutoScroll = $true

    $optionTable = New-Object System.Windows.Forms.TableLayoutPanel
    $optionTable.Dock = 'Top'
    $optionTable.AutoSize = $true
    $optionTable.AutoSizeMode = 'GrowAndShrink'
    $optionTable.GrowStyle = 'AddRows'
    $optionTable.Padding = '6,6,6,6'
    $optionTable.ColumnCount = 2
    [void]$optionTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 250)))
    [void]$optionTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$optionScrollPanel.Controls.Add($optionTable)
    [void]$optionsLayout.Controls.Add($optionScrollPanel, 0, 1)
    [void]$optionsTab.Controls.Add($optionsLayout)

    $optionsTextBox = New-Object System.Windows.Forms.TextBox
    $optionsTextBox.Dock = 'Fill'
    $optionsTextBox.Multiline = $true
    $optionsTextBox.ReadOnly = $true
    $optionsTextBox.ScrollBars = 'Both'
    $optionsTextBox.Font = New-Object System.Drawing.Font('Consolas', 9)
    [void]$jsonTab.Controls.Add($optionsTextBox)

    $logTextBox = New-Object System.Windows.Forms.TextBox
    $logTextBox.Dock = 'Fill'
    $logTextBox.Multiline = $true
    $logTextBox.ReadOnly = $true
    $logTextBox.ScrollBars = 'Both'
    $logTextBox.Font = New-Object System.Drawing.Font('Consolas', 9)
    [void]$logTab.Controls.Add($logTextBox)

    [void]$tabs.TabPages.AddRange(@($currentTab, $previewTab, $optionsTab, $jsonTab, $logTab))
    [void]$rightLayout.Controls.Add($tabs, 0, 3)
    [void]$split.Panel2.Controls.Add($rightLayout)

    [void]$form.Controls.Add($split)
    [void]$form.Controls.Add($topPanel)

    $script:State.Gui = @{
        Form          = $form
        Split         = $split
        TopPanel      = $topPanel
        Tabs          = $tabs
        ButtonPanel   = $buttonPanel
        Buttons       = $buttonSet
        ApplyButton   = $applyButton
        Grid          = $grid
        CountLabels   = $summaryLabels
        EnvironmentLabel = $environmentLabel
        MetaLabel     = $metaLabel
        TitleLabel    = $titleLabel
        CurrentTextBox = $currentTextBox
        PreviewTextBox = $previewTextBox
        OptionsTextBox = $optionsTextBox
        OptionGuideLabel = $optionGuideLabel
        OptionTable      = $optionTable
        OptionEditors    = @()
        SuppressOptionSync = $false
        LogTextBox     = $logTextBox
        CurrentCode    = $null
        RowIndexByCode = $script:State.Gui.RowIndexByCode
    }

    $grid.Add_SelectionChanged({
        Refresh-GuiSelectionDetails
    })
    $scanAllButton.Add_Click({ Invoke-GuiScanAll })
    $scanButton.Add_Click({ Invoke-GuiScanSelected })
    $previewButton.Add_Click({ Invoke-GuiPreviewSelected })
    $resetOptionsButton.Add_Click({ Invoke-GuiResetSelectedOptions })
    $applyButton.Add_Click({ Invoke-GuiApplySelected })
    $exportButton.Add_Click({ Invoke-GuiExportResults })
    $form.Add_FormClosing({
        Save-CurrentOptionEditor
    })
    $form.Add_SizeChanged({
        Apply-GuiResponsiveLayout
    })
    $form.Add_Shown({
        if ($grid.Rows.Count -gt 0) {
            $grid.Rows[0].Selected = $true
        }
        Apply-GuiResponsiveLayout
        Update-GuiSummary
        Invoke-GuiScanAll
    })

    [void]$form.ShowDialog()
}

function Invoke-Headless {
    if ($Code -and $OptionsJson) {
        Set-CurrentOptionText -Code $Code -Text $OptionsJson
    }

    if ($ExceptionAction -ne 'None') {
        if (-not $Code) {
            throw '-ExceptionAction 사용 시 -Code가 필요합니다.'
        }
        $result = Invoke-ExceptionActionForCode -Code $Code -Action $ExceptionAction -OptionText $OptionsJson
        $payload = [pscustomobject]@{
            Code             = $result.Code
            ExceptionEnabled = $result.ExceptionEnabled
            ExceptionPath    = $result.ExceptionPath
            Result           = ConvertTo-ResultExportObject -Results @($result.Result) -IncludeDetails:$IncludeDetails
        }
        if ($OutputPath) {
            Save-JsonFile -InputObject $payload -Path $OutputPath
        }
        $payload | ConvertTo-Json -Depth 8
        return
    }

    if ($Apply) {
        if (-not $Code) {
            throw '-Apply 사용 시 -Code가 필요합니다.'
        }
        $result = Invoke-ApplyCode -Code $Code -OptionText $OptionsJson
        $payload = [pscustomobject]@{
            Before          = ConvertTo-ResultExportObject -Results @($result.Before) -IncludeDetails:$IncludeDetails
            Plan            = $result.Plan
            BackupDirectory = $result.BackupDirectory
            After           = ConvertTo-ResultExportObject -Results @($result.After) -IncludeDetails:$IncludeDetails
        }
        if ($OutputPath) {
            Save-JsonFile -InputObject $payload -Path $OutputPath
        }
        $payload | ConvertTo-Json -Depth 8
        return
    }

    if ($PreviewOnly) {
        if (-not $Code) {
            throw '-PreviewOnly 사용 시 -Code가 필요합니다.'
        }
        $preview = Invoke-PreviewCode -Code $Code -OptionText $OptionsJson
        $payload = [pscustomobject]@{
            Result = ConvertTo-ResultExportObject -Results @($preview.Result) -IncludeDetails:$IncludeDetails
            Plan   = $preview.Plan
        }
        if ($OutputPath) {
            Save-JsonFile -InputObject $payload -Path $OutputPath
        }
        $payload | ConvertTo-Json -Depth 8
        return
    }

    if ($Code) {
        $result = Invoke-ScanCode -Code $Code -OptionText $OptionsJson
        $payload = ConvertTo-ResultExportObject -Results @($result) -IncludeDetails:$IncludeDetails
        if ($OutputPath) {
            Save-JsonFile -InputObject $payload -Path $OutputPath
        }
        $payload | ConvertTo-Json -Depth 8
        return
    }

    $results = Invoke-ScanAll
    if ($OutputPath) {
        Export-ScanResults -Results $results -IncludeDetails:$IncludeDetails -OutputPath $OutputPath | Out-Null
    }
    (ConvertTo-ResultExportObject -Results $results -IncludeDetails:$IncludeDetails) | ConvertTo-Json -Depth 8
}

$explicitHeadless = $NoGui -or $ScanOnly -or $PreviewOnly -or $Apply -or $Code -or $OutputPath -or ($ExceptionAction -ne 'None')

try {
    if ($PSScriptRoot) {
        Set-Location -LiteralPath $PSScriptRoot
    }

    Assert-Windows
    Assert-Administrator
    Initialize-EnvironmentContext
    Assert-SupportedServerRelease
    Initialize-Configuration
    Initialize-Catalog
    Initialize-ExceptionState

    if ($explicitHeadless) {
        Invoke-Headless
    } else {
        Show-MainForm
    }
} catch {
    Write-StartupFailure -ErrorRecord $_ -GuiExpected:(-not $explicitHeadless)
    exit 1
}
