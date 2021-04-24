param(
    [string]$InputPath,
    [switch]$Auto = $false,
    [switch]$AMF = $false,
    [switch]$NVENC = $false
)
$defaults = @{
    'c:a'      = 'aac';
    'b:a'      = '317k';
    'aspect:v' = '2';
    'movflags' = '+faststart';
};
$outputs = @{
    '4k' = @{
        'c:v'      = 'libx264';
        'crf'      = '23';
        'coder'    = '0'
        'filter:v' = @{'scale' = '3840:1920' }
    }
    '6k' = @{
        'c:v'      = 'libx265'
        'crf'      = '20';
        'filter:v' = @{'scale' = '5760:2880' }
    }
    '8k' = @{
        'c:v'      = 'libx265'
        'crf'      = '20';
        'filter:v' = @{'scale' = '7680:3840' }
    }
}

# Github releases functions
function Get-GithubRelease {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [string] $Repo,
        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = "Prereleases"
        )]
        [switch] $Prereleases,
        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = "Latest"
        )]
        [switch] $Latest,
        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = "Name"
        )]
        [switch] $Name,
        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = "Tag"
        )]
        [switch] $Tag
    )
    $URI = "https://api.github.com/repos/$repo/releases"
    if ($Latest) {
        $URI += "/latest"
    }
    $releases = Invoke-RestMethod -Method GET -Uri $URI
    if (!$Prereleases) {
        $releases = $releases | Where-Object { $_.prerelease -eq $false }
    }
    if ($Name) {
        return $releases | Where-Object { $_.name -eq $Name }
    }
    if ($Tag) {
        return $releases | Where-Object { $_.tag_name -eq $Tag }
    }
    return , ($releases | Sort-Object published_at -Descending)
}
function Get-GithubAsset {
    Param(
        [Parameter(ValueFromPipeline, Mandatory = $true)] $Release,
        [Parameter(Mandatory = $false)] [switch] $Relative
    )
    $assets = @()
    $Release.assets | ForEach-Object { $assets += $_ }
    if ($Relative) {
        if ($assets.Length -gt 1) {
            switch ($ENV:PROCESSOR_ARCHITECTURE) {
                "X86" {
                    $asset = $assets | Where-Object { 
                        $_.name -like "*x86*"
                    }
                    if ($asset.Length -gt 0) { $assets = $asset }
                }
                "AMD64" {
                    $asset = $assets | Where-Object { 
                        $_.name -like "*x64*" -or
                        $_.name -like "*_64*"
                    }
                    if ($asset.Length -gt 0) { $assets = $asset }
                }
                "ARM32" {
                    $asset = $assets | Where-Object { 
                        $_.name -like "*arm32*" -or
                        (
                            $_.name -like "*arm*" -and
                            $_.name -notlike "*arm64*"
                        )
                    }
                    if ($asset.Length -gt 0) { $assets = $asset }
                }
                "ARM64" {
                    $asset = $assets | Where-Object { 
                        $_.name -like "*arm64*"
                    }
                    if ($asset.Length -gt 0) { $assets = $asset }
                }
            }
            
        }
        if ($assets.Length -gt 1) {
            if ($IsWindows -or $ENV:OS) {
                $asset = $assets | Where-Object { 
                    $_.name -like "*win*"
                }
                if ($asset.Length -gt 0) { $assets = $asset }
            }
            if ($IsMacOS) {
                $asset = $assets | Where-Object { 
                    $_.name -like "*mac*" -or
                    $_.name -like "*osx*"
                }
                if ($asset.Length -gt 0) { $assets = $asset }
            }
            if ($IsLinux) {
                $asset = $assets | Where-Object { 
                    $_.name -like "*linux*"
                }
                if ($asset.Length -gt 0) { $assets = $asset }
            }
            
        }
        if ($assets.Length -gt 1) {
            return $assets | Sort-Object download_count -Descending | Select-Object -First 1
        }
        else {
            return $assets
        }
    }
    else {
        return $assets
    }
}
function Download-GithubAsset {
    Param(
        [Parameter(ValueFromPipeline, Mandatory = $true)] $Asset
    )
    $FileName = Join-Path -Path $([System.IO.Path]::GetTempPath()) -ChildPath $(Split-Path -Path $Asset.browser_download_url -Leaf)
    Invoke-WebRequest -Uri $Asset.browser_download_url -Out $FileName    
    switch ($([System.IO.Path]::GetExtension($Asset.browser_download_url))) {
        ".zip" {
            $tempExtract = Join-Path -Path $([System.IO.Path]::GetTempPath()) -ChildPath $((New-Guid).Guid)
            Expand-Archive -Path $FileName -DestinationPath $tempExtract -Force
            Remove-Item $FileName -Force
            return $tempExtract
        }
        default {
            return $FileName
        }
    }
}
Function Get-Folder($initialDirectory = "") {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.Description = "Select a folder"
    $foldername.rootfolder = "MyComputer"
    $foldername.SelectedPath = $initialDirectory

    if ($foldername.ShowDialog() -eq "OK") {
        $folder += $foldername.SelectedPath
    }
    return $folder
}

Function Install-7zip($7zip_install_path = "") {
    if (!(Test-Path $7zip_install_path)) {
        $scope = Get-ScriptScope
        $7zip_download_uri = "https://www.7-zip.org/a/7z1900-x64.msi"
        $7zip_local_file = Join-Path -Path $([System.IO.Path]::GetTempPath()) -ChildPath $(Split-Path -Path $7zip_download_uri -Leaf)
        Invoke-WebRequest -Uri $7zip_download_uri -Out $7zip_local_file
        $MSIArguments = @(
            "/a"
            ('"{0}"' -f $7zip_local_file)
            "TARGETDIR=`"$scope['dir']`""
            "/qn"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 
    }
}
Function Install-FFMpeg($ffmpeg_install_path = "") {
    $ffmpeg_git = (Get-GithubRelease "BtbN/FFmpeg-Builds" -Latest | Get-GithubAsset | Where-Object -Property name -match "-gpl-shared-vulkan.zip")[0]
    $ffmpeg_release_version = [System.IO.FileInfo]::new($ffmpeg_git.name).BaseName
    if (!(Test-Path $ffmpeg_install_path)) {
        New-Item -ItemType Directory -Force -Path $ffmpeg_install_path | Out-Null
    }
    $ffmpeg_installed_versions = Get-ChildItem -Path $ffmpeg_install_path
    if (($ffmpeg_installed_versions | Where-Object -Property "Name" -EQ $ffmpeg_release_version).Length -eq 0) {
        $ffmpeg_local_file = Join-Path -Path $([System.IO.Path]::GetTempPath()) -ChildPath $(Split-Path -Path $ffmpeg_git.browser_download_url -Leaf)
        Invoke-WebRequest -Uri $ffmpeg_git.browser_download_url -Out $ffmpeg_local_file
        7z x "-o$($ffmpeg_install_path)" $ffmpeg_local_file -r ;
    }
    $ffmpeg_install_path += "\" + $ffmpeg_release_version + "\bin\ffmpeg.exe"
}
Function Install-ContextMenus() {
    $scope = Get-ScriptScope
    
    # Script placement
    $self_install_path = $scope['dir']+"\Scripts"
    $self_install_path += "\"
    $self_path = New-Object System.IO.FileInfo($PSCommandPath)
    $self_install_path += $self_path.BaseName
    $self_install_path += $self_path.Extension

    # Context menu
    $reg_context = "HKCU:\SOFTWARE\Classes\Directory\Background\shell"
    if (!(Test-Path $reg_context)) {
        New-Item -Path $reg_context
    }
    $reg_context_ffmpeg = "$reg_context\ffmpeg"
    if (!(Test-Path $reg_context_ffmpeg)) {
        New-Item -Path $reg_context_ffmpeg | Out-Null
    }
    if (!(Get-ItemProperty -Path $reg_context_ffmpeg).PSObject.Properties.Name -contains "SubCommands") {
        New-ItemProperty -Path $reg_context_ffmpeg -Name "SubCommands" -Value ""
    }
    if (!(Get-ItemProperty -Path $reg_context_ffmpeg).PSObject.Properties.Name -contains "MUIVerb") {
        New-ItemProperty -Path $reg_context_ffmpeg -Name "MUIVerb" -Value "FFMPEG"
    }
    $reg_context_ffmpeg_shell = "$reg_context_ffmpeg\shell"
    if (!(Test-Path $reg_context_ffmpeg_shell)) {
        New-Item -Path $reg_context_ffmpeg_shell | Out-Null
    }
    $reg_context_ffmpeg_shell_all = "$reg_context_ffmpeg_shell\all"
    if (Test-Path $reg_context_ffmpeg_shell_all) {
        Remove-Item -Path $reg_context_ffmpeg_shell_all -Recurse -Force
    }
    # CPU Entry
    $reg_context_ffmpeg_shell_all_cpu = "$reg_context_ffmpeg_shell\all_cpu"
    if (!(Test-Path $reg_context_ffmpeg_shell_all_cpu)) {
        New-Item -Path $reg_context_ffmpeg_shell_all_cpu | Out-Null
    }
    if (!(Get-ItemProperty -Path $reg_context_ffmpeg_shell_all_cpu).PSObject.Properties.Name -contains "MUIVerb") {
        New-ItemProperty -Path $reg_context_ffmpeg_shell_all_cpu -Name "MUIVerb" -Value "Convert All MP4s - CPU"
    }
    $reg_context_ffmpeg_shell_all_cpu_command = "$reg_context_ffmpeg_shell_all_cpu\command"
    if (!(Test-Path $reg_context_ffmpeg_shell_all_cpu_command)) {
        New-Item -Path $reg_context_ffmpeg_shell_all_cpu_command | Out-Null
    }
    Set-ItemProperty -Path $reg_context_ffmpeg_shell_all_cpu_command -Name "(Default)" -Value "PowerShell.exe -ExecutionPolicy Bypass -NoExit -Command `"& '$self_install_path' -InputPath '%v'`""
    # NVENC Entry
    $reg_context_ffmpeg_shell_all_gpu = "$reg_context_ffmpeg_shell\all_gpu"
    if (!(Test-Path $reg_context_ffmpeg_shell_all_gpu)) {
        New-Item -Path $reg_context_ffmpeg_shell_all_gpu | Out-Null
    }
    if (!(Get-ItemProperty -Path $reg_context_ffmpeg_shell_all_gpu).PSObject.Properties.Name -contains "MUIVerb") {
        New-ItemProperty -Path $reg_context_ffmpeg_shell_all_gpu -Name "MUIVerb" -Value "Convert All MP4s - GPU"
    }
    $reg_context_ffmpeg_shell_all_gpu_command = "$reg_context_ffmpeg_shell_all_gpu\command"
    if (!(Test-Path $reg_context_ffmpeg_shell_all_gpu_command)) {
        New-Item -Path $reg_context_ffmpeg_shell_all_gpu_command | Out-Null
    }
    Set-ItemProperty -Path $reg_context_ffmpeg_shell_all_gpu_command -Name "(Default)" -Value "PowerShell.exe -ExecutionPolicy Bypass -NoExit -Command `"& '$self_install_path' -InputPath '%v' -NVENC`""
    # Auto Entry
    $reg_context_ffmpeg_shell_all_auto = "$reg_context_ffmpeg_shell\all_auto"
    if (!(Test-Path $reg_context_ffmpeg_shell_all_auto)) {
        New-Item -Path $reg_context_ffmpeg_shell_all_auto | Out-Null
    }
    if (!(Get-ItemProperty -Path $reg_context_ffmpeg_shell_all_auto).PSObject.Properties.Name -contains "MUIVerb") {
        New-ItemProperty -Path $reg_context_ffmpeg_shell_all_auto -Name "MUIVerb" -Value "Convert All MP4s - Auto"
    }
    $reg_context_ffmpeg_shell_all_auto_command = "$reg_context_ffmpeg_shell_all_auto\command"
    if (!(Test-Path $reg_context_ffmpeg_shell_all_auto_command)) {
        New-Item -Path $reg_context_ffmpeg_shell_all_auto_command | Out-Null
    }
    Set-ItemProperty -Path $reg_context_ffmpeg_shell_all_auto_command -Name "(Default)" -Value "PowerShell.exe -ExecutionPolicy Bypass -NoExit -Command `"& '$self_install_path' -InputPath '%v' -Auto`""
    # AMF Entry
    $reg_context_ffmpeg_shell_all_amf = "$reg_context_ffmpeg_shell\all_amf"
    if (!(Test-Path $reg_context_ffmpeg_shell_all_amf)) {
        New-Item -Path $reg_context_ffmpeg_shell_all_amf | Out-Null
    }
    if (!(Get-ItemProperty -Path $reg_context_ffmpeg_shell_all_amf).PSObject.Properties.Name -contains "MUIVerb") {
        New-ItemProperty -Path $reg_context_ffmpeg_shell_all_amf -Name "MUIVerb" -Value "Convert All MP4s - AMF"
    }
    $reg_context_ffmpeg_shell_all_amf_command = "$reg_context_ffmpeg_shell_all_amf\command"
    if (!(Test-Path $reg_context_ffmpeg_shell_all_amf_command)) {
        New-Item -Path $reg_context_ffmpeg_shell_all_amf_command | Out-Null
    }
    Set-ItemProperty -Path $reg_context_ffmpeg_shell_all_amf_command -Name "(Default)" -Value "PowerShell.exe -ExecutionPolicy Bypass -NoExit -Command `"& '$self_install_path' -InputPath '%v' -AMF`""
}
function Self-Upgrade ([string]$InputPath) {
    Install-ContextMenus
    $current_publish = (New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End (Get-ChildItem $PSCommandPath).LastWriteTime).TotalSeconds
    $release = Get-GithubRelease -Repo ggpwnkthx/FFMPEG-ContextMenu -Latest
    $release_publish = (New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End (Get-Date -Date $release.published_at)).TotalSeconds
    if ($release_publish -gt $current_publish) {
        Write-Host "Performing self-update..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Install-Module -Name PackageManagement -Force -MinimumVersion 1.4.6 -Scope CurrentUser -AllowClobber -Repository PSGallery | Out-Null
        Register-PackageSource -Name nuget.org -Location https://www.nuget.org/api/v2 -ProviderName NuGet | Out-Null
        Set-PackageSource -Name nuget.org -Trusted | Out-Null
        #Install-Package FFMpegCore -Scope CurrentUser -SkipDependencies -Destination . -Force | Out-Null
        Copy-Item -Path ($release | Get-GithubAsset | Download-GithubAsset) -Destination $PSCommandPath -Force
        & $PSCommandPath -InputPath $InputPath
        exit
    }
}
Function Analyze-FFMPEG-StdOut($stdout) {
    Write-Host $stdout
    $output = New-Object PSObject
    $output | Add-Member -MemberType NoteProperty -Name Frame -Value ([string]([regex]::Match($stdout, 'frame=\s*(\d+)')))
    if ($output.Frame.Length -gt 0) {
        $output.Frame = [int]($output.Frame.Substring(6, $output.Frame.Length - 6).Trim())
    }
    $output | Add-Member -MemberType NoteProperty -Name FPS -Value ([string]([regex]::Match($stdout, 'fps=\s*(\d+)')))
    if ($output.FPS.Length -gt 0) {
        $output.FPS = $output.FPS.Substring(4, $output.FPS.Length - 4).Trim()
    }
    $output | Add-Member -MemberType NoteProperty -Name Size -Value ([string]([regex]::Match($stdout, 'size=\s*(\d+).*?\s')))
    if ($output.Size.Length -gt 0) {
        $output.Size = $output.Size.Substring(5, $output.Size.Length - 5).Trim()
    }
    $output | Add-Member -MemberType NoteProperty -Name Time -Value ([string]([regex]::Match($stdout, 'time=(\d+):(\d+):(\d+)')))
    if ($output.Time.Length -gt 0) {
        $output.Time = $output.Time.Substring(5, $output.Time.Length - 5)
    }
    $output | Add-Member -MemberType NoteProperty -Name Bitrate -Value ([string]([regex]::Match($stdout, 'bitrate=\s*(\d+).*?\s')))
    if ($output.Bitrate.Length -gt 0) {
        $output.Bitrate = $output.Bitrate.Substring(8, $output.Bitrate.Length - 8).Trim()
    }
    return $output
}
function Get-ScriptScope {
    $dir = "$env:APPDATA\Eclatech"
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    $reg = "HKCU:\SOFTWARE\Eclatech"
    if (!(Test-Path $reg)) {
        New-Item -Path "HKCU:\SOFTWARE" -Name "Eclatech" | Out-Null
    }
    return @{'dir' = $dir; 'reg' = $reg}
}
function Set-FFMPEGAlias {
    $scope = Get-ScriptScope
    $ffmpeg_install_path = $scope['dir']+"\Files\ffmpeg"
    $ffmpeg_installed_versions = Get-ChildItem -Path $ffmpeg_install_path
    $ffprobe_install_path = $ffmpeg_install_path + "\" + ($ffmpeg_installed_versions | Sort-Object -Property "LastWriteTime" -Descending)[0].Name + "\bin\ffprobe.exe"
    $ffmpeg_install_path += "\" + ($ffmpeg_installed_versions | Sort-Object -Property "LastWriteTime" -Descending)[0].Name + "\bin\ffmpeg.exe"
    Set-Alias -Scope Global -Name ffmpeg -Value $ffmpeg_install_path
    Set-Alias -Scope Global -Name ffprobe -Value $ffprobe_install_path
}
function Get-FFMPEGMaxJobs {
    Param(
        [Parameter(Mandatory = $true)] [string] $Coprocessor
    )
    switch ($Coprocessor.ToUpper()) {
        'CPU' {
            return 1
        }
        'NVENC' {
            $NVENC_LIST = ffmpeg -f lavfi -i nullsrc -c:v nvenc -gpu list -f null - 2>&1 | Select-String "GPU \#" | ForEach-Object { [regex]::Matches([string]$_, "\#.*\>").Value }
            return $NVENC_LIST.Count
        }
        'AMF' {
            $OPENCL_LIST = ffmpeg -v verbose -init_hw_device opencl 2>&1 | Select-String "AMD" | ForEach-Object { 
                $match = [regex]::Matches([string]$_, "\].*\:").Value
                $match.Substring(1,$match.Length-2).Trim()
            }
            return $OPENCL_LIST.Count
        }
    }
}
function Get-FFMPEGExpression {
    Param(
        [Parameter(ValueFromPipeline, Mandatory = $true)] $Job,
        [Parameter(Mandatory = $false)] [string] $Coprocessor
    )
    $Job.PrefixExpression += "-hide_banner "
    $output_filepath = $Job.Outpath + "\" + $Job.Master.BaseName + "_"
    switch ($Job.Parameters['filter:v']["scale"]) {
        '3840:1920' { $output_filepath += "4K.mp4" }
        '5760:2880' { $output_filepath += "6K.mp4" }
        '7680:3840' { $output_filepath += "8K.mp4" }
    }

    if ($Coprocessor -eq "AMF") {
        switch ($Job.Parameters['c:v']) {
            'libx264' { $Job.Parameters['c:v'] = 'h264_amf'}
            'libx265' { $Job.Parameters['c:v'] = 'hevc_amf'}
        }
        switch ($Job.Parameters['filter:v']["scale"]) {
            '3840:1920' { 
                $Job.Parameters['cq'] = [string]([int]$Job.Parameters['crf'] + 4)
                $Job.Parameters['maxrate'] = '16M'
                $Job.Parameters['bufsize'] = '8M'
            }
            '5760:2880' {
                $Job.Parameters['cq'] = [string]([int]$Job.Parameters['crf'] + 9)
                $Job.Parameters['maxrate'] = '20M'
                $Job.Parameters['bufsize'] = '10M'
            }
            '7680:3840' {
                $Job.Parameters['cq'] = [string]([int]$Job.Parameters['crf'] + 9)
                $Job.Parameters['maxrate'] = '24M'
                $Job.Parameters['bufsize'] = '12M'
            }
        }
        $Job.Parameters['filter:v'] = @{
            "hwmap" = "derive_device=opencl:mode=read,format=nv12"
            "hwdownload" = ""
        }
        $Job.Parameters['qmin'] = $Job.Parameters['cq']
        $Job.Parameters['qmax'] = $Job.Parameters['cq']
        $Job.Parameters.Remove('crf')
        $Job.Parameters.Remove('preset')
        $Job.PrefixExpression += "-hwaccel d3d11va "
        $Job.PrefixExpression += "-hwaccel_output_format d3d11 "
    }
    
    if ($Coprocessor -eq "NVENC") {
        switch ($Job.Parameters['c:v']) {
            'libx264' { $Job.Parameters['c:v'] = 'h264_nvenc'}
            'libx265' { $Job.Parameters['c:v'] = 'hevc_nvenc'}
        }
        switch ($Job.Parameters['filter:v']["scale"]) {
            '3840:1920' { 
                $Job.Parameters['cq'] = [string]([int]$Job.Parameters['crf'] + 4)
                $Job.Parameters['maxrate'] = '16M'
                $Job.Parameters['bufsize'] = '8M'
            }
            '5760:2880' {
                $Job.Parameters['cq'] = [string]([int]$Job.Parameters['crf'] + 9)
                $Job.Parameters['maxrate'] = '20M'
                $Job.Parameters['bufsize'] = '10M'
            }
            '7680:3840' {
                $Job.Parameters['cq'] = [string]([int]$Job.Parameters['crf'] + 9)
                $Job.Parameters['maxrate'] = '24M'
                $Job.Parameters['bufsize'] = '12M'
            }
        }
        $Job.Parameters['qmin'] = $Job.Parameters['cq']
        $Job.Parameters['qmax'] = $Job.Parameters['cq']
        $Job.Parameters.Remove('crf')
        $Job.Parameters.Remove('preset')
        $Job.PrefixExpression += "-hwaccel cuda "
        switch ($Job.Master.streams[0].codec_name) {
            hevc { $Job.InputExpression += "-c:v hevc_cuvid " }
            h264 { $Job.InputExpression += "-c:v h264_cuvid " }
        }
    }
    $Job.InputExpression += "-i '" + $Job.Master.FullName + "'"
    foreach ($para in $Job.Parameters.Keys) {
        if ($Job.Parameters[$para] -is [String]) {
            $Job.OutputExpression += " -" + $para + " " + $Job.Parameters[$para]
        }
        if ($Job.Parameters[$para] -is [Hashtable]) {
            $Job.OutputExpression += " -" + $para + " '";
            foreach ($item in $Job.Parameters[$para].Keys) {
                if ($Job.Parameters[$para][$item] -ne '') {
                    $Job.OutputExpression += $item + "=" + $Job.Parameters[$para][$item];
                }
                else {
                    $Job.OutputExpression += $item;
                }
                Switch ($para) {
                    'filter:v' { $Job.OutputExpression += "," }
                    'x264-params' { $Job.OutputExpression += ":" }
                    'x265-params' { $Job.OutputExpression += ":" }
                }
            }
            $Job.OutputExpression = $Job.OutputExpression.Substring(0, $Job.OutputExpression.Length - 1)
            $Job.OutputExpression += "'"
        }
    }
    if (!(Test-Path $output_filepath)) {
        $Job.OutputExpression += " -n '$output_filepath'"
    } else {
        $transcoded = (ffprobe -hide_banner -show_streams -v quiet -print_format json -i $output_filepath | ConvertFrom-Json).streams
        if ($transcoded.Length -gt 0) {
            if ($Job.Master.streams[0].duration -ne $transcoded[0].duration) {
                $Job.OutputExpression += " -y '$output_filepath'"
            }
            else {
                $Job.OutputExpression = ""
            }
        }
        else {
            $Job.OutputExpression += " -y '$output_filepath'"
        }
    }
    $Job.OutputFilePath = $output_filepath
    
    return $Job.PrefixExpression + " " + $Job.InputExpression + " " + $Job.OutputExpression
}

$scope = Get-ScriptScope
Set-FFMPEGAlias

# Self-Install
if ($PSScriptRoot -ne $scope['dir']+"\Scripts") {
    # 7zip
    $7zip_install_path = $scope['dir']+"\Files\7-Zip"
    Install-7zip($7zip_install_path)
    Set-Alias 7z "$7zip_install_path\7z.exe"

    # FFMPEG
    $ffmpeg_install_path = $scope['dir']+"\Files\ffmpeg"
    Install-FFMpeg($ffmpeg_install_path)
    Set-Alias ffmpeg $ffmpeg_install_path

    # Registry
    Install-ContextMenus

    # Script placement
    $self_install_path = $scope['dir']+"\Scripts"
    if (!(Test-Path $self_install_path)) {
        New-Item -ItemType Directory -Force -Path $self_install_path | Out-Null
    }
    Copy-Item $PSCommandPath -Destination $self_install_path -Force

    Write-Host -NoNewLine 'Installed successfully!';
}
else {
    if ($InputPath -eq $null) {
        $InputPath = Get-Folder
    }
    Self-Upgrade -InputPath $InputPath

    $ConcurrentJobCount = @{}
    if ($Auto) {
        $ConcurrentJobCount['CPU'] = Get-FFMPEGMaxJobs -Coprocessor CPU
        $ConcurrentJobCount['NVENC'] = Get-FFMPEGMaxJobs -Coprocessor NVENC
        $ConcurrentJobCount['AMF'] = Get-FFMPEGMaxJobs -Coprocessor AMF
        $ConcurrentJobCount.Key | ForEach-Object {
            if ($ConcurrentJobCount[$_] -eq 0) {
                $ConcurrentJobCount.Remove($_)
            }
        }
    }
    if ($AMF) {
        $ConcurrentJobCount['AMF'] = Get-FFMPEGMaxJobs -Coprocessor AMF
    }
    if ($NVENC) {
        $ConcurrentJobCount['NVENC'] = Get-FFMPEGMaxJobs -Coprocessor NVENC
    }
    if ($ConcurrentJobCount.Keys.Count -eq 0) {
        $ConcurrentJobCount['CPU'] = Get-FFMPEGMaxJobs -Coprocessor CPU
    }

    $masters = Get-ChildItem -Path $InputPath -Filter "*.mp4"
    $dir_processed = "$InputPath\Processed"
    if ($masters.Length -eq 0) {
        $masters = Get-ChildItem -Path $InputPath -Recurse -Filter "*.mp4"
        $dir_processed = Get-Folder -initialDirectory $InputPath
        if ([string]::IsNullOrEmpty($dir_processed)) {
            exit
        }
    }

    $JOB_QUEUE = [System.Collections.Queue]::Synchronized( (New-Object System.Collections.Queue) )
    $i = 0
    foreach ($master in $masters) {
    	try {
            $master | Add-Member -MemberType NoteProperty -Name InputStreams -Value ((ffprobe -hide_banner -show_streams -v quiet -print_format json -i $master.FullName | ConvertFrom-Json).streams)
            
            if ((Split-Path -Path $dir_processed -Parent) -ne ($InputPath)) {
                $outpath = ([string](Split-Path -Path $master.FullName -Parent)).Replace($InputPath, $dir_processed)
            } else {
                $outpath = $dir_processed
            }
            if (!(Test-Path $outpath)) {
                New-Item -ItemType Directory -Force -Path $outpath | Out-Null
            }
            foreach ($format_name in ($outputs.Keys | Sort-Object)) {
                $job = @{
                    Id               = $i
                    JobId            = 0
                    Parameters       = @{}
                    Master           = $master
                    Outpath          = $outpath
                    Progress         = @{}
                    PrefixExpression = ""
                    InputExpression  = ""
                    OutputExpression = ""
                    OutputFilePath   = ""
                }
                $i++
                foreach ($attr in $defaults.Keys) {
                    $job.Parameters[$attr] = $defaults[$attr]
                }
                foreach ($attr in $outputs[$format_name].Keys) {
                    $job.Parameters[$attr] = $outputs[$format_name][$attr]
                }
                $JOB_QUEUE.Enqueue($job)
            }
        } catch {
        	Write-Host $_
            Write-Host "An error occured adding the following file to the job queue:" $master.FullName
        }
    }
    
    $TotalFrames = 0
    $JOB_QUEUE.ToArray() | ForEach-Object {
        $TotalFrames += [int]$_.Master.InputStreams[0].nb_frames
    }
    Write-Progress -Activity "Transcoding Jobs" -Id 1
    While (($JOB_QUEUE.Count -gt 0) -or (Get-Job).Count -ne (Get-Job | Where-Object -Property State -EQ 'Completed').Count) {
        $RunningJobs = Get-Job | Where-Object -Property State -EQ 'Running'
        $ConcurrentJobCount.Keys | ForEach-Object {
            $Coprocessor = $_
            if (($JOB_QUEUE.Count -gt 0) -and ($RunningJobs | Where-Object -Property ProcessorType -EQ $Coprocessor).Count -lt $ConcurrentJobCount[$Coprocessor]) {
                $data = $JOB_QUEUE.Dequeue()
                $expression = $data | Get-FFMPEGExpression -Coprocessor $Coprocessor
                Write-Host $expression
                $job = Start-Job -ArgumentList @((Get-Alias ffmpeg).Definition, $expression) -ScriptBlock {Invoke-Expression($args[0] + " " + $args[1])}
                $job | Add-Member -MemberType NoteProperty -Name ProcessorType -Value $Coprocessor
                $job | Add-Member -MemberType NoteProperty -Name FFMPEGParameters -Value $data
            }
        }
        $TotalFPS = 0
        $CompletedFrames = 0
        Get-Job | ForEach-Object {
            if ($_.State -eq 'Running') {
                $stdout = (Receive-Job -Job $_ 2>&1)
                if (-not [string]::IsNullOrEmpty($stdout)) {
                    $_.FFMPEGParameters.Progress = Analyze-FFMPEG-StdOut($stdout)
                    $completed = [math]::Round(([decimal]$_.FFMPEGParameters.Progress.Frame / [decimal]$_.FFMPEGParameters.Master.InputStreams[0].nb_frames) * 100, 2)
                    $speed = [math]::Round([decimal]$_.FFMPEGParameters.Progress.FPS / (Invoke-Expression $_.FFMPEGParameters.Master.InputStreams[0].avg_frame_rate), 2)
                    if ([int]$_.FFMPEGParameters.Progress.FPS -gt 0) {
                        $RemainingTime = [timespan]::FromSeconds(([int]$_.FFMPEGParameters.Master.InputStreams[0].nb_frames - [int]$_.FFMPEGParameters.Progress.Frame) / [int]$_.FFMPEGParameters.Progress.FPS)
                    }
                    else {
                        $RemainingTime = [timespan]::FromSeconds(0)
                    }
                    $activity = $_.ProcessorType + ": " + $_.FFMPEGParameters.OutputFilePath
                    Write-Progress `
                        -Activity $activity `
                        -Status ( `
                            "Frame: " + $_.FFMPEGParameters.Progress.Frame + "/" + $_.FFMPEGParameters.Master.InputStreams[0].nb_frames + `
                            " | FPS: " + $_.FFMPEGParameters.Progress.FPS + `
                            " | Size: " + $_.FFMPEGParameters.Progress.Size + `
                            " | Bitrate: " + $_.FFMPEGParameters.Progress.Bitrate + `
                            " | Speed: " + $speed + "x" + `
                            " | Remaining: " + ("{0:hh\:mm\:ss\,fff}" -f $RemainingTime) `
                    ) `
                        -PercentComplete $completed `
                        -Id ($_.Id + 2) `
                        -ParentId 1
                }
                $TotalFPS += [int]$_.FFMPEGParameters.Progress.FPS
                $CompletedFrames += [int]$_.FFMPEGParameters.Progress.Frame
            } elseif ($_.State -eq 'Completed') {
                Write-Progress `
                    -Activity "Complete" `
                    -Completed `
                    -Id ($_.Id + 2) `
                    -ParentId 1
                Remove-Job $_
            }
        }
        Write-Progress `
            -Activity "Transcoding Jobs" `
            -Status ( `
                "Frame: $CompletedFrames / $TotalFrames | " + `
                "FPS: $TotalFPS"`
        ) `
            -PercentComplete (($CompletedFrames / $TotalFrames) * 100) `
            -Id 1
    }
    Write-Progress `
        -Activity "Transcoding Jobs" `
        -Completed `
        -Id 1
}
Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');