param(
    [string]$InputPath,
    [switch]$Auto = $false,
    [switch]$NVENC = $false
)
$ConcurrentJobCount_NVENC = 1
$ConcurrentJobCount_CPU = 2

$defaults = @{
    'c:a'      = 'aac';
    'b:a'      = '317k';
    'aspect:v' = '2';
    'movflags' = '+faststart';
};
$outputs = @{
    '1k' = @{
        'c:v'      = 'libx264';
        'crf'      = '23';
        'coder'    = '0'
        'filter:v' = @{'scale' = '1920:960' }
        'ac'       = '2'
    }
    '2k' = @{
        'c:v'      = 'libx264';
        'crf'      = '23';
        'coder'    = '0'
        'filter:v' = @{'scale' = '2880:1440' }
        'ac'       = '2'
    }
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
        'preset'   = 'ultrafast'
    }
    '8k' = @{
        'c:v'      = 'libx265'
        'crf'      = '20';
        'filter:v' = @{'scale' = '7680:3840' }
        'preset'   = 'ultrafast'
    }
}
if ($NVENC) {
    $Auto = $true
    $outputs['1K']['c:v'] = 'h264_nvenc'
    $outputs['1K']['cq'] = [string]([int]$outputs['1K']['crf'] + 5)
    $outputs['1K'].Remove('crf')
    $outputs['1K']['qmin'] = $outputs['1K']['cq']
    $outputs['1K']['qmax'] = $outputs['1K']['cq']
    $outputs['1K']['maxrate'] = '4.5M'
    $outputs['1K']['bufsize'] = '2.25M'
    $outputs['1K']['filter:v']['scale_cuda'] = $outputs['1K']['filter:v']['scale']
    $outputs['1K']['filter:v'].Remove('scale')

    $outputs['2K']['c:v'] = 'h264_nvenc'
    $outputs['2K']['cq'] = [string]([int]$outputs['2K']['crf'] + 5)
    $outputs['2K'].Remove('crf')
    $outputs['2K']['qmin'] = $outputs['2K']['cq']
    $outputs['2K']['qmax'] = $outputs['2K']['cq']
    $outputs['2K']['maxrate'] = '12M'
    $outputs['2K']['bufsize'] = '6M'
    $outputs['2K']['filter:v']['scale_cuda'] = $outputs['2K']['filter:v']['scale']
    $outputs['2K']['filter:v'].Remove('scale')
}
if ($Auto) {   
    $outputs['4K']['c:v'] = 'h264_nvenc'
    $outputs['4K']['cq'] = [string]([int]$outputs['4K']['crf'] + 5)
    $outputs['4K']['filter:v'].Remove('crf')
    $outputs['4K']['qmin'] = $outputs['4K']['cq']
    $outputs['4K']['qmax'] = $outputs['4K']['cq']
    $outputs['4K']['maxrate'] = '16M'
    $outputs['4K']['bufsize'] = '8M'
    $outputs['4K']['filter:v']['scale_cuda'] = $outputs['4K']['filter:v']['scale']
    $outputs['4K']['filter:v'].Remove('crf')
    $outputs['4K']['filter:v'].Remove('scale')

    $outputs['6K']['c:v'] = 'hevc_nvenc'
    $outputs['6K']['cq'] = [string]([int]$outputs['6K']['crf'] + 10)
    $outputs['6K'].Remove('crf')
    $outputs['6K']['qmin'] = $outputs['6K']['cq']
    $outputs['6K']['qmax'] = $outputs['6K']['cq']
    $outputs['6K']['maxrate'] = '20M'
    $outputs['6K']['bufsize'] = '10M'
    $outputs['6K']['filter:v']['scale_cuda'] = $outputs['6K']['filter:v']['scale']
    $outputs['6K']['filter:v'].Remove('scale')
    $outputs['6K'].Remove('preset')

    $outputs['8K']['c:v'] = 'hevc_nvenc'
    $outputs['8K']['cq'] = [string]([int]$outputs['8K']['crf'] + 10)
    $outputs['8K'].Remove('crf')
    $outputs['8K']['qmin'] = $outputs['8K']['cq']
    $outputs['8K']['qmax'] = $outputs['8K']['cq']
    $outputs['8K']['maxrate'] = '24M'
    $outputs['8K']['bufsize'] = '12M'
    $outputs['8K']['filter:v']['scale_cuda'] = $outputs['8K']['filter:v']['scale']
    $outputs['8K']['filter:v'].Remove('scale')
    $outputs['8K'].Remove('preset')
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
        $7zip_download_uri = "https://www.7-zip.org/a/7z1900-x64.msi"
        $7zip_local_file = Join-Path -Path $([System.IO.Path]::GetTempPath()) -ChildPath $(Split-Path -Path $7zip_download_uri -Leaf)
        Invoke-WebRequest -Uri $7zip_download_uri -Out $7zip_local_file
        $MSIArguments = @(
            "/a"
            ('"{0}"' -f $7zip_local_file)
            "TARGETDIR=`"$dir_scope`""
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
    $dir_scope = "$env:APPDATA\Eclatech"
    if (!(Test-Path $dir_scope)) {
        New-Item -ItemType Directory -Force -Path $dir_scope | Out-Null
    }
    $reg_scope = "HKCU:\SOFTWARE\Eclatech"
    if (!(Test-Path $reg_scope)) {
        New-Item -Path "HKCU:\SOFTWARE" -Name "Eclatech" | Out-Null
    }
    
    # Script placement
    $self_install_path = "$dir_scope\Scripts"
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

# Scoping
$dir_scope = "$env:APPDATA\Eclatech"
if (!(Test-Path $dir_scope)) {
    New-Item -ItemType Directory -Force -Path $dir_scope | Out-Null
}
$reg_scope = "HKCU:\SOFTWARE\Eclatech"
if (!(Test-Path $reg_scope)) {
    New-Item -Path "HKCU:\SOFTWARE" -Name "Eclatech" | Out-Null
}

# Self-Install
if ($PSScriptRoot -ne "$dir_scope\Scripts") {
    # 7zip
    $7zip_install_path = "$dir_scope\Files\7-Zip"
    Install-7zip($7zip_install_path)
    Set-Alias 7z "$7zip_install_path\7z.exe"

    # FFMPEG
    $ffmpeg_install_path = "$dir_scope\Files\ffmpeg"
    Install-FFMpeg($ffmpeg_install_path)
    Set-Alias ffmpeg $ffmpeg_install_path

    # Registry
    Install-ContextMenus

    # Script placement
    $self_install_path = "$dir_scope\Scripts"
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

    $ffmpeg_install_path = "$dir_scope\Files\ffmpeg"
    $ffmpeg_installed_versions = Get-ChildItem -Path $ffmpeg_install_path
    $ffprobe_install_path = $ffmpeg_install_path + "\" + ($ffmpeg_installed_versions | Sort-Object -Property "LastWriteTime" -Descending)[0].Name + "\bin\ffprobe.exe"
    $ffmpeg_install_path += "\" + ($ffmpeg_installed_versions | Sort-Object -Property "LastWriteTime" -Descending)[0].Name + "\bin\ffmpeg.exe"
    Set-Alias ffmpeg $ffmpeg_install_path
    Set-Alias ffprobe $ffprobe_install_path

    $masters = Get-ChildItem -Path $InputPath -Filter "*.mp4"
    $dir_processed = "$InputPath\Processed"
    if ($masters.Length -eq 0) {
        $masters = Get-ChildItem -Path $InputPath -Recurse -Filter "*.mp4"
        $dir_processed = Get-Folder -initialDirectory $InputPath
        if ([string]::IsNullOrEmpty($dir_processed)) {
            exit
        }
    }

    if ($NVENC) {
        $GPU_LIST = ffmpeg -f lavfi -i nullsrc -c:v nvenc -gpu list -f null - 2>&1 | Select-String "GPU \#" | ForEach-Object { [regex]::Matches([string]$_, "\#.*\>").Value }
    }
    $GPU_LIST
    $queue_CPU = [System.Collections.Queue]::Synchronized( (New-Object System.Collections.Queue) )
    $queue_NVENC = [System.Collections.Queue]::Synchronized( (New-Object System.Collections.Queue) )
    $i = 0
    foreach ($master in $masters) {
        $master | Add-Member -MemberType NoteProperty -Name streams -Value ((ffprobe -hide_banner -show_streams -v quiet -print_format json -i $master.FullName | ConvertFrom-Json).streams)
        
        if ((Split-Path -Path $dir_processed -Parent) -ne ($InputPath)) {
            $outpath = ([string](Split-Path -Path $master.FullName -Parent)).Replace($InputPath, $dir_processed)
        }
        else {
            $outpath = $dir_processed
        }
        if (!(Test-Path $outpath)) {
            New-Item -ItemType Directory -Force -Path $outpath | Out-Null
        }
        foreach ($format_name in ($outputs.Keys | Sort-Object)) {
            $job = New-Object -TypeName PSObject -Property @{
                Id               = $i
                Parameters       = @{}
                PrefixExpression = ""
                InputExpression  = ""
                OutputExpression = ""
                InputStreams     = $master.streams
                OutputFilePath   = ""
                Progress         = @{}
            }
            $i++
            $parameters = @{}
            foreach ($attr in $defaults.Keys) {
                $parameters[$attr] = $defaults[$attr]
            }
            foreach ($attr in $outputs[$format_name].Keys) {
                $parameters[$attr] = $outputs[$format_name][$attr]
            }
            $job.PrefixExpression += "-hide_banner "
            if ($parameters['c:v'] -eq "hevc_nvenc" -or $parameters['c:v'] -eq "h264_nvenc") {
                $job.PrefixExpression += "-hwaccel cuda -hwaccel_output_format cuda "
                switch ($master.streams[0].codec_name) {
                    hevc { $job.InputExpression += "-c:v hevc_cuvid " }
                    h264 { $job.InputExpression += "-c:v h264_cuvid " }
                }
            }
            
            $job.InputExpression += "-i '" + $master.FullName + "'"

            $output_expression = ""
            foreach ($para in $parameters.Keys) {
                if ($parameters[$para] -is [String]) {
                    $output_expression += " -" + $para + " " + $parameters[$para]
                }
                if ($parameters[$para] -is [Hashtable]) {
                    $output_expression += " -" + $para + " '";
                    foreach ($item in $parameters[$para].Keys) {
                        if ($parameters[$para][$item] -ne '') {
                            $output_expression += $item + "=" + $parameters[$para][$item];
                        }
                        else {
                            $output_expression += $item;
                        }
                        Switch ($para) {
                            'filter:v' { $output_expression += "," }
                            'x264-params' { $output_expression += ":" }
                            'x265-params' { $output_expression += ":" }
                        }
                    }
                    $output_expression = $output_expression.Substring(0, $output_expression.Length - 1)
                    $output_expression += "'"
                }
            }
            $job.Parameters = $parameters
            $output_filepath = $outpath + "\" + $master.BaseName + "_" + $format_name + ".mp4"
            $job.OutputFilePath = $output_filepath
            if (!(Test-Path $output_filepath)) {
                $output_expression += " -n '$output_filepath'"
            }
            else {
                $transcoded = (ffprobe -hide_banner -show_streams -v quiet -print_format json -i  $output_filepath | ConvertFrom-Json).streams
                if ($transcoded.Length -gt 0) {
                    if ($master.streams[0].duration -ne $transcoded[0].duration) {
                        $output_expression += " -y '$output_filepath'"
                    }
                    else {
                        $output_expression = ""
                    }
                }
                else {
                    $output_expression += " -y '$output_filepath'"
                }
            }
            if (-not [string]::IsNullOrEmpty($output_expression)) {
                $job.OutputExpression = $output_expression
                if ($parameters['c:v'] -eq "hevc_nvenc" -or $parameters['c:v'] -eq "h264_nvenc") {
                    $queue_NVENC.Enqueue($job)
                }
                else {
                    $queue_CPU.Enqueue($job)
                }
            }
        }
    }
    
    $TotalFrames = 0
    $batch = $queue_CPU.ToArray() + $queue_NVENC.ToArray()
    $batch | ForEach-Object { 
        $TotalFrames += [int]$_.InputStreams[0].nb_frames
    }
    Write-Progress -Activity "Transcoding Jobs" -Id 1
    While (($queue_CPU.Count -gt 0 -or $queue_NVENC.Count -gt 0) -or (Get-Job).Count -ne (Get-Job | Where-Object -Property State -EQ 'Completed').Count) {
        $RunningJobs = Get-Job | Where-Object -Property State -EQ 'Running'
        if ($queue_CPU.Count -gt 0 -and ($RunningJobs | Where-Object -Property ProcessorType -EQ 'CPU').Count -lt $ConcurrentJobCount_CPU) {
            $data = $queue_CPU.Dequeue()
            $job = Start-Job -ArgumentList @($ffmpeg_install_path, $data) -ScriptBlock {
                Set-Alias ffmpeg $arg[0]
                Invoke-Expression("ffmpeg " + $args[1].PrefixExpression + " " + $args[1].InputExpression + " " + $args[1].OutputExpression)
            }
            $job | Add-Member -MemberType NoteProperty -Name ProcessorType -Value 'CPU'
            $batch | Where-Object -Property Id -EQ $data.Id | Add-Member -MemberType NoteProperty -Name JobId -Value $job.Id
        }
        if ($queue_NVENC.Count -gt 0 -and ($RunningJobs | Where-Object -Property ProcessorType -EQ 'NVENC').Count -lt $ConcurrentJobCount_NVENC) {
            $data = $queue_NVENC.Dequeue()
            $job = Start-Job -ArgumentList @($ffmpeg_install_path, $data) -ScriptBlock {
                Set-Alias ffmpeg $arg[0]
                Invoke-Expression("ffmpeg " + $args[1].PrefixExpression + " " + $args[1].InputExpression + " " + $args[1].OutputExpression)
            }
            $job | Add-Member -MemberType NoteProperty -Name ProcessorType -Value 'NVENC'
            $batch | Where-Object -Property Id -EQ $data.Id | Add-Member -MemberType NoteProperty -Name JobId -Value $job.Id
        }
        $TotalFPS = 0
        $CompletedFrames = 0
        Get-Job | ForEach-Object {
            $data = $batch | Where-Object -Property JobID -EQ $_.Id
            if ($_.State -eq 'Running') {
                $stdout = (Receive-Job -Job $_ 2>&1)
                if (-not [string]::IsNullOrEmpty($stdout)) {
                    $data.Progress = Analyze-FFMPEG-StdOut($stdout)
                    $completed = [math]::Round(([decimal]$data.Progress.Frame / [decimal]$data.InputStreams[0].nb_frames) * 100, 2)
                    $speed = [math]::Round([decimal]$data.Progress.FPS / (Invoke-Expression $data.InputStreams[0].avg_frame_rate), 2)
                    if ([int]$data.Progress.FPS -gt 0) {
                        $RemainingTime = [timespan]::FromSeconds(([int]$data.InputStreams[0].nb_frames - [int]$data.Progress.Frame) / [int]$data.Progress.FPS)
                    }
                    else {
                        $RemainingTime = [timespan]::FromSeconds(0)
                    }
                    $activity = $_.ProcessorType + ": " + $data.OutputFilePath
                    Write-Progress `
                        -Activity $activity `
                        -Status ( `
                            "Frame: " + $data.Progress.Frame + "/" + $data.InputStreams[0].nb_frames + `
                            " | FPS: " + $data.Progress.FPS + `
                            " | Size: " + $data.Progress.Size + `
                            " | Bitrate: " + $data.Progress.Bitrate + `
                            " | Speed: " + $speed + "x" + `
                            " | Remaining: " + ("{0:hh\:mm\:ss\,fff}" -f $RemainingTime) `
                    ) `
                        -PercentComplete $completed `
                        -Id ($data.Id + 2) `
                        -ParentId 1
                }
                $TotalFPS += [int]$data.Progress.FPS
                $CompletedFrames += [int]$data.Progress.Frame
            }
            if ($_.State -eq 'Completed') {
                Write-Progress -Activity $data.OutputFilePath -Completed -Id ($data.Id + 2) -ParentId 1
                $CompletedFrames += [int]$data.InputStreams[0].nb_frames
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
