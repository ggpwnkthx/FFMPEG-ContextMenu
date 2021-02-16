param([string]$InputPath)

$defaults = @{
	'c:a'			= 'aac';
	'b:a'			= '317k';
	'aspect:v'		= '2';
    'movflags'      = '+faststart';
};
$outputs = @{
    '1k' = @{
	    'c:v'	   = 'libx264';
	    'crf'      = '23';
        'coder'    = '0'
        'filter:v' = @{'scale' = '1920:960'}
        'ac'       = '2'
    }
    '2k'   = @{
	    'c:v'	   = 'libx264';
	    'crf'      = '23';
        'coder'    = '0'
        'filter:v' = @{'scale' = '2880:1440'}
        'ac'       = '2'
    }
    '4k'   = @{
	    'c:v'	   = 'libx264';
	    'crf'      = '23';
        'coder'    = '0'
        'filter:v' = @{'scale' = '3840:1920'}
    }
    '6k'   = @{
        'c:v'      = 'libx265'
	    'crf'      = '20';
        'filter:v' = @{'scale' = '5760:2880'}
        'preset'   = 'ultrafast'
    }
    '8k'   = @{
        'c:v'      = 'libx265'
	    'crf'      = '20';
        'filter:v' = @{'scale' = '7680:3840'}
        'preset'   = 'ultrafast'
    }
}

# Github releases functions
function Get-GithubRelease {
    [CmdletBinding(DefaultParameterSetName='Default')]
    Param(
        [Parameter(
            Mandatory=$true,
            Position=0
        )]
        [string] $Repo,
        [Parameter(
            Mandatory=$true,
            Position=1,
            ParameterSetName="Prereleases"
        )]
        [switch] $Prereleases,
        [Parameter(
            Mandatory=$true,
            Position=1,
            ParameterSetName="Latest"
        )]
        [switch] $Latest,
        [Parameter(
            Mandatory=$true,
            Position=1,
            ParameterSetName="Name"
        )]
        [switch] $Name,
        [Parameter(
            Mandatory=$true,
            Position=1,
            ParameterSetName="Tag"
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
        return $releases | Where-Object {$_.name -eq $Name}
    }
    if ($Tag) {
        return $releases | Where-Object {$_.tag_name -eq $Tag}
    }
    return ,($releases | Sort published_at -Descending)
}
function Get-GithubAsset {
    Param(
        [Parameter(ValueFromPipeline,Mandatory=$true)] $Release,
        [Parameter(Mandatory=$false)] [switch] $Relative
    )
    $assets = @()
    $Release.assets | Foreach { $assets += $_ }
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
            return $assets | Sort download_count -Descending | Select -First 1
        } else {
            return $assets
        }
    } else {
        return $assets
    }
}
function Download-GithubAsset {
    Param(
        [Parameter(ValueFromPipeline,Mandatory=$true)] $Asset
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
function Self-Upgrade ([string]$InputPath) {
    $current_publish = (New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End (Get-ChildItem $PSCommandPath).LastWriteTime).TotalSeconds
    $release = Get-GithubRelease -Repo ggpwnkthx/FFMPEG-ContextMenu -Latest
    $release_publish = (New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End (Get-Date -Date $release.published_at)).TotalSeconds
    if ($release_publish -gt $current_publish) {
        Copy-Item -Path ($release | Get-GithubAsset | Download-GithubAsset) -Destination $PSCommandPath -Force
        & $PSCommandPath -InputPath $InputPath
        exit
    }
}

Function Get-Folder($initialDirectory="") {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.Description = "Select a folder"
    $foldername.rootfolder = "MyComputer"
    $foldername.SelectedPath = $initialDirectory

    if($foldername.ShowDialog() -eq "OK")
    {
        $folder += $foldername.SelectedPath
    }
    return $folder
}

# Scoping
$dir_scope = "$env:APPDATA\Eclatech"
if(!(Test-Path $dir_scope)) {
    New-Item -ItemType Directory -Force -Path $dir_scope | Out-Null
}
$reg_scope = "HKCU:\SOFTWARE\Eclatech"
if(!(Test-Path $reg_scope)) {
    New-Item -Path "HKCU:\SOFTWARE" -Name "Eclatech" | Out-Null
}

# Self-Install
if ($PSScriptRoot -ne "$dir_scope\Scripts") {
    # 7zip
    $7zip_install_path = "$dir_scope\Files\7-Zip"
    if(!(Test-Path $7zip_install_path)) {
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
    Set-Alias 7z "$7zip_install_path\7z.exe"

    # FFMPEG
    $ffmpeg_git = (Get-GithubRelease "BtbN/FFmpeg-Builds" -Latest | Get-GithubAsset | Where-Object -Property name -match "-gpl-shared-vulkan.zip")[0]
    $ffmpeg_release_version = [System.IO.FileInfo]::new($ffmpeg_git.name).BaseName
    $ffmpeg_install_path = "$dir_scope\Files\ffmpeg"
    if(!(Test-Path $ffmpeg_install_path)) {
        New-Item -ItemType Directory -Force -Path $ffmpeg_install_path | Out-Null
    }
    $ffmpeg_installed_versions = Get-ChildItem -Path $ffmpeg_install_path
    if (($ffmpeg_installed_versions | Where-Object -Property "Name" -EQ $ffmpeg_release_version).Length -eq 0) {
        $ffmpeg_local_file = Join-Path -Path $([System.IO.Path]::GetTempPath()) -ChildPath $(Split-Path -Path $ffmpeg_git.browser_download_url -Leaf)
        Invoke-WebRequest -Uri $ffmpeg_git.browser_download_url -Out $ffmpeg_local_file
        7z x "-o$($ffmpeg_install_path)" $ffmpeg_local_file -r ;
    }
    $ffmpeg_install_path += "\"+$ffmpeg_release_version+"\bin\ffmpeg.exe"
    Set-Alias ffmpeg $ffmpeg_install_path

    # Registry
    $reg_ffmpeg = "$reg_scope\ffmpeg"
    if(!(Test-Path $reg_ffmpeg)) {
        New-Item -Path $reg_scope -Name "ffmpeg" | Out-Null
    }

    # Script placement
    $self_install_path = "$dir_scope\Scripts"
    if(!(Test-Path $self_install_path)) {
        New-Item -ItemType Directory -Force -Path $self_install_path | Out-Null
    }
    Copy-Item $PSCommandPath -Destination $self_install_path -Force
    $self_install_path += "\"
    $self_path = New-Object System.IO.FileInfo($PSCommandPath)
    $self_install_path += $self_path.BaseName
    $self_install_path += $self_path.Extension

    # Context menu
    $reg_context = "HKCU:\SOFTWARE\Classes\Directory\Background\shell"
    if(!(Test-Path $reg_context)) {
        New-Item -Path $reg_context
    }
    $reg_context_ffmpeg = "$reg_context\ffmpeg"
    if(!(Test-Path $reg_context_ffmpeg)) {
        New-Item -Path $reg_context_ffmpeg | Out-Null
    }
    if(!(Get-ItemProperty -Path $reg_context_ffmpeg).PSObject.Properties.Name -contains "SubCommands") {
        New-ItemProperty -Path $reg_context_ffmpeg -Name "SubCommands" -Value ""
    }
    if(!(Get-ItemProperty -Path $reg_context_ffmpeg).PSObject.Properties.Name -contains "MUIVerb") {
        New-ItemProperty -Path $reg_context_ffmpeg -Name "MUIVerb" -Value "FFMPEG"
    }
    $reg_context_ffmpeg_shell = "$reg_context_ffmpeg\shell"
    if(!(Test-Path $reg_context_ffmpeg_shell)) {
        New-Item -Path $reg_context_ffmpeg_shell | Out-Null
    }
    $reg_context_ffmpeg_shell_all = "$reg_context_ffmpeg_shell\all"
    if(!(Test-Path $reg_context_ffmpeg_shell_all)) {
        New-Item -Path $reg_context_ffmpeg_shell_all | Out-Null
    }
    if(!(Get-ItemProperty -Path $reg_context_ffmpeg_shell_all).PSObject.Properties.Name -contains "MUIVerb") {
        New-ItemProperty -Path $reg_context_ffmpeg_shell_all -Name "MUIVerb" -Value "Convert All MP4s"
    }
    $reg_context_ffmpeg_shell_all_command = "$reg_context_ffmpeg_shell_all\command"
    if(!(Test-Path $reg_context_ffmpeg_shell_all_command)) {
        New-Item -Path $reg_context_ffmpeg_shell_all_command | Out-Null
    }
    Set-ItemProperty -Path $reg_context_ffmpeg_shell_all_command -Name "(Default)" -Value "PowerShell.exe -ExecutionPolicy Bypass -NoExit -Command `"& '$self_install_path' '%v'`""
    Write-Host -NoNewLine 'Installed successfully!';
} else {
    if ($InputPath -eq $null) {
        $InputPath = Get-Folder
    }
    Self-Upgrade -InputPath $InputPath

    $ffmpeg_install_path = "$dir_scope\Files\ffmpeg"
    $ffmpeg_installed_versions = Get-ChildItem -Path $ffmpeg_install_path
    $ffmpeg_install_path += "\" + ($ffmpeg_installed_versions | Sort-Object -Property "LastWriteTime" -Descending)[0].Name + "\bin\ffmpeg.exe"
    Set-Alias ffmpeg $ffmpeg_install_path

    $masters = Get-ChildItem -Path $InputPath -Filter "*.mp4"
    $dir_processed = "$InputPath\Processed"
    if($masters.Length -eq 0) {
        $masters = Get-ChildItem -Path $InputPath -Recurse -Filter "*.mp4"
        $dir_processed = Get-Folder -initialDirectory $InputPath
        if ([string]::IsNullOrEmpty($dir_processed)) {
            exit
        }
    }

    $wshell = New-Object -ComObject Wscript.Shell
    $NVENC = $wshell.Popup("Do you want to enable NVENC?",0,"Alert",64+4)
    
    foreach ($master in $masters) {
        if((Split-Path -Path $dir_processed -Parent) -ne ($InputPath)) {
            $outpath = ([string](Split-Path -Path $master.FullName -Parent)).Replace($InputPath, $dir_processed)
        } else {
            $outpath = $dir_processed
        }
        if(!(Test-Path $outpath)) {
            New-Item -ItemType Directory -Force -Path $outpath | Out-Null
        }
        foreach($key in ($outputs.Keys | Sort)) {
            $parameters = @{}
	        foreach($attr in $defaults.Keys) {
		        $parameters[$attr] = $defaults[$attr]
	        }
	        foreach($attr in $outputs[$key].Keys) {
		        $parameters[$attr] = $outputs[$key][$attr]
	        }

            $expression = "ffmpeg "
            if ($NVENC -eq 6) {
                $expression += "-hwaccel auto "
                if ($parameters["c:v"] -eq "libx264") {
                    $parameters["c:v"] = "h264_nvenc"
                }
                if ($parameters["c:v"] -eq "libx265") {
                    $parameters["c:v"] = "hevc_nvenc"
                }
                if ($parameters.Keys -match "preset") {
                    switch($parameters["preset"]) {
                        "ultrafast" {
                            $parameters["preset"] = "fast"
                        }
                        "superfast" {
                            $parameters["preset"] = "fast"
                        }
                        "veryfast" {
                            $parameters["preset"] = "fast"
                        }
                        "faster" {
                            $parameters["preset"] = "fast"
                        }
                        "fast" {
                            $parameters["preset"] = "fast"
                        }
                        "medium" {
                            $parameters["preset"] = "medium"
                        }
                        "slow" {
                            $parameters["preset"] = "slow"
                        }
                        "slower" {
                            $parameters["preset"] = "lossless"
                        }
                        "veryslow" {
                            $parameters["preset"] = "losslesshp"
                        }
                        default {
                            $parameters["preset"] = "default"
                        }
                    }
                }
                if ($parameters.Keys -match "crf") {
                    $parameters["crf"] = [string]([int]$parameters["crf"] + 4)
                    $parameters["cq"] = $parameters["crf"]
                    $parameters["qmin"] = $parameters["crf"]
                    $parameters["qmax"] = $parameters["crf"]
                    $parameters["b:v"] = "0"
                    $parameters["rc"] = "vbr"
                    $parameters.Remove("crf")
                }
            }
            $expression += "-i '" + $master.FullName + "'";

	        foreach($para in $parameters.Keys) {
		        if($parameters[$para] -is [String]){
			        $expression += " -"+$para+" "+$parameters[$para];
		        }
		        if($parameters[$para] -is [Hashtable]){
			        $expression += " -"+$para+" '";
			        foreach($item in $parameters[$para].Keys){
                        if ($parameters[$para][$item] -ne '') {
				            $expression += $item+"="+$parameters[$para][$item];
                        } else {
                            $expression += $item;
                        }
                        Switch ($para) {
                            'filter:v' { $expression += "," }
                            'x264-params' { $expression += ":" }
                            'x265-params' { $expression += ":" }
                        }
			        }
			        $expression = $expression.Substring(0,$expression.Length-1)
			        $expression += "'"
		        }
	        }
            $output_filepath = $outpath + "\"  + $master.BaseName + "_" + $key + ".mp4"
            if(!(Test-Path $output_filepath)) {
                $expression += " -n '$output_filepath'"
            } else {
                Write-Host "$output_filepath already exists. Checking length for consistency."
                $original = Get-FileMetaData $master.FullName
                $transcoded = Get-FileMetaData $output_filepath
                if ($original.Length -ne $transcoded.Length) {
                    $expression += " -y '$output_filepath'"
                } else {
                    $expression = ""
                }
            }
            if (-not [string]::IsNullOrEmpty($expression)) {
                Write-Host $expression
                Invoke-Expression ($expression)
            } else {
                Write-Host "No FFMPEG expression."
            }
        }
    }
}
Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
