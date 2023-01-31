function Update-TeamMessage{
    param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Message
    )
    $ContentType = 'Application/Json'
    $Body = @{ text = $Message } 
    $Uri = '(insert)'

    Invoke-RestMethod -Method post -ContentType $ContentType -Body ($Body | ConvertTo-Json) -Uri $Uri
}

$log = ""
$Retry = 0
$Builds = @{
   22621 = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2023/01/windows11.0-kb5022303-x64_87d49704f3f7312cddfe27e45ba493048fdd1517.msu"
   22000 =  "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2023/01/windows10.0-kb5022287-x64_55641f1989bae2c2d0f540504fb07400a0f187b3.msu"
   19045 = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2023/01/windows10.0-kb5022282-x64_fdb2ea85e921869f0abe1750ac7cee34876a760c.msu"
   19044 = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2023/01/windows10.0-kb5022282-x64_fdb2ea85e921869f0abe1750ac7cee34876a760c.msu"
   19043 = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2022/12/windows10.0-kb5021233-x64_00bbf75a829a2cb4f37e4a2b876ea9503acfaf4d.msu"
   19042 = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2023/01/windows10.0-kb5022282-x64_fdb2ea85e921869f0abe1750ac7cee34876a760c.msu"

  
}


function Get-WinREVersion{
    try{
        return (Get-WindowsImage -imagepath ((reagentc /info | findstr "\\?\GLOBALROOT\device").replace("Windows RE location: ", "").TRIM() + "\winre.wim") -index 1).SPBuild
    }catch{
        return $null
    }
}
function Get-WinREPath{
    try{
        return (reagentc /info | findstr '\\?\GLOBALROOT\device').replace('Windows RE location: ', '').trim()
    }catch{
        return $null
    }
    
}
function Get-OSBuild{
    try{
        return [System.Environment]::OSVersion.Version.Build
    }catch{
        return $null
    }
}
function Get-WinReMsu{
    param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Url
    )
    try{
        Invoke-WebRequest -Uri $MSUPatch -OutFile "C:\Windows\Temp\WinREFix.msu"
    }catch{
        return $false
    }
    return Test-Path -Path "C:\Windows\Temp\WinREFix.msu"

}
function Clear-Files{
    param(
    [Parameter(Mandatory=$true, Position=0)]
    [string[]]$filePath
    )

    foreach($f in $filePath){
        Remove-Item -Path $f -Force
        if([System.IO.File]::Exists($f)){
            $log += "Failed to cleanup $f"
        }else{
            $log += "$f cleaned up"
        }
    }
    Update-TeamMessage -Message $log
}



function Update-WinRE{
    $hostname = [System.Environment]::MachineName

    $winREPath = Get-WinREPath
    if([string]::IsNullOrEmpty($winREPath)){$log = "$hostname WinRE Location Not Found"; Update-TeamMessage -Message $log; return;}

    $winREVersion = Get-WinREVersion
    if($winREVersion -ge "1105"){$log = "$hostname does not require patching<br/> current build: $winREVersion"; Update-TeamMessage -Message $log; return;}


    $osBuild = Get-OSBuild
    if([string]::IsNullOrEmpty($osBuild)){$log = "$hostname OS build not found"; Update-TeamMessage -Message $log; return;}

    $MSUPatch = $Builds.Get_Item($osBuild)
    
    if([string]::IsNullOrEmpty($MSUPatch)){$log = "$hostnameUnable to retrieve windows update KB"; Update-TeamMessage -Message $log; return; }
    
    if(!(Get-WinReMsu -Url $MSUPatch)){$log = "$hostname Failed to download MSU from $MSUPatch"; Update-TeamMessage -Message $log; return;}
    
    
    if(!([System.IO.File]::Exists("C:\Windows\System32\ReAgentC.exe"))){$log = "$hostname ReAgentC.exe not found"; Update-TeamMessage -Message $log; return;}
    
    $mountPath = "C:\mount"
    New-Item -ItemType Directory -Path $mountPath -Force
    if(!(Test-Path -Path $mountPath)){$log = "$hostname Failed to create directory at $mountPath"; Update-TeamMessage -Message $log; return;}
    
    $reAgentMountStatus = & ReAgentC.exe /mountre /path $mountPath 2>&1

    if(!($reAgentMountStatus[0] -match "Operation Successful")){
        $log = $reAgentMountStatus
        Update-TeamMessage -Message $log
        Clear-Files -filePath $mountPath,$winREPath
        return
    }

    try{
        #ReAgentC.exe /mountre /path $mountPath
        Dism /Add-Package /Image:$mountPath /PackagePath:$winREMsuPath
        dism /image:$mountPath /cleanup-image /StartComponentCleanup /ResetBase
        ReAgentC.exe /unmountre /path $mountPath /commit
        
    }catch{
        $log = "Failed to patch winRE on $hostname" 
        Update-TeamMessage -Message $log
    }

    Clear-Files -filePath $mountPath,$winREPath

    $winREVersion = Get-WinREVersion
    if($winREVersion -ge "1105"){
        $log = "$hostname was patched<br/> current build: $winREVersion"
    }else{
        $log = "$hostname was not patched<br/> current build: $winREVersion"
    }
    Update-TeamMessage -Message $log
    
}
  


Update-WinRE



    
    
   
    
   <# if(!($reAgentMountState.ToLower() -match "operation successful")){ 
        
        $log = "Failed ReAgentC mount process";
        Update-TeamMessage -Message $log;
        
        if($reAgentMountState.ToLower() -contains "c1420127"){
            
            if($Retry -le 0){
            
             $Retry++
             Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\WIMMount\Mounted Images" -Force -ErrorAction SilentlyContinue
             Update-WinRE
            }

        Clear-Files -filePath $mountPath,$winREPath
        $log = "Failed to patch winRE due to error c1420127d"
        Update-TeamMessage -Message $log
        return;
    }
}#>
    
