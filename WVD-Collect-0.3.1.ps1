# =====================================================
#
# DISCLAIMER:
#
# THE SCRIPT IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
#
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SCRIPT OR THE USE OR OTHER DEALINGS IN THE SCRIPT.
#
# =====================================================
# 
# IMPORTANT NOTICE: 
# 
# This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows Virtual Desktop.
# 
# The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names and user names.
# 
# Once data collection has been completed, the script will save the data in a subfolder and also compress the results into a ZIP file. The folder or ZIP file are not automatically sent to Microsoft. 
# 
# You can send the ZIP file to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.
# 
# Find our privacy statement here: https://privacy.microsoft.com/en-us/privacy 
# 
# =====================================================


param (
    [switch]$Profile = $false,
    [switch]$ClientAutoTrace = $false,
    [switch]$Certificate = $false,
    [switch]$MSRA = $false,    
    [switch]$Debug = $false
)

$version = "WVD-Collect (0.3.1-200502)"
# by Robert Klemencz @ Microsoft Customer Service and Support



# Functions

Function Write-Log {
  param( [string] $msg)
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg -ForegroundColor cyan
  $msg | Out-File -FilePath $outfile -Append
}


Function Write-LogDetails {
    param( [string] $msg)
    if ($debug) {$status = 1}
    else {$status = 0}

if ($status -eq 1) {  
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg -ForegroundColor DarkGray
  $msg | Out-File -FilePath $outfile -Append
  }
}


Function Write-LogError {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " [INFO] " + $msg
  $msg | Out-File -FilePath $outfile -Append
}


Function Write-LogNotes {
  param( [string] $msg)
  Write-Host $msg -ForegroundColor White
  $msg | Out-File -FilePath $outfile -Append
}


Function ExecQuery {
  param(
    [string] $NameSpace,
    [string] $Query
  )
  # Write-Log ("Executing query " + $Query)
  if ($PSVersionTable.psversion.ToString() -ge "3.0") {
    $ret = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  } else {
    $ret = Get-WmiObject -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  }
  # Write-Log (($ret | measure).count.ToString() + " results")
  return $ret
}


Function ArchiveLog {
  param( [string] $LogName )
  $cmd = "wevtutil al """+ $resFile + "EventLogs\" + $env:computername + "_evt_" + $LogName + ".evtx"" /l:en-us >>""" + $outfile + """ 2>>""" + $errfile + """"
  Write-LogDetails $cmd
  Invoke-Expression $cmd
}


Add-Type -MemberDefinition @"
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint NetApiBufferFree(IntPtr Buffer);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetGetJoinInformation(
  string server,
  out IntPtr NameBuffer,
  out int BufferType);
"@ -Namespace Win32Api -Name NetApi32


Function GetNBDomainName {
  $pNameBuffer = [IntPtr]::Zero
  $joinStatus = 0
  $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
    $null,               # lpServer
    [Ref] $pNameBuffer,  # lpNameBuffer
    [Ref] $joinStatus    # BufferType
  )
  if ( $apiResult -eq 0 ) {
    [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
    [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
  }
}


Function GetStore($store) {
  $certlist = Get-ChildItem ("Cert:\LocalMachine\" + $store)

  foreach ($cert in $certlist) {
    $EKU = ""
    foreach ($item in $cert.EnhancedKeyUsageList) {
      if ($item.FriendlyName) {
        $EKU += $item.FriendlyName + " / "
      } else {
        $EKU += $item.ObjectId + " / "
      }
    }

    $row = $tbcert.NewRow()

    foreach ($ext in $cert.Extensions) {
      if ($ext.oid.value -eq "2.5.29.14") {
        $row.SubjectKeyIdentifier = $ext.SubjectKeyIdentifier.ToLower()
      }
      if (($ext.oid.value -eq "2.5.29.35") -or ($ext.oid.value -eq "2.5.29.1")) { 
        $asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
        $aki = $asn.Format($true).ToString().Replace(" ","")
        $aki = (($aki -split '\n')[0]).Replace("KeyID=","").Trim()
        $row.AuthorityKeyIdentifier = $aki
      }
    }
    if ($EKU) {$EKU = $eku.Substring(0, $eku.Length-3)} 
    $row.Store = $store
    $row.Thumbprint = $cert.Thumbprint.ToLower()
    $row.Subject = $cert.Subject
    $row.Issuer = $cert.Issuer
    $row.NotAfter = $cert.NotAfter
    $row.EnhancedKeyUsage = $EKU
    $row.SerialNumber = $cert.SerialNumber.ToLower()
    $tbcert.Rows.Add($row)
  } 
}


Function FileVersion {
  param(
    [string] $FilePath,
    [bool] $Log = $false
  )
  if (Test-Path -Path $FilePath) {
    $fileobj = Get-item $FilePath
    $filever = $fileobj.VersionInfo.FileMajorPart.ToString() + "." + $fileobj.VersionInfo.FileMinorPart.ToString() + "." + $fileobj.VersionInfo.FileBuildPart.ToString() + "." + $fileobj.VersionInfo.FilePrivatepart.ToString()

    if ($log) {
      ($FilePath + "," + $filever + "," + $fileobj.CreationTime.ToString("yyyyMMdd HH:mm:ss")) | Out-File -FilePath ($resFile + "ver_KeyFileVersions.csv") -Append
    }
    return $filever | Out-Null
  } else {
    return ""
  }
}



# =============================================================================

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path

$resName = "WVD-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName
$resFile = $resDir + "\" + $env:computername +"_"

$outfile = $resFile + "WVD-Collect-Output.txt"
$errfile = $resFile + "WVD-Collect-Errors.txt"
$RdrOut =  " >>""" + $outfile + """"
$RdrErr =  " 2>>""" + $errfile + """"
$fqdn = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

$OSVer = ([environment]::OSVersion.Version.Major) + ([environment]::OSVersion.Version.Minor) /10

New-Item -itemtype directory -path $resDir | Out-Null

Write-Log $version



##### Disclaimer

Write-LogNotes "
=====================================================

DISCLAIMER:

THE SCRIPT IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SCRIPT OR THE USE OR OTHER DEALINGS IN THE SCRIPT.

=====================================================

IMPORTANT NOTICE: 

This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows Virtual Desktop.

The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names and user names.

Once data collection has been completed, the script will save the data in a subfolder and also compress the results into a ZIP file. The folder or ZIP file are not automatically sent to Microsoft. 

You can send the ZIP file to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.

Find our privacy statement here: https://privacy.microsoft.com/en-us/privacy

=====================================================
"

$confirm = Read-Host ("Do you agree to continue? [Y/N]")
if ($confirm.ToLower() -ne "y") {exit}
Write-host



##### Collecting PowerShell version

    Write-Log "Collecting PowerShell version"
    $PSVersionTable | Out-File -FilePath ($resfile + "PSVersion.txt") -Append



##### Collecting files

        Write-Log "Collecting log files"
        New-Item -Path ($resFile + 'LogFiles\') -ItemType Directory | Out-Null
                     
        # Collecting DSC Logs

            if (Test-path -path 'c:\packages\plugins\microsoft.powershell.dsc') {

                $verfolder = get-ChildItem c:\packages\plugins\microsoft.powershell.dsc -recurse | foreach {If ($_.psiscontainer) {$_.fullname}} | select -first 1  
                $filepath = $verfolder + "\Status\"

                if (Test-path -path $filepath) {
                  Copy-Item $filepath ($resFile + "LogFiles\Microsoft.PowerShell.DSC\") -Recurse -ErrorAction Continue 2>>$errfile
                  Write-LogDetails "Copy-Item $filepath ($resFile + ""LogFiles\Microsoft.PowerShell.DSC\"") -ErrorAction Continue 2>>$errfile"
                } else {
                  Write-LogError "The DSC Provisioning log is not present"
                }

            } else {
              Write-LogError "The 'c:\packages\plugins\microsoft.powershell.dsc' folder is not present"
            }


        # Collecting Monitoring Agent Log

            if (Test-path -path 'C:\Packages\Plugins\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent') {

                $verfolder = get-ChildItem C:\Packages\Plugins\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent -recurse | foreach {If ($_.psiscontainer) {$_.fullname}} | select -first 1  
                $filepath = $verfolder + "\Status\"

                if (Test-path -path $filepath) {
                  Copy-Item $filepath ($resFile + "LogFiles\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent\") -Recurse -ErrorAction Continue 2>>$errfile
                  Write-LogDetails "Copy-Item $filepath ($resFile + ""LogFiles\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent\"") -ErrorAction Continue 2>>$errfile"
                } else {
                  Write-LogError "The Monitoring Agent log is not present"
                }

            } else {
              Write-LogError "The 'C:\Packages\Plugins\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent' folder is not present"
            }

            
        # Collecting Azure VM Agent Log

            if (Test-path -path 'C:\WindowsAzure\Logs\WaAppAgent.log') {  
              Copy-Item 'C:\WindowsAzure\Logs\WaAppAgent.log' ($resFile + "LogFiles\" + $env:computername + "_log_WaAppAgent.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\WindowsAzure\Logs\WaAppAgent.log' ($resFile + ""LogFiles\"" + $env:computername + ""_log_WaAppAgent.txt"") -ErrorAction Continue 2>>$errfile"              
            } else {
              Write-LogError "The Azure VM Agent log is not present"
            }
            
            
        # Collecting Domain Join Logs

            if (Test-path -path 'c:\packages\plugins\Microsoft.Compute.JsonADDomainExtension') {

                $verfolder = get-ChildItem c:\packages\plugins\Microsoft.Compute.JsonADDomainExtension -recurse | foreach {If ($_.psiscontainer) {$_.fullname}} | select -first 1  
                $filepath = $verfolder + "\Status\"

                if (Test-path -path $filepath) {
                  Copy-Item $filepath ($resFile + "LogFiles\Microsoft.Compute.JsonADDomainExtension\") -Recurse -ErrorAction Continue 2>>$errfile
                  Write-LogDetails "Copy-Item $filepath ($resFile + ""LogFiles\Microsoft.Compute.JsonADDomainExtension\"") -ErrorAction Continue 2>>$errfile"
                } else {
                  Write-LogError "The Domain Join log is not present"
                }

            } else {
              Write-LogError "The 'c:\packages\plugins\Microsoft.Compute.JsonADDomainExtension' folder is not present"
            }
                              

            if (Test-path -path 'C:\Windows\debug\NetSetup.LOG') {
              Copy-Item 'C:\Windows\debug\NetSetup.LOG' ($resFile + "LogFiles\" + $env:computername + "_log_NetSetup.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\Windows\debug\NetSetup.LOG' ($resFile + ""LogFiles\"" + $env:computername + ""_log_NetSetup.txt"") -ErrorAction Continue 2>>$errfile"
            } else {
              Write-LogError "The NetSetup file is not present"
            }
            

        # Collecting Windows Azure Plugin Logs
        
            if (Test-path -path 'C:\WindowsAzure\Logs\Plugins') {
              Copy-Item 'C:\WindowsAzure\Logs\Plugins\*' ($resFile + "LogFiles\") -Recurse -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\WindowsAzure\Logs\Plugins\*' ($resFile + ""LogFiles\"") -Recurse -ErrorAction Continue 2>>$errfile"
            } else {
              Write-LogError "The Windows Azure Plugins logs are not present"
            }

                
        # Collecting RDInfra Agent Log

            if (Test-path -path 'C:\Program Files\Microsoft RDInfra\AgentInstall.txt') {  
              Copy-Item 'C:\Program Files\Microsoft RDInfra\AgentInstall.txt' ($resFile + "LogFiles\" + $env:computername + "_log_AgentInstall.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\Program Files\Microsoft RDInfra\AgentInstall.txt' ($resFile + ""LogFiles\"" + $env:computername + ""_log_AgentInstall.txt"") -ErrorAction Continue 2>>$errfile"              
            } else {
              Write-LogError "The RDInfra Agent log is not present"
            }


        # Collecting RDInfra Geneva Log

            if (Test-path -path 'C:\Program Files\Microsoft RDInfra\GenevaInstall.txt') {
              Copy-Item 'C:\Program Files\Microsoft RDInfra\GenevaInstall.txt' ($resFile + "LogFiles\" + $env:computername + "_log_GenevaInstall.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\Program Files\Microsoft RDInfra\GenevaInstall.txt' ($resFile + ""LogFiles\"" + $env:computername + ""_log_GenevaInstall.txt"") -ErrorAction Continue 2>>$errfile"
            } else {
              Write-LogError "The RDInfra Geneva Agent log is not present"
            }


        # Collecting RDInfra SXS Log

            if (Test-path -path 'C:\Program Files\Microsoft RDInfra\SXSStackInstall.txt') {
              Copy-Item 'C:\Program Files\Microsoft RDInfra\SXSStackInstall.txt' ($resFile + "LogFiles\" + $env:computername + "_log_SXSStackInstall.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\Program Files\Microsoft RDInfra\SXSStackInstall.txt' ($resFile + ""LogFiles\"" + $env:computername + ""_log_SXSStackInstall.txt"") -ErrorAction Continue 2>>$errfile"
            } else {
              Write-LogError "The RDInfra SXSStack log is not present"
            }


        # Collecting Scriptlog

            if (Test-path -path 'C:\Windows\Temp\ScriptLog.log') {
              Copy-Item 'C:\Windows\Temp\ScriptLog.log' ($resFile + "LogFiles\" + $env:computername + "_log_ScriptLog.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\Windows\Temp\ScriptLog.log' ($resFile + ""LogFiles\"" + $env:computername + ""_log_ScriptLog.txt"") -ErrorAction Continue 2>>$errfile"
            } else {
              Write-LogError "The ScriptLog file is not present"
            }

                    
        # Collecting FSLogix Logs

            if ($Profile) {
                if (Test-path -path 'C:\ProgramData\FSLogix\Logs') {
                  Copy-Item 'C:\ProgramData\FSLogix\Logs\' ($resFile + "LogFiles\FSLogix\") -Recurse -ErrorAction Continue 2>>$errfile
                  Write-LogDetails "Copy-Item 'C:\ProgramData\FSLogix\Logs\' ($resFile + ""LogFiles\FSLogix\"") -Recurse -ErrorAction Continue 2>>$errfile"
                } else {
                  Write-LogError "The FSLogix logs are not present"
                }
            }



##### Collecting DSC configuration information

    Write-Log "Collecting DSC configuration information"

    Write-LogDetails "Get-DscConfiguration output"
    Get-DscConfiguration 2>>$errfile | Out-File -FilePath ($resFile + "Get-DscConfiguration.txt")

    Write-LogDetails "Get-DscConfigurationStatus output"
    Get-DscConfigurationStatus -all 2>>$errfile | Out-File -FilePath ($resFile + "Get-DscConfigurationStatus.txt")



##### Collecting Geneva scheduled task information

        Write-Log "Collecting Geneva scheduled task information"

        if (Get-ScheduledTask GenevaTask -ErrorAction Ignore) { 
            $cmd = "Export-ScheduledTask -TaskName GenevaTask >>""" + $resFile + "schtasks_GenevaTask.xml""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd

            $cmd = "Get-ScheduledTaskInfo -TaskName GenevaTask >>""" + $resFile + "schtasks_GenevaTaskInfo.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd

        } else { 
            Write-LogError "The Geneva Scheduled Task is not present"
        }



##### Collecting RDP and networking information

        Write-Log "Collecting RDP and networking information"


        # Get-NetConnectionProfile output

            Get-NetConnectionProfile | Out-File -FilePath ($resFile + "NetConnectionProfile.txt") -Append
            Write-LogDetails "Get-NetConnectionProfile | Out-File -FilePath ($resFile + ""NetConnectionProfile.txt"") -Append"


        # Collecting firewall rules

            $cmd = "netsh advfirewall firewall show rule name=all >""" + $resFile + "FirewallRules.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting netstat output

            $cmd = "netstat -anob >""" + $resFile + "Netstat.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting ipconfig /all output

            $cmd = "ipconfig /all >""" + $resFile + "Ipconfig.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting proxy settings

            $cmd = "netsh winhttp show proxy >""" + $resFile + "WinHTTP-Proxy.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


            "------------------" | Out-File -FilePath ($resFile + "WinHTTP-Proxy.txt") -Append
            "NSLookup WPAD" | Out-File -FilePath ($resFile + "WinHTTP-Proxy.txt") -Append
            "" | Out-File -FilePath ($resFile + "WinHTTP-Proxy.txt") -Append
            $cmd = "nslookup wpad >>""" + $resFile + "WinHTTP-Proxy.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting qwinsta information

            $cmd = "qwinsta /counter >>""" + $resFile + "Qwinsta.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd



##### Collecting policy information

        Write-Log "Collecting group policy information (gpresult)"

        $cmd = "gpresult /h """ + $resFile + "Gpresult.html""" + $RdrErr
        write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        $cmd = "gpresult /r /v >""" + $resFile + "Gpresult.txt""" + $RdrErr
        write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


##### Collecting group memberships

        Write-Log "Collecting group membership information"


        # Exporting members of Remote Desktop Users group

            if ([ADSI]::Exists("WinNT://localhost/Remote Desktop Users")) {
                $cmd = "net localgroup ""Remote Desktop Users"" >>""" + $resFile + "LocalGroupsMembership.txt""" + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
            } else {
                Write-LogError "The 'Remote Desktop Users' group is not present"
            }
                       
                                      
        # Exporting members of Offer Remote Assistance Helpers group

            if ($MSRA) {
                if ([ADSI]::Exists("WinNT://localhost/Offer Remote Assistance Helpers")) {
                    $cmd = "net localgroup ""Offer Remote Assistance Helpers"" >>""" + $resFile + "LocalGroupsMembership.txt""" + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
                } else {
                    Write-LogError "The 'Offer Remote Assistance Helpers' group is not present"
                }

                if ([ADSI]::Exists("WinNT://localhost/Distributed COM Users")) {
                    $cmd = "net localgroup ""Distributed COM Users"" >>""" + $resFile + "LocalGroupsMembership.txt""" + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
                } else {
                    Write-LogError "The 'Distributed COM Users' group is not present"
                }
            }



##### Collecting registry keys

        Write-Log "Collecting registry key information"
        New-Item -Path ($resFile + 'RegistryKeys\') -ItemType Directory | Out-Null


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent

            if (Test-Path HKLM:\SOFTWARE\Microsoft\RDInfraAgent) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent """ + $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-RDInfraAgent.txt"" /y " + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDAgentBootLoader

            if (Test-Path HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDAgentBootLoader """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-RDAgentBootLoader.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDAgentBootLoader is not present"
            }

        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMonitoringAgent

            if (Test-Path HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMonitoringAgent """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-RDMonitoringAgent.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMonitoringAgent is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server

            if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server') {        
            $cmd = "reg export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Control-TerminalServer.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' is not present"
            }

        
        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server

            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server') {        
            $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-WinNT-CV-TerminalServer.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client

            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client') {        
            $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-TerminalServerClient.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client' is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies

            if (Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-Win-CV-Policies.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders

            if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Control-SecurityProviders.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography

            if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Control-Cryptography.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography

            if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-Policies-MS-Cryptography.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa

            if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Control-LSA.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation

            if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation) {          
              $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-Policies-MS-Win-CredentialsDelegation.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services

            if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-Policies-MS-WinNT-TerminalServices.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' is not present"
            }
        

        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC

            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Azure\DSC') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-Azure-DSC.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC' is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix

            if ($Profile) {
                if (Test-Path HKLM:\SOFTWARE\FSLogix) {          
                  $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-FSLogix.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix is not present"
                }
        

        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\FSLogix

                if (Test-Path HKLM:\SOFTWARE\FSLogix) {          
                  $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\FSLogix """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-Policies-FSLogix.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\FSLogix is not present"
                }
            }


        # Collecting registry key HKEY_CURRENT_USER\SOFTWARE\Microsoft\RdClientRadc

           if (Test-Path HKCU:\SOFTWARE\Microsoft\RdClientRadc) {          
              $cmd = "reg export HKEY_CURRENT_USER\SOFTWARE\Microsoft\RdClientRadc """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-RdClientRadc.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_CURRENT_USER\SOFTWARE\Microsoft\RdClientRadc is not present"
            } 


       # Collecting registry key HKEY_CURRENT_USER\SOFTWARE\Microsoft\Remote Desktop

           if (Test-Path 'HKCU:\SOFTWARE\Microsoft\Remote Desktop') {          
              $cmd = "reg export 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Remote Desktop' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-RemoteDesktop.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Remote Desktop' is not present"
            }
       

       # Collecting registry key HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office

           if ($Profile) {
               if (Test-Path HKCU:\Software\Microsoft\Office) {          
                  $cmd = "reg export 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_FSLogix-SW-MS-Office.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office' is not present"
                }


       # Collecting registry key HKEY_CURRENT_USER\Software\Policies\Microsoft\office

               if (Test-Path HKCU:\Software\Policies\Microsoft\office) {          
                  $cmd = "reg export 'HKEY_CURRENT_USER\Software\Policies\Microsoft\office' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_FSLogix-SW-Policies-Office.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office' is not present"
                }
                
       # Collecting registry key HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive

               if (Test-Path HKCU:\SOFTWARE\Microsoft\OneDrive) {          
                  $cmd = "reg export 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_FSLogix-SW-MS-OneDrive.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive' is not present"
                }
       

       # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search

               if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Search') {          
                  $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_FSLogix-SW-MS-WindowsSearch.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search' is not present"
                }
 
      
       # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList

               if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') {          
                  $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-WinNT-CV-ProfileList.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' is not present"
                }
            }
        

##### Collecting event logs

        Write-Log "Collecting event log information"
        New-Item -Path ($resFile + 'EventLogs\') -ItemType Directory | Out-Null


        # Collecting System event log

            $cmd = "wevtutil epl System """+ $resFile + "EventLogs\" + $env:computername + "_evt_System.evtx""" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            ArchiveLog "System"
                

        # Collecting Application event log

            $cmd = "wevtutil epl Application """+ $resFile + "EventLogs\" + $env:computername + "_evt_Application.evtx""" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            ArchiveLog "Application"


        # Collecting Security event log

            $cmd = "wevtutil epl Security """+ $resFile + "EventLogs\" + $env:computername + "_evt_Security.evtx""" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            ArchiveLog "Security"
            

        # Collecting WindowsAzure Diagnostics and Status event logs
        
            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Diagnostics/Bootstrapper -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Diagnostics/Bootstrapper """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Diag-Bootstrapper.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Diag-Bootstrapper"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Diagnostics/Bootstrapper' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Diagnostics/GuestAgent -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Diagnostics/GuestAgent """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Diag-GuestAgent.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Diag-GuestAgent"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Diagnostics/GuestAgent' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Diagnostics/Heartbeat -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Diagnostics/Heartbeat """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Diag-Heartbeat.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Diag-Heartbeat"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Diagnostics/Heartbeat' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Diagnostics/Runtime -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Diagnostics/Runtime """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Diag-Runtime.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Diag-Runtime"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Diagnostics/Runtime' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Status/GuestAgent -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Status/GuestAgent """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Status-GuestAgent.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Status-GuestAgent"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Status/GuestAgent' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Status/Plugins -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Status/Plugins """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Status-Plugins.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Status-Plugins"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Status/Plugins' is not present"
            }


        # Collecting CAPI2 event log

            if ($Certificate) {
                if (Get-WinEvent -ListLog Microsoft-Windows-CAPI2/Operational -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl Microsoft-Windows-CAPI2/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_CAPI2.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "capi2"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-CAPI2/Operational' is not present"
                }
            }


        # Collecting DSC event log

            if (Get-WinEvent -ListLog Microsoft-Windows-DSC/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-DSC/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_DSC-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "DSC-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-DSC/Operational' is not present"
            }


        # Collecting WinRM event log

            if (Get-WinEvent -ListLog Microsoft-Windows-WinRM/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-WinRM/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_WinRM-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WinRM-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-WinRM/Operational' is not present"
            }


        # Collecting PowerShell event log

            if (Get-WinEvent -ListLog Microsoft-Windows-PowerShell/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-PowerShell/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_PowerShell-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "PowerShell-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-PowerShell/Operational' is not present"
            }
            

        # Collecting Remote Desktop Services RdpCoreTS event logs
            
            if (Get-WinEvent -ListLog Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_RemoteDesktopServicesRdpCoreTS-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "RemoteDesktopServicesRdpCoreTS-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin """+ $resFile + "EventLogs\" + $env:computername + "_evt_RemoteDesktopServicesRdpCoreTS-Admin.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "RemoteDesktopServicesRdpCoreTS-Admin"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin' is not present"
            }


        # Collecting Remote Desktop Services RdpCoreCDV event log

            if (Get-WinEvent -ListLog Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_RemoteDesktopServicesRdpCoreCDV-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "RemoteDesktopServicesRdpCoreCDV-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational' is not present"
            }


        # Collecting Terminal Services LocalSessionManager event logs

            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-LocalSessionManager/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesLocalSessionManager-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesLocalSessionManager-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-LocalSessionManager/Admin -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Admin """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesLocalSessionManager-Admin.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesLocalSessionManager-Admin"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Admin' is not present"
            }


        # Collecting Terminal Services RemoteConnectionManager event logs

            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesRemoteConnectionManager-Admin.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesRemoteConnectionManager-Admin"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin' is not present"
            }
            
            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesRemoteConnectionManager-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesRemoteConnectionManager-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' is not present"
            }


        # Collecting Terminal Services PnP Devices event logs

            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-PnPDevices/Admin -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-PnPDevices/Admin """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesPnPDevices-Admin.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesPnPDevices-Admin"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-PnPDevices/Admin' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-PnPDevices/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-PnPDevices/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesPnPDevices-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesPnPDevices-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-PnPDevices/Operational' is not present"
            }


        # Collecting User Profile Service event log

            if ($Profile) {
                if (Get-WinEvent -ListLog 'Microsoft-Windows-User Profile Service/Operational' -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-User Profile Service/Operational' """+ $resFile + "EventLogs\" + $env:computername + "_evt_UserProfileService-Operational.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "UserProfileService-Operational"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-User Profile Service/Operational' is not present"
                }
            }

        # Collecting Remote Assistance event logs

            if ($MSRA) {
                if (Get-WinEvent -ListLog Microsoft-Windows-RemoteAssistance/Operational -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-RemoteAssistance/Operational' """+ $resFile + "EventLogs\" + $env:computername + "_evt_RemoteAssistance-Operational.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "RemoteAssistance-Operational"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-RemoteAssistance/Operational' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-RemoteAssistance/Admin -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-RemoteAssistance/Admin' """+ $resFile + "EventLogs\" + $env:computername + "_evt_RemoteAssistance-Admin.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "RemoteAssistance-Admin"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-RemoteAssistance/Admin' is not present"
                }
            }


        # Collecting VHDMP event logs

            if ($Profile) {
                if (Get-WinEvent -ListLog Microsoft-Windows-VHDMP-Operational -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-VHDMP-Operational' """+ $resFile + "EventLogs\" + $env:computername + "_evt_VHDMP-Operational.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "VHDMP-Operational"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-VHDMP-Operational' is not present"
                }


        # Collecting SMBclient and SMBserver event logs

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBClient/Operational -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBClient/Operational' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBClient-Operational.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBClient-Operational"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBClient/Operational' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBClient/Connectivity -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBClient/Connectivity' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBClient-Connectivity.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBClient-Connectivity"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBClient/Connectivity' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBClient/Security -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBClient/Security' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBClient-Security.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBClient-Security"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBClient/Security' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBServer/Operational -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBServer/Operational' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBServer-Operational.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBServer-Operational"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBServer/Operational' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBServer/Connectivity -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBServer/Connectivity' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBServer-Connectivity.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBServer-Connectivity"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBServer/Connectivity' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBServer/Security -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBServer/Security' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBServer-Security.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBServer-Security"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBServer/Security' is not present"
                }
            }


##### Collecting certificate information

    if ($Certificate) {
        Write-Log "Collecting certificate information"


        # Collecting certificates details

            $cmd = "Certutil -verifystore -v MY > """ + $resFile + "Certificates-My.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd

            $tbCert = New-Object system.Data.DataTable
            $col = New-Object system.Data.DataColumn Store,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn Thumbprint,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn Subject,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn Issuer,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn NotAfter,([DateTime]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn IssuerThumbprint,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn EnhancedKeyUsage,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn SerialNumber,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn SubjectKeyIdentifier,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn AuthorityKeyIdentifier,([string]); $tbCert.Columns.Add($col)
        
            GetStore "My"


        # Matching issuer thumbprints

            $aCert = $tbCert.Select("Store = 'My' ")
            foreach ($cert in $aCert) {
              $aIssuer = $tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
              if ($aIssuer.Count -gt 0) {
                $cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
              }
            }
            $tbcert | Export-Csv ($resFile + "Certificates.tsv") -noType -Delimiter "`t"
    }



##### Collecting installed Windows updates

        Write-Log "Collecting list of installed Windows updates"
        Get-HotFix -ErrorAction SilentlyContinue 2>>$errfile | Sort-Object -Property InstalledOn -ErrorAction SilentlyContinue | Out-File ($resFile + "Hotfixes.txt")
        Write-LogDetails "Get-HotFix -ErrorAction SilentlyContinue 2>>$errfile | Sort-Object -Property InstalledOn -ErrorAction SilentlyContinue | Out-File ($resFile + ""Hotfixes.txt"")"
        


##### Collecting file versions and system information
        
        Write-Log "Collecting details about currently running processes"
        $proc = ExecQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath from Win32_Process"
        if ($PSVersionTable.psversion.ToString() -ge "3.0") {
          $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
        } else {
          $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
        }

        if ($proc) {
          $proc | Sort-Object Name |
          Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
          @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
          @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
          @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, $StartTime, CommandLine |
          Out-String -Width 500 | Out-File -FilePath ($resFile + "RunningProcesses.txt")


          Write-Log "Collecting file version of running and key system binaries"
          $binlist = $proc | Group-Object -Property ExecutablePath
          foreach ($file in $binlist) {
            if ($file.Name) {
              FileVersion -Filepath ($file.name) -Log $true
            }
          }

          (get-item -Path 'C:\Windows\System32\*.dll').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_System32_DLL.txt")
          (get-item -Path 'C:\Windows\System32\*.exe').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_System32_EXE.txt")
          (get-item -Path 'C:\Windows\System32\*.sys').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_System32_SYS.txt")
          (get-item -Path 'C:\Windows\System32\drivers\*.sys').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_Drivers.txt")
          (get-item -Path 'C:\Windows\SysWOW64\*.dll').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_SysWOW64_DLL.txt")
          (get-item -Path 'C:\Windows\SysWOW64\*.exe').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_SysWOW64_EXE.txt")
        
        
        # Collecting MSRDC binary information (when installed in "per machine" mode)
                
          if (Test-Path 'C:\Program Files\Remote Desktop\msrdc.exe') {
              FileVersion -Filepath ("C:\Program Files\Remote Desktop\msrdc.exe") -Log $true
          } else {
              Write-LogError "The file 'C:\Program Files\Remote Desktop\msrdc.exe' is not present"
          }
        
          if (Test-Path 'C:\Program Files\Remote Desktop\msrdcw.exe') {
              FileVersion -Filepath ("C:\Program Files\Remote Desktop\msrdcw.exe") -Log $true
          } else {
              Write-LogError "The file 'C:\Program Files\Remote Desktop\msrdcw.exe' is not present"
          }
        

        # Collecting MSRDC binary information (when installed in "per user" mode - only from the current user)

        $msrdcpath = 'C:\Users\' + $env:USERNAME + '\AppData\Local\Apps\Remote Desktop\msrdc.exe'
        $msrdcwpath = 'C:\Users\' + $env:USERNAME + '\AppData\Local\Apps\Remote Desktop\msrdcw.exe'

          if (Test-Path $msrdcpath) {
              FileVersion -Filepath $msrdcpath -Log $true
          } else {
              Write-LogError "The file '$msrdcpath' is not present"
          }
        
          if (Test-Path $msrdcwpath) {
              FileVersion -Filepath $msrdcwpath -Log $true
          } else {
              Write-LogError "The file '$msrdcwpath' is not present"
          }
        

        # Collecting service details

          Write-Log "Collecting services details"
          $svc = ExecQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"

          if ($svc) {
            $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName | Out-String -Width 400 | Out-File -FilePath ($resFile + "Services.txt")
          }
          

        # Collecting system information

          Write-Log "Collecting system information"

          $pad = 27
          $OS = ExecQuery -Namespace "root\cimv2" -Query "select Caption, CSName, OSArchitecture, BuildNumber, InstallDate, LastBootUpTime, LocalDateTime, TotalVisibleMemorySize, FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles from Win32_OperatingSystem"
          $CS = ExecQuery -Namespace "root\cimv2" -Query "select Model, Manufacturer, SystemType, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, DNSHostName, Domain, DomainRole from Win32_ComputerSystem"
          $BIOS = ExecQuery -Namespace "root\cimv2" -query "select BIOSVersion, Manufacturer, ReleaseDate, SMBIOSBIOSVersion from Win32_BIOS"
          $TZ = ExecQuery -Namespace "root\cimv2" -Query "select Description from Win32_TimeZone"
          $PR = ExecQuery -Namespace "root\cimv2" -Query "select Name, Caption from Win32_Processor"

          $ctr = Get-Counter -Counter "\Memory\Pool Paged Bytes" -ErrorAction Continue 2>>$errfile
          $PoolPaged = $ctr.CounterSamples[0].CookedValue 
          $ctr = Get-Counter -Counter "\Memory\Pool Nonpaged Bytes" -ErrorAction Continue 2>>$errfile
          $PoolNonPaged = $ctr.CounterSamples[0].CookedValue 

          "Computer name".PadRight($pad) + " : " + $OS.CSName | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Model".PadRight($pad) + " : " + $CS.Model | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Manufacturer".PadRight($pad) + " : " + $CS.Manufacturer | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "BIOS Version".PadRight($pad) + " : " + $BIOS.BIOSVersion | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "BIOS Manufacturer".PadRight($pad) + " : " + $BIOS.Manufacturer | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "BIOS Release date".PadRight($pad) + " : " + $BIOS.ReleaseDate | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "SMBIOS Version".PadRight($pad) + " : " + $BIOS.SMBIOSBIOSVersion | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "SystemType".PadRight($pad) + " : " + $CS.SystemType | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Processor".PadRight($pad) + " : " + $PR.Name + " / " + $PR.Caption | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Processors physical/logical".PadRight($pad) + " : " + $CS.NumberOfProcessors + " / " + $CS.NumberOfLogicalProcessors | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Memory physical/visible".PadRight($pad) + " : " + ("{0:N0}" -f ($CS.TotalPhysicalMemory/1mb)) + " MB / " + ("{0:N0}" -f ($OS.TotalVisibleMemorySize/1kb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Pool Paged / NonPaged".PadRight($pad) + " : " + ("{0:N0}" -f ($PoolPaged/1mb)) + " MB / " + ("{0:N0}" -f ($PoolNonPaged/1mb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
                              
            [string]$WinVerMajor = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMajorVersionNumber).CurrentMajorVersionNumber
            [string]$WiNVerMinor = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMinorVersionNumber).CurrentMinorVersionNumber
            [string]$WinVerBuild = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentBuild).CurrentBuild
            [string]$WinVerRevision = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' UBR).UBR
            $WinVer = "Build Number".PadRight($pad) + " : " + $WinVerMajor + "." + $WiNVerMinor + "." + $WinVerBuild + "." + $WinVerRevision | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
                      
          "Installation type".PadRight($pad) + " : " + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallationType | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Time zone".PadRight($pad) + " : " + $TZ.Description | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Install date".PadRight($pad) + " : " + $OS.InstallDate | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Local time".PadRight($pad) + " : " + $OS.LocalDateTime | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "DNS Domain name".PadRight($pad) + " : " + $CS.Domain | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "NetBIOS Domain name".PadRight($pad) + " : " + (GetNBDomainName) | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          $roles = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controller", "Primary Domain Controller"
          "Domain role".PadRight($pad) + " : " + $roles[$CS.DomainRole] | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append

          $drives = @()
          $drvtype = "Unknown", "No Root Directory", "Removable Disk", "Local Disk", "Network Drive", "Compact Disc", "RAM Disk"
          $Vol = ExecQuery -NameSpace "root\cimv2" -Query "select * from Win32_LogicalDisk"
          foreach ($disk in $vol) {
            $drv = New-Object PSCustomObject
            $drv | Add-Member -type NoteProperty -name Letter -value $disk.DeviceID 
            $drv | Add-Member -type NoteProperty -name DriveType -value $drvtype[$disk.DriveType]
            $drv | Add-Member -type NoteProperty -name VolumeName -value $disk.VolumeName 
            $drv | Add-Member -type NoteProperty -Name TotalMB -Value ($disk.size)
            $drv | Add-Member -type NoteProperty -Name FreeMB -value ($disk.FreeSpace)
            $drives += $drv
          }
          $drives | 
          Format-Table -AutoSize -property Letter, DriveType, VolumeName, @{N="TotalMB";E={"{0:N0}" -f ($_.TotalMB/1MB)};a="right"}, @{N="FreeMB";E={"{0:N0}" -f ($_.FreeMB/1MB)};a="right"} |
          Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
        } else {
          $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
          $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
          @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
          @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
          @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
          Out-String -Width 300 | Out-File -FilePath ($resFile + "RunningProcesses.txt")
        }


          $cmd = "msinfo32 /nfo """ + $resFile + "msinfo32.nfo""" + $RdrErr
          Write-LogDetails $cmd
          Invoke-Expression $cmd

          while (!(Test-Path ($resFile + "msinfo32.nfo"))) { Start-Sleep 30 }



##### Collecting RDClient AutoTraces

    if ($ClientAutoTrace) {
        
        Write-Log "Collecting RDClient AutoTraces"

        $ETLfolder = 'C:\Users\' + $env:USERNAME + '\AppData\Local\Temp\DiagOutputDir\RdClientAutoTrace\'
        
        if (Test-path -path $ETLfolder) {
                        
            Copy-Item $ETLfolder ($resFile + 'RdClientAutoTrace\') -Recurse -ErrorAction Continue 2>>$errfile            
            Write-LogDetails "Copy-Item $ETLfolder ($resFile + ""RdClientAutoTrace\"") -Recurse -ErrorAction Continue 2>>$errfile"
        } else {
            Write-LogError "The RD Client AutoTrace folder is not present"
        }
}



##### Archive results

        Write-Host
        Write-Log "Data collection complete - archiving files!"

        $destination = $Root + "\" + $resName + ".zip"
        $cmd = "Compress-Archive -Path $resDir -DestinationPath $destination -CompressionLevel Optimal -Force"
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        $amsg = "Location of the collected and archived data: " + $Root + "\"
        Write-Log $amsg
                