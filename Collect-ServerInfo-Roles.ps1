<#
.SYNOPSIS
Collect-ServerInfo.ps1 - PowerShell script to collect information about Windows servers

.DESCRIPTION 
This PowerShell script runs a series of WMI and other queries to collect information
about Windows servers.

.OUTPUTS
Each server's results are output to HTML.

.PARAMETER -Verbose
See more detailed progress as the script is running.

.EXAMPLE
.\Collect-ServerInfo.ps1 SERVER1
Collect information about a single server.

.EXAMPLE
"SERVER1","SERVER2","SERVER3" | .\Collect-ServerInfo.ps1
Collect information about multiple servers.

.EXAMPLE
Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} | %{.\Collect-ServerInfo.ps1 $_.DNSHostName}
Collects information about all servers in Active Directory.


.NOTES
Written by Paul Cunningham
Technical Consultant/Director at LockLAN Systems Pty Ltd - https://www.locklan.com.au
Microsoft MVP, Office Servers and Services - http://exchangeserverpro.com

You can also find me on:

* Twitter: https://twitter.com/paulcunningham
* Twitter: https://twitter.com/ExchServPro
* LinkedIn: http://au.linkedin.com/in/cunninghamp/
* Github: https://github.com/cunninghamp

License:

The MIT License (MIT)

Copyright (c) 2016 Paul Cunningham

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Change Log:
V1.00, 20/04/2015 - First release
V1.01, 01/05/2015 - Updated with better error handling
#>


[CmdletBinding()]

Param (

    [parameter(ValueFromPipeline=$True)]
    [string[]]$ComputerName

)

Begin
{
    #Initialize
    Write-Verbose "Initializing"

}

Process
{

    #---------------------------------------------------------------------
    # Process each ComputerName
    #---------------------------------------------------------------------

    if (!($PSCmdlet.MyInvocation.BoundParameters[“Verbose”].IsPresent))
    {
        Write-Host "Processing $ComputerName"
    }

    Write-Verbose "=====> Processing $ComputerName <====="

    $htmlreport = @()
    $htmlbody = @()
    $htmlfile = "$($ComputerName).html"
    $spacer = "<br />"

    #---------------------------------------------------------------------
    # Do 10 pings and calculate the fastest response time
    # Not using the response time in the report yet so it might be
    # removed later.
    #---------------------------------------------------------------------
    
    try
    {
        $bestping = (Test-Connection -ComputerName $ComputerName -Count 10 -ErrorAction STOP | Sort ResponseTime)[0].ResponseTime
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $bestping = "Unable to connect"
    }

    if ($bestping -eq "Unable to connect")
    {
        if (!($PSCmdlet.MyInvocation.BoundParameters[“Verbose”].IsPresent))
        {
            Write-Host "Unable to connect to $ComputerName"
        }

        "Unable to connect to $ComputerName"
    }
    else
    {

        #---------------------------------------------------------------------
        # Collect computer system information and convert to HTML fragment
        #---------------------------------------------------------------------
    
        Write-Verbose "Collecting computer system information"

        $subhead = "<h3>Computer System Information</h3>"
        $htmlbody += $subhead
    
        try
        {
            $csinfo = Get-WmiObject Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction STOP |
                Select-Object NAME, MANUFACTURER, MODEL,
                            @{Name='PHYSICAL PROCESSORS';Expression={$_.NumberOfProcessors}},
                            @{Name='LOGICAL PROCESSORS';Expression={$_.NumberOfLogicalProcessors}},
                            @{Name='TOTAL PHYSICAL MEMORY (GB)';Expression={$tpm = $_.TotalPhysicalMemory/1GB; "{0:F0}" -f $tpm}},
                            @{Name='FQDN';Expression={$_.DNSHostName}},
                            @{Name='DOMAIN';Expression={$_.Domain}}
       
            $htmlbody += $csinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
       
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }
        
        #---------------------------------------------------------------------
        # Collect computer system information and convert to HTML fragment
        #---------------------------------------------------------------------
    
        Write-Verbose "Collecting computer domain information"

        $subhead = "<h3>Computer Domain Information</h3>"
        $htmlbody += $subhead
    
        try
        {
            $csinfo = Get-WmiObject Win32_NtDomain -ComputerName $ComputerName -ErrorAction STOP |
                Select-Object @{Name="DOMAIN FOREST NAME";Expression={$_.DnsForestName}},
                              @{Name="DOMAIN CONTROLLER NAME";Expression={$_.DomainControllerName}},
                              @{Name="DOMAIN CONTROLLER IP";Expression={$_.DomainControllerAddress}}
           
            $htmlbody += $csinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
       
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }
               
        #---------------------------------------------------------------------
        # Collect network interface information and convert to HTML fragment
        #---------------------------------------------------------------------    

        $subhead = "<h3>Network Interface Information</h3>"
        $htmlbody += $subhead

        Write-Verbose "Collecting network interface information"

        try
        {
            $nics = @()                       
            $nicinfo = @(Get-WmiObject Win32_NetworkAdapter -ComputerName $ComputerName -ErrorAction STOP | Where-Object {$_.MACAddress -like "*:*"} |
                Select-Object 
                @{Name='NAME';Expression={$_.Name}},
                @{Name='ADAPTERTYPE';Expression={$_.AdapterType}},
                @{Name='MACADDRESS';Expression={$_.MACAddress}},
                @{Name='CONNECTIONNAME';Expression={$_.NetConnectionID}},
                @{Name='ENABLED';Expression={$_.NetEnabled}},
                @{Name='SPEED';Expression={$_.Speed/1000000}})            
            
            $nwinfo = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -ErrorAction STOP | Where-Object {$_.IpSubnet -like "255*" } |
                Select-Object DESCRIPTION, DHCPSERVER, MACADDRESS,
                @{Name='IPADDRESS';Expression={$_.IpAddress -join '; '}},  
                @{Name='IPSUBNET';Expression={$_.IpSubnet -join '; '}},  
                @{Name='DEFAULTIPGATEWAY';Expression={$_.DefaultIPgateway -join '; '}},  
                @{Name='DNSSERVERSEARCHORDER';Expression={$_.DNSServerSearchOrder -join '; '}}
            
            foreach ($nic in $nwinfo)
            {
                $nicObject = New-Object PSObject
                $nicObject | Add-Member NoteProperty -Name "DESCRIPTION" -Value $nic.Description
                $nicObject | Add-Member NoteProperty -Name "IP ADDRESS" -Value $nic.IpAddress
                $nicObject | Add-Member NoteProperty -Name "SUBNET" -Value $nic.IpSubnet
                $nicObject | Add-Member NoteProperty -Name "GATEWAY" -Value $nic.DefaultIPgateway
                $nicObject | Add-Member NoteProperty -Name "DNS SERVER" -Value $nic.DNSServerSearchOrder
                $nicObject | Add-Member NoteProperty -Name "DHCP SERVER" -Value $nic.DHCPServer
                $nicObject | Add-Member NoteProperty -Name "MAC ADDRESS" -Value $nic.MACAddress
                $nics += $nicObject
            }

            $htmlbody += $nics | ConvertTo-Html -Fragment
            $htmlbody += $spacer
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }
        
        #---------------------------------------------------------------------
        # Collect operating system information and convert to HTML fragment
        #---------------------------------------------------------------------
    
        Write-Verbose "Collecting operating system information"

        $subhead = "<h3>Operating System Information</h3>"
        $htmlbody += $subhead
    
        try
        {
            $osinfo = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction STOP | 
                Select-Object   @{Name='OPERATING SYSTEM';Expression={$_.Caption}},
                                @{Name='ARCHITECTURE';Expression={$_.OSArchitecture}}, VERSION,
                                @{Name='BUILD NUMBER';Expression={$_.BUILDNUMBER}}, ORGANIZATION,
                                @{Name='LAST BOOT TIME';Expression={$_.ConverttoDateTime($_.lastbootuptime)}},
                                @{Name='INSTALL DATE';Expression={
                                $installdate = [datetime]::ParseExact($_.InstallDate.SubString(0,8),"yyyyMMdd",$null);
                                $installdate.ToShortDateString()}},
                                @{Name='WINDOWS DIRECTORY';Expression={$_.WINDOWSDIRECTORY}}

            $htmlbody += $osinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }        

        #---------------------------------------------------------------------
        # Collect Local Administrators and convert to HTML fragment
        #---------------------------------------------------------------------
    
        Write-Verbose "Collecting Local Administrators"

        $subhead = "<h3>Local Administrators</h3>"
        $htmlbody += $subhead
    
        try
        {
            ###$localgroup = Get-WmiObject -Query "ASSOCIATORS OF {Win32_Group.Domain=$ComputerName,Name='Administrators'} WHERE ResultClass = Win32_UserAccount" | Select Caption
            $localgroup = Get-WmiObject -Query "ASSOCIATORS OF {Win32_Group.Domain='$($env:COMPUTERNAME)',Name='Administrators'} WHERE ResultClass = Win32_UserAccount" | 
                Select  @{Name='NAME';Expression={$_.Name}},
                        @{Name='USER ACCOUNT';Expression={$_.Caption}},
                        @{Name='SID';Expression={$_.SID}}
            $htmlbody += $localgroup | ConvertTo-Html -Fragment
            $htmlbody += $spacer
       
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }

        #---------------------------------------------------------------------
        # Collect physical memory information and convert to HTML fragment
        #---------------------------------------------------------------------

        Write-Verbose "Collecting physical memory information"

        $subhead = "<h3>Physical Memory Information</h3>"
        $htmlbody += $subhead

        try
        {
            $memorybanks = @()
            $physicalmemoryinfo = @(Get-WmiObject Win32_PhysicalMemory -ComputerName $ComputerName -ErrorAction STOP |
                Select-Object DEVICELOCATOR, MANUFACTURER, SPEED, CAPACITY)

            foreach ($bank in $physicalmemoryinfo)
            {
                $memObject = New-Object PSObject
                $memObject | Add-Member NoteProperty -Name "DEVICE LOCATOR" -Value $bank.DeviceLocator
                $memObject | Add-Member NoteProperty -Name "MANUFACTURER" -Value $bank.Manufacturer
                $memObject | Add-Member NoteProperty -Name "SPEED" -Value $bank.Speed
                $memObject | Add-Member NoteProperty -Name "CAPACITY (GB)" -Value ("{0:F0}" -f $bank.Capacity/1GB)

                $memorybanks += $memObject
            }

            $htmlbody += $memorybanks | ConvertTo-Html -Fragment
            $htmlbody += $spacer
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }


        #---------------------------------------------------------------------
        # Collect pagefile information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>PageFile Information</h3>"
        $htmlbody += $subhead

        Write-Verbose "Collecting pagefile information"

        try
        {
            $pagefileinfo = Get-WmiObject Win32_PageFileUsage -ComputerName $ComputerName -ErrorAction STOP |
                Select-Object @{Name='PAGEFILE NAME';Expression={$_.Name}},
                            @{Name='ALLOCATED SIZE (MB)';Expression={$_.AllocatedBaseSize}}

            $htmlbody += $pagefileinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }


        #---------------------------------------------------------------------
        # Collect BIOS information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>BIOS Information</h3>"
        $htmlbody += $subhead

        Write-Verbose "Collecting BIOS information"

        try
        {
            $biosinfo = Get-WmiObject Win32_Bios -ComputerName $ComputerName -ErrorAction STOP |
                Select-Object STATUS, VERSION, MANUFACTURER,
                            @{Name='RELEASE DATE';Expression={
                                $releasedate = [datetime]::ParseExact($_.ReleaseDate.SubString(0,8),"yyyyMMdd",$null);
                                $releasedate.ToShortDateString()
                            }},
                            @{Name='SERIAL NUMBER';Expression={$_.SerialNumber}}

            $htmlbody += $biosinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }


        #---------------------------------------------------------------------
        # Collect Logical Disk information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>Logical Disk information</h3>"
        $htmlbody += $subhead

        Write-Verbose "Collecting Logical Disk information"

        try
        {
            $diskinfo = Get-WmiObject Win32_LogicalDisk -ComputerName $ComputerName -ErrorAction STOP | 
                Select-Object   @{Name='DRIVE LETTER';Expression={$_.DEVICEID}},
                                @{Name='FILE SYSTEM';Expression={$_.FILESYSTEM}}, 
                                @{Name='VOLUME NAME';Expression={$_.VOLUMENAME}},
                                @{Expression={$_.Size /1Gb -as [int]};Label="TOTAL SIZE (GB)"},
                                @{Expression={$_.Freespace / 1Gb -as [int]};Label="FREE SPACE (GB)"}

            $htmlbody += $diskinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }

        #---------------------------------------------------------------------
        # Collect Network Share and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>Network Share Information</h3>"
        $htmlbody += $subhead
 
        Write-Verbose "Collecting Network Share information"
        
        try
        {
            $share = Get-WmiObject Win32_share -ComputerName $ComputerName -ErrorAction STOP | Sort-Object NAME |
            Select-Object @{Name='SHARE NAME';Expression={$_.Name}}, 
                          @{Name='LOCAL PATH';Expression={$_.Path}}, 
                          @{Name='SHARE DESCRIPTION';Expression={$_.Description}}
        
            $htmlbody += $share | ConvertTo-Html -Fragment
            $htmlbody += $spacer         
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }       
        
        #---------------------------------------------------------------------
        # Collect operating system installed roles & features and convert to HTML fragment
        #---------------------------------------------------------------------
    
        Write-Verbose "Collecting Operating System Installed Role and Feature"

        $subhead = "<h3>Operating System Installed Role and Feature</h3>"
        $htmlbody += $subhead
    
        try
        {
            $roles = Get-WindowsFeature | ? { $_.Installed -eq "Installed"} -ErrorAction STOP |
                Select-Object DISPLAYNAME, NAME, INSTALLSTATE
       
            $htmlbody += $roles | ConvertTo-Html -Fragment
            $htmlbody += $spacer       
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }

        #---------------------------------------------------------------------
        # Collect software information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>Software Information</h3>"
        $htmlbody += $subhead
 
        Write-Verbose "Collecting Software information"
        
        try
        {
            $software = Get-WmiObject Win32_Product -ComputerName $ComputerName -ErrorAction STOP | Sort-Object NAME |
            Select-Object NAME, VERSION, VENDOR, @{Name='INSTALLED DATE';Expression={$_.InstallDate}}
        
            $htmlbody += $software | ConvertTo-Html -Fragment
            $htmlbody += $spacer         
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }       

		#---------------------------------------------------------------------
        # Collect Running Service and convert to HTML fragment
        #---------------------------------------------------------------------
    
        Write-Verbose "Collecting Running Service"

        $subhead = "<h3>Running Service</h3>"
        $htmlbody += $subhead
    
        try
        {
            $services = Get-Service | ? { $_.Status -eq "Running" -and $_.StartType -eq "Automatic"} | Sort DisplayName -ErrorAction STOP |
            Select-Object @{Name='DISPLAY NAME';Expression={$_.DisplayName}},
                          @{Name='NAME';Expression={$_.Name}},
                          @{Name='STATUS';Expression={$_.Status}},
                          @{Name='STARTUP TYPE';Expression={$_.StartType}}
                   
            $htmlbody += $services | ConvertTo-Html -Fragment
            $htmlbody += $spacer
       
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }

        #---------------------------------------------------------------------
        # Collect HotFix information and convert to HTML fragment
        #---------------------------------------------------------------------
    
        Write-Verbose "Collecting Installed HotFix/Patch information"

        $subhead = "<h3>Installed HotFix/Patch</h3>"
        $htmlbody += $subhead
    
        try
        {
            $hotfixinfo = Get-HotFix -ComputerName $ComputerName -ErrorAction STOP | Sort-Object InstalledOn -Descending |
            Select-Object @{Name='DESCRIPTION';Expression={$_.Description}},
                          @{Name='HOTFIX ID';Expression={$_.HotFixID}},
                          @{Name='INSTALLED ON';Expression={$_.InstalledOn}},
                          @{Name='INSTALLED BY';Expression={$_.InstalledBy}}
                                        
            $htmlbody += $hotfixinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }
        
        #---------------------------------------------------------------------
        # Generate the HTML report and output to file
        #---------------------------------------------------------------------
	
        Write-Verbose "Producing HTML report"
    
        $reportime = Get-Date

        #Common HTML head and styles
	    $htmlhead="<html>
				    <style>
				    BODY{font-family: Arial; font-size: 8pt;}
				    H1{font-size: 20px;}
				    H2{font-size: 18px;}
				    H3{font-size: 16px;}
				    TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
				    TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
				    TD{border: 1px solid black; padding: 5px; }
				    td.pass{background: #7FFF00;}
				    td.warn{background: #FFE600;}
				    td.fail{background: #FF0000; color: #ffffff;}
				    td.info{background: #85D4FF;}
				    </style>
				    <body>
				    <h1 align=""center"">Server Info: $ComputerName</h1>
				    <h3 align=""center"">Generated: $reportime</h3>"

        $htmltail = "</body>
			    </html>"

        $htmlreport = $htmlhead + $htmlbody + $htmltail

        $htmlreport | Out-File $htmlfile -Encoding Utf8
		### ii *.html
    }

}

End
{
    #Wrap it up
    Write-Verbose "=====> Finished <====="
}

### http://cbtgeeks.com/2019/02/07/how-to-find-your-authenticating-domain-controller/
### Get-WmiObject -Class win32_ntdomain