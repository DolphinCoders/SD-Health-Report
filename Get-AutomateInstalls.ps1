<#
.SYNOPSIS
  This function allows you to audit AD Computers or by using a list of computer names
  to see if Automate is installed on it to be printed to the screen or exported
.PARAMETER TransferInstall
  True if you wish to also transfer and install 
.EXAMPLE
  Check-ADAutomateInstalls -TransferInstall True
#>

Function Get-AutomateInstalls {
    [CmdletBinding()]
	
    param (

        [Parameter(ValueFromPipeline)]
        [String[]]$ComputerNames,

        [Parameter()]
        [Boolean]$TransferInstall=$False,

        [Parameter()]
        [String]$FiletoInstall="c:\reports\Automate_Install.msi",

        [Parameter()]
        [String]$ExportFile="c:\reports\" + (Get-Date -f yyyy-MM-dd) + "\automate.csv"

	)
	    
    Begin {
	
        # Get Start Time so we can output how long it takes the script to run
        $StartDTM = (Get-Date)

        # Create some blank arrays to store our lists
        $ComputersScriptInstalled = @()
        $ComputersAlreadyInstalled = @()
        $ComputersNeedInstall = @()
        $ComputersNoPSSession = @()
        $ComputersNoWinRM = @()
        $ComputersToCount = @()
		
		# Create the table used for output
        $DisplayResults = New-Object System.Data.DataTable "ADComputersAutomate"
        $col1 = New-Object System.Data.DataColumn Name
        $col2 = New-Object System.Data.DataColumn WinRM
        $col3 = New-Object System.Data.DataColumn PSSession
        $col4 = New-Object System.Data.DataColumn AlreadyInstalled
        $col5 = New-Object System.Data.DataColumn TransferInstall
        $col6 = New-Object System.Data.DataColumn ConnectionTest
        $col7 = New-Object System.Data.DataColumn LastLogon        
        $col8 = New-Object System.Data.DataColumn CurrentLogonUser
        $DisplayResults.Columns.Add($col1)
        $DisplayResults.Columns.Add($col2)
        $DisplayResults.Columns.Add($col3)
        $DisplayResults.Columns.Add($col4)
        $DisplayResults.Columns.Add($col5)
    	$DisplayResults.Columns.Add($col6)
		$DisplayResults.Columns.Add($col7)
		$DisplayResults.Columns.Add($col8)

		CheckPathExists $ExportFile "Export"

    }

    Process {

		# If nothing was passed through, grab all AD computers
		If ($Null -eq $ComputerNames) {
			$ComputersToCount += (Get-ADComputer -Filter * -Properties *).Name
		} else {
			# Computers piped in will all go through the same process as using the parameter
			$ComputersToCount += $ComputerNames
		}

    }

    End {
        
		# Count each PC, this will be used later to check and make sure we accounted for each one
        [int]$ComputerCount = ($ComputersToCount).Count
        [int]$Iteration = 0
		
        Do
        {
	        ForEach ($Computer in $ComputersToCount)
	        {
				# Initialize variables we'll be using later			
		        [int]$Retry = 0
		        [int]$InstallCode = 0
                [double]$PercentComplete = 0
		        [int]$RetryCopyFile = 0
		        [int]$CopyCode = 0
				$Heartbeat = $False
                
				# Create the table to output our results
                $ComputerRow = $DisplayResults.NewRow()
                $ComputerRow.Name = $Computer 
                $ComputerRow.LastLogon = [datetime]::FromFileTime((Get-ADComputer -Identity $Computer -Properties * | ForEach-Object { $_.LastLogonTimeStamp } | Out-String)).ToString('g') 

				# Write the progress to the screen as it goes through the loop
                $PercentComplete = [math]::Round($Iteration / $ComputersToCount.Count * 100, 2)
                Write-Progress -Activity "Checking Computer $Computer" -Status "($PercentComplete% Complete:" -PercentComplete $PercentComplete;
                
				# Tests the connection, seeing if the PC is currently online
				If(Test-Connection -ComputerName $Computer -Count 1 -Quiet)
                {
                    $ComputerRow.ConnectionTest = $True                 
                }
                Else
                {
					# Tried to rest RDP port 3389 for connectivity incase ICMP is blocked
                    Try {
						If(Test-NetConnection -ComputerName $Computer -Port 3389 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | ForEach-Object { $_.TcpTestSucceeded } )
						{
							$ComputerRow.ConnectionTest = $True
						}
						Else
						{
							$ComputerRow.ConnectionTest = $False
						}
					}
					Catch {					
						$ComputerRow.ConnectionTest = $False
					}
                }
				
				# Tries to get the currently signed in user
				Try {
					$ComputerRow.CurrentLogonUser = (Get-WmiObject -Class win32_computersystem -ComputerName $Computer -ErrorAction "Stop").UserName
				} 
				Catch {
					$ComputerRow.CurrentLogonUser = "Unknown"
				}	
                
		        # Test WinRM, if this fails we can't perform any other tasks
		        Write-Host "Testing WSMAN Connection to $Computer"
				Try {
				    $Heartbeat = (Test-WSMan -ComputerName $Computer -ErrorAction SilentlyContinue)
				}
				Catch {
					$Heartbeat = $False
				}
		        If (!$Heartbeat)
		        {
			        Write-Host "$Computer is not able to be connected to via WinRM"
                    $ComputersNoWinRM += $Computer
                    $ComputerRow.WinRM = $False 
                    $ComputerRow.PSSession = "Unknown"
                    $ComputerRow.AlreadyInstalled = "Unknown"
                    $ComputerRow.TransferInstall = $False
		        }
		        Else
		        {
			        Write-Host "WinRM appears to be open for $Computer"
                    $ComputerRow.WinRM = $True
					
			        # Runs the exe in silent mode. Please note that when PowerShell runs the .exe file you wont see it if youre logged in as a user anyways because it wont launch it in an interactive login by default
			
			        Write-Host "Creating a new PSSession to $Computer"
			        $session = New-PSSession -ComputerName $computer -ErrorAction SilentlyContinue
			        If ($null -ne $Session)
			        {
                        $ComputerRow.PSSession = $True 
				        Write-Host "Creating a new PSDrive on $Computer"
				        Invoke-Command -Session $session -ScriptBlock { New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR } | Out-Null
				
				        Write-Host "Checking to see if Automate is installed"
				        $Check = Invoke-Command -Session $session -ScriptBlock { (Get-ChildItem "HKCR:\Installer\Products") | Where-Object { $_.GetValue("ProductName") -like "*Labtech*" } }
				        If ($null -ne $Check)
				        {
					        Write-Host "$Computer has Automate Installed!"
                            $ComputersAlreadyInstalled += $Computer
                            $ComputerRow.AlreadyInstalled = $True
                            $ComputerRow.TransferInstall = $False
				        }
				        Else
				        {
					        Write-Host "$Computer does not currently have Automate installed! Continuing"
                            If($TransferInstall)
                            {
                                $ComputerRow.AlreadyInstalled = $False
					            Write-Host "Creating C:\temp\ on $Computer"
					            #Creates a directory on the remote machine 
					            Invoke-Command -Session $session -ScriptBlock { New-Item -ItemType Directory "C:\temp" -ErrorAction SilentlyContinue } | Out-Null
					            Write-Host "Done!"
					            Do
					                                                                                                                                                                                                                                            {
						        Write-Host "Copying over the Windows Agent File to $Computer..."
						        #Copies over the file to our new directory we created above
						        Copy-Item -Path $FiletoInstall -Destination "\\$computer\C$\temp\" -Force -ErrorAction Continue
						        Write-Host "Done!"
						
						        $CheckforFile = Invoke-Command -Session $session -ScriptBlock { Test-Path -Path C:\temp\Automate_Install.msi }
						        If ($CheckforFile -eq $True)
						        {
							        $CopyCode++
							        Do
							        {
								        Write-Host "Installing the agent on $Computer..."
								        Invoke-Command -Session $session -ScriptBlock { Start-Process "msiexec.exe" -ArgumentList "/i C:\temp\Automate_Install.msi /q" -Wait }
								
								        Write-Host "Checking to see if Automate is installed"
								        $Check = Invoke-Command -Session $session -ScriptBlock { (Get-ChildItem "HKCR:\Installer\Products") | Where-Object { $_.GetValue("ProductName") -like "*Labtech*" } }
								        if ($null -ne $Check)
								        {
									        Write-Host "$Computer has $Automate Installed!"
									        #Adds 1 to the variable to keep track of how many computers don't have the path and will be worked on
									        $ComputersScriptInstalled += $Computer					
									        $InstallCode++
                                            $ComputerRow.TransferInstall = $False
								        }
								        Else
								        {
									        $Retry++
									        Write-Host "Install Failed"
									        #Adds 1 to the variable to keep track of how many computers don't have the path and will be worked on
									        If ($Retry -eq 1)
									        {
										        Write-Host "Retrying install of Automate on $Computer"
									        }
								        }
							        }
									# Retry until we have tried three times or we have successfully installed
							        Until (($Retry -gt 3) -or ($InstallCode -gt 0))
                                    If(($Retry -gt 3) -or ($InstallCode -gt 0))
                                    {
                                        Write-Host "Uninstall failed on $Computer"
                                        $ComputerRow.TransferInstall = "Attemped"
                                    }
							
							        Write-Host "Exiting pssession"
							        Get-PSSession -Name $Session.Name | Remove-PSSession -ErrorAction SilentlyContinue
							
						        }
						        Else
						        {
							        $RetryCopyFile++
							        Write-Host "Could not copy install files to $Computer"
							        If ($RetryCopyFile -eq 1)
							        {
								        Write-Host "Retrying to copy install files to $Computer"
							        }
						        }
					        }
					            Until (($RetryCopyFile -gt 3) -or ($CopyCode -gt 0))
                            }
                            Else
                            {
                                $ComputerRow.AlreadyInstalled = $False
                                $ComputerRow.TransferInstall = "Applicable"
                                $ComputersNeedInstall += $Computer
                            }
				        }
			        }
			        Else
			        {
				        Write-Host "Could not establish a PSSession to $Computer!"
                        $ComputersNoPSSession += $Computer
                        $ComputerRow.PSSession = $False
                        $ComputerRow.AlreadyInstalled = "Unknown"
                        $ComputerRow.TransferInstall = $False
			        }
		        }
                Write-Host "Removing any ghost PSSessions"
                Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
                $Iteration++
                $DisplayResults.Rows.Add($ComputerRow)
	        }
        }
        # Loop through until all the counts add up to ComputerCount
        Until (
            ($ComputersScriptInstalled).Count + 
            ($ComputersAlreadyInstalled).Count + 
            ($ComputersNoWinRM).Count + 
            ($ComputersNoPSSession).Count + 
            ($ComputersNeedInstall).Count -eq $ComputerCount)

        # Get End Time
        $endDTM = (Get-Date)


        Write-Host "---------STATS----------" -ForegroundColor White
        Write-Host "SCRIPT RUNTIME: $(($endDTM - $startDTM).totalseconds) seconds" -ForegroundColor Green
        Write-Host "COMPUTERS WINRM UNOPEN: " ($ComputersNoWinRM).Count -ForegroundColor Green
        Write-Host "COMPUTERS PSSESSION ERROR: " ($ComputersNoPSSession).Count -ForegroundColor Green
        Write-Host "COMPUTERS INSTALLED SUCESSFULLY: " ($ComputersScriptInstalled).Count -ForegroundColor Green
        Write-Host "COMPUTERS ALREADY INSTALLED: " ($ComputersAlreadyInstalled).Count -ForegroundColor Green

        $DisplayResults | Format-Table | Export-csv -Path $ExportFile -NoTypeInformation

    }
}

Function CheckPathExists($Path, $File) {
	# Checks if the report file path exists, if not it creates it
	$CheckReportPath = Test-Path $Path -ErrorAction SilentlyContinue
	If ($CheckReportPath -eq $False)
	{
		Write-Host "$File path not found! - Creating $Path!"
		New-Item -Path $Path -Force -ItemType File | Out-Null
	}
	Else
	{
		Write-Host "$File file path is already present, continuing"
	}
}