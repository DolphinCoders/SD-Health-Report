<#
.SYNOPSIS
  This function allows you to audit AD Computers or by using a list of computer names
  to see if Labtech is installed on it to be printed to the screen or exported
.PARAMETER TransferInstall
  True if you wish to also transfer and install 
.EXAMPLE
  Check-ADLabtechInstalls -TransferInstall True
#>

Function Get-ADLabtechInstalls {
    [CmdletBinding()]
	
    param (

        [Parameter(ValueFromPipeline)]
        [String[]]$ComputerNames,

        [Parameter()]
        [Boolean]$TransferInstall,

        [Parameter()]
        [String[]]$FiletoInstall="C:\reports\LabTech_Install.msi",
		
        [Parameter()]
        [String[]]$LogFilePath="C:\reports\log.txt",

        [Parameter()]
        [String[]]$ReportFile="C:\reports\report.csv"

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
        $DisplayResults = New-Object System.Data.DataTable "ADComputersAndLabtech"
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
		
		# Checks if the log file path exists, if not it creates it
		$CheckLogPath = Test-Path $LogFile -ErrorAction SilentlyContinue
		If ($CheckLogPath -eq $False)
		{
			Write-Verbose "Log Path not found! - Creating!"
			New-Item -Path $LogFile -Force -ItemType File
		}
		Else
		{
			Write-Verbose "Log file path is already present, continuing"
		}

		# Checks if the report file path exists, if not it creates it
		$CheckReportPath = Test-Path $ReportFile -ErrorAction SilentlyContinue
		If ($CheckReportPath -eq $False)
		{
			Write-Verbose "Report Path not found! - Creating!"
			New-Item -Path $ReportFile -Force -ItemType File
		}
		Else
		{
			Write-Verbose "Report file path is already present, continuing"
		}
		
    }

    Process {

		# Computers piped in will all go through the same process as using the parameter
        $ComputersToCount += $ComputerNames

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
		        Write-Verbose "Testing WSMAN Connection to $Computer"
				Try {
				    $Heartbeat = (Test-WSMan -ComputerName $Computer -ErrorAction SilentlyContinue)
				}
				Catch {
					$Heartbeat = $False
				}
		        If (!$Heartbeat)
		        {
			        Write-Verbose "$Computer is not able to be connected to via WinRM"
                    $ComputersNoWinRM += $Computer
                    $ComputerRow.WinRM = $False 
                    $ComputerRow.PSSession = "Unknown"
                    $ComputerRow.AlreadyInstalled = "Unknown"
                    $ComputerRow.TransferInstall = $False
		        }
		        Else
		        {
			        Write-Verbose "WinRM appears to be open for $Computer"
                    $ComputerRow.WinRM = $True
					
			        # Runs the exe in silent mode. Please note that when PowerShell runs the .exe file you wont see it if youre logged in as a user anyways because it wont launch it in an interactive login by default
			
			        Write-Verbose "Creating a new PSSession to $Computer"
			        $session = New-PSSession -ComputerName $computer -ErrorAction SilentlyContinue
			        If ($null -ne $Session)
			        {
                        $ComputerRow.PSSession = $True 
				        Write-Verbose "Creating a new PSDrive on $Computer"
				        Invoke-Command -Session $session -ScriptBlock { New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR } | Out-Null
				
				        Write-Verbose "Checking to see if LabTech is installed"
				        $Check = Invoke-Command -Session $session -ScriptBlock { (Get-ChildItem "HKCR:\Installer\Products") | Where-Object { $_.GetValue("ProductName") -like "*LabTech*" } }
				        If ($null -ne $Check)
				        {
					        Write-Verbose "$Computer has LabTech Installed!"
                            $ComputersAlreadyInstalled += $Computer
                            $ComputerRow.AlreadyInstalled = $True
                            $ComputerRow.TransferInstall = $False
				        }
				        Else
				        {
					        Write-Verbose "$Computer does not currently have LabTech installed! Continuing"
                            If($TransferInstall)
                            {
                                $ComputerRow.AlreadyInstalled = $False
					            Write-Verbose "Creating C:\temp\ on $Computer"
					            #Creates a directory on the remote machine 
					            Invoke-Command -Session $session -ScriptBlock { New-Item -ItemType Directory "C:\temp" -ErrorAction SilentlyContinue } | Out-Null
					            Write-Verbose "Done!"
					            Do
					                                                                                                                                                                                                                                            {
						        Write-Verbose "Copying over the Windows Agent File to $Computer..."
						        #Copies over the file to our new directory we created above
						        Copy-Item -Path $FiletoInstall -Destination "\\$computer\C$\temp\" -Force -ErrorAction Continue
						        Write-Verbose "Done!"
						
						        $CheckforFile = Invoke-Command -Session $session -ScriptBlock { Test-Path -Path C:\temp\LabTech_Install.msi }
						        If ($CheckforFile -eq $True)
						        {
							        $CopyCode++
							        Do
							        {
								        Write-Verbose "Installing the agent on $Computer..."
								        Invoke-Command -Session $session -ScriptBlock { Start-Process "msiexec.exe" -ArgumentList "/i C:\temp\LabTech_Install.msi /q" -Wait }
								
								        Write-Verbose "Checking to see if LabTech is installed"
								        $Check = Invoke-Command -Session $session -ScriptBlock { (Get-ChildItem "HKCR:\Installer\Products") | Where-Object { $_.GetValue("ProductName") -like "*LabTech*" } }
								        if ($null -ne $Check)
								        {
									        Write-Verbose "$Computer has $LabTech Installed!"
									        #Adds 1 to the variable to keep track of how many computers don't have the path and will be worked on
									        $ComputersScriptInstalled += $Computer					
									        $InstallCode++
                                            $ComputerRow.TransferInstall = $False
								        }
								        Else
								        {
									        $Retry++
									        Write-Verbose "Install Failed"
									        #Adds 1 to the variable to keep track of how many computers don't have the path and will be worked on
									        If ($Retry -eq 1)
									        {
										        Write-Verbose "Retrying install of LabTech on $Computer"
									        }
								        }
							        }
									# Retry until we have tried three times or we have successfully installed
							        Until (($Retry -gt 3) -or ($InstallCode -gt 0))
                                    If(($Retry -gt 3) -or ($InstallCode -gt 0))
                                    {
                                        Write-Verbose "Uninstall failed on $Computer"
                                        $ComputerRow.TransferInstall = "Attemped"
                                    }
							
							        Write-Verbose "Exiting pssession"
							        Get-PSSession -Name $Session.Name | Remove-PSSession -ErrorAction SilentlyContinue
							
						        }
						        Else
						        {
							        $RetryCopyFile++
							        Write-Verbose "Could not copy install files to $Computer"
							        If ($RetryCopyFile -eq 1)
							        {
								        Write-Verbose "Retrying to copy install files to $Computer"
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
				        Write-Verbose "Could not establish a PSSession to $Computer!"
                        $ComputersNoPSSession += $Computer
                        $ComputerRow.PSSession = $False
                        $ComputerRow.AlreadyInstalled = "Unknown"
                        $ComputerRow.TransferInstall = $False
			        }
		        }
                Write-Verbose "Removing any ghost PSSessions"
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

        $DisplayResults | Export-csv -Path $ReportFile -NoTypeInformation

    }
}