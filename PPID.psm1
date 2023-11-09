<#
.Synopsis
   PPID     By: Kevin Tobin
   
   ALIASES:  ParentProcessIDSearch,  ProcessSearch,  ParentProcessSearch,  PPS
.DESCRIPTION
   Threat Hunting
   Search for all the child objects created under a given Parent Process ID

   (Get-CimInstance CIM_Process) |  
   select processID,ParentProcessId,processname,CreationDate,Caption,path,Description,Commandline | ?{
        $_.processname -like "*$Name*" -and $_.processID -like "$ProcID*" -and $_.ParentProcessID -like "$ParentID*"
        }
.EXAMPLE
   Pps chrome -Verbose
   # WILL AUTOCORRECT TO SEARCH FOR PROCESSNAME WITH CHROME
.EXAMPLE
   Pps 18148
   # DEFAULT SEARCH BY PARENT PID
.EXAMPLE
   pPS -child 21072
.EXAMPLE
   PPID 0
   # FIND ORPHANED PROCESSES (NOTE THAT SYSTEM & SYSTEM IDLE PROCESS WILL ALWAYS SHOW)
.EXAMPLE
   ppid -raw -id (ppid -raw -id $(ppid -id (ppid -raw -id $((ppid -id 10444 -raw).ParentProcessID)).parentProcessID).ParentProcessID)
   # RECURSIVELY CHECK PARENT ID TO FIND NEXT PARENT OF PROCESS # 10444
   # WARNING: WHEN NOTHING IS RETURNED YOU'VE REACHED THE ORIGINAL PARENT, 
   # AS A RESULT, IF YOU RUN PPID WITH NO ARGUMENTS IT'LL RETURN EVERY SINGLE PROCESS!!!
   # SO YOU MUST ALREADY KNOW HOW DEEP YOU NEED TO GO WHEN USING A COMMAND LIKE THIS
   # THIS IS BETTER SUITED TO BE NESTED IN A CUSTOM LOOP
.EXAMPLE
   ppid 1616 -Colorize -Name wudfhost
.EXAMPLE
   PPID -Colorize -Name SVCHOST.EXE  -ExcludePath "C:\Windows\system32\"
.EXAMPLE
   ppid -raw -n SystemSettingsBroker | select CommandLine | fl
   # RETURN COMMANDLINE COMMANDS FOR GIVEN SERVICE NAME
   ppid -raw -n signal | select CommandLine | fl
   # RETURN COMMANDLINE COMMANDS FOR THE SIGNAL PROGRAM (Assuming this is running on the target device)
#>
function PPID
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [alias("ParentProcessId","Parent","PPID","pp")] $ParentID,
        [alias("processID","ChildID", "PID","p", "id")] $ProcID,
        [alias("ProcessName")] [string] $Name,

        # Param2 help description
        [switch]
        $Raw,
        [switch] $Colorize,
        $ExcludePath,
        $Color = "red",
        $Global:Data_File = "$env:TEMP\PPID.txt"
    )

    Begin
    {
        $Cmdlet = "PPID"

        If ($ParentID -match "[a-z]")
        {
            $LN = 100
            write-verbose "$LN `t $Cmdlet `t Correct PPID to ProcessName"  ; $LN++
            $Name = "$ParentID"; write-verbose "$LN `t $Cmdlet `t Name    : $Name" ; $LN++
            $ParentID = "";      write-verbose "$LN `t $Cmdlet `t ParentID: $ParentID" ; $LN++
        }
    }
    Process
    {



        IF ($Raw)
        {
            If ($ExcludePath -notlike "")
            {
                (Get-CimInstance CIM_Process) |  select processID,ParentProcessId,processname,CreationDate,Caption,path,Description,Commandline | ?{$_.processname -like "*$Name*" -and $_.processID -like "$ProcID*" -and $_.ParentProcessID -like "$ParentID*" -and $_.Path -notlike "$ExcludePath*"}
            }
            Else
            {
                (Get-CimInstance CIM_Process) |  select processID,ParentProcessId,processname,CreationDate,Caption,path,Description,Commandline | ?{$_.processname -like "*$Name*" -and $_.processID -like "$ProcID*" -and $_.ParentProcessID -like "$ParentID*" }
            }
        }
        ELSE
        {
            If ($Colorize)
            {
                # COLOR
                    If ($ExcludePath -notlike "")
                    {
                        $Data = (Get-CimInstance CIM_Process) |  select processID,ParentProcessId,processname,CreationDate,Caption,path,Description,Commandline |  ?{<# $_.processname -like "*$Name*" -and #> $_.processID -like "$ProcID*" -and $_.ParentProcessID -like "$ParentID*" -and $_.Path -notlike "$ExcludePath*"} 
                    }
                    Else
                    {
                        $Data = (Get-CimInstance CIM_Process) |  select processID,ParentProcessId,processname,CreationDate,Caption,path,Description,Commandline |  ?{<# $_.processname -like "*$Name*" -and #> $_.processID -like "$ProcID*" -and $_.ParentProcessID -like "$ParentID*"} 
                    }
                    
                    #$Global:Data_Matches = $Data | ? {$_.ParentProcessID -like "$ParentID"} | ft -AutoSize > "$env:temp\Data_MatchesFile.txt"
                    #$Global:Data_Matches = gc "$env:temp\Data_MatchesFile.txt"

                    If ($Data_File -like "$env:TEMP\PPID.txt")
                    {
                        # If using Default Data file, create a new one each time.  If user provided file, simply read that instead of creating a new one.
                            $Data | ft -AutoSize > $Data_File
                    }
                    gc $Data_File | % {
                        if ($_ -like "*$Name*") {Write-Host -f $Color "$_" } else { Write-Host "$_" } 
                        } 
            }
            Else
            {
                if ($ExcludePath -notlike "")
                {
                    (Get-CimInstance CIM_Process) |  select processID,ParentProcessId,processname,CreationDate,Caption,path,Description,Commandline | ?{$_.processname -like "*$Name*" -and $_.processID -like "$ProcID*" -and $_.ParentProcessID -like "$ParentID*" -and $_.Path -notlike "$ExcludePath*"} | ft -AutoSize | oh -Paging -ErrorAction SilentlyContinue
                }
                else
                {
                    # DEFAULT
                        (Get-CimInstance CIM_Process) |  select processID,ParentProcessId,processname,CreationDate,Caption,path,Description,Commandline |  ?{$_.processname -like "*$Name*" -and $_.processID -like "$ProcID*" -and $_.ParentProcessID -like "$ParentID*"} | ft -AutoSize | oh -Paging -ErrorAction SilentlyContinue
                }
            }

        }
        
    }
    End
    {
    }
}
#
New-Alias -name ParentProcessIDSearch -Value PPID
New-Alias -name ProcessSearch -Value PPID
New-Alias -name ParentProcessSearch -Value PPID
New-Alias -name PPS -Value PPID
New-Alias -name PSList -Value PPID
Export-ModuleMember -Alias * -Function PPID