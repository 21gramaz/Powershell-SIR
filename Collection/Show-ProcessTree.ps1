<#     Show-ProcessTree
    https://p0w3rsh3ll.wordpress.com/#>

Function Show-ProcessTree {            
    [CmdletBinding()]            
    Param()            
    Begin {            
        # Identify top level processes            
        # They have either an identified processID that doesn't exist anymore            
        # Or they don't have a Parentprocess ID at all            
        $allprocess = Get-WmiObject -Class Win32_process            
        $uniquetop = ($allprocess).ParentProcessID | Sort-Object -Unique            
        $existingtop = ($uniquetop | ForEach-Object -Process { $allprocess | Where ProcessId -EQ $_ }).ProcessID            
        $nonexistent = (Compare-Object -ReferenceObject $uniquetop -DifferenceObject $existingtop).InPutObject            
        $topprocess = ($allprocess | ForEach-Object -Process {            
                if ($_.ProcessID -eq $_.ParentProcessID) {            
                    $_.ProcessID            
                }            
                if ($_.ParentProcessID -in $nonexistent) {            
                    $_.ProcessID            
                }            
            })            
        # Sub functions            
        # Function that indents to a level i            
        function Indent {            
            Param([Int]$i)            
            $Global:Indent = $null            
            For ($x = 1; $x -le $i; $x++) {            
                $Global:Indent += [char]9            
            }            
        }            
        Function Get-ChildProcessesById {            
            Param($ID)            
            # use $allprocess variable instead of Get-WmiObject -Class Win32_process to speed up            
            $allprocess | Where-Object { $_.ParentProcessID -eq $ID } | ForEach-Object {            
                Indent $i            
                '{0}{1} {2}' -f $Indent, $_.ProcessID, ($_.Name -split "\.")[0]            
                $i++            
                # Recurse            
                Get-ChildProcessesById -ID $_.ProcessID            
                $i--            
            }            
        } # end of function            
    }            
    Process {            
        $topprocess | ForEach-Object {            
            '{0} {1}' -f $_, (Get-Process -Id $_).ProcessName            
            # Avoid processID 0 because parentProcessId = processID            
            if ($_ -ne 0 ) {            
                $i = 1            
                Get-ChildProcessesById -ID $_            
            }            
        }            
    }             
    End {}            
}