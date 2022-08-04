Function Show-PSHelp {
<#
	.Synopsis
		Collection of help topics when using PowerShell
	.Description
		Contains
		Module Help
		FunctionProtoType
		Variables
		Error handling
		Object Creation
		File Manipulation
		URI
		Data Manipulation
		Encoding/Decoding
		Regex
	.NOTES
		Author: Tom Willett
		Date: 9/4/2021
#>
Param([Parameter(Mandatory=$false)][string]$ans='')
	if ($ans -eq '') {
		$ans = read-host -prompt "Enter Category
		a - Module Help
		b - FunctionProtoType
		c - Variables
		d - Error handling
		e - Object Creation
		f - File Manipulation
		g - URI
		h - Data Manipulation
		i - Encoding/Decoding
		j - Regex
		
		Category> "
	}
	switch ( $ans )
	{
		'a' { show-modulehelp }
		'b' { show-functionprototype }
		'c' { show-variables }
		'd' { show-error }
		'e' { show-object }
		'f' { show-fileOps }
		'g' { show-uri }
		'h' { show-dataManipulation }
		'i' { show-encodeDecode }
		'j' { show-regex }
	}
}

function show-modulehelp {
write-host ""
write-host "Module Help" -fore green

$out = @'

PSHelp - a collection of PowerShell help
ForensicsByTom - A collection of Help and functions to help with forensics investigations
Functions:
	get-eventlogs -- Process windows event logs
	convert-IIStoCSV - Read IIS logs and convert them to csv files
	get-ipfromfile -- Pull IP addresses from a text file
	convert-base64 -- convert base64 encoded string
	get-IISWebShell -- NSA routine looking for web shells
	get-teamslog -- reads recent history from Microsoft Teams
	get-etllog -- converts an etl log to a PowerShell object
	parse-emailHeaders -- converts an email header to PowerShell Object
	## Utility
	split-csv -- Break up long csv into chunks that fit in Excel
		$splitrecs = 1,200,000 - number of records per file - can be changed
	df -- Show disk free space
	open-matches -- opens the files found with sls
	## Linux 	
	get-linuxlogs -- Process Linux event logs
	get-utmp -- Convert UTMP,BTMP,WTMP Linux files
	list-timezones -- lists timezones and names - needed for get-utmp
	convert-bashHistory -- Convert bash history files with date/times to human readable
	##File handling routines using dot net routines for speed.
	out-UTF8 -- outputs file in UTF8 no BOM -- always appends.
	join-files -- appends one file to another
	split-file -- splits a file by line into smaller sizes
		$splitsize initially set to 500,000,000 bytes but can be changed
	count-lines -- counts the lines in a file
	sort-file -- sort the lines in a file
	remove-duplicates -- remove duplicates from a file 
	get-fileEncoding -- reads the bom of a file to get the encoding
	##Require Internet Connection
	get-shodan -- uses shodan.io api to retrieve information
	get-ipgeo -- IP Geolocation using either ip-api.com or ip-geolocation

'@
write-host $out
}

function show-functionprototype {
write-host ""
write-host "Function Prototype Help" -fore green

$out = @'

function prototype {
<#
	.Synopsis
		Does Something
	.Description
		Does Something in more detail
	.Parameter width
		width of window
	.Parameter height
		height of window
	.NOTES
		Author: Tom Willett
		Date: 9/4/2021
#>

Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$width,
	[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$height)
	begin {
	}
	process {
		Code
	}
	end {
	}
}

'@
write-host $out
}

function show-variables {
write-host ""
write-host "Various PowerShell Variables" -fore green

$out = @'

# get current execution environment info
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptDir = split-path -parent $ScriptPath
$ScriptName = [system.io.path]::GetFilenameWithoutExtension($ScriptPath)

# Use [System.IO.Path] to get parts of path
[System.IO.Path]::GetFilename("")
[System.IO.Path]::GetFilenamewithoutextension("")
[System.IO.Path]::GetDirectoryName("")
[System.IO.Path]::GetExtension("")

# environment variables
$env:computername 
#Profile Path
$Profile 
#PowerShell Version
$PSVersionTable

'@
write-host $out
}

function show-error {
write-host ""
write-host "Error Actions" -fore green

$out = @'

# Error action
# -ErrorAction SilentlyContinue
$ErrorActionPreference = "SilentlyContinue"
"continue"
"stop"
"inquire"

'@
write-host $out
}

function show-object {
write-host ""
write-host "Object Creation Help" -fore green

$out = @'

#
$report = @()
$temp = "" | Select Computer, Username

$temp = [pscustomobject]@{
	UserName = "Tom"
	Computer= "Computername"
}

$data = new-object -typename psobject
$data | add-member -notepropertyname 'Time' -NotePropertyValue $_._time
$data | add-member -notepropertyname 'Connecting IP' -notepropertyvalue $_.'Connecting IP'
$data | add-member -notepropertyname 'Status Code' -notepropertyvalue $_.'Status Code'

'@
write-host $out
}

function show-fileOps {
write-host ""
write-host "File Operations Help" -fore green

$out = @'

# To read a whole file in as one string
[Io.File]::ReadAllText($path)
# get-content reads it in as an array of strings.
#
# To write byte code to file
$var_code | Set-Content am-malware.bin -Encoding Byte

Add-Type -assembly "System.IO.Compression"

$wor = [IO.MemoryStream][Convert]::FromBase64String('')
$boo = New-Object System.IO.Compression.DeflateStream($wor,[IO.Compression.CompressionMode]::Decompress)
$UnFiBy = New-Object Byte[](587776)
$boo.Read($UnFiBy, 0, 587776) | Out-Null
$UnFiBy| set-content E:\malware\oln\adsfmalware.bin -encoding byte 

# data Conversion
to convert hex in the format 0x34 0x2e
[byte[]]$bytes = ($hex -split ' ')

'@
write-host $out
}

function show-uri {
write-host ""
write-host "URI Manipulation" -fore green

$out = @'

#Execute from web $url
iex ((new-object net.webclient).DownloadString($url))
#
#host name
([system.uri]'http://something.net').host
#tld 
((([system.uri]'http://something.net').host.split('.'))[-2,-1]) -join '.' 

'@
write-host $out
}

function show-dataManipulation {
write-host ""
write-host "Data Manipulation" -fore green

$out = @'

#histogram
$m | select "File Name" | group-object "File Name" | select count, name | sort count -descending | select -first 25
#
# unique items in array
$m | select -uniq
#
# Return only match from sls
| select -exp matches | select value
gc $fl | %{if($_ -match '[0-9a-f]{40}'){$matches[0]}} | out-utf8 tmp.txt
# return captures from sls
| %{$r = $_.matches.groups.captures[1].value + ' - ' + $_.matches.groups.captures[2].value;$r}
# return only line from sls
| select line
# Get only files
gci . *.* -rec | where { ! $_.PSIsContainer }
# Add Field to CSV
$s = Import-Csv file.csv
$s | Select-Object *,@{Name='column3';Expression={'setvalue'}} | Export-Csv file.csv -NoTypeInformation

'@
write-host $out
}

function show-encodeDecode {
write-host ""
write-host "Encoding/Decoding Help" -fore green

$out = @'

#Encode in Base64
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(‘This is a secret’))
#Decode Base64
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VABoAGkAcwAgAGkAcwAgAGEAIABzAGUAYwByAGUAdAA="))

#Time Zone Conversion
$dt = "2020-12-19 23:33"
[System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($dt,'Eastern Standard Time','UTC')
#Convert Unix Filetime
(([datetime] '1970-01-01Z').ToUniversalTime()).addseconds($unixfiletime)

To encode a command for execution
$cmd = "cmd.exe" // whatever
$bytes=[system.text.encoding]::unicode.getbytes($cmd)
$enc = [convert]::tobase64string($bytes)

url encode/decode
Add-Type -AssemblyName System.Web
$Encode = [System.Web.HttpUtility]::UrlEncode($URL) 
$Decode = [System.Web.HttpUtility]::UrlDecode($Encode) 

call it on the command line with -encoded $enc

#hex-to-ascii
[char][byte][convert]::toint16($hex,16)
#dec-to-ascii
[char][byte][convert]::toint16($dec)
#ascii-to-hex
[convert]::tostring([byte][char]$chr,16)
#ascii-to-dec
[byte][char]$chr

#convert string to hex
[System.BitConverter]::ToString([System.Text.Encoding]::Default.GetBytes($mystr))

#convert to base64
[System.Convert]::ToBase64String([System.Text.Encoding]::Default.GetBytes($str))

'@
write-host $out
}

function show-regex {
write-host ""
write-host "Regex Help" -fore green

$out = @'

Bitcoin - '(?i)^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'
Email - '(?i)\b[\w._%+-]+@[\w.-]+\.\w{2,}\b'
Email - ^[a-zA-Z0-9_\-.]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+$
CCregex - (\b3611\d{10}|3[47]\d{13}\b|\b6011[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b|\b35\d{2}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b|\b5[1-5]\d{2}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b|\b4\d{3}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b|\b3[0-8]\d{12}\b)')
url - '^((http[s]?|ftp):\/)?\/?([^:\/\s]+)((\/\w+)*\/)([\w\-\.]+[^#?\s]+)(.*)?(#[\w\-]+)?$'
IP - '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
ip - '(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
md5 (?i)[0-9a-f]{32}
sha1 (?i)[0-9a-f]{40}
sha256 (?i)[0-9a-f]{64}
Base64 (?:[A-Za-z0-9+\/]{4}\\n?)*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)
Private Address Filtering
'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
'192\.168\.\d{1,3}\.\d{1,3}'
'172\.1[6-9]\.\d{1,3}\.\d{1,3}'
'172\.2[0-9]\.\d{1,3}\.\d{1,3}'
'172\.3[0-1]\.\d{1,3}\.\d{1,3}'

hex digit (?i)[0-9a-f]+
regex options
case insensitive (?i)
multiline (?m)
single line (?s)

#Character classes
.	any character except newline
\w\d\s	word, digit, whitespace
\W\D\S	not word, digit, whitespace
[abc]	any of a, b, or c
[^abc]	not a, b, or c
[a-g]	character between a & g
#Anchors
^abc$	start / end of the string
\b\B	word, not-word boundary
#Escaped characters
\.\*\\	escaped special characters
\t\n\r	tab, linefeed, carriage return
#Groups & Lookaround
(abc)	capture group
\1	backreference to group #1
(?:abc)	non-capturing group
(?=abc)	positive lookahead
(?!abc)	negative lookahead
#Quantifiers & Alternation
a* a+ a?	0 or more, 1 or more, 0 or 1
a{5} a{2,}	exactly five, two or more
a{1,3}	between one & three
a+? a{2,}?	match as few as possible
ab|cd	match ab or cd

'@
write-host $out
}


function get-eventlogs {
<#

.SYNOPSIS

Reads a windows event log file (evtx) and converts it to a csv 

.DESCRIPTION

Reads evt and evtx windows log files and outputs a powershell object. 
It returns DateTime, EventID, Level, ShortEvent, User, Event, Properties, LogSource, LogSourceType, and Machine.

Evt logs can sometimes get corrupted and you will get the error "The data is invalid".  Run fixevt.exe
to fix the log file.  http://www.whiteoaklabs.com/computer-forensics.html

.PARAMETER logFile

logfile is required -- the path to the log file.

.EXAMPLE

 .\get-eventlogs.ps1 c:\windows\system32\winevt\application.evtx | export-csv -notype c:\temp\app.csv

 Reads the log file at c:\windows\system32\winevt\application.evtx and puts the output in c:\temp\app.csv

 .EXAMPLE

 dir *.evtx |.\get-eventlog.ps1 | export-csv -notype c:\temp\log.csv

 converts all the evtx logs puts the output in c:\temp\app.csv
 
.NOTES

Author: Tom Willett 
Date: 5/19/2021

#>

Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$FullName)

	process {
		$fext = [system.io.path]::getextension($FullName)
		$filter = @{Path="$FullName"}
		if ($fext -eq ".evt") {
			$old = $true
		} else {
			$old = $false
		}
		get-winevent -oldest:$old -filterhashtable $filter | 
		select-object @{Name="DateTime";Expression={$_.timecreated}},@{Name="EventID";Expression={$_.ID}},Level,@{Name="ShortEvent";Expression={$_.TaskDisplayName}},@{Name="User";Expression={$_.UserId}}, @{Name="Event";Expression={(($_.message).replace("`n", " ")).replace("`t"," ")}}, @{Name="Properties";Expression={([string]::Join(" - ",$_.properties.value)).replace(',',';')}}, @{Name="Record";Expression={$_.RecordID}}, @{Name="LogSource";Expression={$_.logname}}, @{Name="LogSourceType";Expression={$_.ProviderName}},@{Name="Machine";Expression={$_.MachineName}}
	}
}


#records in each csv split
$splitrecs = 1200000

function split-csv {
<#
	.SYNOPSIS
		Break up long csv into chunks that fit in Excel 
	.DESCRIPTION
		Break up long csv into chunks that fit in Excel (1,200,000 log records) 
	.Parameter logfile
		Name of the csv file to split into chunks
	.NOTES
	Author: Tom Willett 
	Date: 8/29/2021
#>
Param([Parameter(Mandatory=$True)][string]$logfile)

$fl = get-item $logfile
$base = $fl.basename
$dir = $fl.directoryname

import-csv $fl.fullname | select -first $splitrecs | export-csv -notype ($dir + $base + '1.csv')
import-csv $fl.fullname | select -skip $splitrecs -first $splitrecs | export-csv -notype ($dir + $base + '2.csv')
import-csv $fl.fullname | select -skip ($splitrecs*2) | export-csv -notype ($dir + $base + '3.csv')
}

function get-linuxlogs {
<#

.SYNOPSIS

Convert a linux log to a powershell object

.DESCRIPTION

Reads a standard linux log, converts it to a PowerShell object with DateTime, Server, LogSource, LogType, Data.

.PARAMETER LogFile

Logfile is required -- the path to the log file.

.EXAMPLE

 get-LinuxLogs c:\temp\secure

 Parse the log file called secure and display the results.
 
.EXAMPLE

 get-LinuxLogs.ps1 c:\temp\secure | export-csv -notypeinformation secure.csv

 Parse the log file called secure and export it to secure.csv.

.EXAMPLE
 dir *.log | get-LinuxLogs | export-csv -notype logs.csv
 
 Parse all the linux logs and export to logs.csv
 
.NOTES

Author: Tom Willett 
Date: 2/26/2015

#>

	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True)][string]$LogFile)

	process {
		write-host "Processing " $logfile
		$log = get-content $logfile
		foreach ($line in $log) {
			if ($line -match '(\S{3} {1,2}\d+ \d\d:\d\d:\d\d) (\S+) (\S+:) (.+)' ) {
				$temp = "" | Select DateTime, Machine, LogSource, LogSourceType, Event
				$temp.DateTime = $matches[1]
				$temp.Machine = $matches[2]
				$temp.LogSourceType = $matches[3]
				$temp.Event = $matches[4]
				$temp.LogSource = $LogFile
				write-output $temp
			}
		}
	}
}

function get-utmp {
<#
 
.SYNOPSIS
 
Parse utmp, wtmp and btmp files from linux
 
.DESCRIPTION

Parse utmp, wtmp and btmp files from linux.  It does timezone conversion of the times.
It requires the companion script utmp-parser.ps1.  The output is DateTime, Utype, 
ProcessID, Device, User, HostName, Addr, Session, Note, LogName, LogPath.

.Parameter uTmpFile

The utmp file to parse-taskfile

.Parameter tz

The time zone to convert the date/times to.  See list-timezones.ps1 to get the time zone names.

.Parameter btmp

Set this value to $true if processing a btmp file or if the file is named btmp it will detect it 
automatically.

.EXAMPLE
 
.\get-utmp.ps1 d:\btmp

Parses the contents of btmp and displays it on the console.
 
.NOTES

Author: Tom Willett 
Date: 3/2/2015

#>

	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True)][string]$uTmpFile,
		[Parameter(Mandatory=$True,ValueFromPipeline=$false)][string]$tz,
		[Parameter(Mandatory=$False,ValueFromPipeline=$false)][boolean]$btmp=$false)

	process {
		write-host "Processing " $uTmpFile
		$dt = get-childitem $uTmpFile
		get-content $uTmpFile -encoding byte -readcount 384 | utmp-parser -btmp $btmp -logname $dt.name -logpath $dt.DirectoryName -tz $tz
	}
}

function utmp-parser {
<#
 
.SYNOPSIS
 
Parse utmp, wtmp and btmp files from linux
 
.DESCRIPTION

Parse utmp, wtmp and btmp files from linux.  It does timezone conversion of the times.
This is an intermediate script it expects the data to be sent to it in 384 byte chuncks
for parsing.

.NOTES

Author: Tom Willett 
Date: 3/2/2015

#>

	Param([Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelinebyPropertyName=$true)][byte[]]$uTemp,
		[boolean]$btmp, [string]$logName, [string]$LogPath, [string]$tz)

	begin {
		$pidTable = @{}
	}

	process {
		function get_utType {
			Param([Parameter(Mandatory=$True)][int]$Data)
			switch ($Data)
			{
				0 {"empty"}        # No valid user accounting information
				1 {"Run Level"}    # The system's runlevel changed
				2 {"Boot Time"}    # Time of system boot
				3 {"New Time"}     # Time after system clock changed
				4 {"Old Time"}     # Time when system clock changed
				5 {"Init"}         # Process spawned by the init process
				6 {"Login"}        # Session leader of a logged in user
				7 {"User Process Start"} # Normal process
				8 {"Process End"}  # Terminated process
				9 {"Accounting"}   # Accounting
			}
		}
		if ($logName -eq "btmp") { $btmp = $true }
		$ErrorActionPreference = "SilentlyContinue"
		$ptr=0
		$tmp = "" | select "DateTime","Utype","ProcessID","Device","User","HostName","Addr","Session","Note","LogName", "LogPath"
		$utType = [bitconverter]::touint32($utemp,$ptr)
		$tmp.Utype = get_utType($utType)
		$ptr += 4
		$tmp.ProcessID = [bitconverter]::touint16($utemp,$ptr)
		$ptr += 4
		$StrEnd = $ptr
		While($utemp[$StrEnd] -ne 0x0) { $StrEnd += 1 }
		$tmp.Device = [System.Text.Encoding]::ASCII.GetString($utemp[$ptr..($StrEnd-1)])
		$ptr += 36
		$StrEnd = $ptr
		While($utemp[$StrEnd] -ne 0x0) { $StrEnd += 1 }
		$tmp.User = [System.Text.Encoding]::ASCII.GetString($utemp[$ptr..($StrEnd-1)])
		$ptr += 32
		$StrEnd = $ptr
		While($utemp[$StrEnd] -ne 0x0) { $StrEnd += 1 }
		$tmp.HostName = [System.Text.Encoding]::ASCII.GetString($utemp[$ptr..($StrEnd-1)])
		$ptr += 260
		$tmp.Session = [bitconverter]::touint32($utemp,$ptr)
		$ptr += 4
		$Utime = [bitconverter]::touint32($utemp,$ptr)
		[datetime]$origin = '1970-01-01 00:00:00'
		$cst = [system.timezoneinfo]::findsystemtimezonebyid($tz)
		$tmp.DateTime = [system.timezoneinfo]::converttimefromutc($origin.AddSeconds($Utime),$cst)
		$ptr += 8
		$tmp.Addr = $utemp[$ptr].tostring() + "." + $utemp[($ptr+1)].tostring() + "." + $utemp[($ptr+2)].tostring() + "." + $utemp[($ptr+3)].tostring()
		switch ($utType) 
		{
			0 { $tmp.note = "Not a valid entry" }
			1 { $tmp.note = "Run Level Change" }
			2 { $tmp.note = "Boot Time = " + $tmp.DateTime }
			3 { $tmp.note = "System Time changed to " + $tmp.DateTime }
			4 { $tmp.note = "System Time before date/time change = " + $tmp.DateTime }
			5 { $tmp.note = "Process spawned by Init(8) = " + $tmp.ProcessID }
			6 { $tmp.note = "Session leader Process for User Login = " + $tmp.processid }
			7 { 
				$tmp.note = "user=" + $tmp.User + "@" + $tmp.HostName + " (" + $tmp.addr +") ProcessID=" + $tmp.ProcessID + " logged in on device=" + $tmp.device
				$pidTable.add($tmp.ProcessID, $tmp.user)
			  }
			8 { 
				$tmp.user = $pidTable.get_item($tmp.processid)
				$tmp.note = "user=" + $tmp.user + " ProcessID=" + $tmp.ProcessID + " terminated (logged out) on device=" + $tmp.device
			  }
		}
		if ($btmp) {
			$tmp.note = "user=" + $tmp.User + "@" + $tmp.HostName + " (" + $tmp.addr +") log in failed on device=" + $tmp.device
		}
		$tmp.logname = $logname
		$tmp.logpath = $logpath
		write-output $tmp
	}
}

function Convert-IIStoCSV {
<#
	.Synopsis
		Convert IIS logs to CSV
	.Description
		Reads the header information from an IIS log and uses that to convert the log to CSV
	.Parameter logfile
		Log to Process
	.Example
		PS> convert-IIStoCSV iislog.txt | export-csv -notype iislog.cav
	.Example
		PS> dir *.log | convert-IIStoCSV | export-csv -notype iislogs.csv
	.NOTES
		Author: Tom Willett
		Date: 9/4/2021
#>
	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$Logfile)
	process {
		$f = dir $logfile
		((sls '#Fields:' $f.fullname).line).Substring(9) > tmp.csv
		sls -notmatch '^#' $f.fullname | %{$_.line} >> tmp.csv
		import-csv tmp.csv -delim ' ' | export-csv -notype -append ($f.basename + '.csv')
		rm tmp.csv
	}
}

function get-ipfromfile {
<#
	.Synopsis
		Extracts all IP addresses from text file
	.Description
		Extracts all IP addresses from text file using a regex.
	.Parameter filename
		Filename containing IP addresses
	.Example
		PS> get-ipfromfile log.csv > ips.txt
	.Example
		PS> dir *.csv | get-ipfromfile > ips.txt
	.NOTES
		Author: Tom Willett
		Date: 9/5/2021
#>
	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$filename)
	process {
		sls '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' -allmatches $filename | %{$_.matches} | %{$_.value}
	}
}

# Global variables
#desired size of split file - this reads by line so it might be a little larger.
$splitSize = 500000000

function open-matches {
	<#
			.Synopsis
					Open files found with sls
			.Description
					Open files found with sls
			.Parameter match
					Match Info from SLS
			.NOTES
				Author: Tom Willett
				Date: 1/7/2022
				V0.1
	#>

	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][Microsoft.PowerShell.Commands.MatchInfo]$match)

	begin {
		$s = @()
	}
	process {
		$s += $match.path
	}
	end {
		$s | select -unique | %{& $_}	
	}
}

function out-utf8 {
<#

.SYNOPSIS

Output to a file utf8 no bom

.DESCRIPTION

This uses the dot net file writing routines to write the file utf8 no bom always append

.PARAMETER outFile

The file to which the data will be appended

.EXAMPLE     
    type text.txt | out-utf8 c:\example.txt
	takes the text from text.txt and writes it to example.txt encoded utf8 no bom

.NOTES
	
 Author: Tom Willett
 Date: 7/22/2016

#>

Param([Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelinebyPropertyName=$False,Position=0)][string]$outFile,
  [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][AllowEmptyString()][string]$stuff,
  [switch]$append, [switch]$lf)
begin {
	[Environment]::CurrentDirectory = $pwd.path -replace 'Microsoft\.PowerShell\.Core\\FileSystem::',''
	$outFile = [IO.Path]::GetFullPath($outFile)
	if ($append) {
		$mode = [System.IO.FileMode]::Append
	} else {
		$mode = [System.IO.FileMode]::Create
	}
	$access = [System.IO.FileAccess]::Write
	$sharing = [IO.FileShare]::Read
	$fs = New-Object System.IO.FileStream($outFile, $mode, $access, $sharing)
	$streamOut = new-object System.IO.StreamWriter($fs) 
	if ($lf) {
		$streamOut.newline = "`n"
	}
}
process
{
	$streamOut.WriteLine($stuff)
}

end {
	$streamOut.Close()
}
}

function join-files {
<#

.SYNOPSIS

Join two files

.DESCRIPTION

Append inFile to outFile

.PARAMETER inFile

The file to appended (required)

.PARAMETER outFile

The file to which inFile will be appended

.EXAMPLE     
    .\join-files.ps1 c:\example1.txt c:\example2.txt
	Appends example1.txt to example2.txt

.NOTES
	
 Author: Tom Willett
 Date: 7/21/2016

#>

Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$inFile,
  [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$outFile)
process {
$inFile = (dir $inFile).fullname
$outFile = (dir $outFile).fullname
$streamIn = new-object System.IO.StreamReader($inFile)
$mode = [System.IO.FileMode]::Append
$access = [System.IO.FileAccess]::Write
$sharing = [IO.FileShare]::Read
$fs = New-Object System.IO.FileStream($outFile, $mode, $access, $sharing)
$streamOut = new-object System.IO.StreamWriter($fs) 
write-host "Appending $infile to $outfile"
while($streamIn.peek() -ge 0)
{
	$line = $streamIn.ReadLine()
	$streamOut.WriteLine($line)
}

$streamIn.Close()
$streamOut.Close()
}
}

function count-lines {
<#

.SYNOPSIS

Count the lines in a file

.DESCRIPTION

Count the lines in a file

.PARAMETER inFile

The file to count(required)


.EXAMPLE     
    .\count-lines.ps1 c:\example.txt 
	Counts the lines in example.txt

.NOTES
	
 Author: Tom Willett
 Date: 7/22/2016

#>

Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$inFile)
$inFile = (dir $inFile).fullname
$streamIn = new-object System.IO.StreamReader($inFile)
$lines = 0
while($streamIn.peek() -ge 0)
{
	$line = $streamIn.ReadLine()
	$lines += 1
}
$lines
$streamIn.Close()
}

# Global variables
#desired size of split file - this reads by line so it might be a little larger.
$splitSize = 500000000

function split-file {
<#

.SYNOPSIS

Split a file into smaller sized files

.DESCRIPTION

Split a file. This uses the .net file routines.  By default it splits it into 200mb chuncks.  You can change the size by altering the $bufSize variable.
The parts are named by adding 1 2 3 etc to the file name.

.PARAMETER inFile

The file to split (required)

.EXAMPLE     
    .\split.ps1 c:\image.mem
    Splits c:\image.mem into 200MB chuncks c:\image1.mem, c:\image2.mem, c:\image3.mem

.NOTES
	
 Author: Tom Willett
 Date: 7/21/2016

#>

Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$inFile)
$inFile = (dir $inFile).fullname
$streamIn = new-object System.IO.StreamReader($inFile)
$basename = $inFile.substring(0,$inFile.lastindexof("."))
$ext = $inFile.substring($inFile.lastindexof("."))
#desired size of split file - this reads by line so it might be a little larger.
#$splitSize = 900000000
$cnt = 0
$chk = 1
write-host "Splitting $inFile into chunks of size $splitSize"
while($streamIn.peek() -ge 0)
{
	$line = $streamIn.ReadLine()
	if ($cnt -le 0) {
		$t = 0
		$cnt = $splitSize
		$outFile = "$basename$chk$ext"
		$streamOut = new-object System.IO.StreamWriter($outFile)
	}
	$streamOut.WriteLine($line)
	$cnt -= ($line.length + 2)
	$t += 1
	if ($cnt -le 0) {
		$streamOut.Close()
		$chk += 1
		write-host "Wrote $outFile - $t lines"
	}
}

$streamIn.Close()
$streamOut.Close()
write-host "Wrote $outFile"
}

function remove-duplicates {
<#

.SYNOPSIS

Removes duplicates from a file.

.DESCRIPTION

Removes duplicates from a file.
This uses the hashset dot net routines to drastically speed up the process
Maximun size of a hashset is 47,995,853 items

.PARAMETER inFile

The input file name.

.PARAMETER outFile

The file to create with de duped content.

.EXAMPLE     
    .\remove-duplicates.ps1 bigfile.txt bigfilesorted.txt
    De dups bigfile.txt and puts the result in bigfilesorted.txt

.NOTES
	
 Author: Tom Willett
 Date: 7/25/2016

#>

Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$inFile,
  [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$outFile)

#Read file into hash to make unique
$inFile = (dir $inFile).fullname
[Environment]::CurrentDirectory = $pwd.path -replace 'Microsoft\.PowerShell\.Core\\FileSystem::',''
$outFile = [IO.Path]::GetFullPath($outFile)
write-host "Reading File $infile and deduping it."
$hs = new-object System.Collections.Generic.HashSet[string]
$reader = [System.IO.File]::OpenText($inFile)
$t = 0
try {
    while ($reader.peek() -ge 0)
    {
		$line = $reader.ReadLine()
        $t1 = $hs.Add($line)
		$t += 1
		if (($t % 1000000) -eq 0) {
			write-host "$t items"
		}
    }
}
finally {
    $reader.Close()
}
write-host "Writing deduped file $outFile - $t items"
try
{
    $f = New-Object System.IO.StreamWriter $outFile;
    foreach ($s in $hs)
    {
        $f.WriteLine($s);
    }
}
finally
{
    $f.Close();
}
[GC]::Collect()
}

function sort-file {
<#

.SYNOPSIS

Sorts a file

.DESCRIPTION

Sorts a file.
This uses the dot net routines to drastically speed up the process
Limited to 2,146,435,071 items to sort at once with memory limitations.
On a 32GB machine the limit is about 5,000,000,000 -- each time the array 
is expanded the allocation is twice the array size.

.PARAMETER inFile

The input file name.

.PARAMETER outFile

The file to create with sorted content.

.EXAMPLE     
    .\sort-file.ps1 bigfile.txt bigfilesorted.txt
    Sorts bigfile.txt and puts the result in bigfilesorted.txt

.NOTES
	
 Author: Tom Willett
 Date: 7/25/2016

#>
 
Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$inFile,
  [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$outFile)

#Read file into list and sort
$inFile = (dir $inFile).fullname
[Environment]::CurrentDirectory = $pwd.path -replace 'Microsoft\.PowerShell\.Core\\FileSystem::',''
$outFile = [IO.Path]::GetFullPath($outFile)
write-host "Reading file $inFile"
$ls = new-object system.collections.generic.List[string]
$reader = [System.IO.File]::OpenText($inFile)
$t = 0
try {
    while ($reader.peek() -ge 0)
    {
		$line = $reader.ReadLine()
        $t1 = $ls.Add($line)
		$t += 1
		if (($t % 1000000) -eq 0) {
			write-host "$t items"
		}
    }
}
finally {
    $reader.Close()
}
write-host "Sorting File $t items"
$ls.Sort();
write-host "Writing file $outFile"
try
{
    $f = New-Object System.IO.StreamWriter $outFile;
    foreach ($s in $ls)
    {
        $f.WriteLine($s);
    }
}
finally
{
    $f.Close();
}

}

function Get-FileEncoding {
<#
.SYNOPSIS
Gets file encoding.
.DESCRIPTION
The Get-FileEncoding function determines encoding by looking at Byte Order Mark (BOM).
.EXAMPLE
Get-ChildItem  *.ps1 | select FullName, @{n='Encoding';e={Get-FileEncoding $_.FullName}} | where {$_.Encoding -ne 'ASCII'}
This command gets ps1 files in current directory where encoding is not ASCII
.EXAMPLE
Get-ChildItem  *.ps1 | select FullName, @{n='Encoding';e={Get-FileEncoding $_.FullName}} | where {$_.Encoding -ne 'ASCII'} | foreach {(get-content $_.FullName) | set-content $_.FullName -Encoding ASCII}
Same as previous example but fixes encoding using set-content
.Notes
	Author: Tom Willett
	Date: 7/25/2016
#>
	[CmdletBinding()] Param (
	[Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)] [string]$Path
	)

	[byte[]]$byte = get-content -Encoding byte -ReadCount 4 -TotalCount 4 -Path $Path
	
	if ( $byte[0] -eq 0xef -and $byte[1] -eq 0xbb -and $byte[2] -eq 0xbf )
	{ Write-Output 'UTF8' }
	elseif ($byte[0] -eq 0xfe -and $byte[1] -eq 0xff)
	{ Write-Output 'UTF16 - little endian - UCS-2 LE BOM' }
	elseif ($byte[0] -eq 0xff -and $byte[1] -eq 0xfe)
	{ Write-Output 'UTF-16 - big endian (UCS-2 BE BOM)' }
	elseif ($byte[0] -eq 0 -and $byte[1] -eq 0 -and $byte[2] -eq 0xfe -and $byte[3] -eq 0xff)
	{ Write-Output 'UTF32 - big endian' }
	elseif ($byte[0] -eq 0xfe -and $byte[1] -eq 0xff -and $byte[2] -eq 0 -and $byte[3] -eq 0)
	{ Write-Output 'UTF32 - little endian' }
	elseif ($byte[0] -eq 0x2b -and $byte[1] -eq 0x2f -and $byte[2] -eq 0x76)
	{ Write-Output 'UTF7'}
	else
	{ Write-Output 'ASCII' }
}

function convert-base64 {
        param([Parameter(Mandatory=$True)][string][string]$data)
        [System.Text.Encoding]::utf8.GetString([System.Convert]::FromBase64String($data))
}


function get-ipgeo {
	<#
	.SYNOPSIS
	Get geoip information from ip-api.com.
	.DESCRIPTION
	This looks up an ip from api.ipgeolocation.io which returns reverse lookup and geoip information.
	Note you are limited to 1000 lookups a day with this.
	It outputs a PowerShell object.
	.PARAMETER ip
	The IP to look up.
	.EXAMPLE     
		.\get-ipgeo.ps1 8.8.8.8
		Returns the geoip informatino for 8.8.8.8 as a PowerShell object
	.EXAMPLE     
		type .\ip.txt |.\get-ipgeo.ps1 | export-csv -notypeinformation -append ip.csv
		Looks up the geoip information for all the ips in ip.txt (one per line) 
		It puts the output in ip.csv
	.NOTES
	 Author: Tom Willett
	 Date: 2/14/2015
	 Date: Updated 11/13/2018 to use ip-api.com
	 Date: Updated 11/5/2019 to use api.ipgeolocation.io
	 Date: Updated 9/6/2021 to use both
	#>

	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$ip)
	process {
		$ErrorActionPreference = "SilentlyContinue"
		#enter ipgeolocation.io API key to use ipgeolocation.io instead of ip-api.com
		#ip-geolocation.io limited to 1,000 a day 30,000 a month
		#ip-api.com limited to 45 requests a minute
		if ($apiKey) {
			$geoip = (new-object net.webclient).DownloadString("https://api.ipgeolocation.io/ipgeo?apiKey=$apiKey&ip=$ip")
			$geo = convertfrom-json $geoip
		} else {
			$geoip = convertfrom-json (new-object net.webclient).DownloadString("http://ip-api.com/json/" + $ip + "?fields=query,country,regionName,city,zip,timezone,isp,org,as,mobile,proxy,hosting")
			$geo = "" | select IP,Country,RegionName,City,Zip,Timezone,Isp,Org,AS,Mobile,Proxy,Hosting
			$geo.ip = $geoip.query
			$geo.Country = $geoip.Country
			$geo.RegionName = $geoip.RegionName
			$geo.City = $geoip.city
			$geo.Zip = $geoip.zip
			$geo.Timezone = $geoip.Timezone
			$geo.Isp = $geoip.Isp
			$geo.Org = $geoip.Org
			$geo.AS = $geoip.AS
			$geo.Mobile = $geoip.mobile
			$geo.Proxy = $geoip.Proxy
			$geo.hosting = $geoip.hosting
			#pause to keep from going over limitf
			Start-Sleep -m 1400
		}
		if ($geoip) {
			$geo
		}
	}
}

function convert-bashhistory {
	param([string]$fn)
	<#
	.SYNOPSIS
	Reads a bash history file with date/time records and converts them to readable data/time
	.DESCRIPTION
	Reads a bash history file with date/time records and converts them to readable data/time - sends output to standard out
	.PARAMETER $fn
	The bash history file
	.EXAMPLE
	ps> convert-bashhistory .\.bash_history > bash_history
	Note do not overwrite the original file 
	.NOTES
	Author: Tom Willett 
	Date: 7/10/2021
	#>

	gc $fn | %{if ($_.startswith('#')) {$ft = $_.substring(1);$l='#' + (([datetime] '1970-01-01Z').ToUniversalTime()).addseconds($ft)} else {$l=$_};$l}
}

function get-IISWebShell {
	<#
	.SYNOPSIS
	Analyze IIS logs looking for comman webshells
	.DESCRIPTION
	Analyze IIS logs looking for comman webshells
	.PARAMETER logfile
	Directory where IIS logs are kept - default of C:\inetpub\logs\
	.PARAMETER Percentile
	Looks for URIs with this percent of accesses - default 5%
	.EXAMPLE     
		.\get-IISWebShell -logDir <path to IIS log directory>  
		Analyzes logs in specified directory
	.NOTES
	 Author: NSA
	 Date: 4/21/2020
	#>

	Param  (  
		 [ValidateScript({Test-Path $_ -PathType 'Container'})][string]$logDir="C:\inetpub\logs\",
		 [ValidateRange(1,100)][int]$percentile=5  
	) 
	 
	If ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") 
		{ Throw "Use Full Language Mode (https://devblogs.microsoft.com/powershell/powershell-constrained-languagemode/)" } 
	 
	function analyzeLogs ( $field ) { 
		$URIs = @{} 
		$files = Get-ChildItem -Path $logDir -File -Recurse  
		If ($files.Length -eq 0)  { "No log files at the given location `n$($_)"; Exit } 
	 
		#Parse each file for relevant data. If data not present, continue to next file 
		$files | Foreach-Object {         Try { 
				$_.FullName
				$file = New-Object System.IO.StreamReader -Arg $_.FullName 
				$Cols = @() 
				While ($line = $file.ReadLine()) { 
					If ($line -like "#F*") { 
						$Cols = getHeaders($line)  
					} ElseIf ($Cols.Length -gt 0 -and $line -notlike "#*" ) { 
						$req = $line | ConvertFrom-Csv -Header $Cols  -Delimiter ' ' 
						If ( IrrelevantRequest $req ) { Continue; } 
						#If target field seen for this URI, update our data; otherwise create data object for this URI/field 
						If ($URIs.ContainsKey($req.uri) -and $URIs[ $req.uri ].ContainsKey($req.$field) )  
							{ $URIs[ $req.uri ].Set_Item( $req.$field, $URIs[ $req.uri ][ $req.$field ] + 1 ) }                     ElseIf ($URIs.ContainsKey($req.uri))   
							{ $URIs[ $req.uri ].Add( $req.$field, 1 ) } 
						Else  
							{ $URIs.Add($req.uri, @{ $($req.$field) = 1 }) } 
					} 
				} 
				$file.close() 
			} Catch { 
				Echo "Unable to parse log file $($_.FullName)`n$($_)" 
			} 
		} 
	 
		Echo "These URIs are suspicious because they have the least number of $($field)s requesting them:" 
		$nth_index = [math]::ceiling( ($URIs.Count) * ([decimal]$percentile / 100))  
	 
		#Count the unique fields for each URI 
		ForEach ($key in $($uris.keys)) { $uris.Set_Item( $key, $uris.$key.Count) } 
		 
		$i = 0; 
		$URIs.GetEnumerator() | sort Value | Foreach-Object { 
			$i++ 
			If($i -gt $nth_index) { Break; } 
			Echo "   $($_.Name) is requested by $($_.Value) $($field)(s)" 
	   } 
	} 
	 
	Function getHeaders ( $s ) { 
		$s = (($s.TrimEnd()) -replace "#Fields: ", "" -replace "-","" -replace "\(","" -replace "\)","") 
		$s = $s -replace "scstatus","status" -replace "csuristem","uri" -replace "csUserAgent","agent" -replace "cip","ip" 
		Return $s.Split(' ')  
	} 
	 
	Function IrrelevantRequest ( $req ) { 
		#Skip requests missing required fields 
		ForEach ($val in @("status", "uri","agent","ip")) 
			{ If ($val -notin $req.PSobject.Properties.Name) { Return $True} } 
		#We only care about requests where the server returned success (codes 200-299) 
		If ($req.status -lt 200 -or $req.scstatus -gt 299)  
			{ Return $True }     Return $False 
	} 
	 
	analyzeLogs "agent" 
	analyzeLogs "ip" 
}

function get-Teamslog {
	<#
	.SYNOPSIS
	Reads Teams logs and displays content 
	.DESCRIPTION
	Reads Microsoft Teams logs and extracts the recent content.
	.PARAMETER logFile
	logfile is required -- the path to User AppData\Roaming.
		By default it reads current user log files
	.EXAMPLE
	 .\get-Teamslog.ps1 c:\user\<username>\AppData\Roaming
	 Reads the Teams log file and extracts recent content
	.NOTES
	Author: Tom Willett 
	Date: 7/13/2021
	#>
	param([string]$logfile="$Env:AppData")

	$firstString = "<div"
	$secondString = "div>"

	$logfile += "\Microsoft\Teams\IndexedDB\https_teams.microsoft.com_0.indexeddb.leveldb\*.log"
	$text = Get-Content $logfile
	#Sample pattern
	$pattern = "(?<=$firstString).*?(?=$secondString)"
	$output = [regex]::Matches($text,$pattern).value
	$out = (($output -replace '</ >',"`r`n") -replace "></|><|`r`n`r`n","") | select -unique
	for($i=($out.length - 1);$i -ge 0;$i--) {$out[$i]}
}

function df {
	<#

	.SYNOPSIS
		Returns a 'df' style summary of disk space on a computer(s)
	.DESCRIPTION
		A crude powershell equivelant of the df command in linux.  It works on local and remote computers and will accept a list of computers.
		It uses wmi.

	.OUTPUTS
		A listing of each drive on all computers
		
	.EXAMPLE
		ps> .\df
		
	.NOTES

	 Author: Tom Willett 
	 Date:  3/23/2012

	#>

    $wmiq = "Select * From Win32_LogicalDisk Where Size != Null 
    And DriveType=3 Or DriveType=4"

    function Format-HumanReadable {
        param ($size)
        switch ($size) {
            {$_ -ge 1PB}{"{0:#.##'P'}" -f ($size / 1PB); break}
            {$_ -ge 1TB}{"{0:#.##'T'}" -f ($size / 1TB); break}
            {$_ -ge 1GB}{"{0:#.#'G'}" -f ($size / 1GB); break}
            {$_ -ge 1MB}{"{0:#'M'}" -f ($size / 1MB); break}
            {$_ -ge 1KB}{"{0:#'K'}" -f ($size / 1KB); break}
            default {"{0}" -f ($size) + "B"}
        }
    }
	
	
	Get-WmiObject -Query $wmiq |
    Format-Table -AutoSize @{Label="Vol";Expression={$_.DeviceID}},`
	@{Label="Label";Expression={$_.VolumeName}},`
    @{Label="Size";Expression={Format-HumanReadable `
    $_.Size};Align="Right"},`
    @{Label="Used";Expression={Format-HumanReadable `
    (($_.Size)-($_.FreeSpace))};Align="Right"},`
    @{Label="Avail";Expression={Format-HumanReadable `
    $_.FreeSpace};Align="Right"},`
    @{Label="Use%";Expression={"{0:#}" -f ((($_.Size)-($_.FreeSpace))`
    /($_.Size) * 100)};Align="Right"},@{Label="Type"`
    ;Expression={$_.FileSystem};Align="Center"}
}

function get-etllog {
	<#
	.SYNOPSIS
	Reads a windows etl file and converts it to a PowerShell Object
	.DESCRIPTION
	Reads a windows etl file and converts it to a PowerShell Object
	.PARAMETER logFile
	logfile is required -- the path to the log file.
	.EXAMPLE
	 get-etllog.ps1 C:\ProgramData\Microsoft\Windows Security Health\Logs\SHS-01192022-112816-7-1ff-22000.1.amd64fre.co_release.210604-1628.etl
	.NOTES
	Author: Tom Willett 
	Date: 3/7/2022
	#>

	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$FullName)


	$fext = [system.io.path]::getextension($FullName)
	$filter = @{Path="$FullName"}
	get-winevent -oldest:$true -filterhashtable $filter | select * | fl
}

function list-timezones {
	<#
	.SYNOPSIS     
		Retrieves the Time Zones on your computer and displays them in a Grid View.
	.DESCRIPTION   
		This uses the built in .net routines to display the timezones on your computer.
		It outputs it in GridView
	.NOTES     
		Author: Tom Willett
		Date: 8/28/2014
	.EXAMPLE     
		list-timezones.ps1
		Lists the timezones on your computer.
	#>

	[system.timezoneinfo]::getsystemtimezones() | out-gridview
}

function get-shodan {
<#
	.SYNOPSIS     
		Retrieves Shodan.io information about an IP
	.DESCRIPTION   
		Retrieves Shodan.io information about an IP using the shodan.io API
	.NOTES     
		Author: Tom Willett
	.EXAMPLE     
		get-shodan 192.168.0.1
		Retrieves shodan info about 192.168.0.1
	#>
	param([string]$ip)
	(invoke-webrequest -uri https://internetdb.shodan.io/$ip).content | convertfrom-json	
}

function parse-emailheaders {
	<#

	.SYNOPSIS

	Parse Email Headers

	.DESCRIPTION

	This script parses email headers and returns them in csv format.
	Date headers are converted to UTC -- Headers are reversed so oldest is first and numbered.

	.PARAMETER $headerFile

	The $headerFile paramater is required

	.EXAMPLE

	 .\parse-emailHeader.ps1 .\headers.txt

	 Parses the headers in .\headers.txt and outputs them in object format
	 
	.EXAMPLE

	 .\parse-emailHeader.ps1 .\headers.txt | export-csv -notypeinformation emailheaders.csv

	 Parses headers and exports them to emailheaders.csv in csv format
	 
	.EXAMPLE

	type headers.txt | .\parse-emailHeader.ps1 | export-csv -notypeinformation emailheaders.csv

	Parses the list of header files in headers.txt (format one file per line) and exports them
	to emailheaders.csv

	.NOTES

	Author: Tom Willett 
	Date: 11/8/2014

	#>

	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$headerFile)

	begin {
		$report = @()
	}

	process {
		function ParseDate {
			Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$dt)
			# Parse date and convert to utc
			$rawDate = $dt.Split(" ")
			$offset = [double]$rawDate[5].substring(0,3)
			$emailDate =[datetime]::parseexact($rawDate[1] + " " + $rawDate[2] + " " + $rawDate[3] + " " + $rawDate[4],"d MMM yyyy HH:mm:ss",$null)
			$emailDate = $emailDate.addhours($offset)
			return $emailDate.tostring()
		}
		$rawHeader = get-content $headerFile
		$from = ""
		$emailDate = ""
		$to = ""
		$subject = ""
		for ($i=0;$i -lt $rawHeader.length;$i++) {
			if ($rawHeader[$i].startswith("To:")) { $to = $rawHeader[$i].remove(0,3).trim().replace("<","").replace(">","") }
			if ($rawHeader[$i].startswith("Date:")) { $emailDate = ParseDate($rawHeader[$i].remove(0,5).trim()) }
			if ($rawheader[$i].startswith("Subject:")) { $subject = $rawHeader[$i].remove(0,8).trim() }
			if ($rawheader[$i].startswith("From:")) { $from = $rawHeader[$i].remove(0,5).trim() }
		}
		# now put them in the right order and parse out the headers	
		$tmp = ""
		$j = 1
		for ($i = $rawHeader.length; $i -gt 0; $i--) {
			if ($rawHeader[$i].length -gt 0) {
				$header = "" | select emailDate,Sequence,From,To,Subject,HeaderType,Body
				# continuation lines
				if (($rawHeader[$i].startswith(" ")) -or ($rawHeader[$i].startswith("`t"))) {
					$tmp = $tmp + " " + $rawHeader[$i].trim()
				} else {
					$header.emailDate = $emailDate
					$header.Sequence = $j
					$j++
					$header.From = $from
					$header.To = $to
					$header.Subject = $subject
					$header.HeaderType = $rawHeader[$i].substring(0,$rawHeader[$i].indexof(":"))
					$header.Body = $rawHeader[$i].substring($rawHeader[$i].indexof(":") + 1).trim()
					if (($header.HeaderType.endswith("Date")) -or ($header.HeaderType.endswith("date"))) { $header.Body = parseDate($header.Body) }
					$header.Body = $header.Body + " " + $tmp
					$tmp = ""
					$report += $header
				}
			}
		}
	}

	end {
		$report
	}	
}

$thisDirectory = (Split-Path -parent $MyInvocation.MyCommand.Definition)

new-alias pshelp show-pshelp

Export-ModuleMember -alias pshelp -variable splitSize, splitrecs -Function show-pshelp, get-Teamslog, get-IISWebShell, convert-bashhistory, get-ipgeo, convert-base64, get-eventlogs, split-csv, get-linuxlogs, get-utmp, Convert-IIStoCSV, get-ipfromfile, out-UTF8, join-files, split-file, count-lines, sort-file, remove-duplicates, ConvertTo-sortuniqueFile, get-fileEncoding, df, open-matches, list-timezones, get-shodan, get-etllog, parse-emailheaders
