# Forensics Help
This is a module I created with PowerShell Help and common functions I use when doing Computer Forensics

## The help file contains the following topics:

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

## The functions it contains are:

	df -- Show disk free space
    get-eventlogs -- Process windows event logs
    split-csv -- Break up long csv into chunks that fit in Excel
            $splitrecs = 1,200,000 - number of records per file - can be changed
    get-linuxlogs -- Process Linux event logs
    get-utmp -- Convert UTMP,BTMP,WTMP Linux files
    convert-IIStoCSV - Read IIS logs and convert them to csv files
    get-ipfromfile -- Pull IP addresses from a text file
    convert-base64 -- convert base64 encoded string
    convert-bashHistory -- Convert bash history files with date/times to human readable
    get-IISWebShell -- NSA routine looking for web shells
    get-ipgeo -- IP Geolocation using either ip-api.com or ip-geolocation
    get-teamslog -- reads recent history from Microsoft Teams
    **File handling routines using dot net routines for speed.**
    out-UTF8 -- outputs file in UTF8 no BOM -- always appends.
    join-files -- appends one file to another
    split-file -- splits a file by line into smaller sizes
            $splitsize initially set to 500,000,000 bytes but can be changed
    count-lines -- counts the lines in a file
    sort-file -- sort the lines in a file
    remove-duplicates -- remove duplicates from a file
    get-fileEncoding -- reads the bom of a file to get the encoding
    open-matches -- opens the files found with sls	

## Installation
Open PowerShell as administrator in the directory where the ForensicHelp directory resides and run
    import-module ForensicsHelp -force
