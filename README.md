# YALP
Yet Another Log Parser

BLUF:  It is stupid fast, just try it, you will like it. Needs .NET 4.5 and Powershell.


TLDNR:
Logs are often the bane of a security practitioners’ existence. However, revisiting old shortcomings can have its rewards.

I will never forget I was working alongside Keven Murphy of SANS fame on a mass triage / threat hunting event for a Fortune 500. One of the exercises was pulling the security logs from 40,000 machines and parsing them for Scheduled Task creation events. It was early in the day and I was trying to be helpful when I was told not to worry about the evtx logs as they would have to process overnight. Now little did I know this was the start of a nagging urge to have better evtx log parsing. I slashed up a PowerShell script in about 10 min that was able to parse all those logs in about an hour. Not very performant but still better than overnight.

After that I played with PowerShell parsers off and on for my teams, but it was a recent layoff that allowed me to finally get this first pass.

Full disclosure: I am not a "Professional Coder" I hack things together and am generally a Jack of all Trades. You will find interesting code choices some that I will explain and some that I won’t. I appreciate all feedback.

YALP is written primarily in C#, however it is more useful to a responder if it is embedded as inline code in a PowerShell script. This allows for some simple parameter modification and being just a script, (even though it compiles anyway) it is more likely to be allowed in restrictive IR locations.

The Parser is designed to traverse the embedded XML blob from the event. There are XML formatting challenges that result in erratic behavior if a XML library is used. I hacked it to work for a semi-blind parse, I had something similar in PowerShell but as everyone who parses big logs in PowerShell knows that takes forever.

This parser currently parses a 90MB Security log into a collection of CSVs in less than 30 seconds. This was benchmarked on a Dell 5510 with a Corei7 and 32GB. The profile in Visual Studio shows that while the CPU peaks during some concurrent parsing, the RAM is never more than 300MB and again done in less than 30 seconds. Compare that to other parsers and you will be happy.

But wait there's more. These entries are designed to get not just the common fields like ID,LOG,Time,etc rather every effort has been put into extracting the full message body and address the issue of multiple 'DATA' fields colliding. For logs that have well defined key value pairs in the message block they should be extracted. However, in many application logs the extra data field is a bunch of formatted text and no tags. I had to strip all the tabs/newlines/returns to get the parsing to not break so those types of messages will be messy.

I also included some Powershell I made for polling performance data from VSphere and pushing them as a bulk update to ELK, this way the IR analyist can arrive with laptop in hand running a SOF-ELK stack and blow a million logs into some fast visualizations.
