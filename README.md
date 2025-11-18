# DEATHCon 2025 RMM Rodeo
This is a collection of KQL detection queries with accompanying artifacts for various RMM tools. I've copied below example execution of these KQL queries.

# HelpWire

### DNS Query
`HelpWire_DNSActivity.kql` query:

```
let DNSActivity = _ASim_Dns
    | where EventType == "Query"
    | where DnsQuery =~ "stun.helpwire.app"
    | project
        EventStartTime,
        SrcHostname,
        User,
        SrcProcessId,
        SrcProcessName,
        DnsQuery,
        DnsResponseName,
        DnsResponseCode;
DNSActivity
```

Output from execution of the HelpWire tool in Sentinel:

| EventStartTime [UTC]        | SrcHostname                   | User                       | SrcProcessId | SrcProcessName                                      | DnsQuery          | DnsResponseName | DnsResponseCode |
| --------------------------- | ----------------------------- | -------------------------- | ------------ | --------------------------------------------------- | ----------------- | --------------- | --------------- |
| 11/11/2025, 11:25:05.670 PM | smashtitle-SAND.deathmail.net | SMASHTITLE-SAND\azureadmin | 6896         | C:\Users\azureadmin\Downloads\HelpWire NCTA (2).exe | stun.helpwire.app | 184.72.211.115; | 0               |

Additionally, you can find Wireshark output for this DNS query in `HelpWire_DNS_Artifacts.csv`.

### Process Execution
`HelpWire_ProcessActivity.kql` query:
```
let ProcessActivity = _ASim_ProcessEvent
    | where EventType == "ProcessCreated"
    | where CommandLine has_all ("urlparam", "helpwire://?token=")
        or (CommandLine contains "netsh.exe" and CommandLine has_any ("HelpWire Client", "HelpWire Unattended Access", "helpwire.exe"))
        or (CommandLine contains "helpwire.exe" and CommandLine has_all ("/rdc", "--peer"))
    | project
        EventStartTime,
        DvcHostname,
        ActorUsername,
        ActingProcessName,
        CommandLine,
        TargetProcessName;
ProcessActivity
```

Output:


| EventStartTime [UTC]        | DvcHostname                   | ActorUsername              | ActingProcessName                                   | CommandLine                                                                                                                                                                             | TargetProcessName                                   |
| --------------------------- | ----------------------------- | -------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| 11/11/2025, 11:24:36.431 PM | smashtitle-SAND.deathmail.net | SMASHTITLE-SAND\azureadmin | C:\Users\azureadmin\Downloads\HelpWire NCTA (2).exe | ""C:\Windows\system32\netsh.exe"" advfirewall firewall add rule name=""HelpWire Client"" dir=in action=allow program=""C:\Users\azureadmin\Downloads\HelpWire NCTA (2).exe"" enable=yes | C:\Windows\SysWOW64\netsh.exe                       |
| 11/11/2025, 11:21:30.868 PM | smashtitle-SAND.deathmail.net | SMASHTITLE-SAND\azureadmin | C:\Windows\explorer.exe                             | ""C:\Program Files (x86)\HelpWire\Client\helpwire.exe"" urlparam ""helpwire://?token=Ekso9Kk8chJVqcYa9x1ratwIy0CsT60AwutJ4Y06&server=www.helpwire.app&quick=0"" silent                  | C:\Program Files (x86)\HelpWire\Client\helpwire.exe |

You can also find process execution artifacts in `HelpWire_ProcMon.csv`.

### Registry Activity
`HelpWire_RegistryActivity.kql` query:
```
let RegistryActivity = _ASim_RegistryEvent
    | where EventType == "RegistryValueSet"
    | where (RegistryKey has "HelpWire\\Client" and RegistryValue has "helpwire.exe") 
        or (RegistryKey has "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" and RegistryValue has "Electronic.HelpWire2.Chat-Client")
    | project 
        EventStartTime,
        Dvc,
        RegistryKey,
        RegistryValue,
        ActorUsername,
        ActingProcessName,
        ActingProcessId;
RegistryActivity
```

Output:

| EventStartTime [UTC]        | Dvc                           | RegistryKey                                                                                                                                                                         | RegistryValue | ActorUsername              | ActingProcessName                                   | ActingProcessId |
| --------------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | -------------------------- | --------------------------------------------------- | --------------- |
| 11/11/2025, 11:23:53.756 PM | smashtitle-SAND.deathmail.net | HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1565251941-2530725656-27758556-500\\Device\HarddiskVolume4\Program Files (x86)\HelpWire\Client | helpwire.exe  | SMASHTITLE-SAND\azureadmin | C:\Program Files (x86)\HelpWire\Client\helpwire.exe | 12828           |

You can also find Regshot output from diff-ing before/after snapshots of HelpWire MSI package installation in `HelpWire_Regshot_diff.txt`.
