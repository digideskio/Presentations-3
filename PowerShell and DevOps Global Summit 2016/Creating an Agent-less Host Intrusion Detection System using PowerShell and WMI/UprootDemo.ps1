break
#region Demo Prep

Get-WmiEventFilter | Remove-CimInstance
Get-WmiEventConsumer | Remove-CimInstance
Get-WmiEventSubscription | Remove-CimInstance

Remove-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name jared -Force -ErrorAction Ignore

Clear-Variable -Name ListeningPostIP -ErrorAction Ignore

Remove-Item -Path C:\Windows\Temp\test.log -Force -ErrorAction Ignore

Clear-Host

#endregion Demo Prep



#region Lateral Movement Detection

# Create an __EventFilter to detect the use of the Win32_Process class' Create method
$props = @{
    'Name' = 'EXT-ProcessCreateMethod';
    'EventNamespace' = 'root/cimv2';
    'Query' = 'SELECT * FROM MSFT_WmiProvider_ExecMethodAsyncEvent_Pre WHERE ObjectPath="Win32_Process" AND MethodName="Create"';
    'QueryLanguage' = 'WQL';
}
$Filter = New-CimInstance -Namespace root\subscription -ClassName __EventFilter -Arguments $props

# Create an NtEventLogEventConsumer to be used with EXT-ProcessCreateMethod Filter
$Template = @(
    'Lateral movement detected!',
    'LogSource: Uproot',
    'UprootEventType: ProcessCreateMethod',
    'Namespace: %Namespace%',
    'Object: %ObjectPath%',
    'Method Executed: %MethodName%',
    'Command Executed: %InputParameters.CommandLine%'
)
$props = @{
    Name = 'Nt_ProcessCreateMethod'
    Category = [UInt16]0
    EventType = [UInt32]2
    EventID = [UInt32]8
    SourceName = 'WSH'
    NumberOfInsertionStrings = [UInt32]$Template.Length
    InsertionStringTemplates = $Template
}
$Consumer = New-CimInstance -Namespace root\subscription -ClassName NtEventLogEventConsumer -Property $props

# Create a __FilterToConsumerBinding instance linking EXT-ProcessCreateMethod w/ Nt_ProcessCreatMethod
$props = @{
    Filter = [Ref]$Filter
    Consumer = [Ref]$Consumer
}               
New-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -Property $props


# Test detection of the Win32_Process class' Create method
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList @(,'cmd.exe')

# Check the application log for lateral movement event
Get-EventLog -LogName Application -Source WSH | 
    Where-Object {$_.Message -eq 'Lateral movement detected!'} |
    Select-Object -ExpandProperty ReplacementStrings

#endregion Lateral Movement Detection

#region Generic WmiEvent

# Use WmiEvent module to make a filter and nteventlogeventconsumer to monitor process creation

Get-Help New-WmiEventFilter

Get-Help New-WmiEventConsumer

Get-Help New-NtEventLogEventConsumer

Get-Help New-WmiEventSubscription

#endregion Generic WmiEvent

#region Registry Persistence

#psEdit $UprootPath\Filters\INT-StartupCommandCreation.ps1
psEdit $UprootPath\Filters\INT-StartupCommandCreation.ps1
. $UprootPath\Filters\INT-StartupCommandCreation.ps1
New-WmiEventFilter @props

psEdit $UprootPath\Consumers\Nt_StartupCommandCreation.ps1
. $UprootPath\Consumers\Nt_StartupCommandCreation.ps1
New-WmiEventConsumer @props

# Store arguments for New-WmiEventSubscriptions
$props = @{
    FilterName = 'INT-StartupCommandCreation'
    ConsumerType = 'NtEventLogEventConsumer'
    ConsumerName = 'Nt_StartupCommandCreation'
}

# Create __FilterToConsumerBinding instance for INT-StartupCommandCreation/Nt_StartupCommandCreation
New-WmiEventSubscription @props


# Test detection of registry persistence
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name jared -Value cmd.exe

# Check event log for Uproot notification
Get-EventLog -LogName Application -Source WSH | 
    Where-Object {$_.Message -eq 'AutoStart Entry Added!'} |
    Select-Object -ExpandProperty ReplacementStrings

#endregion

#region AS_GenericHTTP

psEdit $UprootPath\Consumers\AS_GenericHTTP.ps1

. $UprootPath\Filters\EXT-ProcessStartTrace
$props
New-WmiEventFilter @props

. $UprootPath\Consumers\AS_GenericHTTP.ps1
$props
New-WmiEventConsumer @props

$props = @{
    FilterName = 'EXT-ProcessStartTrace' 
    ConsumerType = 'ActiveScriptEventConsumer'
    ConsumerName = 'AS_GenericHTTP'
}
New-WmiEventSubscription @props

#endregion AS_GenericHTTP

#region Enumerating Permanent Wmi Event Subscriptions

# Enumerating Filters
Get-WmiEventFilter

# Enumerating Consumers
Get-WmiEventConsumer
Get-ActiveScriptEventConsumer
Get-NtEventLogEventConsumer
Get-NtEventLogEventConsumer -Name Nt_StartupCommandCreation
Get-LogFileEventConsumer

# Enumerating Subscriptions (Bindings)
Get-WmiEventSubscription

# Cleanup all Subscriptions
Get-WmiEventConsumer | Remove-CimInstance
Get-WmiEventFilter | Remove-CimInstance
Get-WmiEventSubscription | Remove-CimInstance

#endregion Enumerating Permanent Wmi Event Subscriptions

#region Register-PermanentWmiEvent

Get-Help Register-PermanentWmiEvent

$props = @{
    Name = 'MyFirstSubscription'
    EventNamespace = 'root\cimv2'
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
    QueryLanguage = 'WQL'
    Filename = 'C:\Windows\temp\test.log' 
    Text = "%TargetInstance%"
}
Register-PermanentWmiEvent @props

Get-WmiEventFilter -Name MyFirstSubscription
Get-LogFileEventConsumer -Name MyFirstSubscription

Start-Process -FilePath C:\Windows\notepad.exe

Get-Content C:\Windows\temp\test.log -Wait

#endregion Register-PermanentWmiEvent

#region Install-UprootSignature

# Show what a Signature File looks like
psEdit $UprootPath\Signatures\EventLog.ps1

# Install Signatures
Install-UprootSignature -SigFile EventLog 

Get-WmiEventSubscription

#endregion Install-UprootSignature