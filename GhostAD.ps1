# Load required assemblies
try {
    # Try multiple methods to load the assemblies
    # Method 1: LoadWithPartialName (older but sometimes more reliable)
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")
    
    # Method 2: Add-Type
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    Add-Type -AssemblyName System.DirectoryServices
    
    # Verify the types are available
    $ldapConnectionType = [System.DirectoryServices.Protocols.LdapConnection]
    $ldapIdentifierType = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]
    
    Write-Host "Successfully loaded required assemblies." -ForegroundColor Green
} catch {
    Write-Host "Error loading assemblies - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please ensure the required .NET assemblies are available on this system." -ForegroundColor Red
}

# Function to safely get LDAP attribute value
function Get-LdapAttributeValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.SearchResultEntry]$Entry,
        
        [Parameter(Mandatory = $true)]
        [string]$AttributeName,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsInt,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsInt64,
        
        [Parameter(Mandatory = $false)]
        $DefaultValue
    )
    
    if ($Entry.Attributes.Contains($AttributeName) -and $Entry.Attributes[$AttributeName].Count -gt 0) {
        $value = $Entry.Attributes[$AttributeName][0]
        
        if ($AsInt) {
            return [int]$value
        } elseif ($AsInt64) {
            return [int64]$value
        } else {
            return $value
        }
    } else {
        return $DefaultValue
    }
}

# Function to safely get LDAP attribute value
function Get-LdapAttributeValue {
    param (
        [Parameter(Mandatory = $true)]
        $Entry,
        
        [Parameter(Mandatory = $true)]
        [string]$AttributeName,
        
        [Parameter(Mandatory = $false)]
        $DefaultValue = $null,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsInt,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsInt64,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsDateTime,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsFileTime
    )
    
    if ($Entry.Attributes.Contains($AttributeName) -and $Entry.Attributes[$AttributeName].Count -gt 0) {
        $value = $Entry.Attributes[$AttributeName][0]
        
        if ($AsInt) {
            return [int]$value
        }
        elseif ($AsInt64) {
            return [int64]$value
        }
        elseif ($AsDateTime) {
            try {
                $dateString = $value.ToString()
                if ($dateString -match "^\d{14}\.\d+Z$") {
                    # Handle format like "20230204090748.0Z"
                    $dateString = $dateString -replace "\.0Z$", "Z"
                    return [datetime]::ParseExact($dateString, "yyyyMMddHHmmssZ", [System.Globalization.CultureInfo]::InvariantCulture)
                } else {
                    # Standard parsing
                    return [datetime]$dateString
                }
            } catch {
                Write-Verbose "Failed to parse date - $dateString. Error - $($_.Exception.Message)"
                return $DefaultValue
            }
        }
        elseif ($AsFileTime) {
            try {
                return [datetime]::FromFileTime([int64]$value)
            } catch {
                Write-Verbose "Failed to convert filetime - $value. Error - $($_.Exception.Message)"
                return $DefaultValue
            }
        }
        else {
            return $value.ToString()
        }
    }
    else {
        return $DefaultValue
    }
}

Function Invoke-GhostAD {
<#
.SYNOPSIS
GhostAD - Lightweight Active Directory Enumeration Tool

.DESCRIPTION
GhostAD is a lightweight Active Directory enumeration tool for collecting information from domain environments, including domain information, domain trusts, password policies, admin accounts, etc.

.PARAMETER Domain
Domain to enumerate. If not specified, the current domain will be used.

.PARAMETER Server
Domain controller to connect to. If not specified, one will be automatically selected.

.PARAMETER Credential
Credentials for domain access.

.PARAMETER OutputFile
Path for the HTML report output. If not specified, no HTML file will be generated.

.EXAMPLE
Invoke-GhostAD
Run all enumeration modules in the current domain.

.EXAMPLE
Invoke-GhostAD -Domain 'ghostwolflab.com'
Enumerate the domain 'ghostwolflab.com'.

.EXAMPLE
Invoke-GhostAD -Domain 'ghostwolflab.com' -Server 'DC.ghostwolflab.com'
Enumerate the domain 'ghostwolflab.com' using the specified domain controller 'DC.ghostwolflab.com'.

.EXAMPLE
Invoke-GhostAD -Domain 'ghostwolflab.com' -Credential (Get-Credential)
Enumerate the domain 'ghostwolflab.com' using the provided credentials.

.EXAMPLE
Invoke-GhostAD -OutputFile "C:\Temp\ADReport.html"
Output results to the specified HTML file.
#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $false)]
        [String]$Domain,
        
        [Parameter(Position = 1, Mandatory = $false)]
        [String]$Server,
        
        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [String]$OutputFile
    )
    
    # Script start time
    $StartTime = Get-Date
    
    # Initialize HTML content if OutputFile is specified
    $HtmlHeader = ""
    $script:HtmlContent = ""
    $HtmlFooter = ""
    
    if ($OutputFile) {
        Write-Host "HTML output enabled. Output file: $OutputFile" -ForegroundColor Cyan
        $HtmlHeader = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GhostAD - Active Directory Enumeration Report</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --accent-color: #e74c3c;
            --background-color: #f8f9fa;
            --text-color: #333;
            --light-text: #6c757d;
            --border-color: #dee2e6;
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --info-color: #17a2b8;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--background-color);
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        h1 {
            font-size: 24px;
            margin-bottom: 10px;
        }
        
        h2 {
            font-size: 20px;
            margin: 20px 0 10px 0;
            color: var(--primary-color);
            border-bottom: 2px solid var(--secondary-color);
            padding-bottom: 5px;
        }
        
        h3 {
            font-size: 18px;
            margin: 15px 0 10px 0;
            color: var(--secondary-color);
        }
        
        .section {
            background-color: white;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .info {
            color: var(--info-color);
            padding: 5px 0;
        }
        
        .finding {
            color: var(--accent-color);
            font-weight: bold;
            padding: 5px 0;
        }
        
        .warning {
            color: var(--warning-color);
            font-weight: bold;
            padding: 5px 0;
        }
        
        .error {
            color: var(--danger-color);
            font-weight: bold;
            padding: 5px 0;
        }
        
        .indent {
            margin-left: 20px;
        }
        
        .double-indent {
            margin-left: 40px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        
        th, td {
            padding: 8px;
            text-align: left;
            border: 1px solid var(--border-color);
        }
        
        th {
            background-color: var(--primary-color);
            color: white;
        }
        
        tr:nth-child(even) {
            background-color: var(--background-color);
        }
        
        .summary {
            margin-top: 20px;
            padding: 10px;
            background-color: var(--primary-color);
            color: white;
            border-radius: 5px;
        }
        
        .timestamp {
            font-size: 14px;
            color: var(--light-text);
            margin-top: 5px;
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            padding: 10px;
            font-size: 14px;
            color: var(--light-text);
        }
    </style>
</head>
<body>
    <header>
        <h1>GhostAD - Active Directory Enumeration Report</h1>
        <div class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
    </header>
"@

        $HtmlFooter = @"
    <div class="footer">
        <p>GhostAD - Lightweight Active Directory Enumeration Tool</p>
        <p>Runtime: $((New-TimeSpan -Start $StartTime -End (Get-Date)).ToString())</p>
    </div>
</body>
</html>
"@
    }
    
    # Redefine logging function to support HTML output
    function Write-GhostADLog {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateSet("Info", "Success", "Warning", "Error", "Finding")]
            [String]$Level,
            
            [Parameter(Mandatory = $true)]
            [String]$Message
        )
        
        # Console output
        switch ($Level) {
            "Info" { 
                Write-Host $Message 
            }
            "Success" { 
                Write-Host $Message -ForegroundColor Green 
            }
            "Warning" { 
                Write-Host $Message -ForegroundColor Yellow 
            }
            "Error" { 
                Write-Host $Message -ForegroundColor Red 
            }
            "Finding" { 
                Write-Host $Message -ForegroundColor Magenta 
            }
        }
        
        # HTML output if OutputFile is specified
        if ($OutputFile) {
            # Determine indentation level based on spaces at the beginning of the message
            if ($Message -match "^\s{8,}") {
                # Double indented (8+ spaces)
                $HtmlClass = "double-indent"
                $Message = $Message -replace "^\s+", ""
            }
            elseif ($Message -match "^\s{4,}") {
                # Indented (4+ spaces)
                $HtmlClass = "indent"
                $Message = $Message -replace "^\s+", ""
            }
            else {
                # No indentation
                $HtmlClass = ""
            }
            
            # Add HTML formatted log entry
            $script:HtmlContent += "<div class=`"$Level $HtmlClass`">$Message</div>`n"
            Write-Verbose "Added to HTML: [$Level] $Message"
        }
    }
    
    # HTML section functions
    function New-GhostADHtmlSection {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [String]$Title
        )
        
        if ($OutputFile) {
            $script:HtmlContent += "<div class=`"section`">`n"
            $script:HtmlContent += "<h2>$Title</h2>`n"
        }
    }
    
    function Close-GhostADHtmlSection {
        if ($OutputFile) {
            $script:HtmlContent += "</div>`n"
        }
    }
    
    # Display script information
    Write-Host "GhostAD - Lightweight Active Directory Enumeration Tool" -ForegroundColor Cyan
    Write-Host "Start time: $($StartTime.ToString("yyyy-MM-dd HH:mm:ss"))" -ForegroundColor Cyan
    Write-Host ""
    
    # Build connection parameters
    $ConnectionParams = @{}
    if ($PSBoundParameters['Domain']) { $ConnectionParams['Domain'] = $Domain }
    if ($PSBoundParameters['Server']) { $ConnectionParams['Server'] = $Server }
    if ($PSBoundParameters['Credential']) { $ConnectionParams['Credential'] = $Credential }
    
    # Create HTML overview section
    New-GhostADHtmlSection -Title "Enumeration Overview"
    
    if ($PSBoundParameters['Domain']) {
        Write-GhostADLog -Level Info -Message "Target Domain: $Domain"
    }
    else {
        try {
            $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            Write-GhostADLog -Level Info -Message "Target Domain: $($CurrentDomain.Name) (Current Domain)"
        }
        catch {
            Write-GhostADLog -Level Error -Message "Failed to determine current domain - $($_.Exception.Message)"
            
            Write-GhostADLog -Level Error -Message "Please specify Domain parameter explicitly."
            return
        }
    }
    
    if ($PSBoundParameters['Server']) {
        Write-GhostADLog -Level Info -Message "Target Server: $Server"
    }
    
    if ($PSBoundParameters['Credential']) {
        Write-GhostADLog -Level Info -Message "Using specified credentials: $($Credential.UserName)"
    }
    
    Close-GhostADHtmlSection
    
    # Run domain information enumeration
    New-GhostADHtmlSection -Title "Domain Information"
    Write-GhostADLog -Level Info -Message "Enumerating domain information..."
    try {
        Get-GhostADDomain @ConnectionParams
    }
    catch {
        Write-GhostADLog -Level Error -Message "Domain information enumeration failed - $($_.Exception.Message)"
    }
    Close-GhostADHtmlSection
    
    # Run domain trust enumeration
    New-GhostADHtmlSection -Title "Domain Trusts"
    Write-GhostADLog -Level Info -Message "Enumerating domain trusts..."
    try {
        Get-GhostADTrusts @ConnectionParams
    }
    catch {
        Write-GhostADLog -Level Error -Message "Domain trust enumeration failed - $($_.Exception.Message)"
    }
    Close-GhostADHtmlSection
    
    # Run admin account enumeration
    New-GhostADHtmlSection -Title "Admin Accounts"
    Write-GhostADLog -Level Info -Message "Enumerating admin accounts..."
    try {
        Get-GhostADAdmins @ConnectionParams
    }
    catch {
        Write-GhostADLog -Level Error -Message "Admin account enumeration failed - $($_.Exception.Message)"
    }
    Close-GhostADHtmlSection
    
    # Run user account enumeration
    New-GhostADHtmlSection -Title "User Accounts"
    Write-GhostADLog -Level Info -Message "Enumerating user accounts..."
    try {
        Get-GhostADUsers @ConnectionParams
    }
    catch {
        Write-GhostADLog -Level Error -Message "User account enumeration failed - $($_.Exception.Message)"
    }
    Close-GhostADHtmlSection
    
    # Run computer account enumeration
    New-GhostADHtmlSection -Title "Computer Accounts"
    Write-GhostADLog -Level Info -Message "Enumerating computer accounts..."
    try {
        Get-GhostADComputers @ConnectionParams
    }
    catch {
        Write-GhostADLog -Level Error -Message "Computer account enumeration failed - $($_.Exception.Message)"
    }
    Close-GhostADHtmlSection
    
    # Run GPO enumeration
    New-GhostADHtmlSection -Title "Group Policy Objects"
    Write-GhostADLog -Level Info -Message "Enumerating Group Policy Objects..."
    try {
        Get-GhostADGPOs @ConnectionParams
    }
    catch {
        Write-GhostADLog -Level Error -Message "GPO enumeration failed - $($_.Exception.Message)"
    }
    Close-GhostADHtmlSection
    
    # Run AD CS enumeration
    New-GhostADHtmlSection -Title "Active Directory Certificate Services"
    Write-GhostADLog -Level Info -Message "Enumerating Active Directory Certificate Services..."
    try {
        Get-GhostADADCS @ConnectionParams
    }
    catch {
        Write-GhostADLog -Level Error -Message "AD CS enumeration failed - $($_.Exception.Message)"
    }
    Close-GhostADHtmlSection
    
    # Run ACL enumeration
    New-GhostADHtmlSection -Title "Access Control Lists"
    Write-GhostADLog -Level Info -Message "Enumerating important object ACLs..."
    try {
        Get-GhostADACLs @ConnectionParams
    }
    catch {
        Write-GhostADLog -Level Error -Message "ACL enumeration failed - $($_.Exception.Message)"
    }
    Close-GhostADHtmlSection
    
    # Output results
    if ($OutputFile) {
        try {
            # Generate default filename if none provided
            if ($OutputFile -eq $true -or $OutputFile -eq "") {
                $OutputFile = "GhostAD_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            }
            
            # Ensure we have content
            if ([string]::IsNullOrEmpty($script:HtmlContent)) {
                Write-GhostADLog -Level Warning -Message "No content was collected for the HTML report. Adding default message."
                $script:HtmlContent += "<div class='Info'>No Active Directory information was collected. This could be due to insufficient permissions or connectivity issues.</div>"
            }
            
            Write-Host "Generating HTML report..." -ForegroundColor Cyan
            Write-Host "HTML Header length: $(($HtmlHeader).Length)" -ForegroundColor Cyan
            Write-Host "HTML Content length: $(($script:HtmlContent).Length)" -ForegroundColor Cyan
            Write-Host "HTML Footer length: $(($HtmlFooter).Length)" -ForegroundColor Cyan
            
            $FullHtml = $HtmlHeader + $script:HtmlContent + $HtmlFooter
            Write-Host "Full HTML length: $(($FullHtml).Length)" -ForegroundColor Cyan
            
            # Ensure the output directory exists
            $OutputDir = Split-Path -Path $OutputFile -Parent
            if ($OutputDir -and -not (Test-Path -Path $OutputDir)) {
                New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
            }
            
            # Write the file with absolute path
            $AbsolutePath = $OutputFile
            if (-not [System.IO.Path]::IsPathRooted($OutputFile)) {
                $AbsolutePath = Join-Path -Path (Get-Location).Path -ChildPath $OutputFile
            }
            
            Write-Host "Writing HTML to: $AbsolutePath" -ForegroundColor Cyan
            $FullHtml | Out-File -FilePath $AbsolutePath -Encoding UTF8 -Force
            
            if (Test-Path -Path $AbsolutePath) {
                Write-Host "Results saved to: $AbsolutePath" -ForegroundColor Green
            } else {
                Write-Host "Failed to verify the output file exists: $AbsolutePath" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "Failed to save results to file - $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Error details: $($_.Exception.StackTrace)" -ForegroundColor Red
        }
    }
    
    # Script end time
    $EndTime = Get-Date
    $Duration = $EndTime.Subtract($StartTime)
    
    Write-Host ""
    Write-Host "GhostAD enumeration completed" -ForegroundColor Cyan
    Write-Host "End time: $($EndTime.ToString("yyyy-MM-dd HH:mm:ss"))" -ForegroundColor Cyan
    Write-Host "Runtime: $($Duration.ToString("hh\:mm\:ss"))" -ForegroundColor Cyan
}

# Domain object retrieval function
function Get-GhostADDomainObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]$Domain,
        
        [Parameter(Mandatory = $false)]
        [String]$Server,
        
        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential]$Credential
    )
    
    # Create LDAP connection
    $LdapConnection = $null
    $LdapServer = $Server
    
    if ([string]::IsNullOrEmpty($LdapServer)) {
        if ([string]::IsNullOrEmpty($Domain)) {
            try {
                # Try to get the logon server
                $LdapServer = (Get-Item Env:LOGONSERVER -ErrorAction SilentlyContinue).Value -replace '\\\\', ''
                
                # If that fails, try to get the domain from the computer's domain membership
                if ([string]::IsNullOrEmpty($LdapServer)) {
                    try {
                        $LdapServer = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
                    } catch {
                        Write-GhostADLog -Level Warning -Message "Failed to determine domain automatically - $($_.Exception.Message)"
                        
                        # Try another method
                        try {
                            $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
                            $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
                            $LdapServer = $CurrentDomain.Name
                        } catch {
                            Write-GhostADLog -Level Error -Message "Failed to determine domain using multiple methods - $($_.Exception.Message)"
                            return $null
                        }
                    }
                }
            } catch {
                Write-GhostADLog -Level Error -Message "Failed to determine domain automatically - $($_.Exception.Message)"
                Write-GhostADLog -Level Error -Message "Please specify Domain parameter explicitly."
                return $null
            }
        } else {
            $LdapServer = $Domain
        }
    }
    
    Write-Verbose "Using LDAP server: $LdapServer"
    
    try {
        $LdapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, 389)
        
        if ($Credential) {
            $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier, $Credential.GetNetworkCredential())
        } else {
            $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier)
        }
        
        $LdapConnection.SessionOptions.ProtocolVersion = 3
        $LdapConnection.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
        
        try {
            $LdapConnection.Bind()
        } catch {
            Write-GhostADLog -Level Error -Message "Failed to bind to LDAP server $LdapServer - $($_.Exception.Message)"
            return $null
        }
        
        # Get RootDSE to determine domain DN
        $RootDSERequest = New-Object System.DirectoryServices.Protocols.SearchRequest
        $RootDSERequest.DistinguishedName = ""
        $RootDSERequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
        $RootDSERequest.Filter = "(objectClass=*)"
        $RootDSERequest.Attributes.Add("defaultNamingContext")
        
        try {
            $RootDSEResponse = $LdapConnection.SendRequest($RootDSERequest)
            $DomainDN = $RootDSEResponse.Entries[0].Attributes["defaultNamingContext"][0].ToString()
            
            if ([string]::IsNullOrEmpty($DomainDN)) {
                Write-GhostADLog -Level Error -Message "Failed to get domain DN from RootDSE"
                return $null
            }
            
            # Get domain object
            $DomainRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
            $DomainRequest.DistinguishedName = $DomainDN
            $DomainRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
            $DomainRequest.Filter = "(objectClass=domain)"
            $DomainRequest.Attributes.Add("objectSid")
            $DomainRequest.Attributes.Add("distinguishedName")
            $DomainRequest.Attributes.Add("name")
            $DomainRequest.Attributes.Add("msDS-Behavior-Version")
            
            try {
                $DomainResponse = $LdapConnection.SendRequest($DomainRequest)
                
                if ($DomainResponse.Entries.Count -gt 0) {
                    $DomainEntry = $DomainResponse.Entries[0]
                    $DomainObject = New-Object PSObject
                    
                    # Get domain SID
                    if ($DomainEntry.Attributes.Contains("objectSid")) {
                        $SidBytes = $DomainEntry.Attributes["objectSid"][0]
                        $DomainSid = New-Object System.Security.Principal.SecurityIdentifier($SidBytes, 0)
                        $DomainObject | Add-Member -MemberType NoteProperty -Name "SID" -Value $DomainSid
                    } else {
                        $DomainObject | Add-Member -MemberType NoteProperty -Name "SID" -Value $null
                    }
                    
                    # Get domain DN
                    $DomainObject | Add-Member -MemberType NoteProperty -Name "DistinguishedName" -Value $DomainDN
                    
                    # Get domain name
                    if ($DomainEntry.Attributes.Contains("name")) {
                        $DomainName = $DomainEntry.Attributes["name"][0].ToString()
                        $DomainObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $DomainName
                    } else {
                        $DomainObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $null
                    }
                    
                    # Get domain functional level
                    if ($DomainEntry.Attributes.Contains("msDS-Behavior-Version")) {
                        $DomainLevel = [int]$DomainEntry.Attributes["msDS-Behavior-Version"][0]
                        $DomainObject | Add-Member -MemberType NoteProperty -Name "DomainMode" -Value $DomainLevel
                    } else {
                        $DomainObject | Add-Member -MemberType NoteProperty -Name "DomainMode" -Value $null
                    }
                    
                    return $DomainObject
                } else {
                    Write-GhostADLog -Level Error -Message "No domain object found at $DomainDN"
                    return $null
                }
            } catch {
                Write-GhostADLog -Level Error -Message "Failed to get domain object - $($_.Exception.Message)"
                return $null
            }
        } catch {
            Write-GhostADLog -Level Error -Message "Failed to get RootDSE - $($_.Exception.Message)"
            
            # Try an alternative method to get the domain DN
            try {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $LdapServer)
                $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                $DomainDN = $Domain.GetDirectoryEntry().distinguishedName
                
                if (-not [string]::IsNullOrEmpty($DomainDN)) {
                    # Create a simple domain object with just the DN
                    $DomainObject = New-Object PSObject
                    $DomainObject | Add-Member -MemberType NoteProperty -Name "DistinguishedName" -Value $DomainDN
                    $DomainObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $Domain.Name
                    $DomainObject | Add-Member -MemberType NoteProperty -Name "SID" -Value $null
                    $DomainObject | Add-Member -MemberType NoteProperty -Name "DomainMode" -Value $null
                    
                    return $DomainObject
                } else {
                    Write-GhostADLog -Level Error -Message "Failed to get domain DN using alternative method"
                    return $null
                }
            } catch {
                Write-GhostADLog -Level Error -Message "Failed to get domain information using alternative method - $($_.Exception.Message)"
                return $null
            }
        }
    } catch {
        Write-GhostADLog -Level Error -Message "Failed to create LDAP connection to $LdapServer - $($_.Exception.Message)"
        return $null
    }
}

# Domain information enumeration function
function Get-GhostADDomain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]$Domain,
        
        [Parameter(Mandatory = $false)]
        [String]$Server,
        
        [Parameter(Mandatory = $false)]
        [Switch]$SSL,
        
        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential]$Credential
    )
    
    # Build connection parameters
    $ConnectionParams = @{}
    if ($PSBoundParameters['Domain']) { $ConnectionParams['Domain'] = $Domain }
    if ($PSBoundParameters['Server']) { $ConnectionParams['Server'] = $Server }
    if ($PSBoundParameters['SSL']) { $ConnectionParams['SSL'] = $true }
    if ($PSBoundParameters['Credential']) { $ConnectionParams['Credential'] = $Credential }
    
    $LdapConnection = $null
    
    # Set connection parameters
    if ($Domain) {
        $LdapServer = $Domain
        if ($Server) {
            $LdapServer = $Server
        }
    }
    else {
        try {
            # Try to get current domain using multiple methods
            try {
                $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $LdapServer = $CurrentDomain.Name
            }
            catch {
                # Try alternative method
                $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
                $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
                $LdapServer = $CurrentDomain.Name
            }
            
            if ($Server) {
                $LdapServer = $Server
            }
        }
        catch {
            throw "Unable to determine current domain - $($_.Exception.Message)"
        }
    }
    
    # Set port
    $LdapPort = 389
    if ($SSL) {
        $LdapPort = 636
    }
    
    # Create LDAP connection with explicit constructor
    try {
        $LdapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $LdapPort)
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier)
    }
    catch {
        throw "Failed to create LDAP connection - $($_.Exception.Message)"
    }
    
    # Set credentials
    if ($Credential) {
        $LdapConnection.Credential = $Credential
    }
    
    # Set options
    if ($SSL) {
        $LdapConnection.SessionOptions.SecureSocketLayer = $true
    }
    $LdapConnection.SessionOptions.ProtocolVersion = 3
    
    try {
        $LdapConnection.Bind()
        
        # Get domain trusts
        try {
            $LdapConnection.Bind()
            
            # Get domain DN first
            try {
                $DomainObject = Get-GhostADDomainObject @ConnectionParams
                $DomainDN = $DomainObject.DistinguishedName
                
                if ([string]::IsNullOrEmpty($DomainDN)) {
                    throw "Unable to determine domain distinguished name"
                }
                
                # Create search request with proper base DN
                $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                $SearchRequest.DistinguishedName = $DomainDN
                $SearchRequest.Filter = "(objectClass=trustedDomain)"
                $SearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
                
                $Response = $LdapConnection.SendRequest($SearchRequest)
                
                if ($Response.Entries.Count -eq 0) {
                    Write-GhostADLog -Level Info -Message "No domain trusts found."
                    return
                }
                
                Write-GhostADLog -Level Info -Message "Found $($Response.Entries.Count) domain trust(s):"
                
                foreach ($Entry in $Response.Entries) {
                    $TrustName = $Entry.Attributes["name"][0].ToString()
                    $TrustPartner = $Entry.Attributes["trustPartner"][0].ToString()
                    $TrustDirection = [int]$Entry.Attributes["trustDirection"][0]
                    $TrustType = [int]$Entry.Attributes["trustType"][0]
                    $TrustAttributes = [int]$Entry.Attributes["trustAttributes"][0]
                    
                    # Trust Direction
                    $Direction = switch ($TrustDirection) {
                        1 { "Inbound" }
                        2 { "Outbound" }
                        3 { "Bidirectional" }
                        default { "Unknown" }
                    }
                    
                    # Trust Type
                    $Type = switch ($TrustType) {
                        1 { "Windows NT (Downlevel)" }
                        2 { "Active Directory" }
                        3 { "Kerberos Realm" }
                        4 { "DCE (Distributed Computing Environment)" }
                        default { "Unknown" }
                    }
                    
                    # Trust Attributes
                    $Attributes = @()
                    if ($TrustAttributes -band 0x00000001) { $Attributes += "Non-Transitive" }
                    if ($TrustAttributes -band 0x00000002) { $Attributes += "Uplevel Clients Only" }
                    if ($TrustAttributes -band 0x00000004) { $Attributes += "Quarantined Domain" }
                    if ($TrustAttributes -band 0x00000008) { $Attributes += "Forest Transitive" }
                    if ($TrustAttributes -band 0x00000010) { $Attributes += "Cross Organization" }
                    if ($TrustAttributes -band 0x00000020) { $Attributes += "Within Forest" }
                    if ($TrustAttributes -band 0x00000040) { $Attributes += "Treat as External" }
                    if ($TrustAttributes -band 0x00000080) { $Attributes += "Uses RC4 Encryption" }
                    if ($TrustAttributes -band 0x00000200) { $Attributes += "Cross Organization No TGT Delegation" }
                    if ($TrustAttributes -band 0x00000400) { $Attributes += "PIM Trust" }
                    
                    $AttributesStr = if ($Attributes.Count -gt 0) { $Attributes -join ", " } else { "None" }
                    
                    Write-GhostADLog -Level Info -Message "Trust Name: $TrustName"
                    Write-GhostADLog -Level Info -Message "  - Partner: $TrustPartner"
                    Write-GhostADLog -Level Info -Message "  - Direction: $Direction"
                    Write-GhostADLog -Level Info -Message "  - Type: $Type"
                    Write-GhostADLog -Level Info -Message "  - Attributes: $AttributesStr"
                    
                    # Security findings
                    if ($Direction -eq "Inbound" -or $Direction -eq "Bidirectional") {
                        Write-GhostADLog -Level Finding -Message "  - Security Risk: $Direction trust from $TrustPartner allows access to resources in this domain"
                    }
                    
                    if ($TrustAttributes -band 0x00000008) {
                        Write-GhostADLog -Level Finding -Message "  - Security Risk: Transitive trust can be used for lateral movement across forests"
                    }
                    
                    if ($TrustAttributes -band 0x00000080) {
                        Write-GhostADLog -Level Finding -Message "  - Security Risk: Trust uses weak RC4 encryption"
                    }
                    
                    $Trusts += [PSCustomObject]@{
                        Name = $TrustName
                        Partner = $TrustPartner
                        Direction = $Direction
                        Type = $Type
                        Attributes = $AttributesStr
                    }
                }
                
                return $Trusts
            }
            catch {
                Write-GhostADLog -Level Error -Message "Failed to enumerate domain trusts - $($_.Exception.Message)"
            }
        }
        catch {
            Write-GhostADLog -Level Error -Message "Failed to bind to LDAP server - $($_.Exception.Message)"
        }
    }
    catch {
        Write-GhostADLog -Level Error -Message "Failed to bind to LDAP server - $($_.Exception.Message)"
    }
}

# Administrator accounts enumeration function
function Get-GhostADAdmins {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]$Domain,
        
        [Parameter(Mandatory = $false)]
        [String]$Server,
        
        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential]$Credential
    )
    
    # Connection parameters
    $ConnectionParams = @{}
    if ($Domain) { $ConnectionParams.Domain = $Domain }
    if ($Server) { $ConnectionParams.Server = $Server }
    if ($Credential) { $ConnectionParams.Credential = $Credential }
    
    # Create LDAP connection
    $LdapConnection = $null
    $LdapServer = $Server
    
    if ([string]::IsNullOrEmpty($LdapServer)) {
        if ([string]::IsNullOrEmpty($Domain)) {
            $LdapServer = (Get-Item Env:LOGONSERVER -ErrorAction SilentlyContinue).Value -replace '\\\\', ''
        } else {
            $LdapServer = $Domain
        }
    }
    
    $LdapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, 389)
    
    if ($Credential) {
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier, $Credential.GetNetworkCredential())
    } else {
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier)
    }
    
    $LdapConnection.SessionOptions.ProtocolVersion = 3
    $LdapConnection.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
    
    try {
        $LdapConnection.Bind()
        
        # Get domain information first to get the domain DN
        $DomainObject = Get-GhostADDomainObject @ConnectionParams
        if ($null -eq $DomainObject) {
            Write-GhostADLog -Level Error -Message "Failed to get domain information"
            return
        }
        
        $DomainDN = $DomainObject.DistinguishedName
        if ([string]::IsNullOrEmpty($DomainDN)) {
            Write-GhostADLog -Level Error -Message "Failed to get domain DN"
            return
        }
        
        # Define privileged groups to check
        $HighPrivGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators"
        )
        
        # Get domain SID
        try {
            $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
            $SearchRequest.DistinguishedName = $DomainDN
            $SearchRequest.Filter = "(objectClass=domain)"
            $SearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
            $SearchRequest.Attributes.Add("objectSid")
            
            $Response = $LdapConnection.SendRequest($SearchRequest)
            
            if ($Response.Entries.Count -gt 0) {
                $Entry = $Response.Entries[0]
                
                if ($Entry.Attributes.Contains("objectSid")) {
                    $DomainSidBytes = $Entry.Attributes["objectSid"][0]
                    $DomainSid = New-Object System.Security.Principal.SecurityIdentifier($DomainSidBytes, 0)
                    
                    foreach ($GroupName in $HighPrivGroups) {
                        # Find the group
                        $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                        $SearchRequest.DistinguishedName = $DomainDN
                        $SearchRequest.Filter = "(&(objectCategory=group)(sAMAccountName=$GroupName))"
                        $SearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
                        $SearchRequest.Attributes.Add("distinguishedName")
                        
                        try {
                            $Response = $LdapConnection.SendRequest($SearchRequest)
                            
                            if ($Response.Entries.Count -gt 0) {
                                $GroupEntry = $Response.Entries[0]
                                $GroupDN = Get-LdapAttributeValue -Entry $GroupEntry -AttributeName "distinguishedName" -DefaultValue ""
                                
                                Write-GhostADLog -Level Info -Message "Enumerating '$GroupName' group members..."
                                
                                # Get enabled user members
                                $MemberSearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                                $MemberSearchRequest.DistinguishedName = $DomainDN
                                $MemberSearchRequest.Filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf=$GroupDN))"
                                $MemberSearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
                                $MemberSearchRequest.Attributes.Add("sAMAccountName")
                                $MemberSearchRequest.Attributes.Add("userAccountControl")
                                $MemberSearchRequest.Attributes.Add("pwdLastSet")
                                
                                try {
                                    $MemberResponse = $LdapConnection.SendRequest($MemberSearchRequest)
                                    
                                    if ($MemberResponse.Entries.Count -gt 0) {
                                        Write-GhostADLog -Level Finding -Message "Found $($MemberResponse.Entries.Count) enabled user accounts in '$GroupName' group:"
                                        
                                        foreach ($UserEntry in $MemberResponse.Entries) {
                                            $UserName = Get-LdapAttributeValue -Entry $UserEntry -AttributeName "sAMAccountName" -DefaultValue "Unknown"
                                            
                                            # Output user details
                                            Write-GhostADLog -Level Info -Message "  - $UserName"
                                        }
                                    } else {
                                        Write-GhostADLog -Level Info -Message "No enabled user accounts found in '$GroupName' group"
                                    }
                                } catch {
                                    Write-GhostADLog -Level Warning -Message "Failed to enumerate members of '$GroupName' group - $($_.Exception.Message)"
                                }
                            } else {
                                Write-GhostADLog -Level Info -Message "'$GroupName' group not found"
                            }
                        } catch {
                            Write-GhostADLog -Level Warning -Message "Failed to find '$GroupName' group - $($_.Exception.Message)"
                        }
                    }
                }
            }
        } catch {
            Write-GhostADLog -Level Warning -Message "Failed to get domain SID - $($_.Exception.Message)"
        }
        
        # Check for users with AdminCount=1
        Write-GhostADLog -Level Info -Message "Enumerating users with AdminCount=1..."
        
        try {
            $AdminCountSearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
            $AdminCountSearchRequest.DistinguishedName = $DomainDN
            $AdminCountSearchRequest.Filter = "(&(objectCategory=person)(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            $AdminCountSearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
            $AdminCountSearchRequest.Attributes.Add("sAMAccountName")
            
            $AdminCountResponse = $LdapConnection.SendRequest($AdminCountSearchRequest)
            
            if ($AdminCountResponse.Entries.Count -gt 0) {
                Write-GhostADLog -Level Info -Message "Users with AdminCount=1 ($($AdminCountResponse.Entries.Count)):"
                
                foreach ($UserEntry in $AdminCountResponse.Entries) {
                    $UserName = Get-LdapAttributeValue -Entry $UserEntry -AttributeName "sAMAccountName" -DefaultValue "Unknown"
                    
                    # Output user details
                    Write-GhostADLog -Level Info -Message "  - $UserName"
                }
            } else {
                Write-GhostADLog -Level Info -Message "No users with AdminCount=1 found"
            }
        } catch {
            Write-GhostADLog -Level Warning -Message "Failed to enumerate users with AdminCount=1 - $($_.Exception.Message)"
        }
    } catch {
        Write-GhostADLog -Level Error -Message "Failed to enumerate administrator accounts - $($_.Exception.Message)"
    }
}

# User accounts enumeration function
function Get-GhostADUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]$Domain,
        
        [Parameter(Mandatory = $false)]
        [String]$Server,
        
        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential]$Credential
    )
    
    # Connection parameters
    $ConnectionParams = @{}
    if ($Domain) { $ConnectionParams.Domain = $Domain }
    if ($Server) { $ConnectionParams.Server = $Server }
    if ($Credential) { $ConnectionParams.Credential = $Credential }
    
    try {
        # Get domain information first to get the domain DN
        $DomainObject = Get-GhostADDomainObject @ConnectionParams
        if ($null -eq $DomainObject) {
            Write-GhostADLog -Level Error -Message "Failed to get domain information"
            return
        }
        
        $DomainDN = $DomainObject.DistinguishedName
        if ([string]::IsNullOrEmpty($DomainDN)) {
            Write-GhostADLog -Level Error -Message "Failed to get domain DN"
            return
        }
        
        # Create LDAP connection
        $LdapServer = $Server
        
        if ([string]::IsNullOrEmpty($LdapServer)) {
            if ([string]::IsNullOrEmpty($Domain)) {
                $LdapServer = (Get-Item Env:LOGONSERVER -ErrorAction SilentlyContinue).Value -replace '\\\\', ''
                if ([string]::IsNullOrEmpty($LdapServer)) {
                    try {
                        $LdapServer = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
                    } catch {
                        Write-GhostADLog -Level Error -Message "Failed to determine domain automatically - $($_.Exception.Message)"
                        return
                    }
                }
            } else {
                $LdapServer = $Domain
            }
        }
        
        $LdapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, 389)
        
        if ($Credential) {
            $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier, $Credential.GetNetworkCredential())
        } else {
            $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier)
        }
        
        $LdapConnection.SessionOptions.ProtocolVersion = 3
        $LdapConnection.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
        
        $LdapConnection.Bind()
        
        Write-GhostADLog -Level Info -Message "Enumerating user accounts..."
        
        # Get user accounts
        $UserSearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
        $UserSearchRequest.DistinguishedName = $DomainDN
        $UserSearchRequest.Filter = "(&(objectCategory=person)(objectClass=user))"
        $UserSearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
        $UserSearchRequest.Attributes.Add("sAMAccountName")
        $UserSearchRequest.Attributes.Add("userAccountControl")
        $UserSearchRequest.Attributes.Add("pwdLastSet")
        
        $UserResponse = $LdapConnection.SendRequest($UserSearchRequest)
        
        $TotalUsers = $UserResponse.Entries.Count
        $EnabledUsers = 0
        $DisabledUsers = 0
        $PasswordNeverExpires = 0
        $NoPasswordRequired = 0
        
        foreach ($UserEntry in $UserResponse.Entries) {
            $UserAccountControl = Get-LdapAttributeValue -Entry $UserEntry -AttributeName "userAccountControl" -AsInt -DefaultValue 0
            
            # Check if user is enabled
            $UserEnabled = !(($UserAccountControl -band 2) -eq 2)
            
            if ($UserEnabled) {
                $EnabledUsers++
            } else {
                $DisabledUsers++
            }
            
            # Check for password never expires
            if (($UserAccountControl -band 0x10000) -eq 0x10000) {
                $PasswordNeverExpires++
            }
            
            # Check for no password required
            if (($UserAccountControl -band 0x20) -eq 0x20) {
                $NoPasswordRequired++
            }
        }
        
        Write-GhostADLog -Level Info -Message "Total user accounts: $TotalUsers"
        Write-GhostADLog -Level Info -Message "Enabled user accounts: $EnabledUsers"
        Write-GhostADLog -Level Info -Message "Disabled user accounts: $DisabledUsers"
        Write-GhostADLog -Level Finding -Message "User accounts with 'Password Never Expires': $PasswordNeverExpires"
        Write-GhostADLog -Level Finding -Message "User accounts with 'No Password Required': $NoPasswordRequired"
        
        # Check for users with password never expires
        if ($PasswordNeverExpires -gt 0) {
            Write-GhostADLog -Level Info -Message "Users with 'Password Never Expires' flag:"
            
            $NeverExpiresRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
            $NeverExpiresRequest.DistinguishedName = $DomainDN
            $NeverExpiresRequest.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
            $NeverExpiresRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
            $NeverExpiresRequest.Attributes.Add("sAMAccountName")
            $NeverExpiresRequest.Attributes.Add("userAccountControl")
            
            try {
                $NeverExpiresResponse = $LdapConnection.SendRequest($NeverExpiresRequest)
                
                for ($i = 0; $i -lt [Math]::Min($NeverExpiresResponse.Entries.Count, 10); $i++) {
                    $UserEntry = $NeverExpiresResponse.Entries[$i]
                    $UserName = Get-LdapAttributeValue -Entry $UserEntry -AttributeName "sAMAccountName" -DefaultValue "Unknown"
                    $UserAccountControl = Get-LdapAttributeValue -Entry $UserEntry -AttributeName "userAccountControl" -DefaultValue 0
                    $UserEnabled = !([int]$UserAccountControl -band 2)
                    $UserStatus = if ($UserEnabled) { "Enabled" } else { "Disabled" }
                    
                    Write-GhostADLog -Level Info -Message "  - $UserName ($UserStatus)"
                }
                
                if ($NeverExpiresResponse.Entries.Count > 10) {
                    Write-GhostADLog -Level Info -Message "  ... and $($NeverExpiresResponse.Entries.Count - 10) more"
                }
            } catch {
                Write-GhostADLog -Level Warning -Message "Failed to enumerate users with 'Password Never Expires' - $($_.Exception.Message)"
            }
        }
        
        # Check for users with no password required
        if ($NoPasswordRequired -gt 0) {
            Write-GhostADLog -Level Info -Message "Users with 'No Password Required' flag:"
            
            $NoPasswordRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
            $NoPasswordRequest.DistinguishedName = $DomainDN
            $NoPasswordRequest.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
            $NoPasswordRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
            $NoPasswordRequest.Attributes.Add("sAMAccountName")
            $NoPasswordRequest.Attributes.Add("userAccountControl")
            
            try {
                $NoPasswordResponse = $LdapConnection.SendRequest($NoPasswordRequest)
                
                for ($i = 0; $i -lt [Math]::Min($NoPasswordResponse.Entries.Count, 10); $i++) {
                    $UserEntry = $NoPasswordResponse.Entries[$i]
                    $UserName = Get-LdapAttributeValue -Entry $UserEntry -AttributeName "sAMAccountName" -DefaultValue "Unknown"
                    $UserAccountControl = Get-LdapAttributeValue -Entry $UserEntry -AttributeName "userAccountControl" -DefaultValue 0
                    $UserEnabled = !([int]$UserAccountControl -band 2)
                    $UserStatus = if ($UserEnabled) { "Enabled" } else { "Disabled" }
                    
                    Write-GhostADLog -Level Info -Message "  - $UserName ($UserStatus)"
                }
                
                if ($NoPasswordResponse.Entries.Count > 10) {
                    Write-GhostADLog -Level Info -Message "  ... and $($NoPasswordResponse.Entries.Count - 10) more"
                }
            } catch {
                Write-GhostADLog -Level Warning -Message "Failed to enumerate users with 'No Password Required' - $($_.Exception.Message)"
            }
        }
    } catch {
        Write-GhostADLog -Level Error -Message "Failed to enumerate user accounts - $($_.Exception.Message)"
    }
}

# Computer accounts enumeration function
function Get-GhostADComputers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]$Domain,
        
        [Parameter(Mandatory = $false)]
        [String]$Server,
        
        [Parameter(Mandatory = $false)]
        [Switch]$SSL,
        
        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential]$Credential
    )
    
    # Build connection parameters
    $ConnectionParams = @{}
    if ($PSBoundParameters['Domain']) { $ConnectionParams['Domain'] = $Domain }
    if ($PSBoundParameters['Server']) { $ConnectionParams['Server'] = $Server }
    if ($PSBoundParameters['SSL']) { $ConnectionParams['SSL'] = $true }
    if ($PSBoundParameters['Credential']) { $ConnectionParams['Credential'] = $Credential }
    
    try {
        # Get domain information first to get the domain DN
        $DomainObject = Get-GhostADDomainObject @ConnectionParams
        if ($null -eq $DomainObject) {
            Write-GhostADLog -Level Error -Message "Failed to get domain information"
            return
        }
        
        $DomainDN = $DomainObject.DistinguishedName
        if ([string]::IsNullOrEmpty($DomainDN)) {
            Write-GhostADLog -Level Error -Message "Failed to get domain DN"
            return
        }
        
        # Set connection parameters
        $LdapServer = $Server
        
        if ([string]::IsNullOrEmpty($LdapServer)) {
            if ($Domain) {
                $LdapServer = $Domain
            } else {
                try {
                    # Try to get current domain using multiple methods
                    try {
                        $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                        $LdapServer = $CurrentDomain.Name
                    } catch {
                        # Try alternative method
                        $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
                        $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
                        $LdapServer = $CurrentDomain.Name
                    }
                } catch {
                    Write-GhostADLog -Level Error -Message "Failed to determine current domain - $($_.Exception.Message)"
                    return
                }
            }
        }
        
        # Set port
        $LdapPort = 389
        if ($SSL) {
            $LdapPort = 636
        }
        
        # Create LDAP connection with explicit constructor
        $LdapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $LdapPort)
        
        if ($Credential) {
            $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier, $Credential.GetNetworkCredential())
        } else {
            $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier)
        }
        
        # Set options
        if ($SSL) {
            $LdapConnection.SessionOptions.SecureSocketLayer = $true
        }
        $LdapConnection.SessionOptions.ProtocolVersion = 3
        $LdapConnection.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
        
        $LdapConnection.Bind()
        
        # Enumerate domain controllers first
        Write-GhostADLog -Level Info -Message "Enumerating domain controllers..."
        
        $DCRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
        $DCRequest.DistinguishedName = $DomainDN
        $DCRequest.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        $DCRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
        $DCRequest.Attributes.Add("name")
        $DCRequest.Attributes.Add("dNSHostName")
        $DCRequest.Attributes.Add("userAccountControl")
        $DCRequest.Attributes.Add("operatingSystem")
        $DCRequest.Attributes.Add("operatingSystemVersion")
        $DCRequest.Attributes.Add("lastLogonTimestamp")
        
        $DCResponse = $LdapConnection.SendRequest($DCRequest)
        $DCCount = $DCResponse.Entries.Count
        
        Write-GhostADLog -Level Info -Message "Found $DCCount domain controllers:"
        
        foreach ($DCEntry in $DCResponse.Entries) {
            $DCName = Get-LdapAttributeValue -Entry $DCEntry -AttributeName "name" -DefaultValue "Unknown"
            $DCFQDN = Get-LdapAttributeValue -Entry $DCEntry -AttributeName "dNSHostName" -DefaultValue "Unknown"
            $DCUserAccountControl = Get-LdapAttributeValue -Entry $DCEntry -AttributeName "userAccountControl" -DefaultValue 0
            $DCEnabled = !([int]$DCUserAccountControl -band 2)
            $DCStatus = if ($DCEnabled) { "Enabled" } else { "Disabled" }
            
            # Get OS version
            $DCOS = Get-LdapAttributeValue -Entry $DCEntry -AttributeName "operatingSystem" -DefaultValue "Unknown"
            $DCOSVersion = Get-LdapAttributeValue -Entry $DCEntry -AttributeName "operatingSystemVersion" -DefaultValue "Unknown"
            
            # Get last logon time
            $LastLogonTimestamp = Get-LdapAttributeValue -Entry $DCEntry -AttributeName "lastLogonTimestamp" -DefaultValue $null
            $LastLogon = if ($LastLogonTimestamp -ne $null) {
                try {
                    [datetime]::FromFileTime([int64]$LastLogonTimestamp)
                } catch {
                    "Never"
                }
            } else {
                "Never"
            }
            
            Write-GhostADLog -Level Info -Message "  - $DCName ($DCFQDN)"
            Write-GhostADLog -Level Info -Message "    Status: $DCStatus"
            Write-GhostADLog -Level Info -Message "    OS: $DCOS $DCOSVersion"
            Write-GhostADLog -Level Info -Message "    Last Logon: $LastLogon"
            
            # Check for outdated OS
            if ($DCOS -match "Windows Server (2000|2003|2008|2012)") {
                Write-GhostADLog -Level Finding -Message "    Security Risk: Domain Controller $DCName is running outdated OS: $DCOS"
            }
        }
        
        # Get total computer count
        Write-GhostADLog -Level Info -Message "Enumerating computer accounts..."
        
        $ComputerCountRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
        $ComputerCountRequest.DistinguishedName = $DomainDN
        $ComputerCountRequest.Filter = "(objectCategory=computer)"
        $ComputerCountRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
        $ComputerCountRequest.Attributes.Add("operatingSystem")
        $ComputerCountRequest.Attributes.Add("userAccountControl")
        
        $ComputerCountResponse = $LdapConnection.SendRequest($ComputerCountRequest)
        $TotalComputers = $ComputerCountResponse.Entries.Count
        
        Write-GhostADLog -Level Info -Message "Total computer accounts: $TotalComputers"
        
        # Count enabled/disabled computers
        $EnabledComputers = 0
        $DisabledComputers = 0
        $OSDistribution = @{}
        
        foreach ($ComputerEntry in $ComputerCountResponse.Entries) {
            $UserAccountControl = Get-LdapAttributeValue -Entry $ComputerEntry -AttributeName "userAccountControl" -DefaultValue 0
            $ComputerEnabled = !([int]$UserAccountControl -band 2)
            
            if ($ComputerEnabled) {
                $EnabledComputers++
            } else {
                $DisabledComputers++
            }
            
            # Count OS distribution
            $OS = Get-LdapAttributeValue -Entry $ComputerEntry -AttributeName "operatingSystem" -DefaultValue "Unknown"
            
            if ($OS -ne "Unknown") {
                if ($OSDistribution.ContainsKey($OS)) {
                    $OSDistribution[$OS]++
                } else {
                    $OSDistribution[$OS] = 1
                }
            }
        }
        
        Write-GhostADLog -Level Info -Message "Enabled computer accounts: $EnabledComputers"
        Write-GhostADLog -Level Info -Message "Disabled computer accounts: $DisabledComputers"
        
        # Display OS distribution
        Write-GhostADLog -Level Info -Message "Operating System Distribution:"
        
        foreach ($OS in $OSDistribution.Keys | Sort-Object) {
            $Count = $OSDistribution[$OS]
            $Percentage = [math]::Round(($Count / $TotalComputers) * 100, 2)
            
            Write-GhostADLog -Level Info -Message "  - $OS`: $Count computers ($Percentage%)"
            
            # Check for outdated OS
            if ($OS -match "Windows (95|98|2000|XP|Vista|7|8|Server 2000|Server 2003|Server 2008)") {
                Write-GhostADLog -Level Finding -Message "  - Security Risk: $Count computers are running outdated OS: $OS"
            }
        }
        
        # Get inactive computers (not logged in for 90+ days)
        $InactiveRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
        $InactiveRequest.DistinguishedName = $DomainDN
        $InactiveRequest.Filter = "(&(objectCategory=computer)(lastLogonTimestamp<=133000000000000000))"
        $InactiveRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
        
        try {
            $InactiveResponse = $LdapConnection.SendRequest($InactiveRequest)
            $InactiveCount = $InactiveResponse.Entries.Count
            $InactivePercentage = [math]::Round(($InactiveCount / $TotalComputers) * 100, 2)
            
            Write-GhostADLog -Level Info -Message "Inactive computer accounts (90+ days): $InactiveCount ($InactivePercentage%)"
            
            if ($InactiveCount -gt 0) {
                Write-GhostADLog -Level Finding -Message "Security Risk: $InactiveCount computer accounts have been inactive for more than 90 days"
            }
        } catch {
            Write-GhostADLog -Level Warning -Message "Failed to enumerate inactive computers - $($_.Exception.Message)"
        }
        
        # Get computers with unconstrained delegation
        $UnconstrainedDelegationRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
        $UnconstrainedDelegationRequest.DistinguishedName = $DomainDN
        $UnconstrainedDelegationRequest.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        $UnconstrainedDelegationRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
        $UnconstrainedDelegationRequest.Attributes.Add("name")
        $UnconstrainedDelegationRequest.Attributes.Add("dNSHostName")
        
        try {
            $UnconstrainedDelegationResponse = $LdapConnection.SendRequest($UnconstrainedDelegationRequest)
            $UnconstrainedDelegationCount = $UnconstrainedDelegationResponse.Entries.Count
            
            if ($UnconstrainedDelegationCount -gt 0) {
                Write-GhostADLog -Level Finding -Message "Security Risk: $UnconstrainedDelegationCount computer accounts have unconstrained delegation enabled"
                
                # List computers with unconstrained delegation
                Write-GhostADLog -Level Info -Message "Computers with unconstrained delegation:"
                
                foreach ($ComputerEntry in $UnconstrainedDelegationResponse.Entries) {
                    $ComputerName = Get-LdapAttributeValue -Entry $ComputerEntry -AttributeName "name" -DefaultValue "Unknown"
                    $ComputerFQDN = Get-LdapAttributeValue -Entry $ComputerEntry -AttributeName "dNSHostName" -DefaultValue "Unknown"
                    
                    Write-GhostADLog -Level Info -Message "  - $ComputerName ($ComputerFQDN)"
                }
            }
        } catch {
            Write-GhostADLog -Level Warning -Message "Failed to enumerate computers with unconstrained delegation - $($_.Exception.Message)"
        }
    } catch {
        Write-GhostADLog -Level Error -Message "Failed to enumerate computer accounts - $($_.Exception.Message)"
    }
}

# Group Policy Objects enumeration function
function Get-GhostADGPOs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]$Domain,
        
        [Parameter(Mandatory = $false)]
        [String]$Server,
        
        [Parameter(Mandatory = $false)]
        [Switch]$SSL,
        
        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential]$Credential
    )
    
    # Build connection parameters
    $ConnectionParams = @{}
    if ($PSBoundParameters['Domain']) { $ConnectionParams['Domain'] = $Domain }
    if ($PSBoundParameters['Server']) { $ConnectionParams['Server'] = $Server }
    if ($PSBoundParameters['SSL']) { $ConnectionParams['SSL'] = $true }
    if ($PSBoundParameters['Credential']) { $ConnectionParams['Credential'] = $Credential }
    
    $LdapConnection = $null
    
    # Set connection parameters
    if ($Domain) {
        $LdapServer = $Domain
        if ($Server) {
            $LdapServer = $Server
        }
    }
    else {
        try {
            # Try to get current domain using multiple methods
            try {
                $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $LdapServer = $CurrentDomain.Name
            }
            catch {
                # Try alternative method
                $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
                $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
                $LdapServer = $CurrentDomain.Name
            }
            
            if ($Server) {
                $LdapServer = $Server
            }
        }
        catch {
            throw "Unable to determine current domain - $($_.Exception.Message)"
        }
    }
    
    # Set port
    $LdapPort = 389
    if ($SSL) {
        $LdapPort = 636
    }
    
    # Create LDAP connection with explicit constructor
    $LdapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $LdapPort)
    
    if ($Credential) {
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier, $Credential.GetNetworkCredential())
    } else {
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier)
    }
    
    # Set options
    if ($SSL) {
        $LdapConnection.SessionOptions.SecureSocketLayer = $true
    }
    $LdapConnection.SessionOptions.ProtocolVersion = 3
    
    try {
        $LdapConnection.Bind()
        
        # Get all GPOs
        $GPORequest = New-Object System.DirectoryServices.Protocols.SearchRequest
        $GPORequest.DistinguishedName = "CN=Policies,CN=System," + [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry().distinguishedName
        $GPORequest.Filter = "(objectClass=groupPolicyContainer)"
        $GPORequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::OneLevel
        
        $GPOResponse = $LdapConnection.SendRequest($GPORequest)
        $GPOCount = $GPOResponse.Entries.Count
        
        Write-GhostADLog -Level Info -Message "Found $GPOCount Group Policy Objects:"
        
        $GPOs = @()
        $RecentlyModifiedGPOs = @()
        $DefaultDomainPolicyModified = $false
        $DefaultDCPolicyModified = $false
        
        foreach ($GPOEntry in $GPOResponse.Entries) {
            $GPOGUID = Get-LdapAttributeValue -Entry $GPOEntry -AttributeName "cn" -DefaultValue "Unknown"
            $GPODisplayName = Get-LdapAttributeValue -Entry $GPOEntry -AttributeName "displayName" -DefaultValue "Unknown"
            $GPOPath = $GPOEntry.DistinguishedName
            
            # Get creation time
            $GPOCreated = Get-LdapAttributeValue -Entry $GPOEntry -AttributeName "whenCreated" -AsDateTime -DefaultValue "Unknown"
            
            # Get modification time
            $GPOModified = Get-LdapAttributeValue -Entry $GPOEntry -AttributeName "whenChanged" -AsDateTime -DefaultValue "Unknown"
            
            $GPOs += [PSCustomObject]@{
                DisplayName = $GPODisplayName
                GUID = $GPOGUID
                Path = $GPOPath
                Created = $GPOCreated
                Modified = $GPOModified
                IsDefault = $false
                RecentlyModified = $false
            }
            
            # Check if GPO was modified in the last 30 days
            if ($GPOModified -ne "Unknown" -and $GPOModified -gt (Get-Date).AddDays(-30)) {
                $RecentlyModifiedGPOs += $GPODisplayName
            }
            
            # Check if default policies were modified
            if ($GPODisplayName -eq "Default Domain Policy" -and $GPOModified -ne "Unknown" -and $GPOModified -gt (Get-Date).AddDays(-30)) {
                $DefaultDomainPolicyModified = $true
            }
            
            if ($GPODisplayName -eq "Default Domain Controllers Policy" -and $GPOModified -ne "Unknown" -and $GPOModified -gt (Get-Date).AddDays(-30)) {
                $DefaultDCPolicyModified = $true
            }
            
            Write-GhostADLog -Level Info -Message "  - $GPODisplayName"
            Write-GhostADLog -Level Info -Message "    GUID: $GPOGUID"
            Write-GhostADLog -Level Info -Message "    Created: $GPOCreated"
            Write-GhostADLog -Level Info -Message "    Modified: $GPOModified"
        }
        
        # Report on recently modified GPOs
        if ($RecentlyModifiedGPOs.Count -gt 0) {
            Write-GhostADLog -Level Info -Message "GPOs modified in the last 30 days ($($RecentlyModifiedGPOs.Count)):"
            
            foreach ($GPOName in $RecentlyModifiedGPOs) {
                Write-GhostADLog -Level Info -Message "  - $GPOName"
            }
            
            Write-GhostADLog -Level Finding -Message "Security Note: $($RecentlyModifiedGPOs.Count) GPOs have been modified in the last 30 days. Review changes for unauthorized modifications."
        }
        
        # Report on default policy modifications
        if ($DefaultDomainPolicyModified) {
            Write-GhostADLog -Level Finding -Message "Security Risk: Default Domain Policy has been modified in the last 30 days. This policy should rarely change."
        }
        
        if ($DefaultDCPolicyModified) {
            Write-GhostADLog -Level Finding -Message "Security Risk: Default Domain Controllers Policy has been modified in the last 30 days. This policy should rarely change."
        }
        
        # Get all OUs
        $OURequest = New-Object System.DirectoryServices.Protocols.SearchRequest
        $OURequest.DistinguishedName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry().distinguishedName
        $OURequest.Filter = "(objectClass=organizationalUnit)"
        $OURequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
        
        $OUResponse = $LdapConnection.SendRequest($OURequest)
        $OUCount = $OUResponse.Entries.Count
        
        Write-GhostADLog -Level Info -Message "Found $OUCount Organizational Units:"
        
        $EmptyOUs = @()
        $OUsWithGPOs = @()
        
        foreach ($OUEntry in $OUResponse.Entries) {
            $OUDN = $OUEntry.DistinguishedName
            $OUName = $OUDN.Split(',')[0].Substring(3)
            
            # Check if OU has GPOs linked
            $GPOLinks = if ($OUEntry.Attributes.Contains("gPLink") -and $OUEntry.Attributes["gPLink"].Count -gt 0) {
                $OUEntry.Attributes["gPLink"][0].ToString()
            } else {
                ""
            }
            
            # Check if OU has child objects
            $ChildObjectsRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
            $ChildObjectsRequest.DistinguishedName = $OUDN
            $ChildObjectsRequest.Filter = "(objectClass=*)"
            $ChildObjectsRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::OneLevel
            
            $ChildObjectsResponse = $LdapConnection.SendRequest($ChildObjectsRequest)
            $ChildObjectsCount = $ChildObjectsResponse.Entries.Count
            
            Write-GhostADLog -Level Info -Message "  - $OUName"
            Write-GhostADLog -Level Info -Message "    Distinguished Name: $OUDN"
            Write-GhostADLog -Level Info -Message "    Child Objects: $ChildObjectsCount"
            
            if ($ChildObjectsCount -eq 0) {
                $EmptyOUs += $OUName
                Write-GhostADLog -Level Info -Message "    Status: Empty"
            }
            
            if ($GPOLinks -match "\[" -and $GPOLinks -match "\]") {
                $GPOLinkList = $GPOLinks.Split(']')[0].Split('[')
                
                foreach ($GPOLink in $GPOLinkList) {
                    if ($GPOLink -match "LDAP://CN=\{(.*?)\}") {
                        $LinkedGPOGUID = $Matches[1]
                        $LinkedGPO = $GPOs | Where-Object { $_.GUID -eq $LinkedGPOGUID }
                        
                        if ($LinkedGPO) {
                            Write-GhostADLog -Level Info -Message "      - $($LinkedGPO.DisplayName)"
                        }
                    }
                }
            }
            
            if ($GPOLinks -ne "") {
                $OUsWithGPOs += $OUName
                Write-GhostADLog -Level Info -Message "    GPO Links: Yes"
            } else {
                Write-GhostADLog -Level Info -Message "    GPO Links: None"
            }
        }
        
        # Report on empty OUs
        if ($EmptyOUs.Count -gt 0) {
            Write-GhostADLog -Level Info -Message "Empty Organizational Units ($($EmptyOUs.Count)):"
            
            foreach ($OUName in $EmptyOUs) {
                Write-GhostADLog -Level Info -Message "  - $OUName"
            }
            
            Write-GhostADLog -Level Finding -Message "Security Note: $($EmptyOUs.Count) empty OUs found. Consider cleaning up unused OUs."
        }
        
        # Report on OUs with GPOs
        Write-GhostADLog -Level Info -Message "OUs with GPO links: $($OUsWithGPOs.Count) out of $OUCount"
        
        if ($OUsWithGPOs.Count -eq 0) {
            Write-GhostADLog -Level Finding -Message "Security Risk: No OUs have GPOs linked. Group Policies may not be applied correctly."
        }
        
        return $GPOs
    } catch {
        Write-GhostADLog -Level Error -Message "Failed to enumerate Group Policy Objects - $($_.Exception.Message)"
    }
}

# Active Directory Certificate Services enumeration function
function Get-GhostADADCS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]$Domain,
        
        [Parameter(Mandatory = $false)]
        [String]$Server,
        
        [Parameter(Mandatory = $false)]
        [Switch]$SSL,
        
        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential]$Credential
    )
    
    # Build connection parameters
    $ConnectionParams = @{}
    if ($PSBoundParameters['Domain']) { $ConnectionParams['Domain'] = $Domain }
    if ($PSBoundParameters['Server']) { $ConnectionParams['Server'] = $Server }
    if ($PSBoundParameters['SSL']) { $ConnectionParams['SSL'] = $true }
    if ($PSBoundParameters['Credential']) { $ConnectionParams['Credential'] = $Credential }
    
    $LdapConnection = $null
    
    # Set connection parameters
    if ($Domain) {
        $LdapServer = $Domain
        if ($Server) {
            $LdapServer = $Server
        }
    }
    else {
        try {
            # Try to get current domain using multiple methods
            try {
                $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $LdapServer = $CurrentDomain.Name
            }
            catch {
                # Try alternative method
                $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
                $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
                $LdapServer = $CurrentDomain.Name
            }
            
            if ($Server) {
                $LdapServer = $Server
            }
        }
        catch {
            throw "Unable to determine current domain - $($_.Exception.Message)"
        }
    }
    
    # Set port
    $LdapPort = 389
    if ($SSL) {
        $LdapPort = 636
    }
    
    # Create LDAP connection with explicit constructor
    $LdapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $LdapPort)
    
    if ($Credential) {
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier, $Credential.GetNetworkCredential())
    } else {
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier)
    }
    
    # Set options
    if ($SSL) {
        $LdapConnection.SessionOptions.SecureSocketLayer = $true
    }
    $LdapConnection.SessionOptions.ProtocolVersion = 3
    
    try {
        $LdapConnection.Bind()
        
        # Search for Certificate Authorities
        Write-GhostADLog -Level Info -Message "Searching for Active Directory Certificate Services..."
        
        $CARequest = New-Object System.DirectoryServices.Protocols.SearchRequest
        $CARequest.DistinguishedName = "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration," + [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry().distinguishedName
        $CARequest.Filter = "(objectClass=certificationAuthority)"
        $CARequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
        
        try {
            $CAResponse = $LdapConnection.SendRequest($CARequest)
            $CACount = $CAResponse.Entries.Count
            
            if ($CACount -gt 0) {
                Write-GhostADLog -Level Info -Message "Found $CACount Certificate Authorities:"
                
                foreach ($CAEntry in $CAResponse.Entries) {
                    $CAName = $CAEntry.Attributes["cn"][0].ToString()
                    $CADNSName = if ($CAEntry.Attributes.Contains("dNSHostName")) {
                        $CAEntry.Attributes["dNSHostName"][0].ToString()
                    } else {
                        "Unknown"
                    }
                    
                    $CAFlags = if ($CAEntry.Attributes.Contains("flags")) {
                        [int]$CAEntry.Attributes["flags"][0]
                    } else {
                        0
                    }
                    
                    $CACertificateCount = if ($CAEntry.Attributes.Contains("cACertificate")) {
                        $CAEntry.Attributes["cACertificate"].Count
                    } else {
                        0
                    }
                    
                    Write-GhostADLog -Level Info -Message "  - $CAName"
                    Write-GhostADLog -Level Info -Message "    DNS Name: $CADNSName"
                    Write-GhostADLog -Level Info -Message "    Certificates: $CACertificateCount"
                    
                    # Check for certificate templates
                    $TemplateRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                    $TemplateRequest.DistinguishedName = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry().distinguishedName
                    $TemplateRequest.Filter = "(objectClass=pKICertificateTemplate)"
                    $TemplateRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::OneLevel
                    
                    try {
                        $TemplateResponse = $LdapConnection.SendRequest($TemplateRequest)
                        $TemplateCount = $TemplateResponse.Entries.Count
                        
                        Write-GhostADLog -Level Info -Message "    Certificate Templates: $TemplateCount"
                        
                        $VulnerableTemplates = @()
                        
                        foreach ($TemplateEntry in $TemplateResponse.Entries) {
                            $TemplateName = $TemplateEntry.Attributes["cn"][0].ToString()
                            $TemplateOID = if ($TemplateEntry.Attributes.Contains("msPKI-Cert-Template-OID")) {
                                $TemplateEntry.Attributes["msPKI-Cert-Template-OID"][0].ToString()
                            } else {
                                "Unknown"
                            }
                            
                            # Check for vulnerable enrollment rights
                            $EnrollmentRights = if ($TemplateEntry.Attributes.Contains("pkiExtendedKeyUsage")) {
                                $TemplateEntry.Attributes["pkiExtendedKeyUsage"] | ForEach-Object { $_.ToString() }
                            } else {
                                @()
                            }
                            
                            $SchemaVersion = if ($TemplateEntry.Attributes.Contains("msPKI-Template-Schema-Version")) {
                                [int]$TemplateEntry.Attributes["msPKI-Template-Schema-Version"][0]
                            } else {
                                1
                            }
                            
                            $EnrollmentFlags = if ($TemplateEntry.Attributes.Contains("msPKI-Enrollment-Flag")) {
                                [int]$TemplateEntry.Attributes["msPKI-Enrollment-Flag"][0]
                            } else {
                                0
                            }
                            
                            # Check if template allows requesters to supply subject
                            $SuppliesSubject = $SchemaVersion -ge 2 -and ($EnrollmentFlags -band 1) -eq 1
                            
                            # Check if template allows requesters to specify SAN
                            $SpecifySAN = $SchemaVersion -ge 3 -and ($EnrollmentFlags -band 0x00080000) -eq 0x00080000
                            
                            # Determine if template is potentially vulnerable
                            $IsVulnerable = $false
                            $VulnerabilityReason = ""
                            
                            if ($SuppliesSubject) {
                                $IsVulnerable = $true
                                $VulnerabilityReason = "Allows subject specification"
                            }
                            
                            if ($SpecifySAN) {
                                $IsVulnerable = $true
                                $VulnerabilityReason = "Allows SAN specification"
                            }
                            
                            if ($IsVulnerable) {
                                $VulnerableTemplates += $TemplateName
                                Write-GhostADLog -Level Finding -Message "    Security Risk: Certificate template '$TemplateName' is potentially vulnerable: $VulnerabilityReason"
                            }
                        }
                        
                        if ($VulnerableTemplates.Count -gt 0) {
                            Write-GhostADLog -Level Finding -Message "    Critical Security Risk: Found $($VulnerableTemplates.Count) potentially vulnerable certificate templates that could be abused for privilege escalation"
                        }
                    }
                    catch {
                        Write-GhostADLog -Level Warning -Message "    Unable to enumerate certificate templates - $($_.Exception.Message)"
                    }
                    
                    # Check for enrollment service
                    $EnrollmentServiceRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                    $EnrollmentServiceRequest.DistinguishedName = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry().distinguishedName
                    $EnrollmentServiceRequest.Filter = "(objectClass=pKIEnrollmentService)"
                    $EnrollmentServiceRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::OneLevel
                    
                    try {
                        $EnrollmentServiceResponse = $LdapConnection.SendRequest($EnrollmentServiceRequest)
                        $EnrollmentServiceCount = $EnrollmentServiceResponse.Entries.Count
                        
                        Write-GhostADLog -Level Info -Message "    Enrollment Services: $EnrollmentServiceCount"
                        
                        foreach ($ServiceEntry in $EnrollmentServiceResponse.Entries) {
                            $ServiceName = $ServiceEntry.Attributes["cn"][0].ToString()
                            $ServiceDNSName = if ($ServiceEntry.Attributes.Contains("dNSHostName")) {
                                $ServiceEntry.Attributes["dNSHostName"][0].ToString()
                            } else {
                                "Unknown"
                            }
                            
                            Write-GhostADLog -Level Info -Message "      - $ServiceName ($ServiceDNSName)"
                        }
                    }
                    catch {
                        Write-GhostADLog -Level Warning -Message "    Unable to enumerate enrollment services - $($_.Exception.Message)"
                    }
                }
            }
            else {
                Write-GhostADLog -Level Info -Message "No Active Directory Certificate Services found."
            }
        }
        catch {
            Write-GhostADLog -Level Warning -Message "Unable to enumerate certificate authorities - $($_.Exception.Message)"
        }
    }
    catch {
        Write-GhostADLog -Level Error -Message "Failed to enumerate Active Directory Certificate Services - $($_.Exception.Message)"
    }
}

# Active Directory Access Control Lists enumeration function
function Get-GhostADACLs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]$Domain,
        
        [Parameter(Mandatory = $false)]
        [String]$Server,
        
        [Parameter(Mandatory = $false)]
        [Switch]$SSL,
        
        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential]$Credential
    )
    
    # Build connection parameters
    $ConnectionParams = @{}
    if ($PSBoundParameters['Domain']) { $ConnectionParams['Domain'] = $Domain }
    if ($PSBoundParameters['Server']) { $ConnectionParams['Server'] = $Server }
    if ($PSBoundParameters['SSL']) { $ConnectionParams['SSL'] = $true }
    if ($PSBoundParameters['Credential']) { $ConnectionParams['Credential'] = $Credential }
    
    $LdapConnection = $null
    
    # Set connection parameters
    if ($Domain) {
        $LdapServer = $Domain
        if ($Server) {
            $LdapServer = $Server
        }
    }
    else {
        try {
            # Try to get current domain using multiple methods
            try {
                $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $LdapServer = $CurrentDomain.Name
            }
            catch {
                # Try alternative method
                $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
                $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
                $LdapServer = $CurrentDomain.Name
            }
            
            if ($Server) {
                $LdapServer = $Server
            }
        }
        catch {
            throw "Unable to determine current domain - $($_.Exception.Message)"
        }
    }
    
    # Set port
    $LdapPort = 389
    if ($SSL) {
        $LdapPort = 636
    }
    
    # Create LDAP connection with explicit constructor
    $LdapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $LdapPort)
    
    if ($Credential) {
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier, $Credential.GetNetworkCredential())
    } else {
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier)
    }
    
    # Set options
    if ($SSL) {
        $LdapConnection.SessionOptions.SecureSocketLayer = $true
    }
    $LdapConnection.SessionOptions.ProtocolVersion = 3
    
    try {
        $LdapConnection.Bind()
        
        Write-GhostADLog -Level Info -Message "Enumerating important Active Directory ACLs..."
        
        # Get domain object
        try {
            $DomainObject = Get-GhostADDomainObject @ConnectionParams
            $DomainDN = $DomainObject.DistinguishedName
            
            if ([string]::IsNullOrEmpty($DomainDN)) {
                throw "Unable to determine domain distinguished name"
            }
            
            # Important object paths to check
            $ImportantObjects = @{}
            
            # Add Domain Root
            $ImportantObjects['DomainRoot'] = @{Name = "Domain Root"; DN = $DomainDN}
            
            # Try to add Domain Controllers OU if it exists
            try {
                $DCOURequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                $DCOURequest.DistinguishedName = "OU=Domain Controllers,$DomainDN"
                $DCOURequest.Filter = "(objectClass=*)"
                $DCOURequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
                $DCOUResponse = $LdapConnection.SendRequest($DCOURequest)
                if ($DCOUResponse.Entries.Count -gt 0) {
                    $ImportantObjects['DomainControllers'] = @{Name = "Domain Controllers OU"; DN = "OU=Domain Controllers,$DomainDN"}
                }
            } catch {
                Write-GhostADLog -Level Warning -Message "Domain Controllers OU not found - $($_.Exception.Message)"
            }
            
            # Try to add AdminSDHolder if it exists
            try {
                $AdminSDHolderRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                $AdminSDHolderRequest.DistinguishedName = "CN=AdminSDHolder,CN=System,$DomainDN"
                $AdminSDHolderRequest.Filter = "(objectClass=*)"
                $AdminSDHolderRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
                $AdminSDHolderResponse = $LdapConnection.SendRequest($AdminSDHolderRequest)
                if ($AdminSDHolderResponse.Entries.Count -gt 0) {
                    $ImportantObjects['AdminSDHolder'] = @{Name = "AdminSDHolder"; DN = "CN=AdminSDHolder,CN=System,$DomainDN"}
                }
            } catch {
                Write-GhostADLog -Level Warning -Message "AdminSDHolder not found - $($_.Exception.Message)"
            }
            
            # Try to add Schema if it exists
            try {
                $SchemaRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                $SchemaRequest.DistinguishedName = "CN=Schema,CN=Configuration,$DomainDN"
                $SchemaRequest.Filter = "(objectClass=*)"
                $SchemaRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
                $SchemaResponse = $LdapConnection.SendRequest($SchemaRequest)
                if ($SchemaResponse.Entries.Count -gt 0) {
                    $ImportantObjects['Schema'] = @{Name = "Schema"; DN = "CN=Schema,CN=Configuration,$DomainDN"}
                }
            } catch {
                Write-GhostADLog -Level Warning -Message "Schema not found - $($_.Exception.Message)"
            }
            
            # Try to add Configuration if it exists
            try {
                $ConfigRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                $ConfigRequest.DistinguishedName = "CN=Configuration,$DomainDN"
                $ConfigRequest.Filter = "(objectClass=*)"
                $ConfigRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
                $ConfigResponse = $LdapConnection.SendRequest($ConfigRequest)
                if ($ConfigResponse.Entries.Count -gt 0) {
                    $ImportantObjects['Configuration'] = @{Name = "Configuration"; DN = "CN=Configuration,$DomainDN"}
                }
            } catch {
                Write-GhostADLog -Level Warning -Message "Configuration not found - $($_.Exception.Message)"
            }
            
            # Try to add Group Policy Objects if they exist
            try {
                $GPORequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                $GPORequest.DistinguishedName = "CN=Policies,CN=System,$DomainDN"
                $GPORequest.Filter = "(objectClass=*)"
                $GPORequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
                $GPOResponse = $LdapConnection.SendRequest($GPORequest)
                if ($GPOResponse.Entries.Count -gt 0) {
                    $ImportantObjects['GPO'] = @{Name = "Group Policy Objects"; DN = "CN=Policies,CN=System,$DomainDN"}
                }
            } catch {
                Write-GhostADLog -Level Warning -Message "Group Policy Objects container not found - $($_.Exception.Message)"
            }
            
            foreach ($Object in $ImportantObjects.Values) {
                Write-GhostADLog -Level Info -Message "  - $($Object.Name) ($($Object.DN))"
            }
            
            # Rights that are interesting from a security perspective
            $InterestingRights = @(
                "GenericAll",
                "GenericWrite",
                "WriteProperty",
                "WriteDacl",
                "WriteOwner",
                "Self",
                "DeleteTree",
                "Delete",
                "ExtendedRight"
            )
            
            # Map of well-known SIDs to names
            $WellKnownSids = @{
                "S-1-1-0" = "Everyone"
                "S-1-5-7" = "Anonymous Logon"
                "S-1-5-11" = "Authenticated Users"
                "S-1-5-18" = "SYSTEM"
                "S-1-5-32-544" = "Administrators"
                "S-1-5-32-545" = "Users"
                "S-1-5-32-546" = "Guests"
                "S-1-5-32-548" = "Account Operators"
                "S-1-5-32-549" = "Server Operators"
                "S-1-5-32-550" = "Print Operators"
                "S-1-5-32-551" = "Backup Operators"
                "S-1-5-32-552" = "Replicators"
            }
            
            # Map of extended rights GUIDs to their names
            $ExtendedRightsMap = @{
                "00000000-0000-0000-0000-000000000000" = "All Extended Rights"
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes"
                "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All"
                "00299570-246d-11d0-9819-00aa0040529b" = "Reset Password"
                "ab721a53-1e2f-11d0-9819-00aa0040529b" = "Change Password"
            }
            
            # Function to resolve SID to name
            function Resolve-SID {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$SID
                )
                
                if ($WellKnownSids.ContainsKey($SID)) {
                    return $WellKnownSids[$SID]
                }
                
                # Try to resolve domain SIDs
                try {
                    $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                    $SearchRequest.DistinguishedName = $DomainDN
                    $SearchRequest.Filter = "(objectSid=$SID)"
                    $SearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
                    
                    $Response = $LdapConnection.SendRequest($SearchRequest)
                    
                    if ($Response.Entries.Count -gt 0) {
                        $Entry = $Response.Entries[0]
                        $Name = Get-LdapAttributeValue -Entry $Entry -AttributeName "name" -DefaultValue "Unknown"
                        return $Name
                    }
                } catch {
                    # Silently fail and return the SID
                    $ErrorMsg = $_.Exception.Message
                    Write-GhostADLog -Level Warning -Message ("  Error resolving SID {0} - {1}" -f $SID, $ErrorMsg)
                }
                
                return $SID
            }
            
            # Function to check if a right is interesting
            function Is-InterestingRight {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$Right
                )
                
                foreach ($InterestingRight in $InterestingRights) {
                    if ($Right -like "*$InterestingRight*") {
                        return $true
                    }
                }
                
                return $false
            }
            
            # Check each important object
            foreach ($Object in $ImportantObjects.Values) {
                Write-GhostADLog -Level Info -Message "Checking ACLs for $($Object.Name) ($($Object.DN))"
                
                try {
                    # Get the object's security descriptor
                    $SecurityRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                    $SecurityRequest.DistinguishedName = $Object.DN
                    $SecurityRequest.Filter = "(objectClass=*)"
                    $SecurityRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
                    $SecurityRequest.Attributes.Add("nTSecurityDescriptor")
                    
                    try {
                        $SecurityResponse = $LdapConnection.SendRequest($SecurityRequest)
                        
                        if ($SecurityResponse.Entries.Count -gt 0) {
                            $Entry = $SecurityResponse.Entries[0]
                            
                            # Safely get the security descriptor
                            if ($Entry.Attributes.Contains("nTSecurityDescriptor") -and $Entry.Attributes["nTSecurityDescriptor"].Count -gt 0) {
                                try {
                                    $SecurityDescriptor = $Entry.Attributes["nTSecurityDescriptor"][0]
                                    
                                    # Convert the security descriptor to a readable format
                                    $SD = New-Object System.DirectoryServices.ActiveDirectorySecurity
                                    $SD.SetSecurityDescriptorBinaryForm($SecurityDescriptor)
                                    
                                    # Get the ACL
                                    $ACL = $SD.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
                                    
                                    # Filter for interesting rights
                                    $InterestingACEs = $ACL | Where-Object { Is-InterestingRight $_.ActiveDirectoryRights }
                                    
                                    if ($InterestingACEs -and $InterestingACEs.Count -gt 0) {
                                        Write-GhostADLog -Level Info -Message "  Found $($InterestingACEs.Count) interesting ACEs:"
                                        
                                        foreach ($ACE in $InterestingACEs) {
                                            $IdentityName = Resolve-SID $ACE.IdentityReference.Value
                                            $Rights = $ACE.ActiveDirectoryRights.ToString()
                                            $AccessType = $ACE.AccessControlType.ToString()
                                            $IsInherited = $ACE.IsInherited
                                            
                                            Write-GhostADLog -Level Info -Message "    - Identity: $IdentityName"
                                            Write-GhostADLog -Level Info -Message "      Rights: $Rights"
                                            Write-GhostADLog -Level Info -Message "      Access: $AccessType"
                                            Write-GhostADLog -Level Info -Message "      Inherited: $IsInherited"
                                            
                                            # Check for dangerous permissions
                                            if (($IdentityName -eq "Everyone" -or $IdentityName -eq "Authenticated Users") -and 
                                                ($Rights -like "*GenericAll*" -or $Rights -like "*GenericWrite*" -or $Rights -like "*WriteDacl*")) {
                                                Write-GhostADLog -Level Finding -Message "      Security Risk: Overly permissive rights for non-administrative group"
                                            }
                                        }
                                    }
                                } catch {
                                    Write-GhostADLog -Level Warning -Message "  Error processing security descriptor - $($_.Exception.Message)"
                                }
                            }
                            else {
                                Write-GhostADLog -Level Warning -Message "  Unable to retrieve security descriptor."
                            }
                        }
                        else {
                            Write-GhostADLog -Level Warning -Message "  Object not found."
                        }
                    } catch {
                        Write-GhostADLog -Level Warning -Message "  Error retrieving security descriptor - $($_.Exception.Message)"
                    }
                }
                catch {
                    Write-GhostADLog -Level Warning -Message "  Error checking ACLs - $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-GhostADLog -Level Error -Message "Failed to enumerate important objects - $($_.Exception.Message)"
        }
    }
    catch {
        Write-GhostADLog -Level Error -Message "Failed to bind to LDAP server - $($_.Exception.Message)"
    }
}

# Domain trust enumeration function
function Get-GhostADTrusts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]$Domain,
        
        [Parameter(Mandatory = $false)]
        [String]$Server,
        
        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential]$Credential
    )
    
    # Connection parameters
    $ConnectionParams = @{}
    if ($Domain) { $ConnectionParams.Domain = $Domain }
    if ($Server) { $ConnectionParams.Server = $Server }
    if ($Credential) { $ConnectionParams.Credential = $Credential }
    
    # Create LDAP connection
    $LdapConnection = $null
    $LdapServer = $Server
    
    if ([string]::IsNullOrEmpty($LdapServer)) {
        if ([string]::IsNullOrEmpty($Domain)) {
            $LdapServer = (Get-Item Env:LOGONSERVER -ErrorAction SilentlyContinue).Value -replace '\\\\', ''
        } else {
            $LdapServer = $Domain
        }
    }
    
    $LdapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, 389)
    
    if ($Credential) {
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier, $Credential.GetNetworkCredential())
    } else {
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier)
    }
    
    $LdapConnection.SessionOptions.ProtocolVersion = 3
    $LdapConnection.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
    
    try {
        $LdapConnection.Bind()
        
        Write-GhostADLog -Level Info -Message "Enumerating domain trusts..."
        
        # Get domain DN first
        try {
            $DomainObject = Get-GhostADDomainObject @ConnectionParams
            $DomainDN = $DomainObject.DistinguishedName
            
            if ([string]::IsNullOrEmpty($DomainDN)) {
                Write-GhostADLog -Level Error -Message "Failed to get domain DN"
                return
            }
            
            # Search for trusts
            $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
            $SearchRequest.DistinguishedName = $DomainDN
            $SearchRequest.Filter = "(objectClass=trustedDomain)"
            $SearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
            $SearchRequest.Attributes.Add("name")
            $SearchRequest.Attributes.Add("trustPartner")
            $SearchRequest.Attributes.Add("trustDirection")
            $SearchRequest.Attributes.Add("trustType")
            $SearchRequest.Attributes.Add("trustAttributes")
            $SearchRequest.Attributes.Add("whenCreated")
            $SearchRequest.Attributes.Add("whenChanged")
            
            $Response = $LdapConnection.SendRequest($SearchRequest)
            
            $TrustCount = $Response.Entries.Count
            
            if ($TrustCount -gt 0) {
                Write-GhostADLog -Level Finding -Message "Found $TrustCount domain trust relationships:"
                
                # Create a table for trusts
                $TrustTable = @()
                
                foreach ($Entry in $Response.Entries) {
                    $TrustName = Get-LdapAttributeValue -Entry $Entry -AttributeName "name" -DefaultValue "Unknown"
                    $TrustPartner = Get-LdapAttributeValue -Entry $Entry -AttributeName "trustPartner" -DefaultValue "Unknown"
                    $TrustDirection = Get-LdapAttributeValue -Entry $Entry -AttributeName "trustDirection" -AsInt -DefaultValue 0
                    $TrustType = Get-LdapAttributeValue -Entry $Entry -AttributeName "trustType" -AsInt -DefaultValue 0
                    $TrustAttributes = Get-LdapAttributeValue -Entry $Entry -AttributeName "trustAttributes" -AsInt -DefaultValue 0
                    $WhenCreated = Get-LdapAttributeValue -Entry $Entry -AttributeName "whenCreated" -AsDateTime -DefaultValue "Unknown"
                    $WhenChanged = Get-LdapAttributeValue -Entry $Entry -AttributeName "whenChanged" -AsDateTime -DefaultValue "Unknown"
                    
                    # Interpret trust direction
                    $DirectionString = "Unknown"
                    switch ($TrustDirection) {
                        0 { $DirectionString = "Disabled" }
                        1 { $DirectionString = "Inbound" }
                        2 { $DirectionString = "Outbound" }
                        3 { $DirectionString = "Bidirectional" }
                    }
                    
                    # Interpret trust type
                    $TypeString = "Unknown"
                    switch ($TrustType) {
                        1 { $TypeString = "Windows NT (Downlevel)" }
                        2 { $TypeString = "Active Directory" }
                        3 { $TypeString = "Kerberos Realm" }
                        4 { $TypeString = "DCE (Discontinued)" }
                    }
                    
                    # Check for security concerns
                    $TrustIssues = @()
                    
                    # Check for inbound and bidirectional trusts (potential security risk)
                    if ($TrustDirection -eq 1 -or $TrustDirection -eq 3) {
                        $TrustIssues += "Security Risk: $DirectionString trust allows access from $TrustPartner"
                    }
                    
                    # Check for transitive trusts
                    $IsTransitive = ($TrustAttributes -band 0x1) -eq 0x1
                    if ($IsTransitive) {
                        $TrustIssues += "Security Risk: Transitive trust allows access to other trusted domains"
                    }
                    
                    # Check for SID filtering
                    $SIDFilteringEnabled = ($TrustAttributes -band 0x4) -eq 0x4
                    if (-not $SIDFilteringEnabled -and ($TrustDirection -eq 1 -or $TrustDirection -eq 3)) {
                        $TrustIssues += "Security Risk: SID filtering is not enabled"
                    }
                    
                    # Check for external trusts
                    $IsExternal = ($TrustAttributes -band 0x40) -eq 0x40
                    if ($IsExternal) {
                        $TrustIssues += "External trust with $TrustPartner"
                    }
                    
                    # Add to table
                    $TrustTable += [PSCustomObject]@{
                        Name = $TrustName
                        Partner = $TrustPartner
                        Direction = $DirectionString
                        Type = $TypeString
                        Created = $WhenCreated
                        LastChanged = $WhenChanged
                        Issues = ($TrustIssues -join ", ")
                    }
                    
                    # Log details
                    Write-GhostADLog -Level Info -Message "Trust: $TrustName"
                    Write-GhostADLog -Level Info -Message "  Partner: $TrustPartner"
                    Write-GhostADLog -Level Info -Message "  Direction: $DirectionString"
                    Write-GhostADLog -Level Info -Message "  Type: $TypeString"
                    Write-GhostADLog -Level Info -Message "  Created: $WhenCreated"
                    Write-GhostADLog -Level Info -Message "  Last Changed: $WhenChanged"
                    
                    foreach ($Issue in $TrustIssues) {
                        Write-GhostADLog -Level Warning -Message "  $Issue"
                    }
                }
                
                # Check domain and forest functional levels
                try {
                    # Get domain functional level
                    $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                    $SearchRequest.DistinguishedName = $DomainDN
                    $SearchRequest.Filter = "(objectClass=domain)"
                    $SearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
                    $SearchRequest.Attributes.Add("msDS-Behavior-Version")
                    
                    $Response = $LdapConnection.SendRequest($SearchRequest)
                    
                    if ($Response.Entries.Count -gt 0 -and $Response.Entries[0].Attributes.Contains("msDS-Behavior-Version")) {
                        $DomainLevel = [int]$Response.Entries[0].Attributes["msDS-Behavior-Version"][0]
                        
                        $DomainLevelString = "Unknown"
                        switch ($DomainLevel) {
                            0 { $DomainLevelString = "Windows 2000 (Level 0)" }
                            1 { $DomainLevelString = "Windows Server 2003 (Level 1)" }
                            2 { $DomainLevelString = "Windows Server 2003 R2 (Level 2)" }
                            3 { $DomainLevelString = "Windows Server 2008 (Level 3)" }
                            4 { $DomainLevelString = "Windows Server 2008 R2 (Level 4)" }
                            5 { $DomainLevelString = "Windows Server 2012 (Level 5)" }
                            6 { $DomainLevelString = "Windows Server 2012 R2 (Level 6)" }
                            7 { $DomainLevelString = "Windows Server 2016 (Level 7)" }
                            default { $DomainLevelString = "Windows Server 2019 or newer (Level $DomainLevel)" }
                        }
                        
                        Write-GhostADLog -Level Info -Message "Domain Functional Level: $DomainLevelString"
                        
                        # Check for outdated functional level
                        if ($DomainLevel -lt 4) {
                            Write-GhostADLog -Level Warning -Message "Security Risk: Domain functional level is outdated ($DomainLevelString)"
                        }
                    }
                    
                    # Get forest functional level
                    $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                    $SearchRequest.DistinguishedName = "CN=Partitions,CN=Configuration,$DomainDN"
                    $SearchRequest.Filter = "(objectClass=crossRefContainer)"
                    $SearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
                    $SearchRequest.Attributes.Add("msDS-Behavior-Version")
                    
                    $Response = $LdapConnection.SendRequest($SearchRequest)
                    
                    if ($Response.Entries.Count -gt 0 -and $Response.Entries[0].Attributes.Contains("msDS-Behavior-Version")) {
                        $ForestLevel = [int]$Response.Entries[0].Attributes["msDS-Behavior-Version"][0]
                        
                        $ForestLevelString = "Unknown"
                        switch ($ForestLevel) {
                            0 { $ForestLevelString = "Windows 2000 (Level 0)" }
                            1 { $ForestLevelString = "Windows Server 2003 (Level 1)" }
                            2 { $ForestLevelString = "Windows Server 2003 R2 (Level 2)" }
                            3 { $ForestLevelString = "Windows Server 2008 (Level 3)" }
                            4 { $ForestLevelString = "Windows Server 2008 R2 (Level 4)" }
                            5 { $ForestLevelString = "Windows Server 2012 (Level 5)" }
                            6 { $ForestLevelString = "Windows Server 2012 R2 (Level 6)" }
                            7 { $ForestLevelString = "Windows Server 2016 (Level 7)" }
                            default { $ForestLevelString = "Windows Server 2019 or newer (Level $ForestLevel)" }
                        }
                        
                        Write-GhostADLog -Level Info -Message "Forest Functional Level: $ForestLevelString"
                        
                        # Check for outdated functional level
                        if ($ForestLevel -lt 4) {
                            Write-GhostADLog -Level Warning -Message "Security Risk: Forest functional level is outdated ($ForestLevelString)"
                        }
                    }
                }
                catch {
                    Write-GhostADLog -Level Warning -Message "Failed to get domain or forest functional level - $($_.Exception.Message)"
                }
            }
            else {
                Write-GhostADLog -Level Info -Message "No domain trusts found"
            }
        }
        catch {
            Write-GhostADLog -Level Error -Message "Failed to enumerate domain trusts - $($_.Exception.Message)"
        }
    }
    catch {
        Write-GhostADLog -Level Error -Message "Failed to bind to LDAP server - $($_.Exception.Message)"
    }
}
