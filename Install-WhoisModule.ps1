# --- (WinPS 5.1 対応) TLS 1.2 を必ず有効化 ---
try {
    $sp = [Net.ServicePointManager]::SecurityProtocol
    if (-not ($sp.HasFlag([Net.SecurityProtocolType]::Tls12))) {
        [Net.ServicePointManager]::SecurityProtocol = $sp -bor [Net.SecurityProtocolType]::Tls12
    }
} catch {}

function Get-RdapWhois {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position=0)]
        [Alias('Name','Ip','Asn')]
        [string[]]$Query,

        [ValidateSet('Auto','Domain','IP','ASN')]
        [string]$Type = 'Auto',

        [switch]$Raw,

        [int]$TimeoutSec = 15,
        [int]$MaxRetry   = 2
    )

    begin {
        # IANA RDAP Bootstrap
        $script:IanaBootstrap = @{
            'Domain' = 'https://data.iana.org/rdap/dns.json'
            'IP'     = 'https://data.iana.org/rdap/ipv4.json'
            'ASN'    = 'https://data.iana.org/rdap/asn.json'
        }

        # セッション内キャッシュ
        if (-not $script:RdapCache) { $script:RdapCache = @{} }

        function Get-Json {
            param(
                [Parameter(Mandatory)][string]$Url,
                [Parameter(Mandatory)][int]$TimeoutSec
            )
            $bak = $global:ProgressPreference
            $global:ProgressPreference = 'SilentlyContinue'
            try {
                Invoke-RestMethod -Method GET -Uri $Url -TimeoutSec $TimeoutSec -ErrorAction Stop
            } finally {
                $global:ProgressPreference = $bak
            }
        }

        function Get-RdapServerForDomain {
            param([Parameter(Mandatory)][string]$Domain)
            $tld = ($Domain -replace '^\.+','').Split('.')[-1].ToLower()
            $key = "dns:$tld"
            if ($script:RdapCache.ContainsKey($key)) { return $script:RdapCache[$key] }

            $dns = Get-Json -Url $script:IanaBootstrap['Domain'] -TimeoutSec $TimeoutSec

            # services は [[tld群],[url群]] の配列配列
            $entry = $null
            foreach ($svc in $dns.services) {
                $tlds = $svc[0]
                $urls = $svc[1]
                if ($tlds -and ($tlds -contains $tld)) {
                    $entry = New-Object psobject -Property @{ Urls = $urls }
                    break
                }
            }

            $server = $null
            if ($entry -and $entry.Urls -and $entry.Urls.Count -gt 0) {
                $server = $entry.Urls[0]
            }
            if (-not $server) { $server = 'https://rdap.org' }  # フォールバック

            $script:RdapCache[$key] = ($server.TrimEnd('/'))
            return $script:RdapCache[$key]
        }

        function Get-RdapServerForIP {
            param([string]$Ip)
            $key = "ip"
            if ($script:RdapCache.ContainsKey($key)) { return $script:RdapCache[$key] }

            $ipBootstrap = Get-Json -Url $script:IanaBootstrap['IP'] -TimeoutSec $TimeoutSec
            $server = $null
            if ($ipBootstrap -and $ipBootstrap.rdap_base_urls -and $ipBootstrap.rdap_base_urls.Count -gt 0) {
                $server = $ipBootstrap.rdap_base_urls[0]
            }
            if (-not $server) { $server = 'https://rdap.apnic.net' }

            $script:RdapCache[$key] = ($server.TrimEnd('/'))
            return $script:RdapCache[$key]
        }

        function Get-RdapServerForAsn {
            $key = "asn"
            if ($script:RdapCache.ContainsKey($key)) { return $script:RdapCache[$key] }

            $asnBootstrap = Get-Json -Url $script:IanaBootstrap['ASN'] -TimeoutSec $TimeoutSec
            $server = $null
            if ($asnBootstrap -and $asnBootstrap.rdap_base_urls -and $asnBootstrap.rdap_base_urls.Count -gt 0) {
                $server = $asnBootstrap.rdap_base_urls[0]
            }
            if (-not $server) { $server = 'https://rdap.apnic.net' }

            $script:RdapCache[$key] = ($server.TrimEnd('/'))
            return $script:RdapCache[$key]
        }

        function Guess-Type {
            param([Parameter(Mandatory)][string]$Text)
            $q = $Text.Trim()
            if ($q -match '^(?i)AS?\d+$') { return 'ASN' }

            $ipObj = $null
            if ([System.Net.IPAddress]::TryParse($q, [ref]$ipObj)) { return 'IP' }

            if ($q -match '^[A-Za-z0-9\-\.]+\.[A-Za-z]{2,}$') { return 'Domain' }
            return 'Domain'
        }

        function Invoke-Rdap {
            param(
                [Parameter(Mandatory)][string]$Endpoint,
                [Parameter(Mandatory)][int]$MaxRetry,
                [Parameter(Mandatory)][int]$Timeout
            )

            $attempt = 0
            while ($true) {
                try {
                    return Invoke-RestMethod -Method GET -Uri $Endpoint -TimeoutSec $Timeout -ErrorAction Stop
                } catch {
                    $attempt++
                    $resp   = $null
                    $status = $null
                    if ($_.Exception -and $_.Exception.Response) {
                        $resp = $_.Exception.Response
                        if ($resp.StatusCode) { $status = [int]$resp.StatusCode.value__ }
                    }

                    # 文字列は先に組み立ててから使う（式内 if は 5.1 非対応）
                    $statusText = '?'
                    if ($status) { $statusText = [string]$status }

                    if ($status -in 429,500,502,503,504 -and $attempt -le $MaxRetry) {
                        Write-Verbose ("RDAP retry {0} for {1} (HTTP {2})" -f $attempt, $Endpoint, $statusText)
                        Start-Sleep -Seconds ([Math]::Min(2*$attempt, 5))
                        continue
                    }

                    Write-Error ("RDAP HTTP error {0} on {1}: {2}" -f $statusText, $Endpoint, $_.Exception.Message)
                    throw
                }
            }
        }

        function Shape-Output {
            param($json)
            if (-not $json) { return $null }

            # CIDR（v4/v6 のどちらか）
            $cidr = $null
            if ($json.cidr0_cidrs) {
                if ($json.cidr0_cidrs.v4prefix) { $cidr = $json.cidr0_cidrs.v4prefix }
                elseif ($json.cidr0_cidrs.v6prefix) { $cidr = $json.cidr0_cidrs.v6prefix }
            }

            # Nameservers
            $ns = $null
            if ($json.nameservers) {
                $ns = ($json.nameservers | Where-Object { $_ -and $_.ldhName } | ForEach-Object { $_.ldhName }) -join ', '
            }

            # Events
            $ev = $null
            if ($json.events) {
                $ev = ($json.events | ForEach-Object { "{0}:{1}" -f $_.eventAction, $_.eventDate }) -join '; '
            }

            # Entities
            $ent = $null
            if ($json.entities) {
                $ent = ($json.entities | ForEach-Object { if($_ -and $_.roles){ $_.roles -join '/' } }) -join ', '
            }

            # Remarks
            $rem = $null
            if ($json.remarks) {
                $rem = ($json.remarks | ForEach-Object { if($_ -and $_.description){ $_.description -join ' ' } }) -join ' | '
            }

            # Links
            $lnk = $null
            if ($json.links) {
                $lnk = ($json.links | ForEach-Object { $_.href }) -join ', '
            }

            [PSCustomObject]@{
                Handle          = $json.handle
                ObjectClassName = $json.objectClassName
                LdhName         = $json.ldhName
                UnicodeName     = $json.unicodeName
                Port43          = $json.port43
                Nameservers     = $ns
                Events          = $ev
                Status          = ($json.status) -join ', '
                Entities        = $ent
                NetworkStart    = $json.startAddress
                NetworkEnd      = $json.endAddress
                CIDR            = $cidr
                Remarks         = $rem
                Links           = $lnk
                Raw             = $json
            }
        }
    }

    process {
        foreach ($q in $Query) {
            if (-not $q) { continue }

            $resolvedType = if ($Type -eq 'Auto') { Guess-Type -Text $q } else { $Type }

            try {
                $endpoint = $null
                switch ($resolvedType) {
                    'Domain' {
                        $srv = Get-RdapServerForDomain -Domain $q
                        $endpoint = "$srv/domain/$q"
                    }
                    'IP' {
                        $srv = Get-RdapServerForIP -Ip $q
                        $endpoint = "$srv/ip/$q"
                    }
                    'ASN' {
                        $asn = $q.ToUpper()
                        if ($asn -notmatch '^AS\d+$') { $asn = "AS$asn" }
                        $srv = Get-RdapServerForAsn
                        $endpoint = "$srv/autnum/$asn"
                    }
                    default {
                        throw "Unsupported type: $resolvedType"
                    }
                }

                # キャッシュ
                $json = $null
                if ($script:RdapCache.ContainsKey($endpoint)) {
                    $json = $script:RdapCache[$endpoint]
                } else {
                    $json = Invoke-Rdap -Endpoint $endpoint -MaxRetry $MaxRetry -Timeout $TimeoutSec
                    $script:RdapCache[$endpoint] = $json
                }

                if ($Raw) {
                    Write-Output $json
                } else {
                    Write-Output (Shape-Output -json $json)
                }
            }
            catch {
                Write-Error ("RDAP lookup failed for '{0}' ({1}): {2}" -f $q, $resolvedType, $_.Exception.Message)
            }
        }
    }
}

# --- 自動ロードトリガ "whois" ---
function whois {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, Position=0)]
        [string[]]$Query,
        [ValidateSet('Auto','Domain','IP','ASN')]
        [string]$Type = 'Auto',
        [switch]$Raw,
        [int]$TimeoutSec = 15,
        [int]$MaxRetry   = 2
    )
    process {
        Get-RdapWhois -Query $Query -Type $Type -Raw:$Raw -TimeoutSec $TimeoutSec -MaxRetry $MaxRetry
    }
}

# alias も公開
Set-Alias -Name whois -Value Get-RdapWhois -Scope Local

# エクスポート
Export-ModuleMember -Function Get-RdapWhois, whois -Alias whois
