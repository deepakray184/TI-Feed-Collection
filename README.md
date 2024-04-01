# TIFeedCollection

This project is to collect IP/Hash/Domain using KQL query. 

| Feeds             | Link           | Status |          
| ------------- | ------------- |    ------------- | 
| IPSum         | https://github.com/stamparm/ipsum/blob/master/ipsum.txt    | Done |
|          |     | Done |
|          |     | Done |
|          |     | Done |
|          |     | Done |
|          |     | Done |
|          |     | Done |








Reference - https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/main/MISP
urls =  {'https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv': 'all',
        'http://data.phishtank.com/data/online-valid.csv': 'url',
        'https://dl.red.flag.domains/red.flag.domains.txt': 'domain',
        'https://dl.red.flag.domains/red.flag.domains_fr.txt': 'domain',
        'https://dl.red.flag.domains/red.flag.domains_ovh.txt': 'domain',
        'https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt': 'unknow',
        'https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt': 'unknow',
        'https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt': 'unknow',
        'https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt': 'unknow',
        'https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt': 'unknow',
        'https://malware-filter.gitlab.io/malware-filter/pup-filter-domains.txt': 'domain',
        'https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt': 'domain',
        'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt': 'domain',
        'https://malware-filter.gitlab.io/malware-filter/pup-filter-domains.txt': 'domain',
        'https://raw.githubusercontent.com/bigdargon/hostsVN/master/extensions/threat/hosts': 'unknow',
        'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt': 'domain',
        'https://raw.githubusercontent.com/cbuijs/ut1/master/malware/domains': 'domain',
        'https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/domain-list.txt': 'domain',
        'https://raw.githubusercontent.com/KitsapCreator/pihole-blocklists/master/malware-malicious.txt': 'unknow',
        'https://raw.githubusercontent.com/KitsapCreator/pihole-blocklists/master/scam-spam.txt': 'unknow',
        'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/fake.txt': 'unknow',
        'https://www.openphish.com/feed.txt': 'unknow',
        'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains/output/domains/ACTIVE/list': 'domain',
        'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains/output/domains/INACTIVE/list': 'domain',
        'https://github.com/tetzispa/domains-names/tree/main/domainesq': 'domain'}![image](https://github.com/deepakray184/TIFeedCollection/assets/22987796/de3461a2-d6c6-4a40-aa10-510a6327da43)

        let MISPFeed = externaldata(MD5: string)[@"https://bazaar.abuse.ch/export/txt/md5/recent"] with (format="txt", ignoreFirstRecord=True);
let MD5Regex = '[a-f0-9]{32}';

let MISPFeed = externaldata(Row: string)[@"https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';


let MISPFeed = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';

let IPsum = externaldata(DestIP: string, )[@"https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"] with (format="txt", ignoreFirstRecord=True)
| extend IPAddress = extract(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0, DestIP)
| where isnotempty(IPAddress)
| distinct IPAddress;
IP
| limit 10 ![image](https://github.com/deepakray184/TIFeedCollection/assets/22987796/37cb55a3-d229-4e32-97a2-9d7cc41b5f94)






let MISPFeed1 = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt"] with (format="txt", ignoreFirstRecord=True);
let MISPFeed2 = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt"] with (format="txt", ignoreFirstRecord=True);
let MISPFeed3 = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt"] with (format="txt", ignoreFirstRecord=True);
let MiraiFeed = externaldata(DestIP: string)[@"https://mirai.security.gives/data/ip_list.txt"] with (format="txt", ignoreFirstRecord=True);
let ProofPointFeed = externaldata(DestIP: string)[@"https://rules.emergingthreats.net/blockrules/compromised-ips.txt"] with (format="txt", ignoreFirstRecord=True);
let FeodoFeed = externaldata(Row: string)[@"https://feodotracker.abuse.ch/downloads/ipblocklist.csv"] with (format="txt", ignoreFirstRecord=True);
let DiamondFoxFeed = externaldata(Row: string)[@"https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt"] with (format="txt", ignoreFirstRecord=True);
let CINFeed = externaldata(DestIP: string)[@"https://cinsscore.com/list/ci-badguys.txt"] with (format="txt", ignoreFirstRecord=True);
let blocklistdeFeed = externaldata(DestIP: string)[@"https://lists.blocklist.de/lists/all.txt"] with (format="txt", ignoreFirstRecord=True);
let C2IntelFeeds = externaldata(IP: string, ioc:string)[@"https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"] with (format="csv", ignoreFirstRecord=True);
let DigitalsideFeed = externaldata(DestIP: string)[@"https://osint.digitalside.it/Threat-Intel/lists/latestips.txt"] with (format="txt", ignoreFirstRecord=True);
let MontySecurityFeed = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt"] with (format="txt", ignoreFirstRecord=True);
let TriggeredIP = SecurityAlert
| where AlertName contains "SOC-9008"
| mv-expand todynamic(Entities)
| extend IPAddress = tostring(Entities.Address)
| project IPAddress;
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP1 = materialize (
       MISPFeed1 
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
let MaliciousIP2 = materialize (
       MISPFeed2 
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
let MaliciousIP3 = materialize (
       MISPFeed3 
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
let MaliciousIP4 = materialize (
       MiraiFeed 
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
let MaliciousIP5 = materialize (
       ProofPointFeed 
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
let MaliciousIP6 = materialize (
       FeodoFeed 
       | extend IP = extract(IPRegex, 0, Row)
       | where isnotempty(IP)
       | distinct IP
        );
let MaliciousIP7 = materialize (
       DiamondFoxFeed 
       | extend DomainOrIP = extract(@'//(.*?)/', 1, Row)
       | extend DomainOrIPToLower = tolower(DomainOrIP)
       | where DomainOrIPToLower matches regex IPRegex
       | distinct DomainOrIP
        );
let MaliciousIP8 = materialize (
       CINFeed 
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
let MaliciousIP9 = materialize (
       blocklistdeFeed 
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
let MaliciousIP10 = C2IntelFeeds
| project IP;
let MaliciousIP11 = materialize (
       DigitalsideFeed
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
let MaliciousIP12 = materialize (
       MontySecurityFeed
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
CommonSecurityLog
| where SourceIP !in (TriggeredIP)
| where SourceIP in (MaliciousIP1) or SourceIP in (MaliciousIP2) or SourceIP in (MaliciousIP3) or DestinationIP in (MaliciousIP1) or DestinationIP in (MaliciousIP2) or DestinationIP in (MaliciousIP3) or SourceIP in (MaliciousIP4) or SourceIP in (MaliciousIP5) or SourceIP in (MaliciousIP6) or SourceIP in (MaliciousIP7) or SourceIP in (MaliciousIP8) or SourceIP in (MaliciousIP9) or SourceIP in (MaliciousIP10) or SourceIP in (MaliciousIP11) or SourceIP in (MaliciousIP12)
| where DeviceAction == "accept"
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| summarize count() by SourceIP, DeviceAction
