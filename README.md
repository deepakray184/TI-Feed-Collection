# Threat Intel Feeds

This project is to collect Threat Intel feed links mentioned below. 

| Link | Type |
| --- | --- |
| `https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv` | all |
| `http://data.phishtank.com/data/online-valid.csv` | url |
| `https://dl.red.flag.domains/red.flag.domains.txt` | domain |
| `https://dl.red.flag.domains/red.flag.domains_fr.txt` | domain |
| `https://dl.red.flag.domains/red.flag.domains_ovh.txt` | domain |
| `https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt` | unknown |
| `https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt` | unknown |
| `https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt` | unknown |
| `https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt` | unknown |
| `https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt` | unknown |
| `https://malware-filter.gitlab.io/malware-filter/pup-filter-domains.txt` | domain |
| `https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt` | domain |
| `https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt` | domain |
| `https://malware-filter.gitlab.io/malware-filter/pup-filter-domains.txt` | domain |
| `https://raw.githubusercontent.com/bigdargon/hostsVN/master/extensions/threat/hosts` | unknown |
| `https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt` | domain |
| `https://raw.githubusercontent.com/cbuijs/ut1/master/malware/domains` | domain |
| `https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/domain-list.txt` | domain |
| `https://raw.githubusercontent.com/KitsapCreator/pihole-blocklists/master/malware-malicious.txt` | unknown |
| `https://raw.githubusercontent.com/KitsapCreator/pihole-blocklists/master/scam-spam.txt` | unknown |
| `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/fake.txt` | unknown |
| `https://www.openphish.com/feed.txt` | unknown |
| `https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains/output/domains/ACTIVE/list` | domain |
| `https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains/output/domains/INACTIVE/list` | domain |
| `https://github.com/tetzispa/domains-names/tree/main/domainesq` | domain |

## KQL Query Example

```python
let MISPFeed = externaldata(MD5: string)[@"https://bazaar.abuse.ch/export/txt/md5/recent"] with (format="txt", ignoreFirstRecord=True);
let MD5Regex = '[a-f0-9]{32}';

let MISPFeed = externaldata(Row: string)[@"https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';

let MISPFeed = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
```

## Reference
https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/main/MISP
