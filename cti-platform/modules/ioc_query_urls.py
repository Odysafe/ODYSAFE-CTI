"""
Odysafe CTI Platform
Copyright (C) 2026 ODYSAFE CTI Project

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Module pour générer les URLs de requête par type d'IOC
"""
import base64
import ipaddress
import urllib.parse
import re


def _parse_mitre_attack_technique(technique_id: str) -> tuple:
    """
    Parse MITRE ATT&CK technique ID to separate main technique from sub-technique.
    
    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., 'T1070.004' or 'T1070')
        
    Returns:
        Tuple of (main_technique, subtechnique) where subtechnique is None if not present
    """
    # Match pattern like T####.### or T####
    match = re.match(r'^(T\d{4})(?:\.(\d{3}))?$', technique_id.upper())
    if match:
        main_technique = match.group(1)
        subtechnique = match.group(2) if match.group(2) else None
        return main_technique, subtechnique
    return technique_id, None

def get_ioc_scope(ioc_type: str, ioc_value: str) -> dict:
    """Return deterministic scope context for IOC enrichment decisions."""
    ioc_type_lower = str(ioc_type or '').lower()
    value = str(ioc_value or '').strip()
    if ioc_type_lower not in {'ip', 'ip4', 'ip6', 'ipv4', 'ipv6'}:
        return {
            'scope': 'NOT_APPLICABLE',
            'label': 'Not applicable',
            'external_reputation_applicable': True,
            'reason': 'Scope filtering is only applied to IP indicators.',
            'suggested_pivots': [],
        }

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return {
            'scope': 'INVALID',
            'label': 'Invalid IP',
            'external_reputation_applicable': False,
            'reason': 'The value is not a valid IP address.',
            'suggested_pivots': ['Review extraction source', 'Check original value'],
        }

    documentation_networks = (
        ipaddress.ip_network('192.0.2.0/24'),
        ipaddress.ip_network('198.51.100.0/24'),
        ipaddress.ip_network('203.0.113.0/24'),
        ipaddress.ip_network('2001:db8::/32'),
    )
    if any(ip in network for network in documentation_networks):
        return {
            'scope': 'DOCUMENTATION',
            'label': 'Documentation range',
            'external_reputation_applicable': False,
            'reason': 'This IP belongs to a documentation range. External reputation lookups are not recommended.',
            'suggested_pivots': ['Cross-workspace recurrence', 'Source context', 'Internal notes'],
        }
    if ip.is_private:
        return {
            'scope': 'PRIVATE',
            'label': 'Private / internal',
            'external_reputation_applicable': False,
            'reason': 'This IP is private or internal. External reputation tools are not applicable.',
            'suggested_pivots': ['Cross-workspace recurrence', 'Internal sources', 'Internal graph', 'Memory notes'],
        }
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return {
            'scope': 'RESERVED',
            'label': 'Reserved / non-routable',
            'external_reputation_applicable': False,
            'reason': 'This IP is reserved or non-routable. External reputation tools are not applicable.',
            'suggested_pivots': ['Source context', 'Original extraction', 'Internal notes'],
        }
    return {
        'scope': 'PUBLIC',
        'label': 'Public internet',
        'external_reputation_applicable': True,
        'reason': 'External reputation and infrastructure enrichment tools are applicable.',
        'suggested_pivots': ['BGP', 'AbuseIPDB', 'VirusTotal', 'Shodan', 'OTX'],
    }


def get_query_urls(ioc_type: str, ioc_value: str) -> list:
    """
    Génère une liste d'URLs de requête pour un type d'IOC donné.
    
    Args:
        ioc_type: Le type d'IOC (ex: 'URL', 'IP', 'MD5', 'url', 'ip4', etc.)
        ioc_value: La valeur de l'IOC
        
    Returns:
        Liste de dictionnaires avec 'name' (nom de la source) et 'url' (URL complète)
    """
    urls = []
    ioc_type_upper = ioc_type.upper()
    ioc_type_lower = ioc_type.lower()
    ioc_value_clean = ioc_value.strip()
    
    # Indicateurs réseau et web
    if ioc_type_upper == 'URL' or ioc_type_lower == 'url':
        # VirusTotal
        try:
            url_base64 = base64.urlsafe_b64encode(ioc_value_clean.encode()).decode().rstrip('=')
            urls.append({
                'name': 'VirusTotal',
                'url': f'https://www.virustotal.com/gui/url/{url_base64}/'
            })
        except Exception:
            # Ignore errors when generating VirusTotal URL
            pass
        # URLScan.io
        url_encoded = urllib.parse.quote(ioc_value_clean, safe='')
        urls.append({
            'name': 'URLScan.io',
            'url': f'https://urlscan.io/search/#{url_encoded}'
        })
        # Hybrid Analysis
        urls.append({
            'name': 'Hybrid Analysis',
            'url': f'https://www.hybrid-analysis.com/search?query={url_encoded}'
        })
        # AlienVault OTX
        urls.append({
            'name': 'AlienVault OTX',
            'url': f'https://otx.alienvault.com/indicator/url/{url_encoded}'
        })
        # Pulsedive
        urls.append({
            'name': 'Pulsedive',
            'url': f'https://pulsedive.com/indicator/?q={url_encoded}'
        })
    
    elif ioc_type_upper in ['FQDN', 'DOMAIN', 'DOMAINE'] or ioc_type_lower == 'fqdn':
        # URLhaus
        urls.append({
            'name': 'URLhaus',
            'url': f'https://urlhaus.abuse.ch/host/{ioc_value_clean}/'
        })
        # VirusTotal
        urls.append({
            'name': 'VirusTotal',
            'url': f'https://www.virustotal.com/gui/domain/{ioc_value_clean}'
        })
        # URLScan.io
        urls.append({
            'name': 'URLScan.io',
            'url': f'https://urlscan.io/domain/{ioc_value_clean}'
        })
        # AlienVault OTX
        urls.append({
            'name': 'AlienVault OTX',
            'url': f'https://otx.alienvault.com/indicator/domain/{ioc_value_clean}'
        })
        # Pulsedive
        urls.append({
            'name': 'Pulsedive',
            'url': f'https://pulsedive.com/indicator/?q={ioc_value_clean}'
        })
        # ThreatFox (only for domains)
        urls.append({
            'name': 'ThreatFox',
            'url': f'https://threatfox.abuse.ch/browse.php?search=ioc:{ioc_value_clean}'
        })
    
    elif ioc_type_upper in ['IP', 'IPV4', 'IPV6'] or ioc_type_lower in ['ip4', 'ip6', 'ip']:
        if not get_ioc_scope(ioc_type, ioc_value_clean)['external_reputation_applicable']:
            return urls
        # BGP.he.net - BGP and network information
        urls.append({
            'name': 'BGP.he.net',
            'url': f'https://bgp.he.net/ip/{ioc_value_clean}'
        })
        # AbuseIPDB
        urls.append({
            'name': 'AbuseIPDB',
            'url': f'https://www.abuseipdb.com/check/{ioc_value_clean}'
        })
        # VirusTotal
        urls.append({
            'name': 'VirusTotal',
            'url': f'https://www.virustotal.com/gui/ip-address/{ioc_value_clean}'
        })
        # AlienVault OTX
        urls.append({
            'name': 'AlienVault OTX',
            'url': f'https://otx.alienvault.com/indicator/ip/{ioc_value_clean}'
        })
        # Pulsedive
        urls.append({
            'name': 'Pulsedive',
            'url': f'https://pulsedive.com/indicator/?q={ioc_value_clean}'
        })
        # Shodan
        urls.append({
            'name': 'Shodan',
            'url': f'https://www.shodan.io/host/{ioc_value_clean}'
        })
        # Shodan InternetDB
        urls.append({
            'name': 'Shodan InternetDB',
            'url': f'https://internetdb.shodan.io/{ioc_value_clean}'
        })
        # ThreatFox (only for IPs)
        urls.append({
            'name': 'ThreatFox',
            'url': f'https://threatfox.abuse.ch/browse.php?search=ioc:{ioc_value_clean}'
        })
    
    # Hashs cryptographiques
    elif ioc_type_upper in ['MD5', 'SHA1', 'SHA256'] or ioc_type_lower in ['md5', 'sha1', 'sha256']:
        # VirusTotal
        urls.append({
            'name': 'VirusTotal',
            'url': f'https://www.virustotal.com/gui/file/{ioc_value_clean}'
        })
        # MalwareBazaar
        urls.append({
            'name': 'MalwareBazaar',
            'url': f'https://bazaar.abuse.ch/sample/{ioc_value_clean}/'
        })
        # Hybrid Analysis (only for SHA256)
        if ioc_type_upper == 'SHA256' or ioc_type_lower == 'sha256':
            urls.append({
                'name': 'Hybrid Analysis',
                'url': f'https://www.hybrid-analysis.com/sample/{ioc_value_clean}'
            })
        # AlienVault OTX
        urls.append({
            'name': 'AlienVault OTX',
            'url': f'https://otx.alienvault.com/indicator/file/{ioc_value_clean}'
        })
        # Pulsedive
        urls.append({
            'name': 'Pulsedive',
            'url': f'https://pulsedive.com/indicator/?q={ioc_value_clean}'
        })
        # Any.run
        urls.append({
            'name': 'Any.run',
            'url': f'https://app.any.run/submissions/#filehash:{ioc_value_clean}'
        })
        # ThreatFox (only for hashes)
        urls.append({
            'name': 'ThreatFox',
            'url': f'https://threatfox.abuse.ch/browse.php?search=ioc:{ioc_value_clean}'
        })
    
    # Adresses Blockchain
    elif ioc_type_upper == 'BITCOIN' or ioc_type_lower == 'bitcoin':
        urls.append({
            'name': 'BitRef',
            'url': f'https://bitref.com/{ioc_value_clean}'
        })
        urls.append({
            'name': 'Blockchain.com',
            'url': f'https://www.blockchain.com/btc/address/{ioc_value_clean}'
        })
        urls.append({
            'name': 'Blockstream',
            'url': f'https://blockstream.info/address/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'ETHEREUM' or ioc_type_lower == 'ethereum':
        urls.append({
            'name': 'Etherscan',
            'url': f'https://etherscan.io/address/{ioc_value_clean}'
        })
        urls.append({
            'name': 'Etherchain',
            'url': f'https://etherchain.org/account/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'BITCOIN_CASH' or ioc_type_lower in ['bitcoincash', 'bitcoin_cash']:
        urls.append({
            'name': 'BlockExplorer',
            'url': f'https://blockexplorer.one/bitcoin-cash/mainnet/address/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'LITECOIN' or ioc_type_lower == 'litecoin':
        urls.append({
            'name': 'BlockExplorer',
            'url': f'https://blockexplorer.one/litecoin/mainnet/address/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'DOGECOIN' or ioc_type_lower == 'dogecoin':
        urls.append({
            'name': 'BlockExplorer',
            'url': f'https://blockexplorer.one/dogecoin/mainnet/address/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'MONERO' or ioc_type_lower == 'monero':
        urls.append({
            'name': 'XMRChain',
            'url': f'https://xmrchain.net/search?value={urllib.parse.quote(ioc_value_clean)}'
        })
    
    elif ioc_type_upper == 'RIPPLE' or ioc_type_lower == 'ripple':
        urls.append({
            'name': 'XRPScan',
            'url': f'https://xrpscan.com/account/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'CARDANO' or ioc_type_lower == 'cardano':
        urls.append({
            'name': 'CardanoScan',
            'url': f'https://cardanoscan.io/address/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'SOLANA' or ioc_type_lower == 'solana':
        urls.append({
            'name': 'Solscan',
            'url': f'https://solscan.io/account/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'TRON' or ioc_type_lower == 'tron':
        urls.append({
            'name': 'Tronscan',
            'url': f'https://tronscan.org/#/address/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'STELLAR' or ioc_type_lower == 'stellar':
        urls.append({
            'name': 'Stellar Expert',
            'url': f'https://stellar.expert/explorer/public/account/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'TEZOS' or ioc_type_lower == 'tezos':
        urls.append({
            'name': 'TzStats',
            'url': f'https://tzstats.com/{ioc_value_clean}'
        })
    
    # Vulnerability identifiers
    elif ioc_type_upper == 'CVE' or ioc_type_lower == 'cve':
        urls.append({
            'name': 'CVE Mitre',
            'url': f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={ioc_value_clean}'
        })
        urls.append({
            'name': 'NVD',
            'url': f'https://nvd.nist.gov/vuln/detail/{ioc_value_clean}'
        })
    
    elif ioc_type_upper in ['MITRE_ATTACK', 'TTP', 'ATTACK'] or ioc_type_lower == 'ttp':
        # Parse MITRE ATT&CK technique to handle sub-techniques
        main_technique, subtechnique = _parse_mitre_attack_technique(ioc_value_clean)
        if subtechnique:
            # Format: /techniques/T1070/004/
            urls.append({
                'name': 'MITRE ATT&CK',
                'url': f'https://attack.mitre.org/techniques/{main_technique}/{subtechnique}/'
            })
        else:
            # Format: /techniques/T1070/
            urls.append({
                'name': 'MITRE ATT&CK',
                'url': f'https://attack.mitre.org/techniques/{main_technique}/'
            })
    
    # Communication
    elif ioc_type_upper == 'EMAIL' or ioc_type_lower == 'email':
        email_encoded = urllib.parse.quote(ioc_value_clean, safe='')
        # AlienVault OTX
        urls.append({
            'name': 'AlienVault OTX',
            'url': f'https://otx.alienvault.com/indicator/email/{email_encoded}'
        })
    
    elif ioc_type_upper == 'PHONENUMBER' or ioc_type_lower == 'phonenumber':
        # Scamcallfighters
        phone_encoded = urllib.parse.quote(ioc_value_clean, safe='')
        urls.append({
            'name': 'Scamcallfighters',
            'url': f'https://www.scamcallfighters.com/search-phone-number/{phone_encoded}'
        })
    
    # Réseaux sociaux
    elif ioc_type_upper == 'TWITTER' or ioc_type_lower in ['twitter', 'twitterhandle']:
        urls.append({
            'name': 'Twitter',
            'url': f'https://twitter.com/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'GITHUB' or ioc_type_lower in ['github', 'githubhandle']:
        urls.append({
            'name': 'GitHub',
            'url': f'https://github.com/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'INSTAGRAM' or ioc_type_lower in ['instagram', 'instagramhandle']:
        urls.append({
            'name': 'Instagram',
            'url': f'https://www.instagram.com/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'LINKEDIN' or ioc_type_lower in ['linkedin', 'linkedinhandle']:
        urls.append({
            'name': 'LinkedIn',
            'url': f'https://www.linkedin.com/in/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'FACEBOOK' or ioc_type_lower in ['facebook', 'facebookhandle']:
        urls.append({
            'name': 'Facebook',
            'url': f'https://www.facebook.com/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'YOUTUBE' or ioc_type_lower in ['youtube', 'youtubehandle', 'youtubechannel']:
        urls.append({
            'name': 'YouTube',
            'url': f'https://www.youtube.com/@{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'TELEGRAM' or ioc_type_lower in ['telegram', 'telegramhandle']:
        urls.append({
            'name': 'Telegram',
            'url': f'https://t.me/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'PINTEREST' or ioc_type_lower in ['pinterest', 'pinteresthandle']:
        urls.append({
            'name': 'Pinterest',
            'url': f'https://www.pinterest.com/{ioc_value_clean}'
        })
    
    # Technical identifiers
    # PACKAGE_ANDROID removed - no external service available
    
    # Financial identifiers
    elif ioc_type_upper == 'WEBMONEY' or ioc_type_lower == 'webmoney':
        urls.append({
            'name': 'WebMoney',
            'url': f'https://passport.webmoney.ru/asp/certview.asp?wmid={ioc_value_clean}'
        })
    
    # Tor and dark web identifiers
    elif ioc_type_upper in ['TOR_V3', 'ONION'] or ioc_type_lower == 'onionaddress':
        # Les adresses Tor nécessitent le navigateur Tor
        # Remove .onion suffix if already present
        onion_address = ioc_value_clean
        if not onion_address.endswith('.onion'):
            onion_address = f'{onion_address}.onion'
        urls.append({
            'name': 'Tor Browser',
            'url': f'http://{onion_address}'
        })
        # Ahmia (Tor search engine)
        urls.append({
            'name': 'Ahmia',
            'url': f'https://ahmia.fi/search/?q={urllib.parse.quote(onion_address)}'
        })
    
    # UUID identifiers
    elif ioc_type_upper == 'UUID' or ioc_type_lower == 'uuid':
        # UUID.info (basic lookup)
        urls.append({
            'name': 'UUID.info',
            'url': f'https://www.uuid.info/?uuid={ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'ARN' or ioc_type_lower == 'arn':
        # AWS ARN lookup (basic - no direct service, but can search)
        # AWS Console search would require login, so we provide a search link
        arn_encoded = urllib.parse.quote(ioc_value_clean, safe='')
        urls.append({
            'name': 'AWS Resource',
            'url': f'https://console.aws.amazon.com/cloudcontrol/home?region=us-east-1#/resources/{arn_encoded}'
        })
    
    # IP Subnets
    elif ioc_type_upper == 'IP4NET' or ioc_type_lower == 'ip4net':
        # Shodan for subnet
        urls.append({
            'name': 'Shodan',
            'url': f'https://www.shodan.io/search?query=net:{ioc_value_clean}'
        })
        # Pulsedive for subnet
        urls.append({
            'name': 'Pulsedive',
            'url': f'https://pulsedive.com/indicator/?q={ioc_value_clean}'
        })
    
    # Additional blockchain addresses
    elif ioc_type_upper == 'ZCASH' or ioc_type_lower == 'zcash':
        urls.append({
            'name': 'Zcash Explorer',
            'url': f'https://explorer.zcha.in/accounts/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'DASHCOIN' or ioc_type_lower == 'dashcoin':
        urls.append({
            'name': 'Dash Explorer',
            'url': f'https://explorer.dash.org/address/{ioc_value_clean}'
        })
    
    # WhatsApp handle
    elif ioc_type_upper == 'WHATSAPP' or ioc_type_lower == 'whatsapphandle':
        urls.append({
            'name': 'WhatsApp',
            'url': f'https://wa.me/{ioc_value_clean}'
        })
    
    # YouTube Channel (different from handle)
    elif ioc_type_upper == 'YOUTUBECHANNEL' or ioc_type_lower == 'youtubechannel':
        # YouTube channel can be by ID or custom URL
        if ioc_value_clean.startswith('UC') or ioc_value_clean.startswith('@'):
            urls.append({
                'name': 'YouTube Channel',
                'url': f'https://www.youtube.com/{ioc_value_clean}'
            })
        else:
            urls.append({
                'name': 'YouTube Channel',
                'url': f'https://www.youtube.com/c/{ioc_value_clean}'
            })
    
    return urls
