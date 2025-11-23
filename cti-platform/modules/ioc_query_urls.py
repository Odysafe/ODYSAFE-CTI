"""
Odysafe CTI Platform
Copyright (C) 2025 Bastien GUIDONE

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
import urllib.parse


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
        # URLhaus
        urls.append({
            'name': 'URLhaus',
            'url': f'https://urlhaus.abuse.ch/url/{ioc_value_clean}/'
        })
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
        # ThreatFox
        urls.append({
            'name': 'ThreatFox',
            'url': f'https://threatfox.abuse.ch/browse.php?search=ioc:{ioc_value_clean}'
        })
    
    elif ioc_type_upper in ['IP', 'IPV4', 'IPV6'] or ioc_type_lower in ['ip4', 'ip6', 'ip']:
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
        # ThreatFox
        urls.append({
            'name': 'ThreatFox',
            'url': f'https://threatfox.abuse.ch/browse.php?search=ioc:{ioc_value_clean}'
        })
        # Shodan InternetDB
        urls.append({
            'name': 'Shodan InternetDB',
            'url': f'https://internetdb.shodan.io/{ioc_value_clean}'
        })
    
    # Hashs cryptographiques
    elif ioc_type_upper == 'MD5' or ioc_type_lower == 'md5':
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
        # ThreatFox
        urls.append({
            'name': 'ThreatFox',
            'url': f'https://threatfox.abuse.ch/browse.php?search=ioc:{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'SHA1' or ioc_type_lower == 'sha1':
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
    
    elif ioc_type_upper == 'SHA256' or ioc_type_lower == 'sha256':
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
        # ThreatFox
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
            'name': 'BlockExplorer',
            'url': f'https://blockexplorer.one/bitcoin/mainnet/address/{ioc_value_clean}'
        })
    
    elif ioc_type_upper == 'ETHEREUM' or ioc_type_lower == 'ethereum':
        urls.append({
            'name': 'Etherscan',
            'url': f'https://etherscan.io/address/{ioc_value_clean}'
        })
        urls.append({
            'name': 'BlockExplorer',
            'url': f'https://blockexplorer.one/ethereum/mainnet/address/{ioc_value_clean}'
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
        urls.append({
            'name': 'MITRE ATT&CK',
            'url': f'https://attack.mitre.org/techniques/{ioc_value_clean}/'
        })
    
    # Communication
    elif ioc_type_upper == 'EMAIL' or ioc_type_lower == 'email':
        urls.append({
            'name': 'Have I Been Pwned',
            'url': f'https://haveibeenpwned.com/account/{urllib.parse.quote(ioc_value_clean)}'
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
    elif ioc_type_upper == 'PACKAGE_ANDROID' or ioc_type_lower == 'packagename':
        urls.append({
            'name': 'Google Play',
            'url': f'https://play.google.com/store/apps/details?id={ioc_value_clean}'
        })
    
    # Financial identifiers
    elif ioc_type_upper == 'WEBMONEY' or ioc_type_lower == 'webmoney':
        urls.append({
            'name': 'WebMoney',
            'url': f'https://passport.webmoney.ru/asp/certview.asp?wmid={ioc_value_clean}'
        })
    
    # Tor and dark web identifiers
    elif ioc_type_upper in ['TOR_V3', 'ONION'] or ioc_type_lower == 'onionaddress':
        # Les adresses Tor nécessitent le navigateur Tor
        urls.append({
            'name': 'Tor Browser',
            'url': f'http://{ioc_value_clean}.onion'
        })
    
    return urls

