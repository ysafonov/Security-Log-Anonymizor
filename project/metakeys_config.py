import functions
from functions import*
# from functions import anonymize_ip
# from functions import anonymize_ipv6
# from functions import anonymize_link_local_ipv6
# categorized meta keys for Elasticsearch
class Elasticsearch:
    EMAIL_KEYS = (
    "email.bcc.address", "email.cc.address", "email.from.address", "email.reply_to.address", "email.sender.address",
    "email.to.address", "threat.enrichments.indicator.email.address", "threat.indicator.email.address", "user.email")
    IP_KEYS = ("client.ip", "client.nat.ip", "destination.ip", "destination.nat.ip", "host.ip", "observer.ip",
               "related.ip", "server.ip", "server.nat.ip", "source.ip", "source.nat.ip",
               "threat.enrichments.indicator.ip", "threat.indicator.ip", 'ip')
    DOMAIN_KEYS = ["TargetDomainName", "client.domain", "client.registrated_domain", "destination.domain", "destination.registrated_domain",
                   "server.domain", "source.domain", "source.registrated_domain", "url.domain", "user.domain", "host.name", 'computer_name']
    DIRECTORY_KEYS = ["file.directory", "file.path"]
    MAC_KEYS = ("observer.mac", "client.mac", "host.mac", "destination.mac", "server.mac", "source.mac")
    USERNAME_KEYS = ["user.name", "TargetUserName", 'host.hostname', 'AccountName']
    FULLNAME_KEYS = ["user.full_name"]
    URL_KEYS = ["url.full", "url.original"]
    ORGANIZATION_KEYS = ["organization.name"]
    ip_function_mapping = ["ipv4", "ipv6", "ipv6_local"]

# categorized meta keys for RSANetWitness
class RSANetWitness:
    EMAIL_KEYS = ["email", "email.dst", "email.src"]
    IP_KEYS = ["forward.ip", 'SourceIP', 'DestinationIP' "alias.ip", "device.ip", "ip.addr", "ip.dst", "ip.src", "tunnel.ip.dst", "tunnel.ip.src", "paddr", "alias.ipv6", "device.ipv6", "ipv6.dst", "ipv6.src", "tunnel.ipv6.dst", "tunnel.ipv6.src"]
    DOMAIN_KEYS =["ad.domain.dst", "ad.domain.src", "domain.dst", "domain.src", "site.id", "event.computer", "domain", 'device.host']
    MAC_KEYS = ['DestinationMac', 'SourceMac' "alias.mac", "eth.src", "eth.dst"]
    DIRECTORY_KEYS = ["directory.src", "directory.dst", "directory.src_path", "directory.dst_path", "obj.name", "process"]
    USERNAME_KEYS = ["ad.username.dst", "ad.username.src", "username", "did", "site.id", "lc.cid", "user.dst"]
    FULLNAME_KEYS = ["fullname"]
    URL_KEYS=['url']
    ORGANIZATION_KEYS=["org.dst", "org.src", "device.group"]
    ip_function_mapping = ["ipv4", "ipv6", "ipv6_local"]

# categorized meta keys for QRadar
class QRadar:
    EMAIL_KEYS = ["recipient-address", "sender-address", "related-recipient-address"]
    IP_KEYS = ["c-ip", "client-ip", "IPAddress", "InterfaceIP", "IP_MulticastScopeName", "IP_Name", "s-ip", "server-ip", "original-client-ip", "original-server-ip", "local-endpoint", "remote-endpoint"]
    DOMAIN_KEYS = ["Domain"]
    MAC_KEYS = ["MACAddress"]
    USERNAME_KEYS = ["cs-username", "UserName", "usrName", "client-hostname", "Hostname", "AccountName"]
    FULLNAME_KEYS = ["ClientName"]