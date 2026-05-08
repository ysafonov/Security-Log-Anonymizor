# categorized meta keys for supported SIEM platforms

from __future__ import annotations


IP_FUNCTION_MAPPING = ["ipv4", "ipv6", "ipv6_local"]


class BaseSIEMMetaKeys:
    """Base class for SIEM meta-key definitions."""

    EMAIL_KEYS = []
    IP_KEYS = []
    DOMAIN_KEYS = []
    DIRECTORY_KEYS = []
    MAC_KEYS = []
    USERNAME_KEYS = []
    FULLNAME_KEYS = []
    URL_KEYS = []
    ORGANIZATION_KEYS = []

    ip_function_mapping = IP_FUNCTION_MAPPING

    @classmethod
    def get_categories(cls) -> dict[str, list[str]]:
        """Return all meta-key categories for the selected SIEM platform."""
        return {
            "email": cls.EMAIL_KEYS,
            "ip": cls.IP_KEYS,
            "domain": cls.DOMAIN_KEYS,
            "directory": cls.DIRECTORY_KEYS,
            "mac": cls.MAC_KEYS,
            "username": cls.USERNAME_KEYS,
            "fullname": cls.FULLNAME_KEYS,
            "url": cls.URL_KEYS,
            "organization": cls.ORGANIZATION_KEYS,
        }

    @classmethod
    def get_all_keys(cls) -> list[str]:
        """Return all unique meta keys while preserving their original order."""
        seen = set()
        result = []

        for keys in cls.get_categories().values():
            for key in keys:
                if key not in seen:
                    seen.add(key)
                    result.append(key)

        return result


class Elasticsearch(BaseSIEMMetaKeys):
    EMAIL_KEYS = [
        "email.bcc.address",
        "email.cc.address",
        "email.from.address",
        "email.reply_to.address",
        "email.sender.address",
        "email.to.address",
        "threat.enrichments.indicator.email.address",
        "threat.indicator.email.address",
        "user.email",
    ]

    IP_KEYS = [
        "client.ip",
        "client.nat.ip",
        "destination.ip",
        "destination.nat.ip",
        "host.ip",
        "observer.ip",
        "related.ip",
        "server.ip",
        "server.nat.ip",
        "source.ip",
        "source.nat.ip",
        "threat.enrichments.indicator.ip",
        "threat.indicator.ip",
        "ip",
    ]

    DOMAIN_KEYS = [
        "TargetDomainName",
        "client.domain",
        "client.registrated_domain",
        "destination.domain",
        "destination.registrated_domain",
        "server.domain",
        "source.domain",
        "source.registrated_domain",
        "url.domain",
        "user.domain",
        "host.name",
        "computer_name",
    ]

    DIRECTORY_KEYS = [
        "file.directory",
        "file.path",
    ]

    MAC_KEYS = [
        "observer.mac",
        "client.mac",
        "host.mac",
        "destination.mac",
        "server.mac",
        "source.mac",
    ]

    USERNAME_KEYS = [
        "user.name",
        "TargetUserName",
        "host.hostname",
        "AccountName",
    ]

    FULLNAME_KEYS = [
        "user.full_name",
    ]

    URL_KEYS = [
        "url.full",
        "url.original",
    ]

    ORGANIZATION_KEYS = [
        "organization.name",
    ]


class RSANetWitness(BaseSIEMMetaKeys):
    EMAIL_KEYS = [
        "email",
        "email.dst",
        "email.src",
    ]

    IP_KEYS = [
        "forward.ip",
        "SourceIP",
        "DestinationIP",
        "alias.ip",
        "device.ip",
        "ip.addr",
        "ip.dst",
        "ip.src",
        "tunnel.ip.dst",
        "tunnel.ip.src",
        "paddr",
        "alias.ipv6",
        "device.ipv6",
        "ipv6.dst",
        "ipv6.src",
        "tunnel.ipv6.dst",
        "tunnel.ipv6.src",
    ]

    DOMAIN_KEYS = [
        "ad.domain.dst",
        "ad.domain.src",
        "domain.dst",
        "domain.src",
        "site.id",
        "event.computer",
        "domain",
        "device.host",
    ]

    MAC_KEYS = [
        "DestinationMac",
        "SourceMac",
        "alias.mac",
        "eth.src",
        "eth.dst",
    ]

    DIRECTORY_KEYS = [
        "directory.src",
        "directory.dst",
        "directory.src_path",
        "directory.dst_path",
        "obj.name",
        "process",
    ]

    USERNAME_KEYS = [
        "ad.username.dst",
        "ad.username.src",
        "username",
        "did",
        "site.id",
        "lc.cid",
        "user.dst",
    ]

    FULLNAME_KEYS = [
        "fullname",
    ]

    URL_KEYS = [
        "url",
    ]

    ORGANIZATION_KEYS = [
        "org.dst",
        "org.src",
        "device.group",
    ]


class QRadar(BaseSIEMMetaKeys):
    EMAIL_KEYS = [
        "recipient-address",
        "sender-address",
        "related-recipient-address",
    ]

    IP_KEYS = [
        "c-ip",
        "client-ip",
        "IPAddress",
        "InterfaceIP",
        "IP_MulticastScopeName",
        "IP_Name",
        "s-ip",
        "server-ip",
        "original-client-ip",
        "original-server-ip",
        "local-endpoint",
        "remote-endpoint",
    ]

    DOMAIN_KEYS = [
        "Domain",
    ]

    MAC_KEYS = [
        "MACAddress",
    ]

    USERNAME_KEYS = [
        "cs-username",
        "UserName",
        "usrName",
        "client-hostname",
        "Hostname",
        "AccountName",
    ]

    FULLNAME_KEYS = [
        "ClientName",
    ]


class Splunk(BaseSIEMMetaKeys):
    EMAIL_KEYS = [
        "email",
        "orig_recipient",
        "orig_src",
        "orig_dest",
        "owner_email",
        "recipient",
        "recipient_domain",
        "return_addr",
        "sender",
        "src_user",
        "src_user_domain",
    ]

    IP_KEYS = [
        "dest_ip",
        "dest_ip_range",
        "dest_translated_ip",
        "dvc_ip",
        "ip",
        "src_ip",
        "src_ip_range",
        "src_translated_ip",
    ]

    DOMAIN_KEYS = [
        "dest_nt_domain",
        "dns",
        "http_referrer_domain",
        "query",
        "recipient_domain",
        "src_dns",
        "dest_dns",
        "src_nt_domain",
        "src_user_domain",
        "ssl_subject_email_domain",
        "url_domain",
    ]

    MAC_KEYS = [
        "dest_mac",
        "dvc_mac",
        "mac",
        "src_mac",
    ]

    USERNAME_KEYS = [
        "owner",
        "owner_id",
        "src_user",
        "src_user_id",
        "src_user_name",
        "user",
        "user_id",
        "user_name",
    ]

    FULLNAME_KEYS = []

    URL_KEYS = [
        "dest_url",
        "http_referrer",
        "uri",
        "uri_path",
        "uri_query",
        "url",
        "url_domain",
    ]

    ORGANIZATION_KEYS = [
        "dest_bunit",
        "dvc_bunit",
        "src_bunit",
        "ssl_issuer_organization",
        "ssl_subject_organization",
        "user_bunit",
        "vendor_account",
    ]

    DIRECTORY_KEYS = []
