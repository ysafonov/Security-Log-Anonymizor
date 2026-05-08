from __future__ import annotations

import ipaddress
import random
from typing import ClassVar
from urllib.parse import urlparse, urlunparse

import randominfo
from faker import Faker


class Functions:
    """
    Utility class for deterministic anonymization of selected data types.

    The class keeps in-memory dictionaries that map original values to generated
    anonymized values. This ensures that the same original value is always
    replaced by the same anonymized value during one application run.

    Example:
        192.168.1.10 -> 192.168.44.87
        192.168.1.10 -> 192.168.44.87  # same result on repeated use
    """

    fake: ClassVar[Faker] = Faker()

    # -------------------------------------------------------------------------
    # In-memory anonymization maps
    # -------------------------------------------------------------------------
    # These dictionaries intentionally live at class level because the rest of
    # the application uses Functions as a shared anonymization state container.

    ip_dictionary: ClassVar[dict[str, str]] = {}
    ipv6_dictionary: ClassVar[dict[str, str]] = {}
    linklocal_dictionary: ClassVar[dict[str, str]] = {}
    url_dictionary: ClassVar[dict[str, str]] = {}
    email_dictionary: ClassVar[dict[str, str]] = {}
    organizations_dictionary: ClassVar[dict[str, str]] = {}
    mac_dictionary: ClassVar[dict[str, str]] = {}
    name_dictionary: ClassVar[dict[str, str]] = {}
    domains_dictionary: ClassVar[dict[str, str]] = {}
    username_dictionary: ClassVar[dict[str, str]] = {}
    win_path_dictionary: ClassVar[dict[str, str]] = {}

    # Private IPv4 ranges according to RFC 1918.
    PRIVATE_IPV4_NETWORKS: ClassVar[tuple[ipaddress.IPv4Network, ...]] = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )

    # Documentation IPv4 ranges according to RFC 5737.
    # These are safer than generating real public IPv4 addresses, because they
    # are reserved for examples and should not point to real systems.
    DOCUMENTATION_IPV4_NETWORKS: ClassVar[tuple[ipaddress.IPv4Network, ...]] = (
        ipaddress.IPv4Network("192.0.2.0/24"),
        ipaddress.IPv4Network("198.51.100.0/24"),
        ipaddress.IPv4Network("203.0.113.0/24"),
    )

    PRESERVED_WINDOWS_COMPONENTS: ClassVar[set[str]] = {
        "Windows",
        "Program Files",
        "Program Files (x86)",
        "Users",
        "System32",
    }

    # -------------------------------------------------------------------------
    # Generic helper methods
    # -------------------------------------------------------------------------

    @staticmethod
    def _get_or_create(mapping: dict[str, str], original_value: str, generator) -> str:
        """
        Return an already generated anonymized value or create a new one.

        This removes repeated dictionary boilerplate from individual anonymizers.
        """
        if original_value not in mapping:
            mapping[original_value] = generator()

        return mapping[original_value]

    @staticmethod
    def _random_ipv4_from_network(network: ipaddress.IPv4Network) -> str:
        """
        Generate a random IPv4 address from the selected network.

        Network and broadcast addresses are excluded when the network size allows
        it. For very small networks, the full range is used as a fallback.
        """
        first_address = int(network.network_address)
        last_address = int(network.broadcast_address)

        if network.num_addresses > 2:
            first_address += 1
            last_address -= 1

        return str(ipaddress.IPv4Address(random.randint(first_address, last_address)))

    @staticmethod
    def _find_private_ipv4_network(ip_address: ipaddress.IPv4Address) -> ipaddress.IPv4Network | None:
        """Return the RFC 1918 private network containing the IP address, if any."""
        for network in Functions.PRIVATE_IPV4_NETWORKS:
            if ip_address in network:
                return network

        return None

    @staticmethod
    def _generate_random_private_ip(private_range: dict[str, str]) -> str:
        """
        Generate a random IPv4 address inside a custom start/end range.

        This method is kept for backward compatibility with the original code.
        Prefer _random_ipv4_from_network for new code.
        """
        start = int(ipaddress.IPv4Address(private_range["start"]))
        end = int(ipaddress.IPv4Address(private_range["end"]))
        return str(ipaddress.IPv4Address(random.randint(start, end)))

    # -------------------------------------------------------------------------
    # IPv4 anonymization
    # -------------------------------------------------------------------------

    @staticmethod
    def anonymize_ip(ip_address: str) -> str:
        """
        Anonymize an IPv4 address while preserving its broad address type.

        - RFC 1918 private addresses are replaced by another address from the
          same private network block.
        - Non-private addresses are replaced by an address from documentation
          ranges reserved for examples.
        - Invalid input is returned unchanged.
        """
        if ip_address in Functions.ip_dictionary:
            return Functions.ip_dictionary[ip_address]

        try:
            parsed_ip = ipaddress.IPv4Address(ip_address)
        except ipaddress.AddressValueError:
            return ip_address

        private_network = Functions._find_private_ipv4_network(parsed_ip)

        if private_network is not None:
            anonymized_ip = Functions._random_ipv4_from_network(private_network)
        else:
            documentation_network = random.choice(Functions.DOCUMENTATION_IPV4_NETWORKS)
            anonymized_ip = Functions._random_ipv4_from_network(documentation_network)

        Functions.ip_dictionary[ip_address] = anonymized_ip
        return anonymized_ip

    # -------------------------------------------------------------------------
    # IPv6 anonymization
    # -------------------------------------------------------------------------

    @staticmethod
    def anonymize_ipv6(ipv6_address: str) -> str:
        """
        Anonymize an IPv6 address by changing one randomly selected 16-bit block.

        The method normalizes compressed IPv6 notation internally, so addresses
        like 2001:db8::1 are handled correctly.
        """
        if ipv6_address in Functions.ipv6_dictionary:
            return Functions.ipv6_dictionary[ipv6_address]

        try:
            parsed_ip = ipaddress.IPv6Address(ipv6_address)
        except ipaddress.AddressValueError:
            return ipv6_address

        blocks = parsed_ip.exploded.split(":")
        random_index = random.randint(0, len(blocks) - 1)
        blocks[random_index] = f"{random.randint(0, 2**16 - 1):04x}"

        anonymized_ipv6 = str(ipaddress.IPv6Address(":".join(blocks)))
        Functions.ipv6_dictionary[ipv6_address] = anonymized_ipv6
        return anonymized_ipv6

    @staticmethod
    def anonymize_link_local_ipv6(ipv6_address: str) -> str:
        """
        Anonymize a link-local IPv6 address while preserving the fe80:: prefix.

        The interface identifier is anonymized block by block. The same original
        block receives the same anonymized block during one application run.
        """
        if ipv6_address in Functions.linklocal_dictionary:
            return Functions.linklocal_dictionary[ipv6_address]

        try:
            parsed_ip = ipaddress.IPv6Address(ipv6_address)
        except ipaddress.AddressValueError:
            return ipv6_address

        if not parsed_ip.is_link_local:
            return ipv6_address

        blocks = parsed_ip.exploded.split(":")

        # Link-local IPv6 addresses use fe80::/10. We preserve the first four
        # blocks and anonymize the interface identifier in the last four blocks.
        prefix_blocks = blocks[:4]
        interface_blocks = blocks[4:]

        anonymized_interface_blocks = []
        for block in interface_blocks:
            anonymized_block = Functions._get_or_create(
                Functions.linklocal_dictionary,
                block,
                lambda: f"{random.randint(0, 2**16 - 1):04x}",
            )
            anonymized_interface_blocks.append(anonymized_block)

        anonymized_ipv6 = str(
            ipaddress.IPv6Address(":".join(prefix_blocks + anonymized_interface_blocks))
        )
        Functions.linklocal_dictionary[ipv6_address] = anonymized_ipv6
        return anonymized_ipv6

    # -------------------------------------------------------------------------
    # MAC, e-mail, URL and domain anonymization
    # -------------------------------------------------------------------------

    @staticmethod
    def anonymize_mac(mac: str) -> str:
        """Anonymize a MAC address and preserve mapping consistency."""
        return Functions._get_or_create(
            Functions.mac_dictionary,
            mac,
            Functions.fake.mac_address,
        )

    @staticmethod
    def _get_email() -> str:
        """
        Generate a fake e-mail address.

        The method keeps the original randominfo-based behavior but centralizes
        e-mail generation in one place.
        """
        base_domain = Functions.fake.domain_name()
        domain = f"@{base_domain}"
        pattern = random.randint(0, 2)

        if pattern == 0:
            return (
                randominfo.get_first_name()
                + randominfo.get_formatted_datetime(
                    "%Y",
                    randominfo.get_birthdate(None),
                    "%d %b, %Y",
                )
                + domain
            )

        if pattern == 1:
            return (
                randominfo.get_last_name()
                + randominfo.get_formatted_datetime(
                    "%d",
                    randominfo.get_birthdate(None),
                    "%d %b, %Y",
                )
                + domain
            )

        return (
            randominfo.get_first_name()
            + randominfo.get_last_name()
            + randominfo.get_formatted_datetime(
                "%y",
                randominfo.get_birthdate(None),
                "%d %b, %Y",
            )
            + domain
        )

    @staticmethod
    def anonymize_email(email: str) -> str:
        """Anonymize an e-mail address and preserve mapping consistency."""
        return Functions._get_or_create(
            Functions.email_dictionary,
            email,
            Functions._get_email,
        )

    @staticmethod
    def anonymize_url(url: str) -> str:
        """
        Anonymize a URL by replacing only the network location/domain.

        Scheme, path, query and fragment are preserved because they may be useful
        for structural analysis of logs.
        """
        if url in Functions.url_dictionary:
            return Functions.url_dictionary[url]

        parsed_url = urlparse(url)

        # If the URL is malformed or does not contain a hostname, keep it as is.
        if not parsed_url.netloc:
            return url

        anonymized_domain = Functions.fake.domain_name()
        anonymized_url = urlunparse(
            (
                parsed_url.scheme,
                anonymized_domain,
                parsed_url.path,
                parsed_url.params,
                parsed_url.query,
                parsed_url.fragment,
            )
        )

        Functions.url_dictionary[url] = anonymized_url
        return anonymized_url

    @staticmethod
    def anonymize_domain(domain: str) -> str:
        """Anonymize a domain name and preserve mapping consistency."""
        return Functions._get_or_create(
            Functions.domains_dictionary,
            domain,
            Functions.fake.domain_name,
        )

    # -------------------------------------------------------------------------
    # Identity and organization anonymization
    # -------------------------------------------------------------------------

    @staticmethod
    def anonymize_name(name: str) -> str:
        """Anonymize a personal name and preserve mapping consistency."""
        return Functions._get_or_create(
            Functions.name_dictionary,
            name,
            Functions.fake.name,
        )

    @staticmethod
    def anonymize_username(username: str) -> str:
        """Anonymize a username and preserve mapping consistency."""
        return Functions._get_or_create(
            Functions.username_dictionary,
            username,
            Functions.fake.user_name,
        )

    @staticmethod
    def anonymize_organization(org_name: str) -> str:
        """Anonymize an organization/company name and preserve mapping consistency."""
        return Functions._get_or_create(
            Functions.organizations_dictionary,
            org_name,
            Functions.fake.company,
        )

    # -------------------------------------------------------------------------
    # Windows path anonymization
    # -------------------------------------------------------------------------

    @staticmethod
    def anonymize_windows_path(path: str) -> str:
        """
        Anonymize a Windows filesystem path.

        Common system directories are preserved to keep the path semantically
        useful. User-specific or application-specific path components are
        replaced by fake words.
        """
        if path in Functions.win_path_dictionary:
            return Functions.win_path_dictionary[path]

        normalized_path = str(path)

        # Preserve drive letter, for example C: or D:.
        drive = ""
        tail = normalized_path
        if len(normalized_path) >= 2 and normalized_path[1] == ":":
            drive = normalized_path[:2]
            tail = normalized_path[2:]

        # Split only by backslash because this function targets Windows paths.
        path_components = [component for component in tail.split("\\") if component]

        anonymized_components = []
        for component in path_components:
            if component in Functions.PRESERVED_WINDOWS_COMPONENTS:
                anonymized_components.append(component)
                continue

            anonymized_component = Functions._get_or_create(
                Functions.win_path_dictionary,
                component,
                Functions.fake.word,
            )
            anonymized_components.append(anonymized_component)

        anonymized_tail = "\\".join(anonymized_components)
        anonymized_path = f"{drive}\\{anonymized_tail}" if drive else anonymized_tail

        Functions.win_path_dictionary[path] = anonymized_path
        return anonymized_path

    # -------------------------------------------------------------------------
    # State management
    # -------------------------------------------------------------------------

    @staticmethod
    def clear_dicts() -> None:
        """
        Clear all in-memory anonymization dictionaries.

        This is useful when the user wants a new anonymization run without
        reusing mappings from previous uploads.
        """
        dictionaries = (
            Functions.username_dictionary,
            Functions.organizations_dictionary,
            Functions.win_path_dictionary,
            Functions.name_dictionary,
            Functions.ip_dictionary,
            Functions.ipv6_dictionary,
            Functions.linklocal_dictionary,
            Functions.email_dictionary,
            Functions.mac_dictionary,
            Functions.domains_dictionary,
            Functions.url_dictionary,
        )

        for dictionary in dictionaries:
            dictionary.clear()
