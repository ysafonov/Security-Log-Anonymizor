from functions import*
import config
from replace import*
configuration = metakeys_config.Elasticsearch
# configuration = metakeys_config.RSANetWitness
# configuration = metakeys_config.QRadar
class Process:

    def _process_nested_keys(data, keys, anonymization_function, configuration):
        # If there is only one key remaining in the keys list
        if len(keys) == 1:
            # Check if the key exists in the data dictionary
            if keys[0] in data:
                # If the key is in the list of IP_KEYS
                if keys[0] in configuration.IP_KEYS:
                    # If the value associated with the key is a list, apply the handle_ip_addresses function to each item in the list
                    if isinstance(data[keys[0]], list):
                        data[keys[0]] = [Process._handle_ip_addresses(item, configuration) for item in data[keys[0]]]
                    # If the value is not a list, apply the handle_ip_addresses function to the value
                    else:
                        data[keys[0]] = Process._handle_ip_addresses(data[keys[0]], configuration)
                # If the key is not in the list of IP_KEYS
                else:
                    # If the value associated with the key is a list, apply the anonymization_function to each item in the list
                    if isinstance(data[keys[0]], list):
                        data[keys[0]] = [anonymization_function(item) for item in data[keys[0]]]
                    # If the value is not a list, apply the anonymization_function to the value
                    else:
                        data[keys[0]] = anonymization_function(data[keys[0]])
        # If there are still multiple keys remaining in the keys list
        else:
            key = keys[0]
            # Check if the key exists in the data dictionary
            if key in data:
                # Recursively call the process_nested_keys function on the value associated with the key
                # with the remaining keys in the keys list, anonymization_function, and configuration as arguments
                Process._process_nested_keys(data[key], keys[1:], anonymization_function, configuration)

    def _handle_ip_addresses(ip, configuration):

        ip_anonymization_mapping = {
            # Create a dictionary that maps IP versions to their corresponding anonymization functions
            configuration.ip_function_mapping[0] : Functions.anonymize_ip,
            configuration.ip_function_mapping[1] : Functions.anonymize_ipv6,
            configuration.ip_function_mapping[2] : Functions.anonymize_link_local_ipv6
        }

        try:
            # Try to create an ipaddress.ip_address object from the given IP
            ip_obj = ipaddress.ip_address(ip)
            # If the IP is IPv4
            if ip_obj.version == 4:
                # Return the result of applying the IPv4 anonymization function from the elasticsearch object on the IP
                return ip_anonymization_mapping["ipv4"](ip)
            # If the IP is IPv6
            elif ip_obj.version == 6:
                # If the IPv6 IP is a link-local address
                if ip_obj.is_link_local:
                    # Return the result of applying the link-local IPv6 anonymization function from the elasticsearch object on the IP
                    return ip_anonymization_mapping["ipv6_local"](ip)
                # If the IPv6 IP is not a link-local address
                else:
                    # Return the result of applying the regular IPv6 anonymization function from the elasticsearch object on the IP
                    return ip_anonymization_mapping["ipv6"](ip)
            # If the given IP is not a valid IP address
        except ValueError:
            # Ignore the error and continue
            pass
            # Return the original IP if it was not successfully anonymized
        return ip

    def _anonymize_keys(data, key_anonymization_mapping, configuration):
        if isinstance(data, dict):
            # Iterate over each key and its corresponding anonymization function in the key_anonymization_mapping
            for key, anonymization_function in key_anonymization_mapping.items():
                # for RSANetWitness uncomment the following 2 lines and comment out the splitting and nested keys
                # RSANetWitness uses different logic than ELK, in ELK dot refers to nested structure and in NetWitness it is a string
                # if key in data:
                #  data[key] = anonymization_function(data[key])
                # Split the key by '.' to handle nested keys
                keys = key.split('.')
                # Call the process_nested_keys function to process the nested keys and apply the anonymization function
                Process._process_nested_keys(data, keys, anonymization_function, configuration)
            # Recursively call the anonymize_keys function on each value in the dictionary that is a dictionary or list
            for value in data.values():
                if isinstance(value, (dict, list)):
                    Process._anonymize_keys(value, key_anonymization_mapping, configuration)
        elif isinstance(data, list):
            # Recursively call the anonymize_keys function on each item in the list
            for item in data:
                Process._anonymize_keys(item, key_anonymization_mapping, configuration)
        # replace value also in strings of JSON log to avoid data leaks
        if "raw_log" in data:
            data["raw_log"] = Replace.anonymize_usernames_in_raw_log(data["raw_log"])
            data["raw_log"] = Replace.anonymize_domains_in_raw_log(data["raw_log"])
            data["raw_log"] = Replace.anonymize_ip_in_raw_log(data["raw_log"])
        if "event" in data and "original" in data["event"]:
            data["event"]["original"] = Replace.anonymize_usernames_in_raw_log(data["event"]["original"])
            data["event"]["original"] = Replace.anonymize_domains_in_raw_log(data["event"]["original"])
            data["event"]["original"] = Replace.anonymize_ip_in_raw_log(data["event"]["original"])
        if "message" in data:
            data["message"] = Replace.anonymize_usernames_in_raw_log(data["message"])
            data["message"] = Replace.anonymize_domains_in_raw_log(data["message"])
            data["message"] = Replace.anonymize_ip_in_raw_log(data["message"])
        if "raw_data" in data:
            data["raw_data"] = Replace.anonymize_usernames_in_raw_log(data["raw_data"])
            data["raw_data"] = Replace.anonymize_domains_in_raw_log(data["raw_data"])
            data["raw_data"] = Replace.anonymize_ip_in_raw_log(data["raw_data"])

        # Return the modified data after applying anonymization
        return data


    def anonymize_data_single_category(data, configuration):
        key_anonymization_mapping = {} #dictionary for mapping keys on functions for the single category anonymization

        if config.EMAIL:
            key_anonymization_mapping.update({key: Functions.anonymize_email for key in configuration.EMAIL_KEYS})
        if config.IPV4 or config.IPV6 or config.LINKLOCAL:
            key_anonymization_mapping.update({key: Functions.anonymize_ip for key in configuration.IP_KEYS})
        if config.DOMAIN:
            key_anonymization_mapping.update({key: Functions.anonymize_domain for key in configuration.DOMAIN_KEYS})
        if config.MAC:
            key_anonymization_mapping.update({key: Functions.anonymize_mac for key in configuration.MAC_KEYS})
        if config.URL:
            key_anonymization_mapping.update({key: Functions.anonymize_url for key in configuration.URL_KEYS})
        if config.WINDOWS_DIR:
            key_anonymization_mapping.update(
                {key: Functions.anonymize_windows_path for key in configuration.DIRECTORY_KEYS})
        if config.HOSTNAME:
            key_anonymization_mapping.update({key: Functions.anonymize_name for key in configuration.FULLNAME_KEYS})
        if config.USERNAME:
            key_anonymization_mapping.update({key: Functions.anonymize_username for key in configuration.USERNAME_KEYS})

        return Process._anonymize_keys(data, key_anonymization_mapping, configuration)

    def anonymize_data(data, configuration):
        key_anonymization_mapping = { #dictionary for mapping keys on functions
            # ** symbol refers to dictionary unpacking
            **{key: Functions.anonymize_email for key in configuration.EMAIL_KEYS},
            **{key: Functions.anonymize_mac for key in configuration.MAC_KEYS},
            **{key: Functions.anonymize_domain for key in configuration.DOMAIN_KEYS},
            **{key: Functions.anonymize_ip for key in configuration.IP_KEYS},
            **{key: Functions.anonymize_username for key in configuration.USERNAME_KEYS},
            **{key: Functions.anonymize_url for key in configuration.URL_KEYS},
            **{key: Functions.anonymize_windows_path for key in configuration.DIRECTORY_KEYS},
            **{key: Functions.anonymize_name for key in configuration.FULLNAME_KEYS},
            **{key: Functions.anonymize_name for key in configuration.ORGANIZATION_KEYS}
        }
        # return data, mapping and chosen configuration
        return Process._anonymize_keys(data, key_anonymization_mapping, configuration)
