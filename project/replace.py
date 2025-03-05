import functions
class Replace:
    def anonymize_usernames_in_raw_log(raw_log): #replace usernames appearing in raw log part with the anonymized value in the dictionary
        for original, anonymized in functions.Functions.username_dictionary.items():
            raw_log = raw_log.replace(original, anonymized)
        return raw_log
    def anonymize_domains_in_raw_log(raw_log): #replace domains appearing in raw log part with the anonymized value in the dictionary
        for original, anonymized in functions.Functions.domains_dictionary.items():
            raw_log = raw_log.replace(original, anonymized)
        return raw_log
    def anonymize_ip_in_raw_log(raw_log): #replace domains appearing in raw log part with the anonymized value in the dictionary
        for original, anonymized in functions.Functions.ip_dictionary.items():
            raw_log = raw_log.replace(original, anonymized)
        return raw_log

