import re
import sys
from functions import*

class Regex:
    def anonymize_ipv4_line(line):
        ip_pattern = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')  # regex for IPv4
        matches = ip_pattern.findall(line)  # find all matches meeting the regex condition in the line
        #iterate through each value and substitute it with its anonymized form
        for ip in matches:  # validation of matches for 0-255 range to prevent false matches
            tmp = ip.split(".")
            if (int(tmp[0]) > 255):
                matches.remove(ip)
            elif (int(tmp[1]) > 255):
                matches.remove(ip)
            elif (int(tmp[2]) > 255):
                matches.remove(ip)
            elif (int(tmp[3]) > 255):
                matches.remove(ip)
        for ip in matches:
                line = re.sub(ip, Functions.anonymize_ip(ip), line)
        # print(sys.getsizeof(Functions.ip_dictionary))
        #return the modified line
        return line

    def anonymize_ipv6_line(line):
        ip_pattern = re.compile(r'\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b|\b(?:[a-fA-F0-9]{1,4}:){1,7}:(?::[a-fA-F0-9]{1,4}){1,6}\b')
        matches = ip_pattern.findall(line)  # find all matches meeting the regex condition in the line
        # iterate through each value and substitute it with its anonymized form
        for ipv6_address in matches:
             line = re.sub(ipv6_address, Functions.anonymize_ipv6(ipv6_address), line)
        # return the modified line
        return line


    def anonymize_linklocal_line(line):
        ip_pattern = re.compile(r'"(fe80:[0-9a-fA-F:]+)"')
        matches = ip_pattern.findall(line)  # find all matches meeting the regex condition in the line
        # iterate through each value and substitute it with its anonymized form
        for linklocal in matches:
             line = re.sub(linklocal, Functions.anonymize_link_local_ipv6(linklocal), line)
        return line

    def anonymize_email_line(line):
        email_pattern = re.compile(r"(?P<email_address>[\w\.-]+@[\w\.-]+\.[\w]+)")
        matches = email_pattern.findall(line)  #takes a line of text as input and performs anonymization on any email addresses found within that line
        # iterate through each value and substitute it with its anonymized form
        for email in matches:
            line = re.sub(email, Functions.anonymize_email(email), line)
        # return the modified line
        return line

    def anonymize_url_line(line):
        url_pattern = re.compile('(?i)\b((?:https?:\/\/|www\.)\S+)\b')
        matches = url_pattern.findall(line) # find all matches meeting the regex condition in the line
        # iterate through each value and substitute it with its anonymized form
        for url in matches:
            line = re.sub(url, Functions.anonymize_url(url), line)
        # return the modified line
        return line

    def anonymize_domain_line(line):
        domain_pattern = re.compile(r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        matches = domain_pattern.findall(line) # find all matches meeting the regex condition in the line
        # iterate through each value and substitute it with its anonymized form
        for domain in matches:
            line = re.sub(domain, Functions.anonymize_domain(domain), line)
        return line

    def anonymize_mac_line(line):
        mac_pattern = re.compile(r'[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}')
        matches = mac_pattern.findall(line) # find all matches meeting the regex condition in the line
        # iterate through each value and substitute it with its anonymized form
        for mac in matches:
            line = re.sub(mac, Functions.anonymize_mac(mac), line)
        # return the modified line
        return line

    def anonymize_windows_line(line):
        win_pattern = re.compile((r"[a-zA-Z]:\\\\((?:.*?\\\\)*).[^\s]*"))
        matches = win_pattern.findall(line) # find all matches meeting the regex condition in the line
        # iterate through each value and substitute it with its anonymized form
        for path in matches:
            line = re.sub(path, Functions.anonymize_windows_path(path), line)
        # return the modified line
        return line
    def complete_anonymization(logs):
        anon_log=""
#performs complete anonymization that takes log as an input until there are logs in the file, if there are no more logs, the loop breaks
        while True:

            line = logs.readline()
            if not line:
                break
            line=str(line.decode("utf-8")) #specify encoding
            line= Regex.anonymize_ipv4_line(line)
            line= Regex.anonymize_ipv6_line(line)
            line = Regex.anonymize_linklocal_line(line)
            line = Regex.anonymize_domain_line(line)
            line=Regex.anonymize_email_line(line)
            line = Regex.anonymize_url_line(line)
            line=Regex.anonymize_mac_line(line)
            line = Regex.anonymize_windows_line(line)
            anon_log += line
        return anon_log
