"""
URLFeatures extrae las caracteristicas relevantes de una URL
"""

import re
from urllib.parse import urlparse
from math import log

class URLFeatures:
    """Extrae caracteristicas de una URL"""

    def __init__(self, url: str):
        self.url = url
        self.urlparsed = urlparse(url, 'http')
        self.shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

    def __get_entropy(self, text):
        text = text.lower()
        probs = [text.count(c) / len(text) for c in set(text)]
        entropy = -sum([p * log(p) / log(2.0) for p in probs])
        return round(entropy, 3)

    # ------------------------
    # EXTRACT LEXICAL FEATURES
    #-------------------------

    def scheme(self):
        """url scheme"""
        scheme = self.urlparsed.scheme
        return scheme if scheme in ['https', 'http', 'ftp', 'mailto', 'file', 'telnet'] else 'http'

    def url_length(self):
        """url length"""
        return len(self.url)

    def path_length(self):
        """url path length"""
        return len(self.urlparsed.path)

    def host_length(self):
        """url host length"""
        return len(self.urlparsed.netloc)

    def host_is_ip(self):
        """url host has ip form?"""
        host = self.urlparsed.netloc
        pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        match = pattern.match(host)
        return match is not None

    def has_port(self):
        """url has a port inside?"""
        has_port = self.urlparsed.netloc.split(':')
        return len(has_port) > 1 and has_port[-1].isdigit()

    def number_of_digits(self):
        """number of digits in the url"""
        digits = [i for i in self.url if i.isdigit()]
        return len(digits)

    def number_of_parameters(self):
        """number of parameters in the url"""
        params = self.urlparsed.query
        return 0 if params == '' else len(params.split('&'))

    def number_of_fragments(self):
        """number of fragments in the url"""
        frags = self.urlparsed.fragment
        return len(frags.split('#')) - 1 if frags == '' else 0

    def url_is_encoded(self):
        """is the url encoded?"""
        return '%' in self.url.lower()

    def num_encoded_char(self):
        """number of encoded characters in the url"""
        encs = [i for i in self.url if i == '%']
        return len(encs)

    def url_entropy(self):
        """url entropy"""
        return self.__get_entropy(self.url)

    def number_of_subdirectories(self):
        """number of subdirectories in the url"""
        d = self.urlparsed.path.split('/')
        return len(d)

    def number_of_periods(self):
        """number of periods in the url"""
        periods = [i for i in self.url if i == '.']
        return len(periods)

    def prefix_suffix_presence(self):
        """Checking the presence of '-' in the domain part of URL"""
        return True if '-' in self.urlparsed.netloc else False

    def use_shortening_services(self):
        """Check if URL is using a shortening service"""
        return True if re.search(self.shortening_services, self.url) else False

    def has_redirection(self):
        """Checks the presence of '//' in the URL"""
        pos = self.url.rfind('//')
        return True if pos > 7 else False

    def has_haveat_sign(self):
        """Checks for the presence of '@' symbol in the URL"""
        return True if '@' in self.url else False

    def has_client_in_string(self):
        """url has the keyword 'client' in the url?"""
        return 'client' in self.url.lower()

    def has_admin_in_string(self):
        """url has the keyword 'admin' in the url?"""
        return 'admin' in self.url.lower()

    def has_server_in_string(self):
        """url has the keyword 'server' in the url?"""
        return 'server' in self.url.lower()

    def has_login_in_string(self):
        """url has the keyword 'login' in the url?"""
        return 'login' in self.url.lower()
    