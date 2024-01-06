"""
Module to extract relevant features from:
- HTML
- URL
"""

import re
from urllib.parse import urlparse
from math import log
from string import punctuation
from pyquery import PyQuery

############################
###### HTML FEATURES #######
############################

class HTMLFeatures:
    """Extracts HTML features"""

    def __init__(self, html:str):
        self.html = html
        self.pq = PyQuery(html)
        self.suspicious_functions = ['eval', 'unescape', 'document.write', 'innerhtml']

    def __get_entropy(self, text):
        text = text.lower()
        probs = [text.count(c) / len(text) for c in set(text)]
        return round(-sum([p * log(p) / log(2.0) for p in probs]), 3)

    def page_entropy(self):
        """Shannon entropy of raw page content excluding HTML tags"""
        return self.__get_entropy(self.pq.text())

    def number_of_script_tags(self):
        """Total number of scripts included in the page"""
        return len(self.pq('script'))

    def length_of_html(self):
        """Total number of characters in HTML page excluding tags"""
        return len(self.pq.text())

    def number_of_page_tokens(self):
        """Total number of words on page separated by '' excluding tags"""
        return len(self.pq.text().lower().split())

    def number_of_sentences(self):
        """Total number of sentences separated by '.' on page excluding tags"""
        return len(self.pq.text().split('.'))

    def number_of_punctuations(self):
        """Total number of punctuations in page content"""
        return len([i for i in self.pq.text() if i in punctuation and i not in ['<', '>', '/']])

    def number_of_capitalizations(self):
        """Total number of upper case characters in page content"""
        return len([i for i in self.html if i.isupper()])

    def average_number_of_tokens_in_sentence(self):
        """Average number of words in all sentences"""
        sentences = self.pq.text().split('.')
        sen_lens = [len(i.split()) for i in sentences]
        return round(sum(sen_lens)/len(sen_lens), 3)

    def number_of_html_tags(self):
        """Total number of HTML tags on page"""
        return len(self.pq('*'))

    def number_of_hidden_tags(self):
        """
        Total number of tags with class or id as 'hidden' or attributes of 
        'visibility' or 'display' as 'none'
        """
        hidden1, hidden2 = self.pq('.hidden'), self.pq('#hidden')
        hidden3, hidden4 = self.pq('*[visibility="none"]'), self.pq('*[display="none"]')
        hidden = hidden1 + hidden2 + hidden3 + hidden4
        return len(hidden)

    def number_iframes(self):
        """Total number of iframe tags on page"""
        iframes = self.pq('iframe') + self.pq('frame')
        return len(iframes)

    def number_objects(self):
        """Total number of objects tags on page"""
        return len(self.pq('object'))

    def number_embeds(self):
        """Total number of embed tags on page"""
        return len(self.pq('embed'))

    def number_of_internal_hyperlinks(self):
        """Total number of internal hyperlinks"""
        return len(self.pq.find('a[href^="/"]'))

    def number_of_external_hyperlinks(self):
        """Total number of external hyperlinks"""
        return len(self.pq.find('a[href^="http"]'))

    def number_of_whitespace(self):
        """Total number of whitespaces in page content"""
        return len([i for i in self.html if i == ' '])

    def number_of_included_elements(self):
        """
        Total number of iframes, frames, scripts, embed, forms and objects that have been externally 
        included, i.e whose tags contain an src attribute
        """
        toi = self.pq('script') + self.pq('iframe') + self.pq('frame') + self.pq('embed') + self.pq('form') + self.pq('object')
        toi = [tag.attr('src') for tag in toi.items()]
        return len([i for i in toi if i])

    def number_of_double_documents(self):
        """Total number of HTML structural tags (body, html, head) that are repeated"""
        count = 0
        x, y, z = self.pq('html'), self.pq('body'), self.pq('head')
        count += len(x)-1 if len(x)>0 else 0
        count += len(y)-1 if len(y)>0 else 0
        count += len(z)-1 if len(z)>0 else 0
        return count

    def average_script_length(self):
        """Average length of all script tag contents"""
        scripts = self.pq('script')
        scripts = [len(script.text()) for script in scripts.items()]
        l = len(scripts)
        if l > 0:
            return round(sum(scripts) / l, 3)
        else:
            return 0

    def average_script_entropy(self):
        """Average entropy of all script tag contents"""
        scripts = self.pq('script')
        scripts = [self.__get_entropy(script.text()) for script in scripts.items()]
        l = len(scripts)
        if l > 0:
            return round(sum(scripts) / l, 3)
        else:
            return 0

    def number_of_suspicious_functions(self):
        """Total number of suspicious functions found in across all script tags"""
        script_content = self.pq('script').text().lower()
        susf = [1 if i in script_content else 0 for i in self.suspicious_functions]
        return sum(susf)

    def keywords_to_words_ratio(self):
        """ 
        Ratio between the number of keywords (i.e., reserved words) and other
        strings occurring in a piece of JavaScript code.
        """
        script = self.pq('script').text()
        keywords = ["var", "const", "let", "for", "while", "if", "return"]
        kw, t = 0, 0

        words = re.split(r'\s+|\W', script)
        for word in words:
            if word and word!='':
                t += 1
                if word in keywords:
                    kw += 1
        return round(kw/t, 3) if t>0 else 0

    def number_of_dom_modifying_functions(self):
        """
        Counts the number of functions used to modify the Document Object Model
        that are referenced in the source code.
        """
        regex_dom_functions = [
            r'createElement\s*\(',
            r'appendChild\s*\(',
            r'removeChild\s*\(',
            r'replaceChild\s*\(',
            r'insertBefore\s*\(',
            r'getElementsByClassName\s*\(',
            r'getElementsByTagName\s*\(',
            r'getElementById\s*\(',
            r'querySelector\s*\(',
            r'querySelectorAll\s*\(',
            r'setAttribute\s*\(',
            r'getAttribute\s*\(',
            r'removeAttribute\s*\(',
            r'clearAttributes\s*\(',
            r'insertAdjacentElement\s*\(',
            r'replaceNode\s*\(',
        ]

        count_dom_functions = sum(
            len(re.findall(regex, self.pq('script').text()))
            for regex in regex_dom_functions
        )

        return count_dom_functions

    def get_features(self):
        """Extracts automatically HTML features"""
        return {
            'suspicious_func_num': self.number_of_suspicious_functions(),
            'page_entropy': self.page_entropy(),
            'script_tags_num': self.number_of_script_tags(),
            'html_length': self.length_of_html(),
            'tokens_num': self.number_of_page_tokens(),
            'sentences_num': self.number_of_sentences(),
            'punctuation_num': self.number_of_punctuations(),
            'capitalization_num': self.number_of_capitalizations(),
            'avg_sentence_tokens_num': self.average_number_of_tokens_in_sentence(),
            'html_tags_num': self.number_of_html_tags(),
            'hidden_tags_num': self.number_of_hidden_tags(),
            'iframe_num': self.number_iframes(),
            'objects_num': self.number_objects(),
            'embeds_num': self.number_embeds(),
            'internal_links_num': self.number_of_internal_hyperlinks(),
            'external_links_num': self.number_of_external_hyperlinks(),
            'whitespaces_num': self.number_of_whitespace(),
            'included_elements_num': self.number_of_included_elements(),
            'double_doc_num': self.number_of_double_documents(),
            'keywords_to_words_ratio': self.keywords_to_words_ratio(),
            'dom_mod_func_num': self.number_of_dom_modifying_functions(),
            'avg_script_len': self.average_script_length(),
            'avg_script_entropy': self.average_script_entropy()
        }

###########################
###### URL FEATURES #######
###########################

class URLFeatures:
    """Extracts URL features"""

    def __init__(self, url: str):
        self.url = url
        self.urlparsed = urlparse(url)
        self.shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

    def entropy(self):
        """Calculates URL entropy"""
        text = self.url.lower()
        probs = [text.count(c) / len(text) for c in set(text)]
        return round(-sum([p * log(p) / log(2.0) for p in probs]), 3)

    def length(self):
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

    def is_encoded(self):
        """is the url encoded?"""
        return '%' in self.url.lower()

    def num_encoded_char(self):
        """number of encoded characters in the url"""
        encs = [i for i in self.url if i == '%']
        return len(encs)

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

    def has_double_slash_in_wrong_position(self):
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

    def get_features(self):
        """Extracts automatically the URL features"""
        return {
            'use_shortening_service': self.use_shortening_services(),
            'prefix_suffix_presence': self.prefix_suffix_presence(),
            'has_double_slash': self.has_double_slash_in_wrong_position(),
            'has_haveat_sign': self.has_haveat_sign(),
            'has_port': self.has_port(),
            'has_admin_keyword': self.has_admin_in_string(),
            'has_server_keyword': self.has_server_in_string(),
            'has_login_keyword': self.has_login_in_string(),
            'has_client_keyword': self.has_client_in_string(),
            'host_is_ip': self.host_is_ip(),
            'is_encoded': self.is_encoded(),
            'length': self.length(),
            'path_length': self.path_length(),
            'host_length': self.host_length(),
            'entropy': self.entropy(),
            'digits_num': self.number_of_digits(),
            'subdirectories_num': self.number_of_subdirectories(),
            'periods_num': self.number_of_periods(),
            'params_num': self.number_of_parameters()
        }
        