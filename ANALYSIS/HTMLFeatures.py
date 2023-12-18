import re
from string import punctuation
from pyquery import PyQuery
from numpy import log

class HTMLFeatures:
    """Extract HTML Content Features"""

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

    def has_right_click_disabled(self):
        """
        search for event “event.button==2” in the webpage source code and 
        check if the right click is disabled
        """
        return True if 'event.button==2' in self.html.lower() else False
    