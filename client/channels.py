import base64
import math


class AmazonChannel:
    # host = '54.239.25.192'
    host = '54.239.26.128'
    port = 443
    overt_hosts = ['www.amazon.com']
    # overt_url = 'https://www.amazon.com'
    support_upstream = True
    cache_parameters = ['field-keywords']

    def calculate_sendable_covert_data(self, overt_data_size):
        overt_data_size -= len('GET /~milad/ HTTP/1.1\r\nHOST: amazon.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n')

        if overt_data_size <= 0:
            return 0

        return int(3 * math.floor(overt_data_size / 4.0))

    def wrap_message(self, data):
        return "GET /~milad/%s HTTP/1.1\r\nHOST: amazon.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n" % base64.b64encode(data)


class AmazonCDNChannel:
    host = '54.230.50.17'
    port = 443
    overt_hosts = ['images-na.ssl-images-amazon.com']
    # overt_url = 'https://www.amazon.com'
    support_upstream = True

    def calculate_sendable_covert_data(self, overt_data_size):
        overt_data_size -= len('GET /~milad/ HTTP/1.1\r\nHOST: images-na.ssl-images-amazon.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n')

        if overt_data_size <= 0:
            return 0

        return int(3 * math.floor(overt_data_size / 4.0))

    def wrap_message(self, data):
        return "GET /~milad/%s HTTP/1.1\r\nHOST: images-na.ssl-images-amazon.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n" % base64.b64encode(data)


class GoogleChannel:
    host = '172.217.17.32'
    
    overt_hosts = ['www.google.com', 'encrypted-tbn1.gstatic.com', 'encrypted-tbn2.gstatic.com', 'encrypted-tbn3.gstatic.com']
    port = 443
    support_upstream = True

    cache_parameters = ['q']

    def calculate_sendable_covert_data(self, overt_data_size):
        overt_data_size -= len('GET /search/~milad/ HTTP/1.1\r\nHOST: google.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n')

        if overt_data_size <= 0:
            return 0

        return int(3 * math.floor(overt_data_size / 4.0))

    def wrap_message(self, data):
        return "GET /search/~milad/%s HTTP/1.1\r\nHOST: google.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n" % base64.b64encode(data)


class BingChannel:
    host = '204.79.197.200'
    overt_hosts = ['www.bing.com']
    port = 443
    support_upstream = True

    def calculate_sendable_covert_data(self, overt_data_size):
        overt_data_size -= len('GET /search/~milad/ HTTP/1.1\r\nHOST: bing.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n')

        if overt_data_size <= 0:
            return 0

        return int(3 * math.floor(overt_data_size / 4.0))

    def wrap_message(self, data):
        return "GET /search/~milad/%s HTTP/1.1\r\nHOST: bing.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n" % base64.b64encode(data)


class YahooChannel:
    host = '98.139.180.149'
    overt_hosts = ['www.yahoo.com', 'udc.yahoo.com', 'geo.yahoo.com']
    port = 443
    support_upstream = True

    def calculate_sendable_covert_data(self, overt_data_size):
        overt_data_size -= len('GET /search/~milad/ HTTP/1.1\r\nHOST: yahoo.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n')

        if overt_data_size <= 0:
            return 0

        return int(3 * math.floor(overt_data_size / 4.0))

    def wrap_message(self, data):
        return "GET /search/~milad/%s HTTP/1.1\r\nHOST: yahoo.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n" % base64.b64encode(data)


class WikipediaChannel:
    host = '208.80.154.224'
    overt_hosts = ['en.wikipedia.org', 'upload.wikipedia.org', 'upload.wikimedia.org']
    port = 443
    support_upstream = True

    def calculate_sendable_covert_data(self, overt_data_size):
        overt_data_size -= len('GET /search/~milad/ HTTP/1.1\r\nHOST: wikipedia.org\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n')

        if overt_data_size <= 0:
            return 0

        return int(3 * math.floor(overt_data_size / 4.0))

    def wrap_message(self, data):
        return "GET /search/~milad/%s HTTP/1.1\r\nHOST: wikipedia.org\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1200, max=1000000\r\n\r\n" % base64.b64encode(data)
