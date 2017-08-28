from io import BytesIO

import re


class Buffer:
    def __init__(self):
        self._buffer = BytesIO()
        self._read_pos = 0
        self._write_pos = 0

    def read(self, amnt=None):
        available = self.available()
        if not available:
            return ''

        if amnt is None or available < amnt:
            amnt = available

        self._buffer.seek(self._read_pos)
        result = self._buffer.read(amnt)
        self._read_pos += len(result)

        return result

    def write(self, data):
        self._buffer.seek(self._write_pos)
        self._buffer.write(data)
        self._write_pos += len(data)

    def available(self):
        return self._write_pos - self._read_pos

    def has_data(self, amnt=0):
        return self.available() > amnt


class HttpResponse:
    def __init__(self):
        self.status_code = None
        self.reason = None
        self.version = None
        self.headers = {}
        self.finished = False

        self._is_chunked = False
        self._chunk_size = None
        self._chunk_buff = []

        self._buffer = []
        self._mode = 'status'
        self._body_buffer = BytesIO()

    def write(self, data):

        if self._mode == 'body':
            if len(self._buffer):
                self._buffer.append(data)
                data = ''.join(self._buffer)
                self._buffer = []

            self.parse_body(data)
            return

        if '\r\n' in data:
            if len(self._buffer):
                self._buffer.append(data)
                data = ''.join(self._buffer)
                self._buffer = []
            index = data.index('\r\n')
            line = data[:index]
            self.parse_line(line)
            self.write(data[index+2:])
        else:
            self._buffer.append(data)

    def parse_body(self, data):
        if not data:
            return

        if not self._is_chunked:
            self._body_buffer.write(data)
            self.finished = self._body_buffer.tell() == int(self.headers['content-length'])
            return

        if self._chunk_size:
            read = data[:self._chunk_size]
            rest = data[self._chunk_size+2:]

            self._body_buffer.write(read)

            if len(read) < self._chunk_size:
                self._chunk_size -= len(read)
            else:
                self._chunk_size = None

            self.parse_body(rest)
        else:
            if '\r\n' not in data:
                self._chunk_buff.append(data)
                return

            index = data.index('\r\n')
            buff, rest = data[:index], data[index+2:]

            if len(self._chunk_buff):
                self._chunk_buff.append(buff)
                buff = ''.join(self._chunk_buff)
                self._chunk_buff = []

            self._chunk_size = int(buff, 16)
            if not self._chunk_size:
                self.finished = True
            else:
                self.parse_body(rest)

    def parse_line(self, line):
        if self._mode == 'status':
            match = re.match("(.+) (\d+) (.+)", line)
            self.version, self.status_code, self.reason = match.groups()
            self._mode = 'headers'
        elif self._mode == 'headers':
            if not line:
                if self.headers.get('transfer-encoding', None) == 'chunked':
                    self._is_chunked = True
                elif self.headers.get('content-length', '0') == '0':
                    self.finished = True
                self._mode = 'body'
            else:
                key, val = re.match('(.+)\s*[:]\s*(.+)', line).groups()
                self.headers[key.lower()] = val

    def set_header(self, header, value):
        self.headers[header.lower()] = value

    def get_header(self, header):
        return self.headers.get(header.title(), None)

    def has_header(self, header):
        return header.lower() in self.headers

    def to_raw(self):
        headers = self.headers
        if 'transfer-encoding' in headers:
            del headers['transfer-encoding']
            headers['content-length'] = self._body_buffer.tell()
        header_str = '\r\n'.join(['{}: {}'.format(h.title(), headers[h]) for h in headers.keys()])

        self._body_buffer.seek(0)
        return '{} {} {}\r\n{}\r\n\r\n{}\r\n'.format(
            self.version,
            self.status_code,
            self.reason,
            header_str,
            self._body_buffer.read()
        )

#
# a = HttpResponse()
#
# a.write('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\n1234567890\r\n05\r\n12345\r\n0\r\n')
#
# print(a.to_raw())