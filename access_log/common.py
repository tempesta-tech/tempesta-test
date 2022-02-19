class AccessLogLine:
    def __init__(self, ip, vhost, method, uri, version, status,
                 response_length, referer, user_agent):
        self.ip = ip
        self.vhost = vhost
        self.method = method
        self.uri = uri
        self.version = version
        self.status = status
        self.response_length = response_length
        self.referer = referer
        self.user_agent = user_agent

    def __repr__(self):
        data = []
        for f in ['ip', 'vhost', 'method', 'uri', 'version', 'status',
                'response_length', 'referer', 'user_agent']:
            x = getattr(self, f)
            if x is not None:
                if isinstance(x, str):
                    data.append('%s => "%s"' % (f, x))
                else:
                    data.append('%s => %d' % (f, x))
        return ', '.join(data)

    @staticmethod
    def parse(s):
        prefix = '[tempesta fw] '
        if s[:len(prefix)] != '[tempesta fw] ':
            return None
        fields = list(map(lambda x: x.strip('"'), s[len(prefix):].split(' ')))
        if len(fields) != 9:
            return None
        return AccessLogLine(
            ip=fields[0],
            vhost=fields[1],
            method=fields[2],
            uri=fields[3],
            version=fields[4],
            status=int(fields[5]),
            response_length=int(fields[6]),
            referer=fields[7],
            user_agent=fields[8],
        )

    @staticmethod
    def from_dmesg(klog):
        klog.update()
        for line in klog.log.split('\n'):
            msg = AccessLogLine.parse(line)
            if msg is not None:
                return msg
        return None
