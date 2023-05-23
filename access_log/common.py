class AccessLogLine:
    def __init__(
        self, ip, vhost, method, uri, version, status, response_length, referer, user_agent
    ):
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
        for f in [
            "ip",
            "vhost",
            "method",
            "uri",
            "version",
            "status",
            "response_length",
            "referer",
            "user_agent",
        ]:
            x = getattr(self, f)
            if x is not None:
                if isinstance(x, str):
                    data.append('%s => "%s"' % (f, x))
                else:
                    data.append("%s => %d" % (f, x))
        return ", ".join(data)

    @staticmethod
    def parse(s):
        prefix = "[tempesta fw] "
        if s[: len(prefix)] != "[tempesta fw] ":
            return None
        fields = s[len(prefix) :].split(" ")
        if len(fields) != 9:
            return None
        # Heuristics: vhost is enclosed with quotes
        host = fields[1]
        if len(host) < 2 or host[0] != '"' or host[-1] != '"':
            return None
        # Heuristics: request line starts with quotes and
        # is not shorter than 4 symbols ("GET)
        line = fields[2]
        if len(line) < 4 or line[0] != '"':
            return None
        fields = list(map(lambda x: x.strip('"'), fields))
        print(fields)
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
        for line in klog.log.decode().split("\n"):
            msg = AccessLogLine.parse(line)
            if msg is not None:
                return msg
        return None
