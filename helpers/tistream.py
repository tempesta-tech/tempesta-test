from StringIO import StringIO

class TiedStream(StringIO):

    def __init__(self, buf='', tied=None):
        self.tied = tied
        #print('TiedStream init')
        StringIO.__init__(self, buf)

    def read(self, n=-1):
        r = StringIO.read(self, n)
        if self.tied:
            self.tied.write(r)
        return r

    def readline(self, length=None):
        r = StringIO.readline(self, length)
        if self.tied:
            self.tied.write(r)
        return r

