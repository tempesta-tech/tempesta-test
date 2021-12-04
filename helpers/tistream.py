from StringIO import StringIO

class TiedStream(StringIO):

    def __init__(self, buf='', tied=None):
        StringIO.__init__(buf)
        self.tied = tied

    def readline(self, length=None):
    	r = StringIO.readline(length)
    	if tied:
    	    tied.write(r)
    	return r

