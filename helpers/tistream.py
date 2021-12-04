from StringIO import StringIO

class TiedStream(StringIO):

    def __init__(self, buf='', tied=None):
        self.tied = tied
        #print('TiedStream init')
        StringIO.__init__(self, buf)

    def readline(self, length=None):
        #print('TiedStream readline')
    	r = StringIO.readline(self, length)
        #print(r)
    	if self.tied:
    	    self.tied.write(r)
    	return r

