import time

import gevent

class Timer(gevent.Greenlet):

    seconds = 60
    callback = None

    def __init__(self, seconds):
        gevent.Greenlet.__init__(self)

    def _run(self):
        print("running Timer({})...".format(self.seconds))
        now = time.time()
        elapsed = now
        while 1:
            now = time.time()
            #print("now - elapsed: {}".format(now - elapsed))
            while now - elapsed >= self.seconds:
                elapsed += self.seconds
                if self.callback:
                    self.callback()
            # sleep
            gevent.sleep(5)
