import time

import gevent

class Timer(gevent.Greenlet):

    callbacks = []

    def __init__(self, seconds):
        gevent.Greenlet.__init__(self)

    def add_timer(self, callback, seconds):
        self.callbacks.append((callback, time.time(), seconds))

    def _run(self):
        print("running Timer...")
        while 1:
            now = time.time()
            for callback, elapsed, seconds in self.callbacks:
                #print("now - elapsed: {}".format(now - elapsed))
                while now - elapsed >= seconds:
                    elapsed += seconds
                    callback()
            # sleep
            gevent.sleep(5)
