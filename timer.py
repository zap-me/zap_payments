import time

import gevent

class Callback():
    def __init__(self, callback, elapsed, seconds):
        self.callback = callback
        self.elapsed = elapsed
        self.seconds = seconds

class Timer(gevent.Greenlet):

    callbacks = []

    def __init__(self, seconds):
        gevent.Greenlet.__init__(self)

    def add_timer(self, callback, seconds):
        self.callbacks.append(Callback(callback, time.time(), seconds))

    def _run(self):
        print("running Timer...")
        while 1:
            now = time.time()
            for cb in self.callbacks:
                #print("now - elapsed: {}, seconds: {}".format(now - cb.elapsed, cb.seconds))
                while now - cb.elapsed >= cb.seconds:
                    cb.elapsed += cb.seconds
                    cb.callback()
            # sleep
            gevent.sleep(5)
