import logging
import datetime

import gevent
import requests
import base58

logger = logging.getLogger(__name__)

class AddressWatcher(gevent.Greenlet):

    def __init__(self, recipient, testnet):
        gevent.Greenlet.__init__(self)

        self.transfer_tx_callback = None
        self.recipient = recipient
        self.testnet = testnet
        if testnet:
            self.url_base = "https://api-test.wavesplatform.com/v0"
            self.asset_id = "CgUrFtinLXEbJwJVjwwcppk4Vpz1nMmR3H5cQaDcUcfe"
            self.url_height = "http://testnet1.wavesnodes.com/blocks/height"
        else:
            self.url_base = "https://api.wavesplatform.com/v0"
            self.asset_id = "9R3iLi4qGLVWKc16Tg98gmRvgg1usGEYd7SgC1W5D6HB"
            self.url_height = "http://nodes.wavesnodes.com/blocks/height"

    def _run(self):
        print("running AddressWatcher...")
        dt = datetime.datetime.utcnow()
        js_datestring = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        after = None
        last = True
        lastTxIds = []
        while 1:
            # poll for more transactions
            url = self.url_base + "/transactions/transfer"
            params = {"recipient": self.recipient, "assetId": self.asset_id, "timeStart": js_datestring, "sort": "asc"}
            if after:
                params["after"] = after
            #logger.info('request to %s with %s', url, params)
            r = requests.get(url, params=params)
            if r.status_code == 200:
                newLastTxIds = []
                body = r.json()
                #logger.info(body)
                for tx in body["data"]:
                    tx = tx["data"]
                    newLastTxIds.append(tx['id'])
                    if tx['id'] in lastTxIds: # this is necessary because "lastCursor" is not always present in the response
                        continue
                    #logger.info('tx %s', tx['id'])
                    if tx["recipient"] == self.recipient:
                        if tx["attachment"]:
                            tx["attachment"] = base58.b58decode(tx["attachment"]).decode("utf-8")
                        if self.transfer_tx_callback:
                            self.transfer_tx_callback(tx)
                if "lastCursor" in body:
                    after = body["lastCursor"]
                if "isLastPage" in body:
                    last = body["isLastPage"]
                lastTxIds = newLastTxIds
            else:
                logger.error('request to %s failed (%d)', r.url, r.status_code)
            # sleep
            gevent.sleep(5)

    def transfer_tx(self, txid):
        url = self.url_base + "/transactions/transfer/" + txid
        r = requests.get(url)
        if r.status_code == 200:
            body = r.json()
            return body["data"]
        return None

    def block_height(self):
        r = requests.get(self.url_height)
        if r.status_code == 200:
            body = r.json()
            return body["height"]
        return None

    def tx_confirmations(self, block_height, txid):
        tx = self.transfer_tx(txid)
        if tx:
            if tx["height"]:
                return block_height - tx["height"]
        return 0

if __name__ == '__main__':
    # setup logging
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter("[%(name)s %(levelname)s] %(message)s"))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()
    # start aw
    aw = AddressWatcher('3Mw8dtWrY7odRods1FjKi4JdASR8FXm5pfr', True)
    aw.start()
    aw.join()