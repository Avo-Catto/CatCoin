from cli import *
from json import loads

if __name__ == '__main__':
    ADDRESS = ('127.0.0.1', '8000')

    res = send('GetPeers', '', ADDRESS)
    peers = loads(res)['res']

    for peer in peers:
        t = transaction()
        res = send('AddTransaction', t, peer.split(':'), ':'.join(ADDRESS))
        print(f'response: {res}')

# GtjBP1e97DrcnMqBM5ERM2dhrR5jRxKXC1bRzpBoND7VP
# 3JhzPr9LYfbE6kpcdM3sqfVahH3K9xabmHWJzB93soc9x8t
