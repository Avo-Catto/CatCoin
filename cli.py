from argparse import ArgumentParser
from uuid import uuid4
from random import randint
from socket import create_connection, SHUT_WR
from json import loads, dumps
from datetime import datetime
from hashlib import sha256
from time import sleep


def get_difficulty(d:int) -> int: 
    return int(
        'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'.replace(
            'F' * d, '0' * d, 1
        ), base=16
    )


def mine_block(block:dict, target_value:int):
    """Create a new Block, hash it and return it."""
    i = 0
    val = target_value + 1
    while val > target_value:
        i += 1
        hash = sha256(f"{block['index']}${block['timestamp']}${block['merkle']}${i}".encode())
        val = int.from_bytes(hash.digest())
        block['nonce'] = i
        block['hash'] = hash.hexdigest()
    return block 


def merkle_hash(l:list[str]) -> str:
    """Hash everything of iterable together to one hash by using the merkle tree."""
    new = []
    count = len(l) - 1
    
    # check if length of list is even
    if not count % 2: rest = l[count] 
    else: rest = ''
    
    # merge hashes
    for i in range(0, count, 2): 
        new.append(sha256(f'{l[i]}${l[i+1]}'.encode()).hexdigest())
    if rest: new.append(sha256(rest.encode()).hexdigest())
    
    # check on how to continue
    if count > 1: return merkle_hash(new)
    if len(new) == 1: return new[0]
    else: return ''


def timestamp_now() -> float:
    return round(datetime.now().timestamp())


def transaction() -> dict: 
    """Create transaction."""
    src = str(uuid4())
    dst = str(uuid4())
    timestamp = timestamp_now()
    val = 3.2 # randint(1, 20) / 10 + randint(1, 10)
    hash_ = sha256(f'{src}${dst}${timestamp}${val}'.encode()).hexdigest()
    return {
        "src": src,
        "dst": dst,
        "timestamp": timestamp,
        "val": val,
        "broadcast": True,
        "hash": hash_
    }


def block(idx: int, prev_hash: str, transactions: list) -> dict:
    """Create block."""
    timestamp = timestamp_now()
    merkle = merkle_hash(list(i['hash'] for i in transactions))
    return {
        "index": idx,
        "timestamp": timestamp,
        "transactions": transactions,
        "previous_hash": prev_hash,
        "nonce": 0, 
        "hash": "", 
        "merkle": merkle
    }


def send(dtype: str, data, addr:tuple) -> str:
    """Send message."""
    with create_connection(addr) as con:
        con.send(dumps({"dtype": dtype, "data": str(data).replace("'", "\"").replace("True", "true").replace("False", "false")}).encode())
        con.shutdown(SHUT_WR)
        res = con.recv(4096).decode()
        # res = loads(res)
        return res


if __name__ == '__main__':
    # Argument Parser
    parser = ArgumentParser()
    parser.add_argument('-t', '--type', default=None, type=str, help='block / transaction / blockchain / add-peer / hash / difficulty / latest / resync / pool / get-pool / get-block')
    parser.add_argument('-c', '--count', default=1, type=int, help='how many messages should be send')
    parser.add_argument('-d', '--delay', default=0.0, type=float, help='seconds between repeating message')
    parser.add_argument('--difficulty', default=14, type=int, help='difficulty of hash')
    parser.add_argument('--address', default='127.0.0.1:8000', type=str, help='address of node')
    args = vars(parser.parse_args())
    
    ADDRESS = args['address'].split(':')

    # get latest hash
    if args['type'] == 'hash':
        for i in range(args['count']):
            res = send("GetLatestHash", "", ADDRESS)
            print(f"response: {res}")

    # send resync chain request
    elif args['type'] == 'resync':
        for i in range(args['count']):
            res = send("CheckBlockchain", "", ADDRESS)
            print(f'response: {res}')

    # add peer 
    elif args['type'] == 'add-peer':
        for i in range(args['count']):
            addr = input("address: ")
            res = send("AddPeer", addr, ADDRESS)
            print(f'response: {res}')

    # get peers 
    elif args['type'] == 'get-peers':
        for i in range(args['count']):
            res = send("GetPeers", "", ADDRESS)
            print(f'response: {res}')

    # send transaction
    elif args['type'] == 'transaction':
        for i in range(args['count']):
            res = send("AddTransaction", transaction(), ADDRESS)
            print(f'Response: {res}')
            sleep(args['delay'])
    
    # get transaction pool
    elif args['type'] == 'get-pool':
        res = send("GetTransactionPool", "", ADDRESS)
        print(f'response: {res}')
    
    # send block
    elif args['type'] == 'block': 
        # get transaction pool
        res = loads(send("GetTransactionPool", "", ADDRESS))
        transactions = res['res']

        # get latest block
        res = send("GetLatestBlock", "", ADDRESS).replace("true", "True").replace("false", "False")
        res_json = loads(res)
        block_json = loads(res_json['res'])
        block_data = block(block_json['index'] + 1, block_json['hash'], transactions)

        # get difficulty & peers
        difficulty_res = loads(send("GetDifficulty", "", ADDRESS))
        peers = loads(send("GetPeers", "", ADDRESS))['res']
        peers.append(':'.join(ADDRESS))

        # mine block
        data = mine_block(block_data, get_difficulty(difficulty_res['res']))
        for i in peers:
            res = send("PostBlock", data, i.split(':')) 
            print(f'response: {res}')
        
    # get blockchain 
    elif args['type'] == 'blockchain':
        res = send("GetBlockchain", "", ADDRESS)
        print(f'response:\n{res}'.replace("'", '"').replace('True', 'true',).replace('False', 'false'))
    
    # get difficulty
    elif args['type'] == 'difficulty':
        res = send("GetDifficulty", "", ADDRESS)
        print(f'response: {res}')

    elif args['type'] == 'latest':
        res = send("GetLatestBlock", "", ADDRESS)
        print(f'response: {res}')

    elif args['type'] == 'pool':
        res = send("GetPoolHash", "", ADDRESS)
        print(f'response: {res}')

    elif args['type'] == 'get-block':
        idx = input('index: ')
        res = send("GetBlock", idx, ADDRESS)
        print(f'response: {res}')

    else: parser.print_help()
