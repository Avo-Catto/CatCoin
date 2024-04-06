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


def merkle_hash(l:list[str]) -> str | None:
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
    else: return None


def timestamp_now() -> float:
    return round(datetime.now().timestamp())


def transaction() -> dict: 
    """Create transaction."""
    src = str(uuid4())
    dst = str(uuid4())
    timestamp = timestamp_now()
    val = randint(1, 20)
    hash_ = sha256(f'{src}${dst}${timestamp}${val}'.encode()).hexdigest()
    return {
        "src": src,
        "dst": dst,
        "timestamp": timestamp,
        "val": val,
        "broadcast": True,
        "hash": hash_
    }


def block(idx: int, prev_hash: str) -> dict:
    """Create block."""
    transactions = list(transaction() for _ in range(randint(1, 4)))
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


def send(dtype: int, data:dict, addr:tuple) -> dict:
    """Send message."""
    with create_connection(addr) as con:
        con.send(dumps({"dtype": dtype, "data": data}).encode())
        con.shutdown(SHUT_WR)
        res = con.recv(4096).decode()
        print(f'received: {res}')
        res = loads(res)
        return res


if __name__ == '__main__':
    # Argument Parser
    parser = ArgumentParser()
    parser.add_argument('-t', '--type', default=None, type=str, help='block / transaction / blockchain / add-peer')
    parser.add_argument('-c', '--count', default=1, type=int, help='how many messages should be send')
    parser.add_argument('-d', '--delay', default=0.0, type=float, help='seconds between repeating message')
    parser.add_argument('-i', '--index', default=1, type=int, help='index of block to send')
    parser.add_argument('-p', '--previous_hash', default='', type=str, help='hash of previous block')
    parser.add_argument('--difficulty', default=14, type=int, help='difficulty of hash')
    parser.add_argument('--address', default='127.0.0.1:8000', type=str, help='address of node')
    args = vars(parser.parse_args())
    
    ADDRESS = args['address'].split(':')

    # add peer 
    if args['type'] == 'add-peer':
        for i in range(args['count']):
            addr = input("address: ")
            res = send(0, {"addr": addr}, ADDRESS)
            if res.get("res") == 0: print("success")
            else: print("failed")
    
    # get peers 
    elif args['type'] == 'get-peers':
        res = send(1, {}, ADDRESS)
        print(res.get('data'))

    # send transaction
    elif args['type'] == 'transaction':
        for i in range(args['count']):
            res = send(2, transaction(), ADDRESS)
            print(f'response: {res.get("res")}')
            sleep(args['delay'])
    
    # get transaction pool
    elif args['type'] == 'get-pool':
        res = send(3, {}, ADDRESS)
        print(res.get('res'))
    
    # send block
    elif args['type'] == 'block': 
        if not args['previous_hash']: 
            print('no previous hash found')
            exit(1)

        data = mine_block(block(args['index'], args['previous_hash']), get_difficulty(args['difficulty']))
        res = send(4, data, ADDRESS) 
        print(f'response: {res.get("res")}')
        data = block(args['index'], data['previous_hash'])
        
    # get blockchain 
    elif args['type'] == 'blockchain':
        res = send(5, {}, ADDRESS)
        print(f'blockchain:\n{res.get("data")}'.replace("'", '"').replace('True', 'true',).replace('False', 'false'))
    
    else: parser.print_help()
