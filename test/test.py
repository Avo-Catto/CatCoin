from argparse import ArgumentParser
from uuid import uuid4
from random import randint
from socket import create_connection, SHUT_WR
from json import loads, dumps
from datetime import datetime
from hashlib import sha256
from time import sleep


ADDRESS = "127.0.0.1:8000"


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
    else: return None


def datetime_now() -> str:
    date = datetime.now().astimezone().isoformat().split('+')
    return f'{date[0]}000+{date[1]}'


def transaction() -> dict: 
    """Create transaction."""
    src = str(uuid4())
    dst = str(uuid4())
    date = datetime_now()
    val = randint(1, 20)
    hash_ = sha256(f'{src}${dst}${date}${val}'.encode()).hexdigest()
    return {
        "src": src,
        "dst": dst,
        "date": date,
        "val": val,
        "broadcast": True,
        "hash": hash_
    }


def block(idx: int, prev_hash: str) -> dict:
    """Create block."""
    transactions = list(transaction() for _ in range(randint(1, 4)))
    nonce = randint(0, 1000)
    datetime_ = datetime_now()
    merkle = merkle_hash(list(i['hash'] for i in transactions))
    return {
        "index": idx,
        "datetime": datetime_,
        "transactions": transactions,
        "previous_hash": prev_hash,
        "nonce": 0, # nonce,
        "hash": sha256(f'{idx}${datetime_}${merkle}${nonce}'.encode()).hexdigest(),
        "merkle": merkle
    }


def send(dtype: int, data:dict) -> dict:
    """Send message."""
    with create_connection(ADDRESS.split(":")) as con:
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
    args = vars(parser.parse_args())

    if args['type'] == 'add-peer':
        for i in range(args['count']):
            # addr = f"{randint(0, 256)}.{randint(0, 256)}.{randint(0, 256)}.{randint(0, 256)}:{randint(0, 65536)}"
            addr = "127.0.0.1:8081"
            res = send(0, {"addr": addr})
            if res.get("res") == 0: print("success")
            else: print("failed")
    
    elif args['type'] == 'get-peers':
        res = send(1, {})
        print(res.get('data'))

    elif args['type'] == 'transaction':
        for i in range(args['count']):
            res = send(2, transaction())
            print(f'response: {res.get("res")}')
            sleep(args['delay'])
    
    elif args['type'] == 'get-pool':
        res = send(3, {})
        print(res.get('res'))

    elif args['type'] == 'block': 
        if not args['previous_hash']: 
            print('no previous hash found')
            exit(1)

        data = block(args['index'], args['previous_hash'])
        for _ in range(args['count']):
            res = send(4, data)
            print(f'response: {res.get("res")}')
            data = block(args['index'], data['previous_hash'])

    elif args['type'] == 'blockchain':
        res = send(5, {})
        print(f'blockchain:\n{res.get("data")}'.replace("'", '"').replace('True', 'true',).replace('False', 'false'))
    
    else: parser.print_help()