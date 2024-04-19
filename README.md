- deviation of timestamp: 5 minutes

- **Node Communication DTypes**

    - **DTYPE:**
        - **0** - add peer
        - **1** - get list of peers
        - **2** - add transaction
        - **3** - get transaction pool
        - **4** - receive block
        - **5** - get blockchain
        - **6** - get blockchain hash
        - **7** - get difficulty

    - **Response:**
        - **0** - success
        - **1** - error
        - **2** - valid
        - **3** - invalid

# Miner

The miner is a simple one.

**Input:**
```
base64({
    "block": block.as_json(),
    "difficulty": u8,
    "start": u64,
})
```

**Return:** 
```
base64({
    "hash": &String,
    "merkle": &String,
    "nonce": u64,
})
```

