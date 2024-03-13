- **Node Communication DTypes**

    - **DTYPE:**
        - ? **0** - alive?
        - **1** - add transaction to transaction pool
        - **2** - validate block
        - **3** - update blockchain; aka receive a list of blocks (shouldn't be open)
    
    - **Response:**
        - **0** - success
        - **1** - error
        - **2** - valid
        - **3** - invalid