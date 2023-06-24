<h1 align="center"> 🚀 ChainReaction 🚀 </h1>

<p align="center">This is a Python-based implementation of a simple yet powerful voting system blockchain. This model leverages the Proof of Work consensus algorithm, signs transactions using asymmetric cryptography (RSA), and maintains a decentralized peer-to-peer network for nodes communication.</p>

---

## 🔧 Requirements

Make sure you have Python 3.6 or later installed, along with the following libraries:

- hashlib
- time
- socket
- threading
- json
- logging
- cryptography

---

## 📚 Components

This project is structured into various components:

### Block 📦

A single block in the blockchain. A block contains an index, timestamp, transactions, the hash of the previous block, a nonce (for mining), and its own unique hash.

### Transaction 🔄

This represents a transaction between two parties. A transaction includes the public keys of the sender and recipient, the transaction amount, and a digital signature. Transactions are both signed and verified.

### Blockchain ⛓️

The core class that stores all blocks and transactions. It supports a variety of operations, including adding transactions, mining blocks, verifying balances, validating the blockchain, and registering voters and candidates.

### PeerManager 🌐

This component manages the peer-to-peer network for a node. It helps the node to discover new peers and exchange peer information.

### Node 🖥️

Represents a network node. A node can handle various requests such as transactions, balance checks, and voter and candidate registration. Nodes can also mine new blocks and communicate with other nodes.

### Wallet 💰

Represents a user's digital wallet. A wallet can generate a pair of private and public keys and sign transactions.

---

## 🚀 Usage

1. Install the necessary Python libraries if you haven't done so already.

2. Run the Python file:

```
python app.py
```


> **NOTE:** Replace "app.py" with the actual name of your Python file.

---

## 🛠️ Future Work

This code represents a simplified model of a voting system blockchain, but there's plenty of room for enhancement:

- Improve security measures and error handling.
- Introduce smart contract functionality.
- Implement more advanced consensus protocols, like Proof of Stake.
- Utilize more scalable and efficient data structures for the blockchain.