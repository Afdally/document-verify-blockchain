const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const axios = require("axios");

class Block {
  constructor(index, timestamp, documentData, previousHash, validator) {
    this.index = index;
    this.timestamp = timestamp;
    this.documentData = documentData;
    this.previousHash = previousHash;
    this.validator = validator;
    this.hash = this.calculateHash();
  }

  calculateHash() {
    return crypto
      .createHash("sha256")
      .update(
        this.index +
          this.previousHash +
          this.timestamp +
          JSON.stringify(this.documentData) +
          this.validator
      )
      .digest("hex");
  }
}

class Blockchain {
  constructor(nodeName, encryptionKey, authorizedValidators) {
    this.nodeName = nodeName;
    this.chain = [];
    this.pendingBlocks = [];
    this.encryptionKey = encryptionKey;
    this.authorizedValidators = authorizedValidators;
    this.loadFromFile();
    if (this.chain.length === 0) {
      this.chain.push(this.createGenesisBlock());
      this.saveToFile();
    }
  }

  createGenesisBlock() {
    return new Block(
      0,
      0,
      "Genesis Block - Document Validation System",
      "0",
      "genesis"
    );
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  async addBlock(newBlock, networkNodes) {
    if (!this.validateBlock(newBlock)) {
      throw new Error("Block tidak valid");
    }

    this.chain.push(newBlock);
    this.saveToFile();

    // Broadcast to network
    await this.broadcastBlock(newBlock, networkNodes);
    return newBlock;
  }

  validateBlock(newBlock) {
    const latestBlock = this.getLatestBlock();

    // Pengecualian untuk genesis block
    if (newBlock.index === 0) {
      return newBlock.validator === "genesis" && newBlock.previousHash === "0";
    }

    // Validasi normal
    const isHashValid = newBlock.hash === newBlock.calculateHash();
    const isPrevHashValid = newBlock.previousHash === latestBlock.hash;
    const isValidatorValid = this.authorizedValidators.includes(newBlock.validator);

    console.log(`[DEBUG] Block validation results:
    - Hash Valid: ${isHashValid}
    - Previous Hash Valid: ${isPrevHashValid}
    - Validator Valid: ${isValidatorValid}`);

    return isHashValid && isPrevHashValid && isValidatorValid;
  }

  async broadcastBlock(block, networkNodes) {
    const blockData = {
      index: block.index,
      timestamp: block.timestamp,
      documentData: block.documentData,
      previousHash: block.previousHash,
      validator: block.validator,
      hash: block.hash,
    };

    const broadcastPromises = [];

    for (const node of networkNodes) {
      if (node !== `http://localhost:${process.env.PORT || 3000}`) {
        try {
          broadcastPromises.push(
            axios.post(`${node}/receive-block`, blockData).catch((err) => {
              console.error(`Error broadcasting to ${node}:`, err.message);
            })
          );
        } catch (err) {
          console.error(`Error broadcasting to ${node}:`, err.message);
        }
      }
    }

    await Promise.allSettled(broadcastPromises);
    return blockData;
  }

  saveToFile() {
    try {
      const data = JSON.stringify(this.chain, null, 2);
      const dir = path.join(__dirname, "node_data", this.nodeName);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(path.join(dir, "blockchain.json"), data);
    } catch (error) {
      console.error("Error saving blockchain:", error);
    }
  }

  loadFromFile() {
    const filePath = path.join(
      __dirname,
      "node_data",
      this.nodeName,
      "blockchain.json"
    );
    if (fs.existsSync(filePath)) {
      try {
        const data = fs.readFileSync(filePath);
        this.chain = JSON.parse(data).map((block) => {
          const newBlock = new Block(
            block.index,
            block.timestamp,
            block.documentData,
            block.previousHash,
            block.validator
          );
          if (newBlock.hash !== block.hash) {
            console.warn(`Warning: Hash mismatch for block ${block.index}`);
          }
          return newBlock;
        });
      } catch (error) {
        console.error("Error loading blockchain:", error);
        this.chain = [];
      }
    }
  }

  async resolveConflicts(networkNodes) {
    let maxLength = this.chain.length;
    let newChain = null;

    for (const node of networkNodes) {
      if (node !== `http://localhost:${process.env.PORT || 3000}`) {
        try {
          const response = await axios.get(`${node}/blocks`);
          if (
            response.data.length > maxLength &&
            this.validateChain(response.data)
          ) {
            maxLength = response.data.length;
            newChain = response.data;
          }
        } catch (err) {
          console.error(`Error checking node ${node}:`, err.message);
        }
      }
    }

    if (newChain) {
      this.chain = newChain;
      this.saveToFile();
      return true;
    }
    return false;
  }

  validateChain(chain) {
    for (let i = 1; i < chain.length; i++) {
      const currentBlock = chain[i];
      const previousBlock = chain[i - 1];

      const tempBlock = new Block(
        currentBlock.index,
        currentBlock.timestamp,
        currentBlock.documentData,
        currentBlock.previousHash,
        currentBlock.validator
      );

      if (currentBlock.hash !== tempBlock.calculateHash()) return false;
      if (currentBlock.previousHash !== previousBlock.hash) return false;
      if (!this.authorizedValidators.includes(currentBlock.validator)) return false;
    }
    return true;
  }

  getBlockByDocumentId(documentId) {
    return this.chain.find(
      (block) =>
        block.documentData && block.documentData.documentId === documentId
    );
  }

  getBlockByDocumentHash(hash) {
    return this.chain.find(
      (block) => block.documentData && block.documentData.documentHash === hash
    );
  }
}

// Fungsi utilitas kriptografi
function encryptData(text, encryptionKey) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(encryptionKey),
    iv
  );
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

function decryptData(text, encryptionKey) {
  try {
    const textParts = text.split(":");
    const iv = Buffer.from(textParts.shift(), "hex");
    const encryptedText = Buffer.from(textParts.join(":"), "hex");
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(encryptionKey),
      iv
    );
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (error) {
    console.error("Decrypt error:", error);
    return null;
  }
}

function calculateFileHash(filePath) {
  try {
    const fileBuffer = fs.readFileSync(filePath);
    const hashSum = crypto.createHash("sha256");
    hashSum.update(fileBuffer);
    return hashSum.digest("hex");
  } catch (error) {
    console.error("Hash calculation error:", error);
    throw new Error("Gagal menghitung hash file");
  }
}

module.exports = {
  Block,
  Blockchain,
  encryptData,
  decryptData,
  calculateFileHash
};