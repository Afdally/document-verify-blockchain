require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");
const fs = require("fs");
const axios = require("axios");
const cors = require("cors");
const DEBUG = true;

const app = express();
const port = process.env.PORT || 3000;

const os = require("os");
const networkInterfaces = os.networkInterfaces();
const getLocalIp = () => {
  for (const interface of Object.values(networkInterfaces)) {
    for (const config of interface) {
      if (config.family === "IPv4" && !config.internal) {
        return config.address;
      }
    }
  }
  return "localhost";
};
const LOCAL_IP = getLocalIp();

// Konfigurasi awal
const NODE_NAME =
  process.env.NODE_NAME || `node_${crypto.randomBytes(2).toString("hex")}`;
const AUTHORIZED_VALIDATORS = [
  "validator1",
  "validator2",
  "genesis",
];
const NETWORK_NODES = new Set(); // Daftar node dalam jaringan

// Konfigurasi kriptografi - menggunakan env var
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY
  ? crypto.scryptSync(process.env.ENCRYPTION_KEY, "salt", 32)
  : crypto.scryptSync("secret-key", "salt", 32); // Fallback untuk development
const IV_LENGTH = 16;

// Konfigurasi penyimpanan dengan validasi file
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, "node_data", NODE_NAME, "uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // Sanitasi nama file
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, "_");
    cb(
      null,
      Date.now() +
        "-" +
        crypto.randomBytes(4).toString("hex") +
        "-" +
        sanitizedName
    );
  },
});

// Validasi file upload
const fileFilter = (req, file, cb) => {
  // Izinkan hanya file yang umum untuk dokumen
  const allowedTypes = [
    "application/pdf",
    "image/jpeg",
    "image/png",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain",
  ];

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new Error(
        "Format file tidak didukung. Gunakan PDF, JPG, PNG, DOC, DOCX, XLS, XLSX, atau TXT."
      ),
      false
    );
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 }, // Batasi ukuran file ke 10MB
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

// Error handling middleware
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    // Error dari Multer
    return res.status(400).send(`Error upload: ${err.message}`);
  } else if (err) {
    // Error lainnya
    return res.status(500).send(`Server error: ${err.message}`);
  }
  next();
});

// ----------------------------
// Enhanced Crypto Functions
// ----------------------------

function encryptData(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPTION_KEY),
    iv
  );
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

function decryptData(text) {
  try {
    const textParts = text.split(":");
    const iv = Buffer.from(textParts.shift(), "hex");
    const encryptedText = Buffer.from(textParts.join(":"), "hex");
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(ENCRYPTION_KEY),
      iv
    );
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (error) {
    console.error("Decrypt error:", error);
    return null; // Mengembalikan null jika dekripsi gagal
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

// ----------------------------
// Enhanced Blockchain Classes
// ----------------------------

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
  constructor(nodeName) {
    this.nodeName = nodeName;
    this.chain = [];
    this.pendingBlocks = [];
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

  async addBlock(newBlock) {
    if (!this.validateBlock(newBlock)) {
      throw new Error("Block tidak valid");
    }

    this.chain.push(newBlock);
    this.saveToFile();

    // Broadcast to network
    await this.broadcastBlock(newBlock);
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
    const isValidatorValid = AUTHORIZED_VALIDATORS.includes(newBlock.validator);

    console.log(`[DEBUG] Block validation results:
    - Hash Valid: ${isHashValid}
    - Previous Hash Valid: ${isPrevHashValid}
    - Validator Valid: ${isValidatorValid}`);

    return isHashValid && isPrevHashValid && isValidatorValid;
  }

  async broadcastBlock(block) {
    const blockData = {
      index: block.index,
      timestamp: block.timestamp,
      documentData: block.documentData,
      previousHash: block.previousHash,
      validator: block.validator,
      hash: block.hash,
    };

    const broadcastPromises = [];

    for (const node of NETWORK_NODES) {
      if (node !== `http://${LOCAL_IP}:${port}`) {
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

    // Tunggu semua broadcast selesai
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
          // Pastikan hash dihitung dengan benar
          if (newBlock.hash !== block.hash) {
            console.warn(`Warning: Hash mismatch for block ${block.index}`);
          }
          return newBlock;
        });
      } catch (error) {
        console.error("Error loading blockchain:", error);
        // Jika error, mulai dengan chain baru
        this.chain = [];
      }
    }
  }

  async resolveConflicts() {
    let maxLength = this.chain.length;
    let newChain = null;

    for (const node of NETWORK_NODES) {
      if (node !== `http://${LOCAL_IP}:${port}`) {
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

      // Recreate the block to verify its hash
      const tempBlock = new Block(
        currentBlock.index,
        currentBlock.timestamp,
        currentBlock.documentData,
        currentBlock.previousHash,
        currentBlock.validator
      );

      if (currentBlock.hash !== tempBlock.calculateHash()) return false;
      if (currentBlock.previousHash !== previousBlock.hash) return false;
      if (!AUTHORIZED_VALIDATORS.includes(currentBlock.validator)) return false;
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

// Inisialisasi blockchain
const docChain = new Blockchain(NODE_NAME);

// ----------------------------
// Enhanced Routes
// ----------------------------

// Route untuk informasi node
app.get("/node-info", (req, res) => {
  try {
    res.json({
      nodeName: NODE_NAME,
      status: NETWORK_NODES.size > 0 ? "Connected" : "Standalone",
      blocksCount: docChain.chain.length - 1, // Kurangi genesis block
      peersCount: NETWORK_NODES.size,
    });
  } catch (error) {
    res.status(500).json({ error: "Gagal mendapatkan informasi node" });
  }
});

// Registrasi node
app.post("/register-node", async (req, res) => {
  try {
    const { nodeUrl } = req.body;

    if (DEBUG) {
      console.log("[DEBUG] Daftar node saat ini:", Array.from(NETWORK_NODES));
    }
    if (!nodeUrl) {
      return res.status(400).json({ error: "URL node diperlukan" });
    }

    if (nodeUrl === `http://${LOCAL_IP}:${port}`) {
      return res
        .status(400)
        .json({ error: "Tidak bisa mendaftarkan node sendiri" });
    }

    if (!NETWORK_NODES.has(nodeUrl)) {
      console.log(`[NETWORK] Menambahkan node baru: ${nodeUrl}`);
      NETWORK_NODES.add(nodeUrl);

      // Sinkronisasi dua arah
      try {
        // Daftarkan diri ke node baru
        await axios.post(`${nodeUrl}/register-node`, {
          nodeUrl: `http://${LOCAL_IP}:${port}`,
        });

        // Sinkronkan semua node yang sudah ada ke node baru
        await axios.post(`${nodeUrl}/sync-nodes`, {
          nodes: Array.from(NETWORK_NODES),
        });

        // Beri tahu node lain tentang node baru
        const syncPromises = [];
        NETWORK_NODES.forEach((node) => {
          if (node !== nodeUrl) {
            syncPromises.push(
              axios.post(`${node}/sync-nodes`, { nodes: [nodeUrl] })
            );
          }
        });

        await Promise.all(syncPromises);
      } catch (err) {
        console.error(
          `[ERROR] Gagal sinkronisasi dengan ${nodeUrl}:`,
          err.message
        );
      }
    }

    res.json({
      message: "Node berhasil terdaftar",
      nodes: Array.from(NETWORK_NODES),
      totalNodes: NETWORK_NODES.size,
    });
  } catch (error) {
    console.error("[ERROR] Registrasi node gagal:", error);
    res.status(500).json({
      error: error.message,
      stack: error.stack,
    });
  }
});

// Sinkronisasi node
app.post("/sync-nodes", (req, res) => {
  try {
    const { nodes } = req.body;

    if (DEBUG) {
      console.log("[SYNC] Menerima sinkronisasi node:", nodes);
    }

    if (!nodes || !Array.isArray(nodes)) {
      return res.status(400).json({ error: "Array nodes diperlukan" });
    }

    nodes.forEach((node) => {
      if (node !== `http://${LOCAL_IP}:${port}`) {
        NETWORK_NODES.add(node);
      }
    });

    res.json({
      message: "Nodes synchronized",
      nodes: Array.from(NETWORK_NODES),
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Proxy API untuk mengakses node lain
app.get("/proxy", async (req, res) => {
  try {
    const { url } = req.query;

    if (!url) {
      return res.status(400).json({ error: "Parameter URL diperlukan" });
    }

    const response = await axios.get(url);
    res.json(response.data);
  } catch (error) {
    console.error("Proxy error:", error.message);
    res.status(500).json({
      error: "Gagal mengakses node remote",
      details: error.message,
    });
  }
});

app.post("/resolve-conflicts", async (req, res) => {
  try {
    const conflictsResolved = await docChain.resolveConflicts();
    res.json({
      resolved: conflictsResolved,
      message: conflictsResolved
        ? "Konflik berhasil diselesaikan"
        : "Tidak ada konflik yang perlu diselesaikan",
      newChainLength: docChain.chain.length,
    });
  } catch (error) {
    res.status(500).json({
      error: "Gagal menyelesaikan konflik",
      details: error.message,
    });
  }
});

// Terima blok dari node lain
app.post("/receive-block", async (req, res) => {
  console.log("[DEBUG] Received block:", req.body);

  try {
    const newBlock = new Block(
      req.body.index,
      req.body.timestamp,
      req.body.documentData,
      req.body.previousHash,
      req.body.validator
    );

    if (docChain.validateBlock(newBlock)) {
      docChain.chain.push(newBlock);
      docChain.saveToFile();
      console.log("[DEBUG] Block added successfully:", newBlock);
      res.json({ message: "Block added", block: newBlock });
    } else {
      console.error("[DEBUG] Invalid block received:", newBlock);
      res.status(400).json({ message: "Invalid block" });
    }
  } catch (err) {
    console.error("[DEBUG] Error processing block:", err);
    res.status(500).json({ message: err.message });
  }
});

// Tampilkan halaman utama
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Tampilkan halaman verifikasi
app.get("/verify", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "verify.html"));
});

// Tampilkan halaman network
app.get("/network", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "network.html"));
});

// Upload dan validasi dokumen baru
app.post("/addDocument", upload.single("document"), async (req, res) => {
  try {
    const { documentId, title, issuer, recipient, issueDate } = req.body;
    const uploadedFile = req.file;

    // Validasi input
    if (!documentId || !title || !issuer || !recipient || !issueDate) {
      return res.status(400).send("Semua bidang harus diisi");
    }

    // Validasi format ID dokumen
    const idRegex = /^[A-Za-z0-9\-_]+$/;
    if (!idRegex.test(documentId)) {
      return res
        .status(400)
        .send(
          "Format ID dokumen tidak valid. Gunakan hanya huruf, angka, tanda hubung dan garis bawah."
        );
    }

    // Cek jika dokumen dengan ID yang sama sudah ada
    const existingDoc = docChain.getBlockByDocumentId(documentId);
    if (existingDoc) {
      return res
        .status(400)
        .send("Dokumen dengan ID ini sudah ada dalam sistem.");
    }

    if (!uploadedFile) {
      return res.status(400).send("Tidak ada file yang diunggah");
    }

    // Enkripsi path file
    const encryptedPath = encryptData(uploadedFile.path);

    // Buat record dokumen baru
    const record = {
      documentId,
      title,
      issuer,
      recipient,
      issueDate,
      documentHash: calculateFileHash(uploadedFile.path),
      filePath: encryptedPath,
      timestamp: Date.now(),
      verificationStatus: true,
    };

    // Tambahkan block baru ke blockchain
    const newBlock = new Block(
      docChain.chain.length,
      Date.now(),
      record,
      docChain.getLatestBlock().hash,
      NODE_NAME
    );

    await docChain.addBlock(newBlock);
    res.redirect("/blockchain");
  } catch (error) {
    console.error("Error adding document:", error);
    res.status(500).send(`Error memproses dokumen: ${error.message}`);
  }
});

// Tampilkan semua dokumen dengan kemampuan edit
app.get("/blockchain", (req, res) => {
  try {
    // Fungsi untuk memeriksa validitas block
    const isBlockValid = (block, previousBlock) => {
      if (block.index === 0) {
        return block.validator === "genesis" && block.previousHash === "0";
      }

      const tempBlock = new Block(
        block.index,
        block.timestamp,
        block.documentData,
        block.previousHash,
        block.validator
      );

      const isHashValid = block.hash === tempBlock.calculateHash();
      const isPrevHashValid = block.previousHash === previousBlock.hash;

      return isHashValid && isPrevHashValid;
    };

    let documentsHTML = `
      <h2>Catatan Dokumen Blockchain (Node: ${NODE_NAME})</h2>
      <div class="blockchain-controls">
        <button onclick="refreshChain()">Refresh</button>
        <button onclick="validateChain()">Validasi Rantai</button>
      </div>
    `;

    docChain.chain.forEach((block, i) => {
      const previousBlock = i > 0 ? docChain.chain[i - 1] : null;
      const isValid = i === 0 || isBlockValid(block, previousBlock);
      const blockClass = isValid ? "block-valid" : "block-invalid";

      if (i === 0) {
        // Genesis block
        documentsHTML += `
          <div class="document-card genesis ${blockClass}">
            <h3>Genesis Block</h3>
            <div class="block-hash">Hash: ${block.hash}</div>
          </div>
        `;
        return;
      }

      let fileStatus = "Tidak Diketahui";
      try {
        if (block.documentData && block.documentData.filePath) {
          const decryptedPath = decryptData(block.documentData.filePath);
          fileStatus =
            decryptedPath && fs.existsSync(decryptedPath) ? "Ada" : "Tidak Ada";
        } else {
          fileStatus = "Tidak Ada Path";
        }
      } catch (error) {
        console.error("Error checking file:", error);
        fileStatus = "Error";
      }

      documentsHTML += `
        <div class="document-card ${blockClass}" id="block-${block.index}">
          <div class="block-header">
            <h3>Block #${block.index}</h3>
            <div class="block-actions">
              <button onclick="editBlock(${block.index})">Edit</button>
            </div>
          </div>
          
          <div class="document-details">
            <div class="hash-info">
              <p><strong>Previous Hash:</strong> 
                <span class="previous-hash" contenteditable="true" data-index="${
                  block.index
                }">
                  ${block.previousHash}
                </span>
              </p>
              <p><strong>Block Hash:</strong> <span class="hash">${
                block.hash
              }</span></p>
            </div>
            
            <div class="document-info">
              <p><strong>ID Dokumen:</strong> <span contenteditable="true" data-field="documentId">${
                block.documentData.documentId
              }</span></p>
              <p><strong>Judul:</strong> <span contenteditable="true" data-field="title">${
                block.documentData.title
              }</span></p>
              <p><strong>Penerbit:</strong> <span contenteditable="true" data-field="issuer">${
                block.documentData.issuer
              }</span></p>
              <p><strong>Penerima:</strong> <span contenteditable="true" data-field="recipient">${
                block.documentData.recipient
              }</span></p>
              <p><strong>Tanggal:</strong> <span contenteditable="true" data-field="issueDate">${
                block.documentData.issueDate
              }</span></p>
              <p><strong>File Status:</strong> ${fileStatus}</p>
              <p><strong>Document Hash:</strong> ${
                block.documentData.documentHash
              }</p>
            </div>
          </div>
          
          <div class="edit-form" id="edit-form-${
            block.index
          }" style="display:none">
            <h4>Edit Block</h4>
            <div class="form-group">
              <label>Previous Hash:</label>
              <input type="text" id="edit-prev-hash-${block.index}" value="${
        block.previousHash
      }">
            </div>
            <div class="form-group">
              <label>Document Data:</label>
              <textarea id="edit-doc-data-${block.index}">${JSON.stringify(
        block.documentData,
        null,
        2
      )}</textarea>
            </div>
            <button onclick="saveBlockChanges(${
              block.index
            })">Save Changes</button>
            <button onclick="document.getElementById('edit-form-${
              block.index
            }').style.display='none'">Cancel</button>
          </div>
        </div>
      `;
    });

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Daftar Dokumen Blockchain</title>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="/css/style.css" rel="stylesheet">
        <style>
          .document-card {
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            transition: all 0.3s;
          }
          
          .block-valid {
            border-left: 5px solid #4CAF50;
            background-color: #f8fff8;
          }
          
          .block-invalid {
            border-left: 5px solid #F44336;
            background-color: #fff8f8;
            animation: pulse 2s infinite;
          }
          
          @keyframes pulse {
            0% { background-color: #fff8f8; }
            50% { background-color: #ffecec; }
            100% { background-color: #fff8f8; }
          }
          
          .block-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
          }
          
          .hash, .previous-hash {
            font-family: monospace;
            word-break: break-all;
          }
          
          .edit-form {
            margin-top: 15px;
            padding: 15px;
            background: #f5f5f5;
            border-radius: 5px;
          }
          
          .form-group {
            margin-bottom: 10px;
          }
          
          .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
          }
          
          .form-group input, .form-group textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
          }
          
          .form-group textarea {
            min-height: 100px;
            font-family: monospace;
          }
          
          button {
            padding: 8px 15px;
            background: #db3466;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
          }
          
          button:hover {
            background:rgb(172, 42, 81);
          }
        </style>
      </head>
      <nav aria-label="Main navigation">
        <div class="logo">BlockDoc</div>
        <div class="nav-menu">
          <a href="/">Tambah</a>
      <a href="/blockchain">Blockchain</a>
          <a href="/verify">Verifikasi</a>
          <a href="/network">Jaringan</a>
        </div>
      </nav>
      
      <header>
        <div class="header-content">
          <h1>Sistem Validasi Dokumen Blockchain</h1>
          <p>Keamanan dan Keaslian Dokumen dengan Teknologi Blockchain</p>
        </div>
      </header>
      <body>
        <div class="container">
          ${documentsHTML}
          <div class="node-info">
            <h3>Informasi Node</h3>
            <p><strong>Nama Node:</strong> ${NODE_NAME}</p>
            <p><strong>Node Terhubung:</strong> ${
              Array.from(NETWORK_NODES).join(", ") || "Tidak ada"
            }</p>
            <p><strong>Total Blok:</strong> ${docChain.chain.length}</p>
            <p><strong>Total Dokumen:</strong> ${docChain.chain.length - 1}</p>
          </div>
        </div>
        
        <script>
          function editBlock(index) {
            document.getElementById('edit-form-' + index).style.display = 'block';
          }
          
          async function saveBlockChanges(index) {
            const prevHash = document.getElementById('edit-prev-hash-' + index).value;
            const docData = document.getElementById('edit-doc-data-' + index).value;
            
            try {
              const response = await fetch('/update-block', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                  index: index,
                  previousHash: prevHash,
                  documentData: JSON.parse(docData)
                })
              });
              
              const result = await response.json();
              if (result.success) {
                alert('Block updated successfully!');
                location.reload();
              } else {
                alert('Error: ' + result.message);
              }
            } catch (error) {
              alert('Error updating block: ' + error.message);
            }
          }
          
          function refreshChain() {
            location.reload();
          }
          
          async function validateChain() {
            try {
              const response = await fetch('/validate-chain', {
                method: 'POST'
              });
              
              const result = await response.json();
              alert(result.valid ? 'Chain is valid!' : 'Chain is invalid!\\n' + result.message);
            } catch (error) {
              alert('Error validating chain: ' + error.message);
            }
          }
        </script>
      </body>
      </html>
    `);
  } catch (error) {
    console.error("Error rendering documents:", error);
    res.status(500).send(`Error menampilkan dokumen: ${error.message}`);
  }
});

// Endpoint untuk validasi rantai
app.post("/validate-chain", (req, res) => {
  try {
    const isValid = docChain.validateChain(docChain.chain);
    res.json({
      valid: isValid,
      message: isValid
        ? "Rantai blockchain valid"
        : "Ditemukan block yang tidak valid dalam rantai",
    });
  } catch (error) {
    res.status(500).json({
      valid: false,
      message: error.message,
    });
  }
});

// Endpoint untuk update block
app.post("/update-block", (req, res) => {
  try {
    const { index, previousHash, documentData } = req.body;

    // Temukan block yang akan diupdate
    const blockToUpdate = docChain.chain.find((b) => b.index === index);
    if (!blockToUpdate) {
      return res
        .status(404)
        .json({ success: false, message: "Block not found" });
    }

    // Update data block
    blockToUpdate.previousHash = previousHash;
    blockToUpdate.documentData = documentData;

    // Hitung ulang hash
    blockToUpdate.hash = new Block(
      blockToUpdate.index,
      blockToUpdate.timestamp,
      blockToUpdate.documentData,
      blockToUpdate.previousHash,
      blockToUpdate.validator
    ).calculateHash();

    // Simpan perubahan
    docChain.saveToFile();

    res.json({ success: true, message: "Block updated" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Route untuk verifikasi dokumen dengan file
app.post("/verifyDocument", upload.single("document"), async (req, res) => {
  try {
    const uploadedFile = req.file;

    if (!uploadedFile) {
      return res.status(400).send("Tidak ada file yang diunggah");
    }

    // Hitung hash dari file yang diupload
    const documentHash = calculateFileHash(uploadedFile.path);

    // Cari dokumen dengan hash yang sama di blockchain
    const foundBlock = docChain.getBlockByDocumentHash(documentHash);

    // Hapus file yang diupload setelah selesai verifikasi
    fs.unlinkSync(uploadedFile.path);

    let resultHTML = `<h2>Hasil Verifikasi Dokumen</h2>`;

    if (foundBlock) {
      resultHTML += `
        <div class="verification-result success">
          <div class="icon">✓</div>
          <h3>Dokumen Terverifikasi</h3>
          <p>Dokumen ini valid dan ditemukan di blockchain.</p>
          
          <div class="document-details">
            <p><strong>ID Dokumen:</strong> ${
              foundBlock.documentData.documentId
            }</p>
            <p><strong>Judul:</strong> ${foundBlock.documentData.title}</p>
            <p><strong>Penerbit:</strong> ${foundBlock.documentData.issuer}</p>
            <p><strong>Penerima:</strong> ${
              foundBlock.documentData.recipient
            }</p>
            <p><strong>Tanggal Penerbitan:</strong> ${
              foundBlock.documentData.issueDate
            }</p>
            <p><strong>Ditambahkan ke Blockchain:</strong> ${new Date(
              foundBlock.timestamp
            ).toLocaleString()}</p>
            <p><strong>Hash Dokumen:</strong> <span class="hash">${
              foundBlock.documentData.documentHash
            }</span></p>
          </div>
        </div>
      `;
    } else {
      resultHTML += `
        <div class="verification-result failure">
          <div class="icon">✗</div>
          <h3>Dokumen Tidak Terverifikasi</h3>
          <p>Dokumen ini tidak ditemukan di blockchain.</p>
          <p>Hash Dokumen: <span class="hash">${documentHash}</span></p>
        </div>
      `;
    }

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Hasil Verifikasi Dokumen</title>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="/css/style.css">
      </head>
      <body>
        <nav aria-label="Main navigation">
          <div class="logo">BlockDoc</div>
          <div class="nav-menu">
            <a href="/">Tambah</a>
      <a href="/blockchain">Blockchain</a>
            <a href="/verify">Verifikasi</a>
            <a href="/network">Jaringan</a>
          </div>
        </nav>
        
        <header>
          <div class="header-content">
            <h1>Sistem Validasi Dokumen Blockchain</h1>
            <p>Keamanan dan Keaslian Dokumen dengan Teknologi Blockchain</p>
          </div>
        </header>
        
        <div class="container">
          ${resultHTML}
          <div class="nav-links">
            <a href="/">Tambah Dokumen Baru</a> | 
            <a href="/verify">Verifikasi Dokumen Lain</a> |
            <a href="/blockchain">Lihat Semua Dokumen</a>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error("Error verifying document:", error);
    res.status(500).send(`Error verifikasi dokumen: ${error.message}`);
  }
});

// Verifikasi dokumen dengan ID
app.post("/verifyDocumentById", (req, res) => {
  try {
    const { documentId } = req.body;

    if (!documentId) {
      return res.status(400).send("ID dokumen tidak boleh kosong");
    }

    // Cari dokumen dengan ID yang sesuai di blockchain
    const foundBlock = docChain.getBlockByDocumentId(documentId);

    let resultHTML = `<h2>Hasil Verifikasi Dokumen</h2>`;

    if (foundBlock) {
      resultHTML += `
        <div class="verification-result success">
          <div class="icon">✓</div>
          <h3>Dokumen Terverifikasi</h3>
          <p>Dokumen dengan ID <strong>${documentId}</strong> ditemukan di blockchain.</p>
          
          <div class="document-details">
            <p><strong>Judul:</strong> ${foundBlock.documentData.title}</p>
            <p><strong>Penerbit:</strong> ${foundBlock.documentData.issuer}</p>
            <p><strong>Penerima:</strong> ${
              foundBlock.documentData.recipient
            }</p>
            <p><strong>Tanggal Penerbitan:</strong> ${
              foundBlock.documentData.issueDate
            }</p>
            <p><strong>Ditambahkan ke Blockchain:</strong> ${new Date(
              foundBlock.timestamp
            ).toLocaleString()}</p>
            <p><strong>Hash Dokumen:</strong> <span class="hash">${
              foundBlock.documentData.documentHash
            }</span></p>
          </div>
        </div>
      `;
    } else {
      resultHTML += `
        <div class="verification-result failure">
          <div class="icon">✗</div>
          <h3>Dokumen Tidak Terverifikasi</h3>
          <p>Dokumen dengan ID <strong>${documentId}</strong> tidak ditemukan di blockchain.</p>
        </div>
      `;
    }

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Hasil Verifikasi Dokumen</title>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="/css/style.css">
      </head>
      <body>
        <nav aria-label="Main navigation">
          <div class="logo">BlockDoc</div>
          <div class="nav-menu">
            <a href="/">Tambah</a>
      <a href="/blockchain">Blockchain</a>
            <a href="/verify">Verifikasi</a>
            <a href="/network">Jaringan</a>
          </div>
        </nav>
        
        <header>
          <div class="header-content">
            <h1>Sistem Validasi Dokumen Blockchain</h1>
            <p>Keamanan dan Keaslian Dokumen dengan Teknologi Blockchain</p>
          </div>
        </header>
        
        <div class="container">
          ${resultHTML}
          <div class="nav-links">
            <a href="/">Tambah Dokumen Baru</a> | 
            <a href="/verify">Verifikasi Dokumen Lain</a> |
            <a href="/blockchain">Lihat Semua Dokumen</a>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error("Error verifying document by ID:", error);
    res.status(500).send(`Error verifikasi dokumen: ${error.message}`);
  }
});

// Endpoint untuk mendapatkan daftar node
app.get("/nodes", (req, res) => {
  res.json({
    nodeName: NODE_NAME,
    nodes: Array.from(NETWORK_NODES),
  });
});

// Endpoint untuk mendapatkan semua blok
app.get("/blocks", (req, res) => {
  res.json(docChain.chain);
});
app.use((req, res, next) => {
  res.status(404).json({
    error: "Endpoint tidak ditemukan",
    requestedUrl: req.originalUrl,
  });
});

app.use((error, req, res, next) => {
  console.error("Global Error:", error);
  res.status(500).json({
    error: "Kesalahan server internal",
    details: process.env.NODE_ENV === "development" ? error.stack : undefined,
  });
});
// Mulai server
app.listen(port, async () => {
  console.log(`Node ${NODE_NAME} running at http://${LOCAL_IP}:${port}`);

  // Otomatis registrasi ke jaringan
  if (process.env.BOOTSTRAP_NODE) {
    try {
      await axios.post(`${process.env.BOOTSTRAP_NODE}/register-node`, {
        nodeUrl: `http://localhost:${port}`,
      });
      await docChain.resolveConflicts();
    } catch (err) {
      console.log("Error connecting to bootstrap node:", err.message);
    }
  }
});
