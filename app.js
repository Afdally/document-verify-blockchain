require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const saltRounds = 10;
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
const AUTHORIZED_VALIDATORS = ["validator1", "validator2", "genesis"];
const NETWORK_NODES = new Set(); // Daftar node dalam jaringan



// Konfigurasi kriptografi - menggunakan env var
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY
  ? crypto.scryptSync(process.env.ENCRYPTION_KEY, "salt", 32)
  : crypto.scryptSync("secret-key", "salt", 32); // Fallback untuk development
const IV_LENGTH = 16;

// Konfigurasi penyimpanan dengan validasi file
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const user = req.session.user;
    const uploadDir = path.join(
      __dirname,
      "node_data",
      user?.username,
      "uploads"
    );
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

app.use(
  session({
    secret: process.env.SESSION_SECRET || "rahasia_kita",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

// Error handling middleware
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).send(`Error upload: ${err.message}`);
  } else if (err) {
    return res.status(500).send(`Server error: ${err.message}`);
  }
  next();
});

class User {
  static filePath = path.join(__dirname, "node_data", "users.json");

  static async getAll() {
    try {
      if (!fs.existsSync(User.filePath)) return [];
      return JSON.parse(await fs.promises.readFile(User.filePath));
    } catch (error) {
      return [];
    }
  }

  static async saveAll(users) {
    await fs.promises.mkdir(path.dirname(User.filePath), { recursive: true });
    await fs.promises.writeFile(User.filePath, JSON.stringify(users, null, 2));
  }

  static async create(username, password, role = "user") {
    const users = await User.getAll();
    if (users.find((u) => u.username === username))
      throw new Error("Username sudah ada");
    const user = {
      username,
      password: await bcrypt.hash(password, saltRounds),
      role,
    };
    users.push(user);
    await User.saveAll(users);
    return user;
  }

  static async findByUsername(username) {
    const users = await User.getAll();
    return users.find((u) => u.username === username);
  }

  static async verify(username, password) {
    const user = await User.findByUsername(username);
    if (!user) return false;
    return (await bcrypt.compare(password, user.password)) ? user : false;
  }
}

// Inisialisasi admin saat server start
async function initializeAdminUser() {
  try {
    const adminExists = await User.findByUsername("admin");
    if (!adminExists) {
      await User.create("admin", "admin123", "admin");
      console.log("Admin user created successfully");
    }
  } catch (error) {
    console.error("Error initializing admin user:", error);
  }
}

const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect("/login");
  next();
};

const requireAdmin = (req, res, next) => {
  if (req.session.user?.role !== "admin")
    return res.status(403).send("Akses ditolak");
  next();
};

const requireAdminOrDocManager = (req, res, next) => {
  if (
    req.session.user?.role !== "admin" &&
    req.session.user?.role !== "document_manager"
  ) {
    return res.status(403).send("Akses ditolak");
  }
  next();
};
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
  constructor() {
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

    console.log(`[DEBUG] Block validation results:
    - Hash Valid: ${isHashValid}
    - Previous Hash Valid: ${isPrevHashValid}`);

    return isHashValid && isPrevHashValid;
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
      try {
        const response = await axios.post(`${node}/receive-block`, blockData);
        console.log(`Broadcast to ${node} success:`, response.data);
      } catch (err) {
        console.error(
          `Error broadcasting to ${node}:`,
          err.response?.data || err.message
        );
      }
    }

    return blockData;
  }

  saveToFile() {
    const filePath = path.join(__dirname, "node_data", "blockchain.json");
    fs.writeFileSync(filePath, JSON.stringify(this.chain, null, 2));
  }

  loadFromFile() {
    const filePath = path.join(__dirname, "node_data", "blockchain.json");
    if (fs.existsSync(filePath)) {
      this.chain = JSON.parse(fs.readFileSync(filePath));
    }
  }

  async resolveConflicts() {
    let maxLength = this.chain.length;
    let newChain = null;

    for (const node of NETWORK_NODES) {
      try {
        const response = await axios.get(`${node}/blocks`);
        const candidateChain = response.data;

        if (
          candidateChain.length > maxLength &&
          this.validateChain(candidateChain)
        ) {
          maxLength = candidateChain.length;
          newChain = candidateChain;
        }
      } catch (err) {
        console.error(`Error checking node ${node}:`, err.message);
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

const docChain = new Blockchain();

// ----------------------------
// Enhanced Routes
// ----------------------------

app.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/");
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/login", async (req, res) => {
  try {
    const user = await User.verify(req.body.username, req.body.password);
    if (!user) return res.status(401).send("Kredensial salah");
    req.session.user = user;
    res.redirect(user.role === "admin" ? "/" : "/");
  } catch (error) {
    res.status(500).send("Error login");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

app.get("/", requireAuth, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/node-info", (req, res) => {
  try {
    const user = req.session.user;
    res.json({
      nodeName: user.username,
      status: NETWORK_NODES.size > 0 ? "Connected" : "Standalone",
      blocksCount: new Blockchain(user.username).chain.length - 1,
      peersCount: NETWORK_NODES.size,
    });
  } catch (error) {
    res.status(500).json({ error: "Gagal mendapatkan informasi node" });
  }
});

app.get("/auth/check", (req, res) => {
  res.json(req.session.user || null);
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

    const latestBlock = docChain.getLatestBlock();

    // Validasi lebih ketat
    if (
      newBlock.previousHash === latestBlock.hash &&
      newBlock.hash === newBlock.calculateHash()
    ) {
      docChain.chain.push(newBlock);
      docChain.saveToFile();
      console.log("[DEBUG] Block added successfully:", newBlock);
      return res.json({ message: "Block added", block: newBlock });
    }

    console.error("[DEBUG] Invalid block received:", newBlock);
    res.status(400).json({
      message: "Invalid block",
      expectedPrevHash: latestBlock.hash,
      receivedPrevHash: newBlock.previousHash,
    });
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
app.get("/document", requireAuth, requireAdminOrDocManager, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "document.html"));
});

// Upload dan validasi dokumen baru
app.post(
  "/addDocument",
  requireAuth,
  requireAdminOrDocManager,
  upload.single("document"),
  (req, res) => {
    try {
      const user = req.session.user;
      const docChain = new Blockchain(user.username);
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
        user.username // Gunakan username sebagai validator
      );

      docChain.addBlock(newBlock);
      res.redirect("/blockchain");
    } catch (error) {
      console.error("Error adding document:", error);
      res.status(500).send(`Error memproses dokumen: ${error.message}`);
    }
  }
);

app.get("/blockchain", requireAuth, requireAdminOrDocManager, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "blockchain.html"));
});

// New endpoint to get blockchain data
app.get("/blockchain-data", requireAuth, requireAdminOrDocManager, (req, res) => {
  try {
    const user = req.session.user;
    const chain = docChain.chain.map(block => {
      // Only process file status for non-genesis blocks
      if (block.index > 0 && block.documentData && block.documentData.filePath) {
        let fileStatus = "Tidak Diketahui";
        try {
          const decryptedPath = decryptData(block.documentData.filePath);
          fileStatus = decryptedPath && fs.existsSync(decryptedPath) ? "Ada" : "Tidak Ada";
        } catch (error) {
          console.error("Error checking file:", error);
          fileStatus = "Error";
        }
        
        return {
          ...block,
          fileStatus
        };
      }
      return block;
    });

    res.json({
      chain,
      nodeName: user.username,
      totalBlocks: chain.length,
      totalDocuments: chain.length - 1
    });
  } catch (error) {
    console.error("Error getting blockchain data:", error);
    res.status(500).json({ error: error.message });
  }
});


app.get("/create-user", requireAuth, requireAdmin, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Buat Document Manager</title>
      <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <link href="/css/style.css" rel="stylesheet">
    </head>
    <body>
      <nav aria-label="Main navigation">
        <div class="logo">BlockDoc</div>
        <div class="nav-menu">
          <a href="/">Verifikasi</a>
          <a href="/document">Tambah</a>
          <a href="/blockchain">Blockchain</a>
          <a href="/logout">Logout</a>
        </div>
      </nav>
      
      <header>
        <div class="header-content">
          <h1>Buat User Document Manager</h1>
          <p>Buat user dengan akses khusus untuk mengelola dokumen</p>
        </div>
      </header>
      
      <div class="container">
        <form action="/create-user" method="POST">
          <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required>
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
          </div>
          <button type="submit">Buat Document Manager</button>
        </form>
      </div>
    </body>
    </html>
  `);
});

app.post("/create-user", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validasi input
    if (!username || !password) {
      return res.status(400).send("Username dan password harus diisi");
    }

    // Buat user baru dengan role document_manager
    await User.create(username, password, "document_manager");
    const userChain = new Blockchain(username);

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Document Manager Dibuat</title>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="/css/style.css" rel="stylesheet">
      </head>
      <body>
        <nav aria-label="Main navigation">
          <div class="logo">BlockDoc</div>
          <div class="nav-menu">
            <a href="/">Verifikasi</a>
            <a href="/document">Tambah</a>
            <a href="/blockchain">Blockchain</a>
            <a href="/logout">Logout</a>
          </div>
        </nav>
        
        <header>
          <div class="header-content">
            <h1>Document Manager Berhasil Dibuat</h1>
          </div>
        </header>
        
        <div class="container">
          <div class="success-message">
            <h2>User document manager berhasil dibuat</h2>
            <p>Username: ${username}</p>
          </div>
          <div class="nav-links">
            <a href="/create-user">Buat Document Manager Lain</a> | 
            <a href="/">Kembali ke Beranda</a>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    res.status(400).send(error.message);
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

    // Find the block to update
    const blockToUpdate = docChain.chain.find((b) => b.index === index);
    if (!blockToUpdate) {
      return res
        .status(404)
        .json({ success: false, message: "Block not found" });
    }

    // Update block data
    blockToUpdate.previousHash = previousHash;
    blockToUpdate.documentData = documentData;

    // Recalculate hash
    blockToUpdate.hash = new Block(
      blockToUpdate.index,
      blockToUpdate.timestamp,
      blockToUpdate.documentData,
      blockToUpdate.previousHash,
      blockToUpdate.validator
    ).calculateHash();

    // Save changes
    docChain.saveToFile();

    res.json({ 
      success: true, 
      message: "Block updated",
      newHash: blockToUpdate.hash
    });
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
                  <a href="/">Verifikasi</a>
      <a href="/document">Tambah</a>
      <a href="/blockchain">Blockchain</a>
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
            <a href="/document">Verifikasi Dokumen Lain</a> |
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
          <a href="/">Verifikasi</a>
      <a href="/document">Tambah</a>
      <a href="/blockchain">Blockchain</a>
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
            <a href="/document">Verifikasi Dokumen Lain</a> |
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
  await initializeAdminUser(); // Panggil inisialisasi admin
  console.log(`Node ${NODE_NAME} running at http://${LOCAL_IP}:${port}`);

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
