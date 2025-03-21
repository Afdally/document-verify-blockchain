const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");
const fs = require("fs");

const app = express();
const port = process.env.PORT || 3000;

// Konfigurasi penyimpanan file
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, "uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({ storage: storage });

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));

// ----------------------------
// SHA-256 Implementation
// ----------------------------

function calculateFileHash(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  const hashSum = crypto.createHash("sha256");
  hashSum.update(fileBuffer);
  return hashSum.digest("hex");
}

// ----------------------------
// Blockchain Classes
// ----------------------------

// Block class untuk setiap block dalam chain
class Block {
  constructor(index, timestamp, documentData, previousHash = "") {
    this.index = index;
    this.timestamp = timestamp;
    this.documentData = documentData;
    this.previousHash = previousHash;
    this.hash = this.calculateHash();
  }

  // Menghitung SHA-256 hash dari konten block ini
  calculateHash() {
    return crypto
      .createHash("sha256")
      .update(
        this.index +
          this.previousHash +
          this.timestamp +
          JSON.stringify(this.documentData)
      )
      .digest("hex");
  }
}

// Blockchain class untuk mengelola rantai block
class Blockchain {
  constructor() {
    this.chain = [this.createGenesisBlock()];
  }

  // Membuat block pertama dalam blockchain
  createGenesisBlock() {
    return new Block(0, Date.now(), "Genesis Block - Document Validation System", "0");
  }

  // Mengambil block terbaru
  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  // Menambahkan block baru ke blockchain
  addBlock(newBlock) {
    newBlock.previousHash = this.getLatestBlock().hash;
    newBlock.hash = newBlock.calculateHash();
    this.chain.push(newBlock);
  }

  // Memeriksa integritas blockchain
  isChainValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      if (currentBlock.hash !== currentBlock.calculateHash()) return false;
      if (currentBlock.previousHash !== previousBlock.hash) return false;
    }
    return true;
  }

  // Mencari dokumen berdasarkan hash
  findDocumentByHash(docHash) {
    for (let i = 1; i < this.chain.length; i++) {
      if (this.chain[i].documentData.documentHash === docHash) {
        return this.chain[i];
      }
    }
    return null;
  }

  // Mencari dokumen berdasarkan ID
  findDocumentById(docId) {
    for (let i = 1; i < this.chain.length; i++) {
      if (this.chain[i].documentData.documentId === docId) {
        return this.chain[i];
      }
    }
    return null;
  }
}

// DocumentRecord class mendefinisikan struktur untuk data dokumen
class DocumentRecord {
  constructor(documentId, title, issuer, recipient, issueDate, documentHash, filePath) {
    this.documentId = documentId;
    this.title = title;
    this.issuer = issuer;
    this.recipient = recipient;
    this.issueDate = issueDate;
    this.documentHash = documentHash;
    this.filePath = filePath;
    this.verificationStatus = true;
  }
}

// Inisialisasi blockchain
let docChain = new Blockchain();

// ----------------------------
// Routes
// ----------------------------

// Halaman utama
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Upload dan validasi dokumen baru
app.post("/addDocument", upload.single("document"), (req, res) => {
  try {
    const { documentId, title, issuer, recipient, issueDate } = req.body;
    const uploadedFile = req.file;
    
    if (!uploadedFile) {
      return res.status(400).send("No file uploaded");
    }
    
    // Hitung hash dari file yang diupload
    const documentHash = calculateFileHash(uploadedFile.path);
    
    // Buat record dokumen baru
    const record = new DocumentRecord(
      documentId,
      title,
      issuer,
      recipient,
      issueDate,
      documentHash,
      uploadedFile.path
    );
    
    // Tambahkan block baru ke blockchain
    const newBlock = new Block(docChain.chain.length, Date.now(), record);
    docChain.addBlock(newBlock);
    
    res.redirect("/documents");
  } catch (error) {
    console.error("Error adding document:", error);
    res.status(500).send("Error processing document");
  }
});

// Tampilkan semua dokumen
app.get("/documents", (req, res) => {
  let documentsHTML = `<h2>Blockchain Document Records</h2>`;
  
  docChain.chain.forEach((block, i) => {
    // Untuk block non-genesis, periksa apakah terjadi perubahan
    let warning = "";
    if (i > 0 && block.previousHash !== docChain.chain[i - 1].hash) {
      warning = `<p class="warning">Warning: Previous block has changed. Chain integrity compromised.</p>`;
    }
    
    // Tampilkan informasi dokumen hanya untuk block non-genesis
    if (i > 0) {
      documentsHTML += `
        <div class="document-card">
          <h3>Document #${block.documentData.documentId}</h3>
          ${warning}
          <div class="document-details">
            <p><strong>Title:</strong> ${block.documentData.title}</p>
            <p><strong>Issuer:</strong> ${block.documentData.issuer}</p>
            <p><strong>Recipient:</strong> ${block.documentData.recipient}</p>
            <p><strong>Issue Date:</strong> ${block.documentData.issueDate}</p>
            <p><strong>Document Hash:</strong> <span class="hash">${block.documentData.documentHash}</span></p>
            <p><strong>Block Hash:</strong> <span class="hash">${block.hash}</span></p>
            <p><strong>Timestamp:</strong> ${new Date(block.timestamp).toLocaleString()}</p>
            <p class="status ${block.documentData.verificationStatus ? 'valid' : 'invalid'}">
              Status: ${block.documentData.verificationStatus ? 'Valid' : 'Invalid'}
            </p>
          </div>
          <div class="document-actions">
            <a href="/verify/${block.documentData.documentId}" class="btn btn-verify">Verify Document</a>
          </div>
        </div>
      `;
    }
  });
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Document Validation System</title>
      <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        :root {
          --primary-color: #db3466;
          --secondary-color: #2ecc71;
          --danger-color: #e74c3c;
          --text-color: #333;
          --light-bg: #f8f9fa;
          --card-bg: #fff;
          --shadow: 0 4px 12px rgba(0,0,0,0.08);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
          font-family: 'Roboto', sans-serif; 
          background-color: var(--light-bg);
          color: var(--text-color);
          line-height: 1.6;
        }
        header { 
          background-color: var(--primary-color); 
          padding: 20px; 
          text-align: center; 
          color: white;
          box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        nav { 
          display: flex; 
          justify-content: center;
          margin-top: 10px;
        }
        nav a { 
          color: white; 
          margin: 0 15px; 
          text-decoration: none; 
          font-weight: 500;
          transition: opacity 0.3s ease;
        }
        nav a:hover { opacity: 0.8; }
        .container { 
          max-width: 1000px; 
          margin: 30px auto; 
          padding: 20px;
        }
        h2 {
          text-align: center;
          margin-bottom: 30px;
          color: var(--primary-color);
        }
        .document-card {
          background: var(--card-bg);
          margin: 25px 0;
          padding: 25px;
          border-radius: 12px;
          box-shadow: var(--shadow);
          transition: transform 0.3s ease, box-shadow 0.3s ease;
          animation: fadeInUp 0.6s ease forwards;
          position: relative;
          overflow: hidden;
        }
        .document-card:hover {
          transform: translateY(-5px);
          box-shadow: 0 6px 16px rgba(0,0,0,0.12);
        }
        .document-details {
          margin: 15px 0;
        }
        .document-details p {
          margin: 8px 0;
        }
        .hash {
          font-family: monospace;
          background: #f1f1f1;
          padding: 2px 4px;
          border-radius: 4px;
          font-size: 0.9em;
          word-break: break-all;
        }
        .status {
          display: inline-block;
          padding: 5px 10px;
          border-radius: 20px;
          font-weight: bold;
          margin-top: 10px;
        }
        .valid {
          background-color: rgba(46, 204, 113, 0.2);
          color: #27ae60;
        }
        .invalid {
          background-color: rgba(231, 76, 60, 0.2);
          color: #c0392b;
        }
        .document-actions {
          margin-top: 15px;
          display: flex;
          gap: 10px;
        }
        .btn {
          display: inline-block;
          padding: 10px 15px;
          border-radius: 6px;
          text-decoration: none;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.3s ease;
        }
        .btn-verify {
          background-color: var(--secondary-color);
          color: white;
        }
        .btn-verify:hover {
          background-color: #27ae60;
        }
        .warning {
          background-color: rgba(231, 76, 60, 0.2);
          color: #c0392b;
          padding: 10px;
          border-radius: 6px;
          font-weight: 500;
          margin: 10px 0;
        }
        .nav-links { 
          text-align: center; 
          margin-top: 30px;
        }
        .nav-links a { 
          margin: 0 10px; 
          text-decoration: none; 
          color: var(--primary-color); 
          font-weight: 500;
          transition: color 0.3s ease;
        }
        .nav-links a:hover { 
          color: #2980b9;
        }
        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @media (max-width: 768px) {
          .container { padding: 15px; }
          header nav { flex-direction: column; }
          header nav a { margin: 5px 0; }
          .document-card { padding: 20px; }
        }
      </style>
    </head>
    <body>
      <header>
        <h1>Blockchain Document Validation System</h1>
        <nav>
          <a href="/">Add Document</a>
          <a href="/documents">View Documents</a>
          <a href="/verify">Verify Document</a>
        </nav>
      </header>
      <div class="container">
        ${documentsHTML}
        <div class="nav-links">
          <a href="/">Add New Document</a> | 
          <a href="/verify">Verify Document</a>
        </div>
      </div>
    </body>
    </html>
  `);
});

// Halaman verifikasi dokumen
app.get("/verify", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "verify.html"));
});

// Proses verifikasi dokumen yang diupload
app.post("/verifyDocument", upload.single("document"), (req, res) => {
  try {
    const uploadedFile = req.file;
    
    if (!uploadedFile) {
      return res.status(400).send("No file uploaded");
    }
    
    // Hitung hash dari file yang diupload
    const documentHash = calculateFileHash(uploadedFile.path);
    
    // Cari dokumen dengan hash yang sama di blockchain
    const foundBlock = docChain.findDocumentByHash(documentHash);
    
    // Hapus file yang diupload untuk verifikasi setelah selesai
    fs.unlinkSync(uploadedFile.path);
    
    let resultHTML = `<h2>Document Verification Result</h2>`;
    
    if (foundBlock) {
      resultHTML += `
        <div class="verification-result success">
          <div class="icon">✓</div>
          <h3>Document Verified Successfully</h3>
          <p>This document exists in our blockchain and is valid.</p>
          
          <div class="document-details">
            <p><strong>Document ID:</strong> ${foundBlock.documentData.documentId}</p>
            <p><strong>Title:</strong> ${foundBlock.documentData.title}</p>
            <p><strong>Issuer:</strong> ${foundBlock.documentData.issuer}</p>
            <p><strong>Recipient:</strong> ${foundBlock.documentData.recipient}</p>
            <p><strong>Issue Date:</strong> ${foundBlock.documentData.issueDate}</p>
            <p><strong>Added to Blockchain:</strong> ${new Date(foundBlock.timestamp).toLocaleString()}</p>
            <p><strong>Document Hash:</strong> <span class="hash">${foundBlock.documentData.documentHash}</span></p>
          </div>
        </div>
      `;
    } else {
      resultHTML += `
        <div class="verification-result failure">
          <div class="icon">✗</div>
          <h3>Document Not Verified</h3>
          <p>This document was not found in our blockchain.</p>
          <p>Document Hash: <span class="hash">${documentHash}</span></p>
        </div>
      `;
    }
    
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Document Verification Result</title>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          :root {
            --primary-color: #db3466;
            --success-color: #2ecc71;
            --danger-color: #e74c3c;
            --text-color: #333;
            --light-bg: #f8f9fa;
            --card-bg: #fff;
            --shadow: 0 4px 12px rgba(0,0,0,0.08);
          }
          * { box-sizing: border-box; margin: 0; padding: 0; }
          body { 
            font-family: 'Roboto', sans-serif; 
            background-color: var(--light-bg);
            color: var(--text-color);
            line-height: 1.6;
          }
          header { 
            background-color: var(--primary-color); 
            padding: 20px; 
            text-align: center; 
            color: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
          }
          nav { 
            display: flex; 
            justify-content: center;
            margin-top: 10px;
          }
          nav a { 
            color: white; 
            margin: 0 15px; 
            text-decoration: none; 
            font-weight: 500;
            transition: opacity 0.3s ease;
          }
          nav a:hover { opacity: 0.8; }
          .container { 
            max-width: 800px; 
            margin: 30px auto; 
            padding: 20px;
          }
          h2 {
            text-align: center;
            margin-bottom: 30px;
            color: var(--primary-color);
          }
          .verification-result {
            background: var(--card-bg);
            margin: 25px 0;
            padding: 30px;
            border-radius: 12px;
            box-shadow: var(--shadow);
            text-align: center;
            animation: fadeIn 0.6s ease;
          }
          .success {
            border-top: 4px solid var(--success-color);
          }
          .failure {
            border-top: 4px solid var(--danger-color);
          }
          .icon {
            font-size: 48px;
            margin-bottom: 20px;
          }
          .success .icon {
            color: var(--success-color);
          }
          .failure .icon {
            color: var(--danger-color);
          }
          .document-details {
            margin: 20px 0;
            text-align: left;
            background: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
          }
          .document-details p {
            margin: 8px 0;
          }
          .hash {
            font-family: monospace;
            background: #f1f1f1;
            padding: 2px 4px;
            border-radius: 4px;
            font-size: 0.9em;
            word-break: break-all;
          }
          .nav-links { 
            text-align: center; 
            margin-top: 30px;
          }
          .nav-links a { 
            margin: 0 10px; 
            text-decoration: none; 
            color: var(--primary-color); 
            font-weight: 500;
            transition: color 0.3s ease;
          }
          .nav-links a:hover { 
            color: #2980b9;
          }
          @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
          }
          @media (max-width: 768px) {
            .container { padding: 15px; }
            header nav { flex-direction: column; }
            header nav a { margin: 5px 0; }
            .verification-result { padding: 20px; }
          }
        </style>
      </head>
      <body>
        <header>
          <h1>Blockchain Document Validation System</h1>
          <nav>
            <a href="/">Add Document</a>
            <a href="/documents">View Documents</a>
            <a href="/verify">Verify Document</a>
          </nav>
        </header>
        <div class="container">
          ${resultHTML}
          <div class="nav-links">
            <a href="/">Add New Document</a> | 
            <a href="/verify">Verify Another Document</a> |
            <a href="/documents">View All Documents</a>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error("Error verifying document:", error);
    res.status(500).send("Error verifying document");
  }
});

// Verifikasi dokumen berdasarkan ID
app.get("/verify/:id", (req, res) => {
  const docId = req.params.id;
  const foundBlock = docChain.findDocumentById(docId);
  
  let resultHTML = `<h2>Document Verification Result</h2>`;
  
  if (foundBlock) {
    // Periksa integritas blockchain
    const isValid = docChain.isChainValid();
    const isBlockValid = foundBlock.hash === foundBlock.calculateHash();
    
    if (isValid && isBlockValid) {
      resultHTML += `
        <div class="verification-result success">
          <div class="icon">✓</div>
          <h3>Document Verified Successfully</h3>
          <p>This document exists in our blockchain and is valid.</p>
          
          <div class="document-details">
            <p><strong>Document ID:</strong> ${foundBlock.documentData.documentId}</p>
            <p><strong>Title:</strong> ${foundBlock.documentData.title}</p>
            <p><strong>Issuer:</strong> ${foundBlock.documentData.issuer}</p>
            <p><strong>Recipient:</strong> ${foundBlock.documentData.recipient}</p>
            <p><strong>Issue Date:</strong> ${foundBlock.documentData.issueDate}</p>
            <p><strong>Added to Blockchain:</strong> ${new Date(foundBlock.timestamp).toLocaleString()}</p>
            <p><strong>Document Hash:</strong> <span class="hash">${foundBlock.documentData.documentHash}</span></p>
            <p><strong>Block Hash:</strong> <span class="hash">${foundBlock.hash}</span></p>
          </div>
        </div>
      `;
    } else {
      resultHTML += `
        <div class="verification-result warning">
          <div class="icon">⚠</div>
          <h3>Document Found But Integrity Compromised</h3>
          <p>The document was found in our blockchain, but the blockchain integrity check failed.</p>
          
          <div class="document-details">
            <p><strong>Document ID:</strong> ${foundBlock.documentData.documentId}</p>
            <p><strong>Title:</strong> ${foundBlock.documentData.title}</p>
            <p><strong>Blockchain Status:</strong> <span class="warning">Compromised</span></p>
          </div>
        </div>
      `;
    }
  } else {
    resultHTML += `
      <div class="verification-result failure">
        <div class="icon">✗</div>
        <h3>Document Not Found</h3>
        <p>No document with ID "${docId}" was found in our blockchain.</p>
      </div>
    `;
  }
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Document Verification Result</title>
      <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        :root {
          --primary-color: #db3466;
          --success-color: #2ecc71;
          --warning-color: #f39c12;
          --danger-color: #e74c3c;
          --text-color: #333;
          --light-bg: #f8f9fa;
          --card-bg: #fff;
          --shadow: 0 4px 12px rgba(0,0,0,0.08);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
          font-family: 'Roboto', sans-serif; 
          background-color: var(--light-bg);
          color: var(--text-color);
          line-height: 1.6;
        }
        header { 
          background-color: var(--primary-color); 
          padding: 20px; 
          text-align: center; 
          color: white;
          box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        nav { 
          display: flex; 
          justify-content: center;
          margin-top: 10px;
        }
        nav a { 
          color: white; 
          margin: 0 15px; 
          text-decoration: none; 
          font-weight: 500;
          transition: opacity 0.3s ease;
        }
        nav a:hover { opacity: 0.8; }
        .container { 
          max-width: 800px; 
          margin: 30px auto; 
          padding: 20px;
        }
        h2 {
          text-align: center;
          margin-bottom: 30px;
          color: var(--primary-color);
        }
        .verification-result {
          background: var(--card-bg);
          margin: 25px 0;
          padding: 30px;
          border-radius: 12px;
          box-shadow: var(--shadow);
          text-align: center;
          animation: fadeIn 0.6s ease;
        }
        .success {
          border-top: 4px solid var(--success-color);
        }
        .warning {
          border-top: 4px solid var(--warning-color);
        }
        .failure {
          border-top: 4px solid var(--danger-color);
        }
        .icon {
          font-size: 48px;
          margin-bottom: 20px;
        }
        .success .icon {
          color: var(--success-color);
        }
        .warning .icon {
          color: var(--warning-color);
        }
        .failure .icon {
          color: var(--danger-color);
        }
        .document-details {
          margin: 20px 0;
          text-align: left;
          background: #f9f9f9;
          padding: 20px;
          border-radius: 8px;
        }
        .document-details p {
          margin: 8px 0;
        }
        .hash {
          font-family: monospace;
          background: #f1f1f1;
          padding: 2px 4px;
          border-radius: 4px;
          font-size: 0.9em;
          word-break: break-all;
        }
        span.warning {
          background-color: rgba(243, 156, 18, 0.2);
          color: #d35400;
          padding: 2px 6px;
          border-radius: 4px;
          border-top: none;
        }
        .nav-links { 
          text-align: center; 
          margin-top: 30px;
        }
        .nav-links a { 
          margin: 0 10px; 
          text-decoration: none; 
          color: var(--primary-color); 
          font-weight: 500;
          transition: color 0.3s ease;
        }
        .nav-links a:hover { 
          color: #2980b9;
        }
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @media (max-width: 768px) {
          .container { padding: 15px; }
          header nav { flex-direction: column; }
          header nav a { margin: 5px 0; }
          .verification-result { padding: 20px; }
        }
      </style>
    </head>
    <body>
      <header>
        <h1>Blockchain Document Validation System</h1>
        <nav>
          <a href="/">Add Document</a>
          <a href="/documents">View Documents</a>
          <a href="/verify">Verify Document</a>
        </nav>
      </header>
      <div class="container">
        ${resultHTML}
        <div class="nav-links">
          <a href="/">Add New Document</a> | 
          <a href="/verify">Verify Another Document</a> |
          <a href="/documents">View All Documents</a>
        </div>
      </div>
    </body>
    </html>
  `);
});

// Mulai server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});