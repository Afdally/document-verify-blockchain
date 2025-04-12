const express = require("express");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const axios = require("axios"); 
const { Block, Blockchain, encryptData, decryptData, calculateFileHash } = require("./blockchain");

function setupRoutes(app, docChain, NODE_NAME, NETWORK_NODES, ENCRYPTION_KEY, AUTHORIZED_VALIDATORS) {
  const router = express.Router();

  // Konfigurasi upload file
  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      const uploadDir = path.join(__dirname, "node_data", NODE_NAME, "uploads");
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
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

  const fileFilter = (req, file, cb) => {
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
    limits: { fileSize: 10 * 1024 * 1024 },
  });

  // Route untuk informasi node
  router.get("/node-info", (req, res) => {
    try {
      res.json({
        nodeName: NODE_NAME,
        status: NETWORK_NODES.size > 0 ? "Connected" : "Standalone",
        blocksCount: docChain.chain.length - 1,
        peersCount: NETWORK_NODES.size,
      });
    } catch (error) {
      res.status(500).json({ error: "Gagal mendapatkan informasi node" });
    }
  });

  // Registrasi node
  router.post("/register-node", async (req, res) => {
    try {
      const { nodeUrl } = req.body;

      if (!nodeUrl) {
        return res.status(400).json({ error: "URL node diperlukan" });
      }

      if (nodeUrl === `http://localhost:${process.env.PORT || 3000}`) {
        return res
          .status(400)
          .json({ error: "Tidak bisa mendaftarkan node sendiri" });
      }

      if (!NETWORK_NODES.has(nodeUrl)) {
        NETWORK_NODES.add(nodeUrl);

        try {
          await axios.post(`${nodeUrl}/register-node`, {
            nodeUrl: `http://localhost:${process.env.PORT || 3000}`,
          });

          await axios.post(`${nodeUrl}/sync-nodes`, {
            nodes: Array.from(NETWORK_NODES),
          });

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
          console.error(`Gagal sinkronisasi dengan ${nodeUrl}:`, err.message);
        }
      }

      res.json({
        message: "Node berhasil terdaftar",
        nodes: Array.from(NETWORK_NODES),
        totalNodes: NETWORK_NODES.size,
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
        stack: error.stack,
      });
    }
  });

  // Sinkronisasi node
  router.post("/sync-nodes", (req, res) => {
    try {
      const { nodes } = req.body;

      if (!nodes || !Array.isArray(nodes)) {
        return res.status(400).json({ error: "Array nodes diperlukan" });
      }

      nodes.forEach((node) => {
        if (node !== `http://localhost:${process.env.PORT || 3000}`) {
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

  // Proxy API
  router.get("/proxy", async (req, res) => {
    try {
      const { url } = req.query;

      if (!url) {
        return res.status(400).json({ error: "Parameter URL diperlukan" });
      }

      const response = await axios.get(url);
      res.json(response.data);
    } catch (error) {
      res.status(500).json({
        error: "Gagal mengakses node remote",
        details: error.message,
      });
    }
  });

  // Resolve conflicts
  router.post("/resolve-conflicts", async (req, res) => {
    try {
      const conflictsResolved = await docChain.resolveConflicts(NETWORK_NODES);
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
  router.post("/receive-block", async (req, res) => {
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
        res.json({ message: "Block added", block: newBlock });
      } else {
        res.status(400).json({ message: "Invalid block" });
      }
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  });

  // Upload dan validasi dokumen baru
  router.post("/addDocument", upload.single("document"), async (req, res) => {
    try {
      const { documentId, title, issuer, recipient, issueDate } = req.body;
      const uploadedFile = req.file;

      if (!documentId || !title || !issuer || !recipient || !issueDate) {
        return res.status(400).send("Semua bidang harus diisi");
      }

      const idRegex = /^[A-Za-z0-9\-_]+$/;
      if (!idRegex.test(documentId)) {
        return res
          .status(400)
          .send(
            "Format ID dokumen tidak valid. Gunakan hanya huruf, angka, tanda hubung dan garis bawah."
          );
      }

      const existingDoc = docChain.getBlockByDocumentId(documentId);
      if (existingDoc) {
        return res
          .status(400)
          .send("Dokumen dengan ID ini sudah ada dalam sistem.");
      }

      if (!uploadedFile) {
        return res.status(400).send("Tidak ada file yang diunggah");
      }

      const encryptedPath = encryptData(uploadedFile.path, ENCRYPTION_KEY);

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

      const newBlock = new Block(
        docChain.chain.length,
        Date.now(),
        record,
        docChain.getLatestBlock().hash,
        NODE_NAME
      );

      await docChain.addBlock(newBlock, NETWORK_NODES);
      res.redirect("/documents");
    } catch (error) {
      res.status(500).send(`Error memproses dokumen: ${error.message}`);
    }
  });

  // Tampilkan semua dokumen
  router.get("/documents", (req, res) => {
    try {
      let documentsHTML = `<h2>Catatan Dokumen Blockchain (Node: ${NODE_NAME})</h2>`;

      docChain.chain.forEach((block, i) => {
        if (i === 0) return;

        let fileStatus = "Tidak Diketahui";
        try {
          if (block.documentData && block.documentData.filePath) {
            const decryptedPath = decryptData(block.documentData.filePath, ENCRYPTION_KEY);
            fileStatus =
              decryptedPath && fs.existsSync(decryptedPath) ? "Ada" : "Tidak Ada";
          } else {
            fileStatus = "Tidak Ada Path";
          }
        } catch (error) {
          fileStatus = "Error";
        }

        documentsHTML += `
          <div class="document-card">
            <h3>Dokumen #${block.documentData.documentId}</h3>
            <div class="document-details">
              <p><strong>Judul:</strong> ${block.documentData.title}</p>
              <p><strong>Penerbit:</strong> ${block.documentData.issuer}</p>
              <p><strong>Penerima:</strong> ${block.documentData.recipient}</p>
              <p><strong>Tanggal Penerbitan:</strong> ${block.documentData.issueDate}</p>
              <p><strong>Validator:</strong> ${block.validator}</p>
              <p><strong>Ditambahkan pada:</strong> ${new Date(block.timestamp).toLocaleString()}</p>
              <p><strong>File Ada:</strong> ${fileStatus}</p>
              <p><strong>Hash Dokumen:</strong> <span class="hash">${block.documentData.documentHash}</span></p>
              <p><strong>Hash Blok:</strong> <span class="hash">${block.hash}</span></p>
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
        </head>
        <nav aria-label="Main navigation">
        <div class="logo">BlockDoc</div>
        <div class="nav-menu">
          <a href="/" >Tambah</a>
          <a href="/documents" >Dokumen</a>
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
              <p><strong>Node Terhubung:</strong> ${Array.from(NETWORK_NODES).join(", ") || "Tidak ada"}</p>
              <p><strong>Total Blok:</strong> ${docChain.chain.length}</p>
              <p><strong>Total Dokumen:</strong> ${docChain.chain.length - 1}</p>
            </div>
          </div>
        </body>
        </html>
      `);
    } catch (error) {
      res.status(500).send(`Error menampilkan dokumen: ${error.message}`);
    }
  });

  // Verifikasi dokumen dengan file
  router.post("/verifyDocument", upload.single("document"), async (req, res) => {
    try {
      const uploadedFile = req.file;

      if (!uploadedFile) {
        return res.status(400).send("Tidak ada file yang diunggah");
      }

      const documentHash = calculateFileHash(uploadedFile.path);
      const foundBlock = docChain.getBlockByDocumentHash(documentHash);

      fs.unlinkSync(uploadedFile.path);

      let resultHTML = `<h2>Hasil Verifikasi Dokumen</h2>`;

      if (foundBlock) {
        resultHTML += `
          <div class="verification-result success">
            <div class="icon">✓</div>
            <h3>Dokumen Terverifikasi</h3>
            <p>Dokumen ini valid dan ditemukan di blockchain.</p>
            
            <div class="document-details">
              <p><strong>ID Dokumen:</strong> ${foundBlock.documentData.documentId}</p>
              <p><strong>Judul:</strong> ${foundBlock.documentData.title}</p>
              <p><strong>Penerbit:</strong> ${foundBlock.documentData.issuer}</p>
              <p><strong>Penerima:</strong> ${foundBlock.documentData.recipient}</p>
              <p><strong>Tanggal Penerbitan:</strong> ${foundBlock.documentData.issueDate}</p>
              <p><strong>Ditambahkan ke Blockchain:</strong> ${new Date(foundBlock.timestamp).toLocaleString()}</p>
              <p><strong>Hash Dokumen:</strong> <span class="hash">${foundBlock.documentData.documentHash}</span></p>
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
              <a href="/documents">Dokumen</a>
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
              <a href="/documents">Lihat Semua Dokumen</a>
            </div>
          </div>
        </body>
        </html>
      `);
    } catch (error) {
      res.status(500).send(`Error verifikasi dokumen: ${error.message}`);
    }
  });

  // Verifikasi dokumen dengan ID
  router.post("/verifyDocumentById", (req, res) => {
    try {
      const { documentId } = req.body;

      if (!documentId) {
        return res.status(400).send("ID dokumen tidak boleh kosong");
      }

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
              <p><strong>Penerima:</strong> ${foundBlock.documentData.recipient}</p>
              <p><strong>Tanggal Penerbitan:</strong> ${foundBlock.documentData.issueDate}</p>
              <p><strong>Ditambahkan ke Blockchain:</strong> ${new Date(foundBlock.timestamp).toLocaleString()}</p>
              <p><strong>Hash Dokumen:</strong> <span class="hash">${foundBlock.documentData.documentHash}</span></p>
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
              <a href="/documents">Dokumen</a>
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
              <a href="/documents">Lihat Semua Dokumen</a>
            </div>
          </div>
        </body>
        </html>
      `);
    } catch (error) {
      res.status(500).send(`Error verifikasi dokumen: ${error.message}`);
    }
  });

  // Endpoint untuk mendapatkan daftar node
  router.get("/nodes", (req, res) => {
    res.json({
      nodeName: NODE_NAME,
      nodes: Array.from(NETWORK_NODES),
    });
  });

  // Endpoint untuk mendapatkan semua blok
  router.get("/blocks", (req, res) => {
    res.json(docChain.chain);
  });

  // Route untuk halaman statis
  router.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
  });

  router.get("/verify", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "verify.html"));
  });

  router.get("/network", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "network.html"));
  });

  // Error handling
  router.use((req, res) => {
    res.status(404).json({
      error: "Endpoint tidak ditemukan",
      requestedUrl: req.originalUrl,
    });
  });

  router.use((error, req, res, next) => {
    res.status(500).json({
      error: "Kesalahan server internal",
      details: process.env.NODE_ENV === "development" ? error.stack : undefined,
    });
  });

  return router;
}

module.exports = setupRoutes;