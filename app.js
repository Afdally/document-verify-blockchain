const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const cors = require("cors");
const { Blockchain } = require("./blockchain");
const setupRoutes = require("./routes");

const app = express();
const port = process.env.PORT || 3000;

// Konfigurasi awal
const NODE_NAME =
  process.env.NODE_NAME || `node_${crypto.randomBytes(2).toString("hex")}`;
const AUTHORIZED_VALIDATORS = [
  "validator1",
  "validator2",
  "genesis",
  NODE_NAME,
];
const NETWORK_NODES = new Set();

// Konfigurasi kriptografi
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY
  ? crypto.scryptSync(process.env.ENCRYPTION_KEY, "salt", 32)
  : crypto.scryptSync("secret-key", "salt", 32);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

// Inisialisasi blockchain
const docChain = new Blockchain(NODE_NAME, ENCRYPTION_KEY, AUTHORIZED_VALIDATORS);

// Setup routes
const router = setupRoutes(
  app,
  docChain,
  NODE_NAME,
  NETWORK_NODES,
  ENCRYPTION_KEY,
  AUTHORIZED_VALIDATORS
);
app.use("/", router);

// Mulai server
app.listen(port, async () => {
  console.log(`Node ${NODE_NAME} running at http://localhost:${port}`);

  // Otomatis registrasi ke jaringan
  if (process.env.BOOTSTRAP_NODE) {
    try {
      await axios.post(`${process.env.BOOTSTRAP_NODE}/register-node`, {
        nodeUrl: `http://localhost:${port}`,
      });
      await docChain.resolveConflicts(NETWORK_NODES);
    } catch (err) {
      console.log("Error connecting to bootstrap node:", err.message);
    }
  }
});