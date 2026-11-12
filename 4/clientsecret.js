const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

let targetUsername = "";
let username = "";
const users = new Map();

const PREFIX = "ENC:";
const CHUNK_SIZE = 190;

const OAEP = { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" };

function encryptFor(targetKey, text) {
  const data = Buffer.from(text, "utf8");
  const parts = [];
  for (let i = 0; i < data.length; i += CHUNK_SIZE) {
    const chunk = data.subarray(i, i + CHUNK_SIZE);
    parts.push(crypto.publicEncrypt({ key: targetKey, ...OAEP }, chunk).toString("base64"));
  }
  return PREFIX + parts.join(".");
}

function tryDecrypt(wrapped) {
  if (typeof wrapped !== "string" || !wrapped.startsWith(PREFIX)) return null;
  try {
    const parts = wrapped.slice(PREFIX.length).split(".");
    const plain = parts.map((p) =>
      crypto.privateDecrypt({ key: privateKey, ...OAEP }, Buffer.from(p, "base64"))
    );
    return Buffer.concat(plain).toString("utf8");
  } catch (err) {
    return null;
  }
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);

    users.set(username, publicKey);
    socket.emit("registerPublicKey", { username, publicKey });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        let match;
        if ((match = message.match(/^!secret (\w+)$/))) {
          if (!users.has(match[1])) {
            console.log(`Unknown user "${match[1]}", no public key found`);
          } else {
            targetUsername = match[1];
            console.log(`Now secretly chatting with ${targetUsername}`);
          }
        } else if (message.match(/^!exit$/)) {
          console.log(`No more secretly chatting with ${targetUsername}`);
          targetUsername = "";
        } else if (targetUsername) {
          const targetKey = users.get(targetUsername);
          socket.emit("message", {
            username,
            message: encryptFor(targetKey, message),
          });
        } else {
          socket.emit("message", { username, message });
        }
      }
      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newUsername, publicKey: newKey } = data;

  if (users.has(newUsername) && users.get(newUsername) !== newKey) {
    console.log(
      `\n⚠️  WARNING: someone tried to register as "${newUsername}" with a different key`
    );
    rl.prompt();
    return;
  }

  users.set(newUsername, newKey);
  console.log(`${newUsername} join the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage } = data;
  if (senderUsername !== username) {
    const plain = tryDecrypt(senderMessage);
    if (plain !== null) {
      console.log(`${senderUsername} (secret): ${plain}`);
    } else {
      console.log(`${senderUsername}: ${senderMessage}`);
    }
    rl.prompt();
  }
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});