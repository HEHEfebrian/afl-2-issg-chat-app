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

let registeredUsername = "";
let username = "";
const users = new Map();

function sign(user, text) {
  return crypto
    .sign("sha256", Buffer.from(JSON.stringify([user, text])), privateKey)
    .toString("base64");
}

function verify(user, text, signature) {
  const key = users.get(user);
  if (!key) return false;
  try {
    return crypto.verify(
      "sha256",
      Buffer.from(JSON.stringify([user, text])),
      key,
      Buffer.from(signature, "base64")
    );
  } catch (err) {
    return false;
  }
}

function wrapMessage(user, text) {
  return sign(user, text) + "|" + text;
}

function unwrapMessage(user, wrapped) {
  const idx = typeof wrapped === "string" ? wrapped.indexOf("|") : -1;
  if (idx === -1) {
    return { text: String(wrapped), valid: false };
  }
  const signature = wrapped.slice(0, idx);
  const text = wrapped.slice(idx + 1);
  return { text, valid: verify(user, text, signature) };
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    registeredUsername = input;
    console.log(`Welcome, ${username} to the chat`);

    users.set(username, publicKey);
    socket.emit("registerPublicKey", { username, publicKey });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        let match;
        if ((match = message.match(/^!impersonate (\w+)$/))) {
          username = match[1];
          console.log(`Now impersonating as ${username}`);
        } else if (message.match(/^!exit$/)) {
          username = registeredUsername;
          console.log(`Now you are ${username}`);
        } else {
          socket.emit("message", {
            username,
            message: wrapMessage(username, message),
          });
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
  console.log(`\n${newUsername} join the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: wrapped } = data;
  if (senderUsername !== username) {
    const { text, valid } = unwrapMessage(senderUsername, wrapped);
    console.log(`${senderUsername}: ${text}`);
    if (!valid) {
      console.log("⚠️  WARNING: this user is fake");
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