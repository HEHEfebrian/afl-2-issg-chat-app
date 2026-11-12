const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const SHARED_SECRET = "my-super-secret-key";

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let username = "";

const HASH_LENGTH = 64;

function computeHash(user, text) {
  return crypto.createHmac("sha256", SHARED_SECRET).update(JSON.stringify([user, text])).digest("hex");
}

function wrapMessage(user, text) {
  return computeHash(user, text) + text;
}

function unwrapMessage(user, wrapped) {
  if (typeof wrapped !== "string" || wrapped.length < HASH_LENGTH) {
    return { text: String(wrapped), valid: false };
  }
  const receivedHash = wrapped.slice(0, HASH_LENGTH);
  const text = wrapped.slice(HASH_LENGTH);
  const valid = computeHash(user, text) === receivedHash;
  return { text, valid };
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        socket.emit("message", {
          username,
          message: wrapMessage(username, message),
        });
      }
      rl.prompt();
    });
  });
});

socket.on("message", (data) => {
  const { username: senderUsername, message: wrapped } = data;
  if (senderUsername !== username) {
    const { text, valid } = unwrapMessage(senderUsername, wrapped);
    console.log(`${senderUsername}: ${text}`);
    if (!valid) {
      console.log(
        "⚠️  WARNING: the message may have been changed during transmission"
      );
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