require("dotenv").config();

const express = require("express");
const http = require("http");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST", "PUT", "DELETE"] } });

app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"] }));
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error("❌ MONGODB_URI is missing");
  process.exit(1);
}

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, lowercase: true, minlength: 3, maxlength: 24 },
  password: { type: String, required: true },
  avatar: { type: String, default: "" },
  status: { type: String, enum: ["online", "offline"], default: "offline" },
  authToken: { type: String, default: "" }
}, { timestamps: true });

const channelSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 50 },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  isPrivate: { type: Boolean, default: false }
}, { timestamps: true });

const inviteSchema = new mongoose.Schema({
  channel: { type: mongoose.Schema.Types.ObjectId, ref: "Channel", required: true },
  inviter: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  invitedUser: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  status: { type: String, enum: ["pending", "accepted", "declined"], default: "pending" }
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  channel: { type: mongoose.Schema.Types.ObjectId, ref: "Channel", default: null },
  dmUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  text: { type: String, required: true, trim: true, maxlength: 2000 }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);
const Channel = mongoose.model("Channel", channelSchema);
const ChannelInvite = mongoose.model("ChannelInvite", inviteSchema);
const Message = mongoose.model("Message", messageSchema);

function escapeRegex(text) { return String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function safeUser(user) { return { id: String(user._id), username: user.username, avatar: user.avatar || "", status: user.status || "offline" }; }
function safeMessage(m) { return m; }
function authFrom(req) {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7) : "";
}

async function authenticate(req, res, next) {
  try {
    const token = authFrom(req);
    if (!token) return res.status(401).json({ error: "Authentication required" });
    const user = await User.findOne({ authToken: token });
    if (!user) return res.status(401).json({ error: "Invalid or expired session" });
    req.user = user;
    next();
  } catch (e) { res.status(500).json({ error: "Authentication failed" }); }
}

app.get("/", (req, res) => res.json({ name: "CELDEX", status: "online", version: "3.0.0" }));
app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: "Username must be 3-24 characters using letters, numbers or underscore." });
    if (password.length < 6 || password.length > 100) return res.status(400).json({ error: "Password must be 6-100 characters." });
    if (await User.findOne({ username })) return res.status(409).json({ error: "Username already exists" });
    const hash = await bcrypt.hash(password, 12);
    const token = crypto.randomBytes(32).toString("hex");
    const user = await User.create({ username, password: hash, authToken: token, status: "online" });
    res.status(201).json({ token, user: safeUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: "Registration failed" }); }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: "Invalid username or password" });
    const token = crypto.randomBytes(32).toString("hex");
    user.authToken = token; user.status = "online"; await user.save();
    res.json({ token, user: safeUser(user) });
  } catch (e) { res.status(500).json({ error: "Login failed" }); }
});

app.post("/api/logout", authenticate, async (req, res) => { req.user.authToken = ""; req.user.status = "offline"; await req.user.save(); res.json({ ok: true }); });
app.get("/api/me", authenticate, (req, res) => res.json(safeUser(req.user)));

app.get("/api/users/search", authenticate, async (req, res) => {
  try {
    const q = String(req.query.q || req.query.username || "").trim().toLowerCase();
    if (!q) return res.json([]);
    const users = await User.find({ username: { $regex: escapeRegex(q), $options: "i" }, _id: { $ne: req.user._id } }).select("_id username avatar status").limit(20);
    res.json(users.map(safeUser));
  } catch (e) { res.status(500).json({ error: "User search failed" }); }
});

app.put("/api/avatar", authenticate, async (req, res) => {
  const avatar = String(req.body.avatar || "").trim();
  if (avatar && !/^https?:\/\//i.test(avatar)) return res.status(400).json({ error: "Avatar must be a valid http/https URL" });
  req.user.avatar = avatar; await req.user.save(); res.json({ avatar });
});

app.post("/api/channels", authenticate, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim().replace(/^#+/, "");
    if (!name || name.length > 50) return res.status(400).json({ error: "Channel name is required and must be 1-50 characters." });
    const channel = await Channel.create({ name, owner: req.user._id, members: [req.user._id], isPrivate: Boolean(req.body.isPrivate) });
    const populated = await Channel.findById(channel._id).populate("owner", "username avatar").populate("members", "username avatar status");
    res.status(201).json(populated);
  } catch (e) { res.status(500).json({ error: "Could not create channel" }); }
});

app.get("/api/channels", authenticate, async (req, res) => {
  const channels = await Channel.find({ members: req.user._id }).populate("owner", "username avatar").sort({ createdAt: 1 });
  res.json(channels);
});

app.get("/api/channels/:channelId", authenticate, async (req, res) => {
  try {
    const c = await Channel.findOne({ _id: req.params.channelId, members: req.user._id }).populate("owner", "username avatar").populate("members", "username avatar status");
    if (!c) return res.status(404).json({ error: "Channel not found or you are not a member" });
    res.json(c);
  } catch { res.status(400).json({ error: "Invalid channel" }); }
});

app.post("/api/channels/:channelId/invite", authenticate, async (req, res) => {
  try {
    const channel = await Channel.findById(req.params.channelId);
    if (!channel) return res.status(404).json({ error: "Channel not found" });
    if (String(channel.owner) !== String(req.user._id)) return res.status(403).json({ error: "Only the channel owner can invite people" });
    const userId = String(req.body.userId || "");
    const target = await User.findById(userId);
    if (!target) return res.status(404).json({ error: "User not found" });
    if (String(target._id) === String(req.user._id)) return res.status(400).json({ error: "You cannot invite yourself" });
    if (channel.members.some(id => String(id) === String(target._id))) return res.status(400).json({ error: "User is already a member" });
    const existing = await ChannelInvite.findOne({ channel: channel._id, invitedUser: target._id, status: "pending" });
    if (existing) return res.status(409).json({ error: "Invite already pending" });
    const invite = await ChannelInvite.create({ channel: channel._id, inviter: req.user._id, invitedUser: target._id });
    const sockets = connectedUsers.get(String(target._id)) || new Set();
    const invitePayload = {
      inviteId: String(invite._id),
      channelId: String(channel._id),
      channelName: channel.name,
      inviter: safeUser(req.user)
    };
    for (const sid of sockets) io.to(sid).emit("channelInvite", invitePayload);
    res.status(201).json({ ok: true, invite: invitePayload });
  } catch (e) { console.error(e); res.status(500).json({ error: "Could not invite user" }); }
});

app.get("/api/channel-invites", authenticate, async (req, res) => {
  const invites = await ChannelInvite.find({ invitedUser: req.user._id, status: "pending" }).populate("channel", "name isPrivate").populate("inviter", "username avatar").sort({ createdAt: -1 });
  res.json(invites);
});

app.post("/api/channel-invites/:inviteId/accept", authenticate, async (req, res) => {
  const invite = await ChannelInvite.findOne({ _id: req.params.inviteId, invitedUser: req.user._id, status: "pending" });
  if (!invite) return res.status(404).json({ error: "Invite not found" });
  invite.status = "accepted"; await invite.save();
  await Channel.updateOne({ _id: invite.channel }, { $addToSet: { members: req.user._id } });
  const channel = await Channel.findById(invite.channel).populate("owner", "username avatar").populate("members", "username avatar status");
  res.json({ ok: true, channel });
});

app.post("/api/channel-invites/:inviteId/decline", authenticate, async (req, res) => {
  const invite = await ChannelInvite.findOneAndUpdate({ _id: req.params.inviteId, invitedUser: req.user._id, status: "pending" }, { status: "declined" }, { new: true });
  if (!invite) return res.status(404).json({ error: "Invite not found" });
  res.json({ ok: true });
});

app.delete("/api/channels/:channelId/members/:userId", authenticate, async (req, res) => {
  const c = await Channel.findById(req.params.channelId);
  if (!c) return res.status(404).json({ error: "Channel not found" });
  if (String(c.owner) !== String(req.user._id)) return res.status(403).json({ error: "Only the owner can remove members" });
  if (String(c.owner) === String(req.params.userId)) return res.status(400).json({ error: "Owner cannot be removed" });
  c.members = c.members.filter(id => String(id) !== String(req.params.userId)); await c.save(); res.json({ ok: true });
});

app.post("/api/channels/:channelId/leave", authenticate, async (req, res) => {
  const c = await Channel.findById(req.params.channelId);
  if (!c) return res.status(404).json({ error: "Channel not found" });
  if (String(c.owner) === String(req.user._id)) return res.status(400).json({ error: "Owner cannot leave their own channel" });
  c.members = c.members.filter(id => String(id) !== String(req.user._id)); await c.save(); res.json({ ok: true });
});

app.get("/api/channels/:channelId/messages", authenticate, async (req, res) => {
  const c = await Channel.findOne({ _id: req.params.channelId, members: req.user._id });
  if (!c) return res.status(403).json({ error: "You are not a member of this channel" });
  const messages = await Message.find({ channel: c._id }).populate("sender", "username avatar status").sort({ createdAt: 1 }).limit(200);
  res.json(messages);
});

app.get("/api/dms", authenticate, async (req, res) => {
  const ids = await Message.find({ dmUsers: req.user._id }).distinct("dmUsers");
  const others = ids.filter(id => String(id) !== String(req.user._id));
  const users = await User.find({ _id: { $in: others } }).select("_id username avatar status");
  res.json(users);
});

app.get("/api/dms/:userId/messages", authenticate, async (req, res) => {
  const other = await User.findById(req.params.userId).select("_id username avatar status");
  if (!other) return res.status(404).json({ error: "User not found" });
  const messages = await Message.find({ dmUsers: { $all: [req.user._id, other._id] }, channel: null }).populate("sender", "username avatar status").sort({ createdAt: 1 }).limit(200);
  res.json(messages);
});

const connectedUsers = new Map();
function addSocket(userId, socketId) { const set = connectedUsers.get(userId) || new Set(); set.add(socketId); connectedUsers.set(userId, set); }
function removeSocket(userId, socketId) { const set = connectedUsers.get(userId); if (!set) return; set.delete(socketId); if (!set.size) connectedUsers.delete(userId); }

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token || "";
    const user = await User.findOne({ authToken: token });
    if (!user) return next(new Error("Authentication failed"));
    socket.user = user; next();
  } catch (e) { next(new Error("Authentication failed")); }
});

io.on("connection", async socket => {
  const user = socket.user;
  addSocket(String(user._id), socket.id);
  user.status = "online"; await user.save();

  socket.on("joinChannel", async channelId => {
    const c = await Channel.findOne({ _id: channelId, members: user._id });
    if (c) socket.join(`channel:${c._id}`);
  });

  socket.on("sendMessage", async ({ channelId, text }) => {
    try {
      const clean = String(text || "").trim();
      if (!clean || clean.length > 2000) return;
      const c = await Channel.findOne({ _id: channelId, members: user._id });
      if (!c) return socket.emit("errorMessage", "You are not a member of this channel");
      const message = await Message.create({ sender: user._id, channel: c._id, text: clean });
      const populated = await Message.findById(message._id).populate("sender", "username avatar status");
      io.to(`channel:${c._id}`).emit("newMessage", populated);
    } catch (e) { socket.emit("errorMessage", "Message could not be sent"); }
  });

  socket.on("joinDM", async userId => {
    const other = await User.findById(userId).select("_id");
    if (other) socket.join(dmRoom(user._id, other._id));
  });

  socket.on("sendDM", async ({ userId, text }) => {
    try {
      const clean = String(text || "").trim();
      if (!clean || clean.length > 2000) return;
      const other = await User.findById(userId);
      if (!other || String(other._id) === String(user._id)) return socket.emit("errorMessage", "User not found");
      const message = await Message.create({ sender: user._id, dmUsers: [user._id, other._id], channel: null, text: clean });
      const populated = await Message.findById(message._id).populate("sender", "username avatar status");
      const room = dmRoom(user._id, other._id);
      socket.join(room);
      const targetSockets = connectedUsers.get(String(other._id)) || new Set();
      for (const sid of targetSockets) io.sockets.sockets.get(sid)?.join(room);
      io.to(room).emit("newDM", populated);
    } catch (e) { socket.emit("errorMessage", "Message could not be sent"); }
  });

  socket.on("voiceJoin", room => socket.join(`voice:${String(room)}`));
  socket.on("voiceLeave", room => socket.leave(`voice:${String(room)}`));
  socket.on("voiceSignal", ({ room, data }) => socket.to(`voice:${String(room)}`).emit("voiceSignal", { from: String(user._id), data }));
  socket.on("voiceOffer", ({ room, data }) => socket.to(`voice:${String(room)}`).emit("voiceOffer", { from: String(user._id), data }));
  socket.on("voiceAnswer", ({ room, data }) => socket.to(`voice:${String(room)}`).emit("voiceAnswer", { from: String(user._id), data }));
  socket.on("voiceIce", ({ room, data }) => socket.to(`voice:${String(room)}`).emit("voiceIce", { from: String(user._id), data }));

  socket.on("disconnect", async () => {
    removeSocket(String(user._id), socket.id);
    if (!connectedUsers.has(String(user._id))) { user.status = "offline"; await user.save(); }
  });
});

function dmRoom(a, b) { return `dm:${[String(a), String(b)].sort().join(":")}`; }

mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log("✅ CELDEX MongoDB connected");
    server.listen(PORT, "0.0.0.0", () => console.log(`🚀 CELDEX server running on port ${PORT}`));
  })
  .catch(err => { console.error("❌ MongoDB connection failed:", err.message); process.exit(1); });
     
