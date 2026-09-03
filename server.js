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

const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = process.env.MONGODB_URI;
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || "*")
  .split(",").map(x => x.trim()).filter(Boolean);

if (!MONGODB_URI) {
  console.error("❌ MONGODB_URI is missing");
  process.exit(1);
}

function corsOrigin(origin, callback) {
  if (!origin || FRONTEND_ORIGINS.includes("*") || FRONTEND_ORIGINS.includes(origin)) return callback(null, true);
  return callback(new Error("CORS origin not allowed"));
}

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(cors({ origin: corsOrigin, credentials: false, methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"] }));
app.use(express.json({ limit: "256kb" }));

// Lightweight in-memory rate limiter. On a multi-instance deployment, replace with Redis.
const rateBuckets = new Map();
function rateLimit({ windowMs, max, key = req => req.ip }) {
  return (req, res, next) => {
    const now = Date.now();
    const k = key(req);
    const old = rateBuckets.get(k);
    if (!old || now - old.start >= windowMs) rateBuckets.set(k, { start: now, count: 1 });
    else old.count++;
    const bucket = rateBuckets.get(k);
    if (bucket.count > max) return res.status(429).json({ error: "Too many requests. Please try again later." });
    res.setHeader("X-RateLimit-Limit", max);
    res.setHeader("X-RateLimit-Remaining", Math.max(0, max - bucket.count));
    next();
  };
}
setInterval(() => {
  const cutoff = Date.now() - 15 * 60 * 1000;
  for (const [k, v] of rateBuckets) if (v.start < cutoff) rateBuckets.delete(k);
}, 5 * 60 * 1000).unref();

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, lowercase: true, minlength: 3, maxlength: 24, index: true },
  password: { type: String, required: true, select: false },
  avatar: { type: String, default: "", maxlength: 500 },
  status: { type: String, enum: ["online", "offline"], default: "offline" },
  lastSeen: { type: Date, default: Date.now },
  sessionTokenHash: { type: String, default: "", select: false }
}, { timestamps: true });

const channelSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 50 },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", index: true }],
  isPrivate: { type: Boolean, default: false }
}, { timestamps: true });
channelSchema.index({ members: 1, createdAt: 1 });

const inviteSchema = new mongoose.Schema({
  channel: { type: mongoose.Schema.Types.ObjectId, ref: "Channel", required: true, index: true },
  inviter: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  invitedUser: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  status: { type: String, enum: ["pending", "accepted", "declined"], default: "pending", index: true }
}, { timestamps: true });
inviteSchema.index({ channel: 1, invitedUser: 1, status: 1 });

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  channel: { type: mongoose.Schema.Types.ObjectId, ref: "Channel", default: null, index: true },
  dmUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", index: true }],
  text: { type: String, required: true, trim: true, maxlength: 2000 }
}, { timestamps: true });
messageSchema.index({ channel: 1, createdAt: -1 });
messageSchema.index({ dmUsers: 1, createdAt: -1 });

const User = mongoose.model("User", userSchema);
const Channel = mongoose.model("Channel", channelSchema);
const ChannelInvite = mongoose.model("ChannelInvite", inviteSchema);
const Message = mongoose.model("Message", messageSchema);

const connectedUsers = new Map();
const voiceRooms = new Map();

function safeUser(user) {
  return { id: String(user._id), username: user.username, avatar: user.avatar || "", status: user.status || "offline", lastSeen: user.lastSeen || null };
}
function safeChannel(c) {
  return { id: String(c._id), _id: String(c._id), name: c.name, isPrivate: !!c.isPrivate, owner: c.owner ? safeUser(c.owner) : String(c.owner), members: Array.isArray(c.members) ? c.members.map(safeUser) : undefined };
}
function escapeRegex(text) { return String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function hashToken(token) { return crypto.createHash("sha256").update(token).digest("hex"); }
function newToken() { return crypto.randomBytes(48).toString("base64url"); }
function dmRoom(a, b) { return `dm:${[String(a), String(b)].sort().join(":")}`; }
function authTokenFrom(req) { return (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim(); }

async function authenticate(req, res, next) {
  try {
    const raw = authTokenFrom(req);
    if (!raw) return res.status(401).json({ error: "Authentication required" });
    const user = await User.findOne({ sessionTokenHash: hashToken(raw) }).select("+sessionTokenHash");
    if (!user) return res.status(401).json({ error: "Invalid or expired session" });
    req.user = user;
    next();
  } catch (e) { console.error("auth:", e); res.status(500).json({ error: "Authentication failed" }); }
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 8 && password.length <= 100;
}
function validateUsername(username) { return /^[a-z0-9_]{3,24}$/.test(username); }
function validateObjectId(id) { return mongoose.isValidObjectId(id); }

app.get("/", (req, res) => res.json({ name: "CELDEX", status: "online", version: "4.0.0" }));
app.get("/health", (req, res) => res.status(mongoose.connection.readyState === 1 ? 200 : 503).json({ ok: mongoose.connection.readyState === 1 }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!validateUsername(username)) return res.status(400).json({ error: "Username must be 3-24 characters using letters, numbers or underscore." });
    if (!validatePassword(password)) return res.status(400).json({ error: "Password must be 8-100 characters." });
    if (await User.exists({ username })) return res.status(409).json({ error: "Username already exists" });
    const hash = await bcrypt.hash(password, 12);
    const token = newToken();
    const user = await User.create({ username, password: hash, sessionTokenHash: hashToken(token), status: "online", lastSeen: new Date() });
    let general = await Channel.findOne({ name: "general" });
    if (!general) general = await Channel.create({ name: "general", owner: user._id, members: [user._id], isPrivate: false });
    else { general.members.addToSet(user._id); await general.save(); }
    res.status(201).json({ user: safeUser(user), token });
  } catch (e) {
    if (e?.code === 11000) return res.status(409).json({ error: "Username already exists" });
    console.error(e); res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!validateUsername(username) || !validatePassword(password)) return res.status(401).json({ error: "Invalid username or password" });
    const user = await User.findOne({ username }).select("+password +sessionTokenHash");
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: "Invalid username or password" });
    const token = newToken();
    user.sessionTokenHash = hashToken(token); user.status = "online"; user.lastSeen = new Date(); await user.save();
    let general = await Channel.findOne({ name: "general" });
    if (!general) general = await Channel.create({ name: "general", owner: user._id, members: [user._id], isPrivate: false });
    else if (!general.members.some(id => String(id) === String(user._id))) { general.members.addToSet(user._id); await general.save(); }
    res.json({ user: safeUser(user), token });
  } catch (e) { console.error(e); res.status(500).json({ error: "Login failed" }); }
});

app.post("/api/logout", authenticate, async (req, res) => {
  req.user.sessionTokenHash = ""; req.user.status = "offline"; req.user.lastSeen = new Date(); await req.user.save();
  res.json({ ok: true });
});
app.get("/api/me", authenticate, (req, res) => res.json(safeUser(req.user)));

app.get("/api/users/search", authenticate, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim().toLowerCase();
    if (!q || q.length > 24) return res.json([]);
    const users = await User.find({ username: { $regex: escapeRegex(q), $options: "i" }, _id: { $ne: req.user._id } }).select("_id username avatar status lastSeen").sort({ username: 1 }).limit(20);
    res.json(users.map(safeUser));
  } catch (e) { console.error(e); res.status(500).json({ error: "User search failed" }); }
});

app.put("/api/avatar", authenticate, async (req, res) => {
  const avatar = String(req.body.avatar || "").trim();
  if (avatar.length > 500 || (avatar && !/^https:\/\//i.test(avatar))) return res.status(400).json({ error: "Avatar must be an HTTPS image URL" });
  req.user.avatar = avatar; await req.user.save();
  res.json({ avatar });
});

app.post("/api/channels", authenticate, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim().replace(/^#+/, "");
    if (!name || name.length > 50) return res.status(400).json({ error: "Channel name must be 1-50 characters." });
    const channel = await Channel.create({ name, owner: req.user._id, members: [req.user._id], isPrivate: !!req.body.isPrivate });
    const populated = await Channel.findById(channel._id).populate("owner", "username avatar status lastSeen").populate("members", "username avatar status lastSeen");
    res.status(201).json(safeChannel(populated));
  } catch (e) { console.error(e); res.status(500).json({ error: "Could not create channel" }); }
});

app.get("/api/channels", authenticate, async (req, res) => {
  try {
    const channels = await Channel.find({ members: req.user._id }).populate("owner", "username avatar status lastSeen").sort({ createdAt: 1 });
    res.json(channels.map(safeChannel));
  } catch (e) { res.status(500).json({ error: "Could not load channels" }); }
});

app.get("/api/channels/:channelId", authenticate, async (req, res) => {
  if (!validateObjectId(req.params.channelId)) return res.status(400).json({ error: "Invalid channel" });
  const c = await Channel.findOne({ _id: req.params.channelId, members: req.user._id }).populate("owner", "username avatar status lastSeen").populate("members", "username avatar status lastSeen");
  if (!c) return res.status(404).json({ error: "Channel not found or you are not a member" });
  res.json(safeChannel(c));
});

app.post("/api/channels/:channelId/invite", authenticate, async (req, res) => {
  try {
    if (!validateObjectId(req.params.channelId) || !validateObjectId(req.body.userId)) return res.status(400).json({ error: "Invalid channel or user" });
    const channel = await Channel.findById(req.params.channelId);
    if (!channel) return res.status(404).json({ error: "Channel not found" });
    if (String(channel.owner) !== String(req.user._id)) return res.status(403).json({ error: "Only the channel owner can invite people" });
    const target = await User.findById(req.body.userId).select("_id username avatar status lastSeen");
    if (!target) return res.status(404).json({ error: "User not found" });
    if (String(target._id) === String(req.user._id)) return res.status(400).json({ error: "You cannot invite yourself" });
    if (channel.members.some(id => String(id) === String(target._id))) return res.status(400).json({ error: "User is already a member" });
    const existing = await ChannelInvite.findOne({ channel: channel._id, invitedUser: target._id, status: "pending" });
    if (existing) return res.status(409).json({ error: "Invite already pending" });
    const invite = await ChannelInvite.create({ channel: channel._id, inviter: req.user._id, invitedUser: target._id });
    const payload = { inviteId: String(invite._id), channelId: String(channel._id), channelName: channel.name, inviter: safeUser(req.user) };
    emitUser(target._id, "channelInvite", payload);
    res.status(201).json({ ok: true, invite: payload });
  } catch (e) { console.error(e); res.status(500).json({ error: "Could not invite user" }); }
});

app.get("/api/channel-invites", authenticate, async (req, res) => {
  const invites = await ChannelInvite.find({ invitedUser: req.user._id, status: "pending" }).populate("channel", "name isPrivate").populate("inviter", "username avatar status lastSeen").sort({ createdAt: -1 });
  res.json(invites);
});

app.post("/api/channel-invites/:inviteId/accept", authenticate, async (req, res) => {
  if (!validateObjectId(req.params.inviteId)) return res.status(400).json({ error: "Invalid invite" });
  const invite = await ChannelInvite.findOneAndUpdate({ _id: req.params.inviteId, invitedUser: req.user._id, status: "pending" }, { status: "accepted" }, { new: true });
  if (!invite) return res.status(404).json({ error: "Invite not found or already handled" });
  const channel = await Channel.findByIdAndUpdate(invite.channel, { $addToSet: { members: req.user._id } }, { new: true }).populate("owner", "username avatar status lastSeen").populate("members", "username avatar status lastSeen");
  if (!channel) return res.status(404).json({ error: "Channel no longer exists" });
  emitUser(req.user._id, "channelAdded", safeChannel(channel));
  res.json({ ok: true, channel: safeChannel(channel) });
});

app.post("/api/channel-invites/:inviteId/decline", authenticate, async (req, res) => {
  if (!validateObjectId(req.params.inviteId)) return res.status(400).json({ error: "Invalid invite" });
  const invite = await ChannelInvite.findOneAndUpdate({ _id: req.params.inviteId, invitedUser: req.user._id, status: "pending" }, { status: "declined" }, { new: true });
  if (!invite) return res.status(404).json({ error: "Invite not found or already handled" });
  res.json({ ok: true });
});

app.delete("/api/channels/:channelId/members/:userId", authenticate, async (req, res) => {
  if (!validateObjectId(req.params.channelId) || !validateObjectId(req.params.userId)) return res.status(400).json({ error: "Invalid channel or user" });
  const c = await Channel.findById(req.params.channelId);
  if (!c) return res.status(404).json({ error: "Channel not found" });
  if (String(c.owner) !== String(req.user._id)) return res.status(403).json({ error: "Only the owner can remove members" });
  if (String(c.owner) === String(req.params.userId)) return res.status(400).json({ error: "Owner cannot be removed" });
  c.members = c.members.filter(id => String(id) !== String(req.params.userId)); await c.save();
  emitUser(req.params.userId, "channelRemoved", { channelId: String(c._id) });
  res.json({ ok: true });
});

app.post("/api/channels/:channelId/leave", authenticate, async (req, res) => {
  if (!validateObjectId(req.params.channelId)) return res.status(400).json({ error: "Invalid channel" });
  const c = await Channel.findById(req.params.channelId);
  if (!c) return res.status(404).json({ error: "Channel not found" });
  if (String(c.owner) === String(req.user._id)) return res.status(400).json({ error: "Owner cannot leave their own channel" });
  c.members = c.members.filter(id => String(id) !== String(req.user._id)); await c.save();
  emitUser(req.user._id, "channelRemoved", { channelId: String(c._id) });
  res.json({ ok: true });
});

app.get("/api/channels/:channelId/messages", authenticate, async (req, res) => {
  if (!validateObjectId(req.params.channelId)) return res.status(400).json({ error: "Invalid channel" });
  const c = await Channel.findOne({ _id: req.params.channelId, members: req.user._id });
  if (!c) return res.status(403).json({ error: "You are not a member of this channel" });
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 200);
  const messages = await Message.find({ channel: c._id }).populate("sender", "username avatar status lastSeen").sort({ createdAt: -1 }).limit(limit);
  res.json(messages.reverse());
});

app.get("/api/dms", authenticate, async (req, res) => {
  const rows = await Message.find({ dmUsers: req.user._id }).sort({ createdAt: -1 }).limit(1000).select("dmUsers createdAt");
  const seen = new Set(); const ids = [];
  for (const row of rows) for (const id of row.dmUsers) if (String(id) !== String(req.user._id) && !seen.has(String(id))) { seen.add(String(id)); ids.push(id); }
  const users = await User.find({ _id: { $in: ids } }).select("_id username avatar status lastSeen");
  users.sort((a, b) => ids.findIndex(x => String(x) === String(a._id)) - ids.findIndex(x => String(x) === String(b._id)));
  res.json(users.map(safeUser));
});

app.get("/api/dms/:userId/messages", authenticate, async (req, res) => {
  if (!validateObjectId(req.params.userId)) return res.status(400).json({ error: "Invalid user" });
  const other = await User.findById(req.params.userId).select("_id username avatar status lastSeen");
  if (!other || String(other._id) === String(req.user._id)) return res.status(404).json({ error: "User not found" });
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 200);
  const messages = await Message.find({ dmUsers: { $all: [req.user._id, other._id] }, channel: null }).populate("sender", "username avatar status lastSeen").sort({ createdAt: -1 }).limit(limit);
  res.json(messages.reverse());
});

function addSocket(userId, socketId) {
  const set = connectedUsers.get(String(userId)) || new Set(); set.add(socketId); connectedUsers.set(String(userId), set);
}
function removeSocket(userId, socketId) {
  const set = connectedUsers.get(String(userId)); if (!set) return false; set.delete(socketId); if (!set.size) connectedUsers.delete(String(userId)); return !connectedUsers.has(String(userId));
}
function emitUser(userId, event, payload) {
  const set = connectedUsers.get(String(userId)) || new Set();
  for (const sid of set) io.to(sid).emit(event, payload);
}
function voiceRoomSet(room) { return voiceRooms.get(String(room)) || new Set(); }

const io = new Server(server, {
  cors: { origin: corsOrigin, credentials: false, methods: ["GET", "POST"] },
  transports: ["websocket", "polling"],
  maxHttpBufferSize: 256 * 1024
});

io.use(async (socket, next) => {
  try {
    const raw = String(socket.handshake.auth?.token || "").trim();
    if (!raw) return next(new Error("Authentication required"));
    const user = await User.findOne({ sessionTokenHash: hashToken(raw) }).select("+sessionTokenHash");
    if (!user) return next(new Error("Authentication failed"));
    socket.user = user;
    next();
  } catch { next(new Error("Authentication failed")); }
});

io.on("connection", async socket => {
  const user = socket.user;
  const uid = String(user._id);
  addSocket(uid, socket.id);
  user.status = "online"; user.lastSeen = new Date(); await user.save();
  io.emit("presence", { userId: uid, status: "online", lastSeen: user.lastSeen });

  socket.on("joinChannel", async channelId => {
    if (!validateObjectId(channelId)) return;
    const c = await Channel.findOne({ _id: channelId, members: user._id });
    if (c) socket.join(`channel:${c._id}`);
  });

  socket.on("sendMessage", async payload => {
    try {
      const channelId = String(payload?.channelId
