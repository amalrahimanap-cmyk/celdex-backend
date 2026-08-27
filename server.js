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

app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"]
}));

app.use(express.json());

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

/* =========================
   DATABASE
========================= */

mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log("✅ CELDEX MongoDB connected"))
    .catch(err => console.error("❌ MongoDB error:", err));


/* =========================
   USER
========================= */

const userSchema = new mongoose.Schema({

    username: {
        type: String,
        required: true,
        unique: true,
        minlength: 3,
        maxlength: 24,
        trim: true
    },

    password: {
        type: String,
        required: true
    },

    avatar: {
        type: String,
        default: ""
    },

    status: {
        type: String,
        default: "offline"
    },

    authToken: {
        type: String,
        default: ""
    }

}, {
    timestamps: true
});

const User = mongoose.model("User", userSchema);


/* =========================
   CHANNEL
========================= */

const channelSchema = new mongoose.Schema({

    name: {
        type: String,
        required: true,
        maxlength: 50
    },

    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },

    members: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    }]

}, {
    timestamps: true
});

const Channel = mongoose.model("Channel", channelSchema);


/* =========================
   MESSAGE
========================= */

const messageSchema = new mongoose.Schema({

    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },

    channel: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Channel",
        default: null
    },

    dmUsers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    }],

    text: {
        type: String,
        required: true,
        maxlength: 2000
    }

}, {
    timestamps: true
});

const Message = mongoose.model("Message", messageSchema);


/* =========================
   AUTH MIDDLEWARE
========================= */

async function authenticate(req, res, next) {

    try {

        const header = req.headers.authorization;

        if (!header || !header.startsWith("Bearer ")) {
            return res.status(401).json({
                error: "Authentication required"
            });
        }

        const token = header.substring(7);

        const user = await User.findOne({
            authToken: token
        });

        if (!user) {
            return res.status(401).json({
                error: "Invalid login session"
            });
        }

        req.user = user;

        next();

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Authentication error"
        });
    }
}


/* =========================
   TEST
========================= */

app.get("/", (req, res) => {

    res.json({
        name: "CELDEX",
        status: "online",
        version: "1.0.0"
    });

});


/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {

    try {

        let { username, password } = req.body;

        username = username?.trim();

        if (!username || !password) {
            return res.status(400).json({
                error: "Username and password are required"
            });
        }

        if (username.length < 3 || username.length > 24) {
            return res.status(400).json({
                error: "Username must be 3-24 characters"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                error: "Password must be at least 6 characters"
            });
        }

        const existingUser = await User.findOne({
            username: username.toLowerCase()
        });

        if (existingUser) {
            return res.status(409).json({
                error: "Username already exists"
            });
        }

        const hashedPassword =
            await bcrypt.hash(password, 12);

        const token =
            crypto.randomBytes(48).toString("hex");

        const user = await User.create({

            username: username.toLowerCase(),

            password: hashedPassword,

            authToken: token,

            status: "online"

        });

        res.status(201).json({

            message: "Account created",

            token,

            user: {
                id: user._id,
                username: user.username,
                avatar: user.avatar
            }

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Registration failed"
        });
    }

});


/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {

    try {

        const { username, password } = req.body;

        const user = await User.findOne({
            username: username?.toLowerCase()
        });

        if (!user) {
            return res.status(401).json({
                error: "Invalid username or password"
            });
        }

        const valid =
            await bcrypt.compare(password, user.password);

        if (!valid) {
            return res.status(401).json({
                error: "Invalid username or password"
            });
        }

        const token =
            crypto.randomBytes(48).toString("hex");

        user.authToken = token;
        user.status = "online";

        await user.save();

        res.json({

            message: "Login successful",

            token,

            user: {
                id: user._id,
                username: user.username,
                avatar: user.avatar
            }

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Login failed"
        });
    }

});


/* =========================
   CURRENT USER
========================= */

app.get("/api/me", authenticate, async (req, res) => {

    res.json({

        id: req.user._id,
        username: req.user.username,
        avatar: req.user.avatar,
        status: req.user.status

    });

});


/* =========================
   UPDATE AVATAR
========================= */

app.put("/api/avatar", authenticate, async (req, res) => {

    try {

        const { avatar } = req.body;

        if (typeof avatar !== "string") {
            return res.status(400).json({
                error: "Invalid avatar"
            });
        }

        req.user.avatar = avatar.substring(0, 500);

        await req.user.save();

        res.json({
            message: "Avatar updated",
            avatar: req.user.avatar
        });

    } catch {

        res.status(500).json({
            error: "Could not update avatar"
        });

    }

});


/* =========================
   CREATE CHANNEL
========================= */

app.post("/api/channels", authenticate, async (req, res) => {

    try {

        const name = req.body.name?.trim();

        if (!name) {
            return res.status(400).json({
                error: "Channel name required"
            });
        }

        const channel = await Channel.create({

            name,

            owner: req.user._id,

            members: [req.user._id]

        });

        res.status(201).json(channel);

    } catch {

        res.status(500).json({
            error: "Could not create channel"
        });

    }

});


/* =========================
   GET CHANNELS
========================= */

app.get("/api/channels", authenticate, async (req, res) => {

    const channels = await Channel.find({
        members: req.user._id
    }).sort({
        createdAt: 1
    });

    res.json(channels);

});


/* =========================
   CHANNEL MESSAGES
========================= */

app.get(
    "/api/channels/:channelId/messages",
    authenticate,
    async (req, res) => {

        const messages = await Message.find({
            channel: req.params.channelId
        })
        .populate("sender", "username avatar")
        .sort({
            createdAt: 1
        })
        .limit(100);

        res.json(messages);

    }
);


/* =========================
   SOCKET AUTH
========================= */

io.use(async (socket, next) => {

    try {

        const token = socket.handshake.auth?.token;

        if (!token) {
            return next(
                new Error("Authentication required")
            );
        }

        const user = await User.findOne({
            authToken: token
        });

        if (!user) {
            return next(
                new Error("Invalid authentication")
            );
        }

        socket.user = user;

        next();

    } catch (error) {

        next(error);

    }

});


/* =========================
   REAL-TIME CHAT
========================= */

io.on("connection", async (socket) => {

    const user = socket.user;

    console.log(
        `🟢 ${user.username} connected`
    );

    user.status = "online";
    await user.save();

    socket.on("joinChannel", async (channelId) => {

        const channel = await Channel.findOne({
            _id: channelId,
            members: user._id
        });

        if (!channel) return;

        socket.join(`channel:${channelId}`);

    });


    socket.on("sendMessage", async (data) => {

        try {

            const { channelId, text } = data;

            if (!channelId || !text) return;

            const channel = await Channel.findOne({
                _id: channelId,
                members: user._id
            });

            if (!channel) return;

            const message = await Message.create({

                sender: user._id,

                channel: channel._id,

                text: String(text).substring(0, 2000)

            });

            const fullMessage =
                await Message.findById(message._id)
                    .populate("sender", "username avatar");

            io.to(`channel:${channelId}`)
                .emit(
                    "newMessage",
                    fullMessage
                );

        } catch (error) {

            console.error(
                "Message error:",
                error
            );

        }

    });


    /* =========================
       AUDIO VOICE SIGNALING
    ========================= */

    socket.on("voiceJoin", (roomId) => {

        socket.join(`voice:${roomId}`);

        socket.to(`voice:${roomId}`)
            .emit("voiceUserJoined", {
                userId: user._id.toString(),
                username: user.username
            });

    });


    socket.on("voiceSignal", (data) => {

        socket.to(`voice:${data.roomId}`)
            .emit("voiceSignal", {
                from: socket.id,
                signal: data.signal
            });

    });


    socket.on("voiceLeave", (roomId) => {

        socket.leave(`voice:${roomId}`);

        socket.to(`voice:${roomId}`)
            .emit("voiceUserLeft", {
                userId: user._id.toString()
            });

    });


    socket.on("disconnect", async () => {

        console.log(
            `🔴 ${user.username} disconnected`
        );

        user.status = "offline";

        await user.save();

    });

});


/* =========================
   SERVER
========================= */

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {

    console.log(
        `🚀 CELDEX server running on port ${PORT}`
    );

}); 
