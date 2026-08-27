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


/* =========================
   CORS
========================= */

app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
}));

app.use(express.json());


/* =========================
   SOCKET.IO
========================= */

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
    .then(() => {
        console.log("✅ CELDEX MongoDB connected");
    })
    .catch(error => {
        console.error(
            "❌ MongoDB error:",
            error
        );
    });


/* =========================
   USER SCHEMA
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
        enum: ["online", "offline"],
        default: "offline"
    },

    authToken: {
        type: String,
        default: ""
    }

}, {
    timestamps: true
});


const User = mongoose.model(
    "User",
    userSchema
);


/* =========================
   CHANNEL SCHEMA
========================= */

const channelSchema = new mongoose.Schema({

    name: {
        type: String,
        required: true,
        maxlength: 50,
        trim: true
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


const Channel = mongoose.model(
    "Channel",
    channelSchema
);


/* =========================
   MESSAGE SCHEMA
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
        maxlength: 2000,
        trim: true
    }

}, {
    timestamps: true
});


const Message = mongoose.model(
    "Message",
    messageSchema
);


/* =========================
   AUTHENTICATION
========================= */

async function authenticate(
    req,
    res,
    next
) {

    try {

        const header =
            req.headers.authorization;


        if (
            !header ||
            !header.startsWith("Bearer ")
        ) {

            return res.status(401).json({
                error: "Authentication required"
            });

        }


        const token =
            header.substring(7);


        const user =
            await User.findOne({
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

        console.error(
            "Authentication error:",
            error
        );


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

app.post(
    "/api/register",
    async (req, res) => {

        try {

            let {
                username,
                password
            } = req.body;


            username =
                username?.trim();


            if (
                !username ||
                !password
            ) {

                return res.status(400).json({
                    error:
                        "Username and password are required"
                });

            }


            if (
                username.length < 3 ||
                username.length > 24
            ) {

                return res.status(400).json({
                    error:
                        "Username must be 3-24 characters"
                });

            }


            if (password.length < 6) {

                return res.status(400).json({
                    error:
                        "Password must be at least 6 characters"
                });

            }


            const normalizedUsername =
                username.toLowerCase();


            const existingUser =
                await User.findOne({
                    username:
                        normalizedUsername
                });


            if (existingUser) {

                return res.status(409).json({
                    error:
                        "Username already exists"
                });

            }


            const hashedPassword =
                await bcrypt.hash(
                    password,
                    12
                );


            const token =
                crypto
                    .randomBytes(48)
                    .toString("hex");


            const user =
                await User.create({

                    username:
                        normalizedUsername,

                    password:
                        hashedPassword,

                    authToken:
                        token,

                    status:
                        "online"

                });


            res.status(201).json({

                message:
                    "Account created",

                token,

                user: {

                    id:
                        user._id,

                    username:
                        user.username,

                    avatar:
                        user.avatar

                }

            });


        } catch (error) {

            console.error(
                "Registration error:",
                error
            );


            res.status(500).json({
                error:
                    "Registration failed"
            });

        }

    }
);


/* =========================
   LOGIN
========================= */

app.post(
    "/api/login",
    async (req, res) => {

        try {

            const {
                username,
                password
            } = req.body;


            if (
                !username ||
                !password
            ) {

                return res.status(400).json({
                    error:
                        "Username and password are required"
                });

            }


            const user =
                await User.findOne({
                    username:
                        username.toLowerCase()
                });


            if (!user) {

                return res.status(401).json({
                    error:
                        "Invalid username or password"
                });

            }


            const valid =
                await bcrypt.compare(
                    password,
                    user.password
                );


            if (!valid) {

                return res.status(401).json({
                    error:
                        "Invalid username or password"
                });

            }


            const token =
                crypto
                    .randomBytes(48)
                    .toString("hex");


            user.authToken =
                token;

            user.status =
                "online";


            await user.save();


            res.json({

                message:
                    "Login successful",

                token,

                user: {

                    id:
                        user._id,

                    username:
                        user.username,

                    avatar:
                        user.avatar

                }

            });


        } catch (error) {

            console.error(
                "Login error:",
                error
            );


            res.status(500).json({
                error:
                    "Login failed"
            });

        }

    }
);


/* =========================
   CURRENT USER
========================= */

app.get(
    "/api/me",
    authenticate,
    async (req, res) => {

        res.json({

            id:
                req.user._id,

            username:
                req.user.username,

            avatar:
                req.user.avatar,

            status:
                req.user.status

        });

    }
);


/* =========================
   UPDATE AVATAR
========================= */

app.put(
    "/api/avatar",
    authenticate,
    async (req, res) => {

        try {

            const {
                avatar
            } = req.body;


            if (
                typeof avatar !==
                "string"
            ) {

                return res.status(400).json({
                    error:
                        "Invalid avatar"
                });

            }


            req.user.avatar =
                avatar.substring(
                    0,
                    500
                );


            await req.user.save();


            res.json({

                message:
                    "Avatar updated",

                avatar:
                    req.user.avatar

            });


        } catch (error) {

            console.error(
                "Avatar error:",
                error
            );


            res.status(500).json({
                error:
                    "Could not update avatar"
            });

        }

    }
);


/* =========================
   CREATE CHANNEL
========================= */

app.post(
    "/api/channels",
    authenticate,
    async (req, res) => {

        try {

            const name =
                req.body.name?.trim();


            if (!name) {

                return res.status(400).json({
                    error:
                        "Channel name required"
                });

            }


            const channel =
                await Channel.create({

                    name,

                    owner:
                        req.user._id,

                    members: [
                        req.user._id
                    ]

                });


            res.status(201).json(
                channel
            );


        } catch (error) {

            console.error(
                "Channel creation error:",
                error
            );


            res.status(500).json({
                error:
                    "Could not create channel"
            });

        }

    }
);


/* =========================
   GET CHANNELS
========================= */

app.get(
    "/api/channels",
    authenticate,
    async (req, res) => {

        try {

            const channels =
                await Channel.find({

                    members:
                        req.user._id

                })
                .sort({
                    createdAt: 1
                });


            res.json(channels);


        } catch (error) {

            console.error(
                "Channel list error:",
                error
            );


            res.status(500).json({
                error:
                    "Could not load channels"
            });

        }

    }
);


/* =========================
   CHANNEL MESSAGES
========================= */

app.get(
    "/api/channels/:channelId/messages",
    authenticate,
    async (req, res) => {

        try {

            const channel =
                await Channel.findOne({

                    _id:
                        req.params.channelId,

                    members:
                        req.user._id

                });


            if (!channel) {

                return res.status(404).json({
                    error:
                        "Channel not found"
                });

            }


            const messages =
                await Message.find({

                    channel:
                        channel._id

                })
                .populate(
                    "sender",
                    "username avatar"
                )
                .sort({
                    createdAt: 1
                })
                .limit(100);


            res.json(messages);


        } catch (error) {

            console.error(
                "Channel messages error:",
                error
            );


            res.status(500).json({
                error:
                    "Could not load messages"
            });

        }

    }
);


/* =========================
   SEARCH USERS
========================= */

app.get(
    "/api/users/search",
    authenticate,
    async (req, res) => {

        try {

            const query =
                req.query.q?.trim();


            if (
                !query ||
                query.length < 2
            ) {

                return res.json([]);

            }


            const users =
                await User.find({

                    username: {
                        $regex:
                            query,
                        $options:
                            "i"
                    },

                    _id: {
                        $ne:
                            req.user._id
                    }

                })
                .select(
                    "username avatar status"
                )
                .limit(20);


            res.json(users);


        } catch (error) {

            console.error(
                "User search error:",
                error
            );


            res.status(500).json({
                error:
                    "Could not search users"
            });

        }

    }
);


/* =========================
   GET DM CONVERSATIONS
========================= */

app.get(
    "/api/dms",
    authenticate,
    async (req, res) => {

        try {

            const messages =
                await Message.find({

                    channel:
                        null,

                    dmUsers:
                        req.user._id

                })
                .populate(
                    "sender",
                    "username avatar status"
                )
                .populate(
                    "dmUsers",
                    "username avatar status"
                )
                .sort({
                    createdAt: -1
                })
                .limit(500);


            const conversations =
                new Map();


            for (
                const message of messages
            ) {

                const otherUser =
                    message.dmUsers.find(
                        person =>
                            String(
                                person._id
                            ) !==
                            String(
                                req.user._id
                            )
                    );


                if (!otherUser)
                    continue;


                const id =
                    String(
                        otherUser._id
                    );


                if (
                    !conversations.has(id)
                ) {

                    conversations.set(
                        id,
                        {

                            user:
                                otherUser,

                            lastMessage: {

                                text:
                                    message.text,

                                createdAt:
                                    message.createdAt

                            }

                        }
                    );

                }

            }


            res.json(
                Array.from(
                    conversations.values()
                )
            );


        } catch (error) {

            console.error(
                "DM list error:",
                error
            );


            res.status(500).json({
                error:
                    "Could not load conversations"
            });

        }

    }
);


/* =========================
   GET DM MESSAGES
========================= */

app.get(
    "/api/dms/:userId/messages",
    authenticate,
    async (req, res) => {

        try {

            const otherUser =
                await User.findById(
                    req.params.userId
                );


            if (!otherUser) {

                return res.status(404).json({
                    error:
                        "User not found"
                });

            }


            if (
                String(otherUser._id) ===
                String(req.user._id)
            ) {

                return res.status(400).json({
                    error:
                        "You cannot DM yourself"
                });

            }


            const messages =
                await Message.find({

                    channel:
                        null,

                    dmUsers: {
                        $all: [

                            req.user._id,

                            otherUser._id

                        ]

                    }

                })
                .populate(
                    "sender",
                    "username avatar"
                )
                .sort({
                    createdAt: 1
                })
                .limit(100);


            res.json(messages);


        } catch (error) {

            console.error(
                "DM messages error:",
                error
            );


            res.status(500).json({
                error:
                    "Could not load DM messages"
            });

        }

    }
);


/* =========================
   SOCKET AUTH
========================= */

io.use(
    async (socket, next) => {

        try {

            const token =
                socket.handshake
                    .auth
                    ?.token;


            if (!token) {

                return next(
                    new Error(
                        "Authentication required"
                    )
                );

            }


            const user =
                await User.findOne({
                    authToken:
                        token
                });


            if (!user) {

                return next(
                    new Error(
                        "Invalid authentication"
                    )
                );

            }


            socket.user =
                user;


            next();


        } catch (error) {

            next(error);

        }

    }
);


/* =========================
   SOCKET CONNECTION
========================= */

io.on(
    "connection",
    async socket => {

        const user =
            socket.user;


        console.log(
            `🟢 ${user.username} connected`
        );


        user.status =
            "online";


        await user.save();


        /* =========================
           CHANNEL JOIN
    
