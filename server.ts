import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";
import multer from "multer";
import dotenv from "dotenv";
import { TelegramClient, Api } from "telegram";
import { StringSession } from "telegram/sessions/index.js";
import { Telegraf, Markup } from "telegraf";
import fs from "fs";
import crypto from "crypto";
import mongoose from "mongoose";
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const archiver = require("archiver");
import stream from "stream";

const generateShareId = () => crypto.randomBytes(3).toString('hex');

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// MongoDB Connection
const mongoUri = process.env.MONGODB_URI || "";
if (mongoUri) {
  mongoose.connect(mongoUri, { dbName: "TG-Drive" })
    .then(() => console.log("MongoDB connected successfully to TG-Drive database"))
    .catch(err => console.error("MongoDB connection error:", err));
}

const FileMetadataSchema = new mongoose.Schema({
  messageId: { type: Number, required: true },
  shareId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  size: { type: Number, required: true },
  date: { type: Number, required: true },
  mimeType: { type: String, required: true },
  folder: { type: String, default: "" },
  caption: { type: String, default: "" },
});

FileMetadataSchema.index({ folder: 1 });
FileMetadataSchema.index({ messageId: 1 });
FileMetadataSchema.index({ shareId: 1 });
FileMetadataSchema.index({ name: 'text' }); // Extra: text index for search if needed, but the user wants escaping for regex anyway

const FileMetadata = mongoose.model("FileMetadata", FileMetadataSchema, "Files");

const FolderSchema = new mongoose.Schema({
  name: { type: String, required: true },
  path: { type: String, default: "" }, // Full path including name
  threadId: { type: Number },
  createdAt: { type: Number, default: () => Math.floor(Date.now() / 1000) },
});

const FolderMetadata = mongoose.model("FolderMetadata", FolderSchema, "Folders");

const BotAuthSchema = new mongoose.Schema({
  chatId: { type: Number, required: true, unique: true },
  username: { type: String },
  authorizedAt: { type: Number, default: () => Math.floor(Date.now() / 1000) },
});

const BotAuth = mongoose.model("BotAuth", BotAuthSchema, "Users");

const BotSessionSchema = new mongoose.Schema({
  chatId: { type: Number, required: true, unique: true },
  data: { type: mongoose.Schema.Types.Mixed, required: true },
  updatedAt: { type: Date, default: Date.now, expires: '1h' } // Auto-cleanup after 1 hour
});

const BotSession = mongoose.model("BotSession", BotSessionSchema, "Sessions");

const BotConfigSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  value: { type: String, required: true },
});

const BotConfig = mongoose.model("BotConfig", BotConfigSchema, "Config");

// Ensure uploads directory exists
const uploadDir = path.resolve(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
} else {
  // Cleanup temp files on startup
  try {
    const files = fs.readdirSync(uploadDir);
    for (const file of files) {
      fs.unlinkSync(path.join(uploadDir, file));
    }
    console.log("Cleaned up uploads directory");
  } catch (err) {
    console.warn("Failed to cleanup uploads directory:", err);
  }
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Auth Middleware
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "password";
// Fix: Don't use raw base64 of credentials as a token if we can avoid it.
// We'll generate a server-side session-like token instead.
const AUTH_SECRET = process.env.AUTH_SECRET || crypto.randomBytes(32).toString('hex');
const AUTH_TOKEN = crypto.createHmac('sha256', AUTH_SECRET)
  .update(`${ADMIN_USERNAME}:${ADMIN_PASSWORD}`)
  .digest('hex');

const requireAuth = (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  // Support both Basic and simple token for flexibility during transition
  if (authHeader === `Basic ${AUTH_TOKEN}` || authHeader === AUTH_TOKEN) {
    return next();
  }
  res.status(401).json({ error: "Unauthorized" });
};

// Login Route
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    res.json({ success: true, token: AUTH_TOKEN });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

// Multer for file uploads - with size limit (2GB)
const upload = multer({ 
  dest: "uploads/",
  limits: { fileSize: 2 * 1024 * 1024 * 1024 } // 2GB limit
});

// Telegram Config
const apiId = Number(process.env.TELEGRAM_API_ID || 0);
const apiHash = process.env.TELEGRAM_API_HASH || "";
const botToken = process.env.TELEGRAM_BOT_TOKEN || "";
const channelId = process.env.TELEGRAM_CHANNEL_ID || "";

const getGramJsPeer = (id: string): any => {
  if (!id || id === "me") return "me";
  const cleanId = id.trim();
  if (/^-?\d+$/.test(cleanId)) {
    try {
      return BigInt(cleanId);
    } catch {
      return cleanId;
    }
  }
  return cleanId;
};

const resolvePeer = async (telegram: TelegramClient, id: string): Promise<any> => {
  if (!id || id === "me") return "me";
  const cleanId = id.trim();
  
  // 1. Try to resolve by direct string (handles usernames and cached IDs)
  try {
    return await telegram.getEntity(cleanId);
  } catch (err) {
    // 2. Try to resolve as BigInt (common for numeric IDs)
    if (/^-?\d+$/.test(cleanId)) {
      try {
        return await telegram.getEntity(cleanId); // String works for getEntity too
      } catch (err2) {
        // 3. Fallback to constructing a peer object if we know the type from the ID prefix
        if (cleanId.startsWith("-100")) {
          // It's a channel/supergroup
          return new Api.InputPeerChannel({
            channelId: BigInt(cleanId.substring(4)) as any,
            accessHash: BigInt(0) as any // accessHash 0 is a placeholder, might fail if not cached
          });
        }
        if (cleanId.startsWith("-")) {
          // it's a regular chat
          return new Api.InputPeerChat({
             chatId: BigInt(cleanId.substring(1)) as any
          });
        }
        // It's likely a user
        return BigInt(cleanId) as any;
      }
    }
    console.warn(`Entity resolution failed for ${id}, using fallback peer string`, err);
    return cleanId;
  }
};

let client: TelegramClient | null = null;
let bot: Telegraf | null = null;

async function getTelegramClient() {
  if (client) return client;
  
  if (!apiId || !apiHash) {
    return null;
  }

  // Persist session in MongoDB per bot token to avoid conflicts
  let sessionString = "";
  const sessionKey = `gramjs_session_${crypto.createHash('md5').update(botToken).digest('hex')}`;
  
  if (mongoUri && mongoose.connection.readyState === 1) {
    try {
      const config = await BotConfig.findOne({ key: sessionKey });
      if (config) sessionString = config.value;
    } catch (e) {
      console.warn("Failed to load session from DB", e);
    }
  }

  const session = new StringSession(sessionString); 
  client = new TelegramClient(session, apiId, apiHash, {
    connectionRetries: 5,
  });

  try {
    await client.start({
      botAuthToken: botToken,
    });
    console.log("Telegram Client connected as Bot");
    
    // Save session back to DB if it changed
    const newSession = client.session.save() as any;
    if (mongoUri && mongoose.connection.readyState === 1 && newSession !== sessionString) {
      try {
        await BotConfig.findOneAndUpdate(
          { key: sessionKey },
          { value: newSession },
          { upsert: true }
        );
      } catch (e) {
        console.warn("Failed to save session to DB", e);
      }
    }
    
    // Resolve channel entity once and cache it internally in GramJS
    if (channelId) {
      try {
        await resolvePeer(client, channelId);
      } catch (err) {
        // Ignore error here, we'll try again during upload
      }
    }
  } catch (err) {
    console.error("Failed to start Telegram Client:", err);
    client = null;
    return null;
  }

  return client;
}

// API Routes
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", telegram: !!client });
});

app.get("/api/config", (req, res) => {
  res.json({
    hasApiId: !!apiId,
    hasApiHash: !!apiHash,
    hasBotToken: !!botToken,
    hasChannelId: !!channelId,
    hasMongo: !!mongoUri && mongoose.connection.readyState === 1,
  });
});

app.post("/api/upload", requireAuth, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    const folder = req.body.folder || "";
    
    let threadId: number | undefined = undefined;
    if (folder && bot && channelId) {
      try {
        let folderMeta = await FolderMetadata.findOne({ path: folder });
        if (folderMeta && folderMeta.threadId) {
          threadId = folderMeta.threadId;
        } else {
          console.log(`[BotAPI] Attempting to create Forum Topic for folder: ${folder}`);
          const topic = await bot.telegram.createForumTopic(channelId, folder);
          threadId = topic.message_thread_id;
          if (!folderMeta) {
            await FolderMetadata.create({ name: folder, path: folder, threadId });
          } else {
            folderMeta.threadId = threadId;
            await folderMeta.save();
          }
        }
      } catch (err: any) {
        console.warn("[BotAPI] Failed to create topic (is group a forum?):", err.message);
      }
    }

    const filePath = req.file.path;
    const caption = folder ? `F[${folder}] | ${req.file.originalname}` : req.file.originalname;
    
    let result: any = null;

    // Reliability Fallback: If file is < 50MB, use Telegraf (Bot API) first
    // Telegraf is more reliable with various ID formats and doesn't require MTProto session cache
    if (req.file.size < 50 * 1024 * 1024 && bot && channelId) {
      try {
        console.log(`[BotAPI] Uploading ${req.file.originalname} via Telegraf...`);
        const telegrafRes = await bot.telegram.sendDocument(channelId, { source: filePath }, { caption, message_thread_id: threadId });
        result = { id: (telegrafRes as any).message_id };
        console.log(`[BotAPI] Upload successful: ${result.id}`);
      } catch (err: any) {
        console.warn("[BotAPI] Telegraf upload failed, falling back to GramJS:", err.message);
      }
    }

    // If Telegraf was skipped or failed, use GramJS (MTProto)
    if (!result) {
      const telegram = await getTelegramClient();
      if (!telegram) {
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        return res.status(412).json({ 
          error: "Telegram not configured", 
          details: "Please set TELEGRAM_API_ID and TELEGRAM_API_HASH in the Secrets panel." 
        });
      }

      console.log(`[MTProto] Uploading ${req.file.originalname} via GramJS...`);
      const peerEntity = await resolvePeer(telegram, channelId);
      
      const gramjsRes = await telegram.sendFile(peerEntity, {
        file: filePath,
        caption: caption,
        forceDocument: true,
        replyTo: threadId,
        progressCallback: (progress) => {
          const percent = Math.round(progress * 100);
          if (percent % 25 === 0) { 
            console.log(`[MTProto] Uploading ${req.file?.originalname}: ${percent}%`);
          }
        }
      });
      result = { id: gramjsRes.id };
      console.log(`[MTProto] Upload successful: ${result.id}`);
    }

    // Cleanup local file
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    // Save metadata to MongoDB
    if (mongoUri) {
      await FileMetadata.create({
        messageId: result.id,
        shareId: generateShareId(),
        name: req.file.originalname,
        size: req.file.size,
        date: Math.floor(Date.now() / 1000),
        mimeType: req.file.mimetype,
        folder: folder,
        caption: caption,
      });
    }

    res.json({ success: true, messageId: result.id });
  } catch (error: any) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    console.error("Upload error:", error);
    
    let errorMsg = error.message;
    if (errorMsg.includes("CHANNEL_INVALID") || errorMsg.includes("PEER_ID_INVALID")) {
      errorMsg = "Telegram error: CHANNEL_INVALID. Please ensure the Bot is an Admin in the channel and try using the @username instead of the numeric ID in Secretpanel.";
    }
    
    res.status(500).json({ error: errorMsg });
  }
});

app.patch("/api/files/:id", requireAuth, async (req, res) => {
  try {
    const { folder, name } = req.body;
    const messageId = parseInt(req.params.id);

    if (mongoUri) {
      const updateData: any = {};
      if (folder !== undefined) updateData.folder = folder;
      if (name !== undefined) updateData.name = name;
      await FileMetadata.findOneAndUpdate({ messageId }, updateData);
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error("Update file error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/files/bulk-delete", requireAuth, async (req, res) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: "Invalid ids array" });
    }

    if (!channelId || channelId === "me") {
      return res.status(412).json({ error: "TELEGRAM_CHANNEL_ID is required for storage." });
    }

    const errors = [];
    const telegram = await getTelegramClient();
    
    // GramJS can delete array of ids
    try {
      if (telegram) {
        const peerEntity = await resolvePeer(telegram, channelId);
        await telegram.deleteMessages(peerEntity, ids, { revoke: true });
      } else {
        // Fallback to iterating bot method
        if (!bot) throw new Error("Telegram not configured");
        for (const id of ids) {
          try {
             await bot.telegram.deleteMessage(channelId, id);
          } catch(e) {
             console.error("Failed to delete via bot", e);
          }
        }
      }
    } catch(e) {
       console.error("Failed bulk delete", e);
    }

    // Delete from MongoDB
    if (mongoUri) {
      await FileMetadata.deleteMany({ messageId: { $in: ids } });
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error("Bulk delete error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/files", requireAuth, async (req, res) => {
  try {
    const { q, sort, folder } = req.query;
    // If MongoDB is connected, prefer it for faster listing and search
    const isMongoConnected = mongoUri && mongoose.connection.readyState === 1;
    
    if (isMongoConnected) {
      let query: any = {};
      
      if (q) {
        const safeQ = (q as string).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        query.name = new RegExp(safeQ, 'i');
      }
      
      if (folder !== undefined) {
        query.folder = folder;
      }

      const type = req.query.type;
      if (type === 'media') {
        query.mimeType = new RegExp('^(image/|video/)', 'i');
      } else if (type === 'photo') {
        query.mimeType = new RegExp('^image/', 'i');
      } else if (type === 'video') {
        query.mimeType = new RegExp('^video/', 'i');
      } else if (type === 'doc') {
        query.mimeType = new RegExp('^(application/|text/|message/)', 'i');
      } else if (type === 'audio') {
        query.mimeType = new RegExp('^audio/', 'i');
      }

      let sortOptions: any = { date: -1 };
      if (sort === 'name') sortOptions = { name: 1 };
      if (sort === 'size') sortOptions = { size: -1 };
      if (sort === 'date_asc') sortOptions = { date: 1 };

      const files = await FileMetadata.find(query).sort(sortOptions).limit(200);
      
      // Lazy migration for files missing shareId
      const mappedFiles = [];
      for (const f of files) {
        if (!f.shareId) {
          f.shareId = generateShareId();
          await f.save();
        }
        mappedFiles.push({
          id: f.messageId,
          shareId: f.shareId,
          name: f.name,
          size: f.size,
          date: f.date,
          mimeType: f.mimeType,
          folder: f.folder,
          caption: f.caption
        });
      }
      return res.json(mappedFiles);
    }

    const telegram = await getTelegramClient();
    if (!telegram) {
      return res.json([]); 
    }

    if (!channelId || channelId === "me") {
      return res.status(412).json({ error: "TELEGRAM_CHANNEL_ID is required to list files." });
    }

    // FALLBACK: If No Mongo, bots CANNOT use getHistory/getMessages(limit)
    // We return an error explaining that MongoDB is required for bots to list files.
    res.status(403).json({ 
      error: "Bot Restricted: MongoDB Required", 
      details: "Telegram Bots cannot read channel history directly. Please connect MongoDB Atlas in the Secrets panel to enable file listing and search."
    });

  } catch (error: any) {
    console.error("List files error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/folders", requireAuth, async (req, res) => {
  try {
    if (mongoUri && mongoose.connection.readyState === 1) {
      const folders = await FolderMetadata.find().sort({ name: 1 });
      return res.json(folders.map(f => f.path));
    }
    res.json([]);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/folders", requireAuth, async (req, res) => {
  try {
    const { path: folderPath } = req.body;
    if (!folderPath) return res.status(400).json({ error: "Path is required" });
    
    if (mongoUri && mongoose.connection.readyState === 1) {
      const existing = await FolderMetadata.findOne({ path: folderPath });
      if (!existing) {
        await FolderMetadata.create({ name: folderPath.split("/").pop(), path: folderPath });
      }
    }
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.patch("/api/folders", requireAuth, async (req, res) => {
  try {
    const { oldPath, newPath } = req.body;
    if (!oldPath || !newPath) return res.status(400).json({ error: "oldPath and newPath required" });

    if (mongoUri && mongoose.connection.readyState === 1) {
      const folder = await FolderMetadata.findOne({ path: oldPath });
      if (folder) {
        folder.name = newPath.split("/").pop();
        folder.path = newPath;
        await folder.save();
      }

      await FileMetadata.updateMany(
        { folder: oldPath },
        { folder: newPath }
      );

      // Handle subfolders and subfiles via regex
      const escapedOldPath = oldPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const filesInSub = await FileMetadata.find({ folder: new RegExp(`^${escapedOldPath}/`) });
      for (const f of filesInSub) {
        f.folder = f.folder.replace(new RegExp(`^${escapedOldPath}/`), `${newPath}/`);
        await f.save();
      }

      const subfolders = await FolderMetadata.find({ path: new RegExp(`^${escapedOldPath}/`) });
      for (const sf of subfolders) {
        sf.path = sf.path.replace(new RegExp(`^${escapedOldPath}/`), `${newPath}/`);
        sf.name = sf.path.split("/").pop();
        await sf.save();
      }
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error("Rename folder error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/files/bulk-download", requireAuth, async (req, res) => {
  try {
    const telegram = await getTelegramClient();
    if (!telegram) return res.status(412).json({ error: "Telegram not configured" });

    const idsRaw = req.query.ids;
    if (!idsRaw || typeof idsRaw !== 'string') return res.status(400).send("No ids provided");
    
    const messageIds = idsRaw.split(",").map(id => parseInt(id)).filter(id => !isNaN(id));
    if (messageIds.length === 0) return res.status(400).send("Invalid ids");

    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="bulk_download_${Date.now()}.zip"`);

    const archive = archiver('zip', { zlib: { level: 5 } });
    archive.on('error', (err: any) => { throw err; });
    archive.pipe(res);

    // Process sequentially or chunks
    // GramJS can getMessages array of ids up to 100
    const peerEntity = await resolvePeer(telegram, channelId);
    for(let i = 0; i < messageIds.length; i += 100) {
        const chunk = messageIds.slice(i, i + 100);
        const messages = await telegram.getMessages(peerEntity, { ids: chunk });
        for (const message of messages) {
            if (message && message.media) {
                const media: any = message.media;
                 // Need file name
                let fileName = `file_${message.id}`;
                if (mongoUri) {
                   const f = await FileMetadata.findOne({ messageId: message.id });
                   if (f) fileName = f.name;
                   else {
                      fileName = media.document?.attributes?.find((a: any) => a.fileName)?.fileName || fileName;
                   }
                } else {
                   fileName = media.document?.attributes?.find((a: any) => a.fileName)?.fileName || fileName;
                }
                
                // Use the telegram client instance directly
                const iter = telegram.iterDownload({ 
                    file: message.media,
                    requestSize: 1024 * 1024
                });
                
                const pass = new stream.PassThrough();
                
                // Add to archive
                archive.append(pass, { name: fileName });
                
                // Download and pipe
                (async () => {
                   for await (const chunk of iter) {
                      pass.write(chunk);
                   }
                   pass.end();
                })().catch(e => {
                  console.error("Bulk download individual error:", e);
                  pass.end();
                });
            }
        }
    }
    
    archive.finalize();

  } catch (error: any) {
    if (!res.headersSent) {
      res.status(500).send(error.message);
    }
  }
});

app.delete("/api/files/:id", requireAuth, async (req, res) => {
  try {
    if (!channelId || channelId === "me") {
      return res.status(412).json({ error: "TELEGRAM_CHANNEL_ID is required for storage." });
    }

    const messageId = parseInt(req.params.id);
    try {
      if (bot) await bot.telegram.deleteMessage(channelId, messageId);
      else throw new Error("Telegraf bot not ready");
    } catch (e) {
      // Fallback to GramJS
      const telegram = await getTelegramClient();
      if (!telegram) return res.status(412).json({ error: "Telegram not configured" });
      const peerEntity = await resolvePeer(telegram, channelId);
      await telegram.deleteMessages(peerEntity, [messageId], { revoke: true });
    }

    // Delete from MongoDB
    if (mongoUri) {
      await FileMetadata.deleteOne({ messageId });
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error("Delete error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/download/:id", async (req, res) => {
  try {
    const telegram = await getTelegramClient();
    if (!telegram) return res.status(412).json({ error: "Telegram not configured" });

    if (!channelId || channelId === "me") {
      return res.status(412).json({ error: "TELEGRAM_CHANNEL_ID is required for storage." });
    }

    const { id } = req.params;
    let file = null;

    // 1. Try finding by shareId (public access)
    file = await FileMetadata.findOne({ shareId: id });

    // 2. If not found by shareId, or if it's a numeric ID, check auth and try messageId
    if (!file) {
      if (!/^\d+$/.test(id)) {
        return res.status(404).send("File not found");
      }
      
      // Require auth for internal message ID access
      const authHeader = req.headers.authorization;
      if (authHeader !== `Basic ${AUTH_TOKEN}` && authHeader !== AUTH_TOKEN) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      
      file = await FileMetadata.findOne({ messageId: parseInt(id) });
    }

    if (!file) return res.status(404).send("File not found");

    const messageId = file.messageId;
    const fileName = file.name;
    const mimeType = file.mimeType;

    const peerEntity = await resolvePeer(telegram, channelId);
    const messages = await telegram.getMessages(peerEntity, { ids: [messageId] });

    if (!messages || !messages[0] || !messages[0].media) {
      return res.status(404).send("File not found in Telegram storage");
    }

    const message = messages[0];
    const media: any = message.media;
    const size = media.document?.size || media.photo?.sizes?.pop()?.size || 0;

    res.setHeader("Content-Type", mimeType);
    res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(fileName)}"`);
    res.setHeader("Content-Length", size);

    // Stream download
    for await (const chunk of telegram.iterDownload({
      file: media,
      requestSize: 1024 * 1024, // 1MB chunks
    })) {
      res.write(chunk);
    }
    res.end();
  } catch (error: any) {
    console.error("Download error:", error);
    if (!res.headersSent) res.status(500).send(error.message);
  }
});

app.get("/api/stream/:id", async (req, res) => {
  try {
    const telegram = await getTelegramClient();
    if (!telegram) return res.status(412).json({ error: "Telegram not configured" });

    const { id } = req.params;
    let file = null;

    // 1. Try finding by shareId (public access)
    file = await FileMetadata.findOne({ shareId: id });

    // 2. If not found by shareId, or if it's a numeric ID, check auth and try messageId
    if (!file) {
      if (!/^\d+$/.test(id)) {
        return res.status(404).send("File not found");
      }
      
      // Require auth for internal message ID access
      const authHeader = req.headers.authorization;
      if (authHeader !== `Basic ${AUTH_TOKEN}` && authHeader !== AUTH_TOKEN) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      
      file = await FileMetadata.findOne({ messageId: parseInt(id) });
    }

    if (!file) return res.status(404).send("File not found");

    const messageId = file.messageId;
    const peerEntity = await resolvePeer(telegram, channelId);

    const messages = await telegram.getMessages(peerEntity, { ids: [messageId] });
    if (!messages || !messages[0] || !messages[0].media) return res.status(404).send("Not Found");

    const message = messages[0];
    const media: any = message.media;
    const totalSize = media.document?.size || media.photo?.sizes?.pop()?.size || 0;
    const mimeType = media.document?.mimeType || "image/jpeg";

    const range = req.headers.range;
    if (range) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : totalSize - 1;
      const chunksize = (end - start) + 1;

      res.writeHead(206, {
        "Content-Range": `bytes ${start}-${end}/${totalSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": chunksize,
        "Content-Type": mimeType,
      });

      for await (const chunk of telegram.iterDownload({
        file: media,
        offset: start as any,
        limit: chunksize as any,
        requestSize: 1024 * 1024,
      })) {
        res.write(chunk);
      }
      res.end();
    } else {
      res.writeHead(200, {
        "Content-Length": totalSize,
        "Content-Type": mimeType,
      });
      for await (const chunk of telegram.iterDownload({
        file: media,
        requestSize: 1024 * 1024,
      })) {
        res.write(chunk);
      }
      res.end();
    }
  } catch (err: any) {
    console.error("Stream error:", err);
    if (!res.headersSent) res.status(500).send(err.message);
  }
});

// Public Share Route
app.get("/s/:id", async (req, res) => {
  try {
    const id = req.params.id;
    let name = "Shared File";
    let size = 0;
    let mime = "application/octet-stream";
    let messageId = 0;
    let shareId = "";

    if (mongoUri) {
      // Find by shareId (random string) or fallback to messageId for legacy
      let f = await FileMetadata.findOne({ shareId: id });
      if (!f && /^\d+$/.test(id)) {
        f = await FileMetadata.findOne({ messageId: parseInt(id) });
      }

      if (f) {
        name = f.name;
        size = f.size;
        mime = f.mimeType;
        messageId = f.messageId;
        shareId = f.shareId || "";
      } else {
        return res.status(404).send("File not found");
      }
    } else {
       return res.status(503).send("Database not available for share links");
    }

    const formatSize = (bytes: number) => {
      if (bytes === 0) return "0 B";
      const k = 1024;
      const sizes = ["B", "KB", "MB", "GB", "TB"];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    };

    const isVideo = mime.startsWith("video/");
    const isImage = mime.startsWith("image/");
    const resourceId = shareId || messageId;

    const html = `
<!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>${name} - TG-Drive Share</title>
          <script src="https://cdn.tailwindcss.com"></script>
          <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700;900&display=swap'); 
            body { font-family: 'Inter', sans-serif; background-color: #0a0a0a; color: white; }
            .custom-blur { backdrop-filter: blur(10px); }
          </style>
      </head>
      <body class="flex items-center justify-center min-h-screen p-6">
          <div class="max-w-2xl w-full bg-[#111] p-8 md:p-12 rounded-[3rem] shadow-2xl border border-neutral-900 text-center">
              <!-- Icon Container with the slight rotate from your dashboard -->
              <div class="w-20 h-20 bg-white rounded-3xl flex items-center justify-center mx-auto mb-8 shadow-xl shadow-black/50 rotate-3">
                  <svg class="text-black w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path>
                  </svg>
              </div>

              <h1 class="text-2xl md:text-3xl font-black text-white mb-2 break-words tracking-tight">${name}</h1>
              <p class="text-neutral-500 font-bold mb-10 uppercase tracking-widest text-[11px]">${formatSize(size)} • ${mime}</p>
              
              <!-- Media Preview Area -->
              <div class="mb-10 rounded-[2.5rem] overflow-hidden bg-[#0a0a0a] border border-neutral-800 shadow-inner">
                ${isVideo ? `<video controls class="w-full max-h-[400px]"><source src="/api/stream/${resourceId}" type="${mime}"></video>` : ''}
                ${isImage ? `<img src="/api/stream/${resourceId}" class="w-full max-h-[400px] object-contain" />` : ''}
                ${(!isVideo && !isImage) ? `
                  <div class="py-24 flex flex-col items-center justify-center gap-4">
                    <svg class="w-12 h-12 text-neutral-800" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
                    <div class="text-neutral-600 font-black uppercase tracking-[0.2em] text-[10px]">No Preview Available</div>
                  </div>` : ''}
              </div>

              <!-- Action Button -->
              <a href="/api/download/${resourceId}" download="${name}" 
                 class="inline-block w-full bg-white text-black py-5 rounded-[2rem] font-black hover:opacity-90 transition-all active:scale-[0.96] shadow-2xl shadow-white/5 text-lg">
                Download Now
              </a>

              <div class="mt-10 flex items-center justify-center gap-4">
                <div class="h-px bg-neutral-900 flex-1"></div>
                <p class="text-[10px] font-black text-neutral-800 uppercase tracking-[0.3em]">Powered by CLOUDYTE</p>
                <div class="h-px bg-neutral-900 flex-1"></div>
              </div>
          </div>
      </body>
      </html>
    `;
    res.send(html);
  } catch (err) {
    res.status(500).send("Error generating share page");
  }
});

// Enhanced Bot File Manager
// Persisted via BotSession in mongo

  // Simple in-memory session cache for Telegram bot auth
  const authorizedCache = new Set<number>();
  
  // Persist auth states and user states to avoid loss on restart
  const getBotSession = async (chatId: number) => {
    if (mongoUri && mongoose.connection.readyState === 1) {
      const session = await BotSession.findOne({ chatId });
      return session?.data || {};
    }
    return {};
  };

  const updateBotSession = async (chatId: number, data: any) => {
    if (mongoUri && mongoose.connection.readyState === 1) {
      await BotSession.findOneAndUpdate(
        { chatId },
        { data, updatedAt: new Date() },
        { upsert: true }
      );
    }
  };

  const setAuthorizedCommands = async (userId: number) => {
    try {
      await bot!.telegram.setMyCommands([
        { command: 'start', description: 'Dashboard & Stats' },
        { command: 'files', description: 'Browse Files' },
        { command: 'search', description: 'Search Files' },
        { command: 'upload', description: 'How to Upload' },
        { command: 'setfolder', description: 'Set Upload Folder' },
        { command: 'dashboard', description: 'Get Dashboard Link' },
        { command: 'logout', description: 'Logout' },
      ], { scope: { type: 'chat', chat_id: userId } });
    } catch (e) {
      console.error("Failed to set authorized commands", e);
    }
  };

  const setUnauthorizedCommands = async (userId: number) => {
    try {
      await bot!.telegram.setMyCommands([
        { command: 'start', description: 'Start' },
        { command: 'login', description: 'Login' },
      ], { scope: { type: 'chat', chat_id: userId } });
    } catch (e) {
      console.error("Failed to set unauthorized commands", e);
    }
  };

  if (botToken) {
    bot = new Telegraf(botToken);

    // Auth Middleware for Bot
    bot.use(async (ctx, next) => {
      if (!ctx.from) return;
      
      const userId = ctx.from.id;
      const msgText = (ctx.message as any)?.text || "";

      // Fast path: User is already known to be authorized
      if (authorizedCache.has(userId)) {
        // If it's a command, we might want to clear "awaiting" states, 
        // but to avoid a DB call on every message, we only do this for slash commands
        // and we'll do it lazily inside the command handlers or accept that 
        // "ghost" states are a minor trade-off for speed.
        // However, if we want to be safe, we can do it here only when needed.
        if (msgText.startsWith("/")) {
          const session = await getBotSession(userId);
          if (session.userState && (session.userState.awaitingFolderIn || session.userState.awaitingRenameFolder || session.userState.awaitingRenameFileId)) {
            session.userState.awaitingFolderIn = undefined;
            session.userState.awaitingRenameFolder = undefined;
            session.userState.awaitingRenameFileId = undefined;
            await updateBotSession(userId, session);
          }
        }
        return next();
      }

      // Slow path: User not in cache, check DB
      if (mongoUri && mongoose.connection.readyState === 1) {
        const isAuth = await BotAuth.findOne({ chatId: userId });
        if (isAuth) {
          authorizedCache.add(userId);
          return next();
        }
      }

      // Handle login flow (needs session for authState)
      const session = await getBotSession(userId);

      // Ensure userStates exists in session for new users
      if (!session.userState) {
        session.userState = { folder: "", currentPath: "" };
        await updateBotSession(userId, session);
      }

      // If it's a command, clear any pending "awaiting" states
      if (msgText.startsWith("/")) {
        session.userState = { 
          ...session.userState, 
          awaitingFolderIn: undefined, 
          awaitingRenameFolder: undefined, 
          awaitingRenameFileId: undefined 
        };
        await updateBotSession(userId, session);
      }

      // Allow the login process to continue
      if (msgText === "/start" || msgText === "/login" || session.authState) {
        return next();
      }

      await ctx.reply("🔐 <b>TG-Drive Security</b>\nThis bot is private. Please use <code>/login</code> to authenticate.", { parse_mode: "HTML" });
    });

  const escapeHtml = (text: string) => {
    return text.toString()
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  };

  const formatSize = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const getBrowserKeyboard = async (path: string = "", page: number = 0) => {
    const itemsPerPage = 10;
    
    const escapeRegExp = (str: string) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const escapedPath = escapeRegExp(path);
    
    // Optimized discovery: use Promise.all and lean queries
    const [folderKeys, dedicated, filesInFolder] = await Promise.all([
      FileMetadata.distinct("folder", { 
        folder: new RegExp(`^${escapedPath ? escapedPath + "/" : ""}`) 
      }),
      FolderMetadata.find({ 
        path: new RegExp(`^${escapedPath ? escapedPath + "/" : ""}[^/]+$`) 
      }).lean(),
      FileMetadata.find({ folder: path }).sort({ date: -1 }).lean()
    ]);

    const folderSet = new Set<string>();
    
    // From files
    folderKeys.forEach((folderPath: any) => {
      if (!folderPath) return;
      const remaining = path ? folderPath.substring(path.length + 1) : folderPath;
      const top = remaining.split("/")[0];
      if (top) folderSet.add(top);
    });

    // From dedicated folders
    dedicated.forEach((f: any) => {
      const remaining = path ? f.path.substring(path.length + 1) : f.path;
      const top = remaining.split("/")[0];
      if (top) folderSet.add(top);
    });

    const folders = Array.from(folderSet).sort().map(f => ({ name: f, type: 'folder' }));
    const files = filesInFolder.map((f: any) => ({ name: f.name, id: f.messageId, type: 'file' }));

    const allItems = [...folders, ...files];
    const totalItems = allItems.length;
    const items = allItems.slice(page * itemsPerPage, (page + 1) * itemsPerPage);

    const buttons = [];

    items.forEach((item: any) => {
      if (item.type === 'folder') {
        const fullPath = path ? `${path}/${item.name}` : item.name;
        buttons.push([Markup.button.callback(`📁 ${item.name}`, `browse:${fullPath}:0`)]);
      } else {
        buttons.push([Markup.button.callback(`📄 ${item.name}`, `file:${item.id}`)]);
      }
    });

    // Pagination Nav
    const pagination = [];
    if (page > 0) {
      pagination.push(Markup.button.callback("⬅️ Previous", `browse:${path}:${page - 1}`));
    }
    if ((page + 1) * itemsPerPage < totalItems) {
      pagination.push(Markup.button.callback("Next ➡️", `browse:${path}:${page + 1}`));
    }
    if (pagination.length > 0) {
      buttons.push(pagination);
    }

    // Nav
    const nav = [];
    if (path) {
      const parent = path.split("/").slice(0, -1).join("/");
      nav.push(Markup.button.callback("📂 Parent", `browse:${parent}:0`));
    }
    buttons.push(nav);

    // Tools
    buttons.push([
      Markup.button.callback("📁 New Folder", `action:mkdir:${path}`),
      Markup.button.callback("📤 Upload", `action:upload:${path}`)
    ]);
    if (path) {
      buttons.push([
        Markup.button.callback("✏️ Rename Folder", `action:renamedir:${path}`)
      ]);
    }

    return Markup.inlineKeyboard(buttons);
  };

  bot.command("start", async (ctx) => {
    await ctx.sendChatAction("typing");
    const isAuth = authorizedCache.has(ctx.from.id);
    if (isAuth) {
      await setAuthorizedCommands(ctx.from.id);
      let statsText = "";
      if (mongoUri) {
        const count = await FileMetadata.countDocuments();
        const sizeResult = await FileMetadata.aggregate([
          { $group: { _id: null, totalSize: { $sum: "$size" } } }
        ]);
        const totalSize = sizeResult[0]?.totalSize || 0;
        statsText = `\n\n📊 <b>Cloud Stats:</b>\nTotal Files: <code>${count}</code>\nStorage Used: <code>${formatSize(totalSize)}</code>`;
      }

      await ctx.reply(`🚀 <b>TG-Drive: Cloud Management</b>${statsText}\n\n━━━━━━━━━━━━━━━━━━━━\n\n🔹 /files - Open cloud file browser\n🔹 /upload - How to upload files\n🔹 /search &lt;query&gt; - Find files in database\n🔹 /setfolder &lt;name&gt; - Set current upload path\n🔹 /dashboard - Get web access link\n\n✨ <b>Tip:</b> Forward any file to this chat to upload it instantly.`, { 
        parse_mode: "HTML"
      });
    } else {
      await setUnauthorizedCommands(ctx.from.id);
      await ctx.reply("🔒 <b>TG-Drive Private Cloud</b>\n\nThis instance is restricted to the administrator. If you are the owner, please authenticate to manage your cloud storage.\n\nType <code>/login</code> to start the secure authentication process.", { 
        parse_mode: "HTML",
        ...Markup.inlineKeyboard([
          [Markup.button.callback("🔑 Login", "login")]
        ])
      });
    }
  });

  bot.action("login", async (ctx) => {
    const session = await getBotSession(ctx.from.id);
    session.authState = { step: 'username' };
    await updateBotSession(ctx.from.id, session);
    ctx.reply("👤 Please enter your admin <b>username</b>:", { parse_mode: "HTML" });
    ctx.answerCbQuery();
  });

  bot.command("login", async (ctx) => {
    const isAuth = authorizedCache.has(ctx.from.id);
    if (isAuth) {
      await setAuthorizedCommands(ctx.from.id);
      return ctx.reply("✅ You are already authenticated.");
    }
    await setUnauthorizedCommands(ctx.from.id);
    const session = await getBotSession(ctx.from.id);
    session.authState = { step: 'username' };
    await updateBotSession(ctx.from.id, session);
    await ctx.reply("👤 Please enter your admin <b>username</b>:", { parse_mode: "HTML" });
  });

  bot.command("logout", async (ctx) => {
    authorizedCache.delete(ctx.from.id);
    if (mongoUri) {
      await BotAuth.deleteOne({ chatId: ctx.from.id });
    }
    await setUnauthorizedCommands(ctx.from.id);
    await ctx.reply("👋 *Logged out successfully.*");
  });

  bot.command("files", async (ctx) => {
    await ctx.sendChatAction("typing");
    const kb = await getBrowserKeyboard("");
    ctx.reply("📂 <b>Cloud Browser</b> (Root)", { parse_mode: "HTML", ...kb });
  });

  bot.command("setfolder", async (ctx) => {
    const f = ctx.message.text.split(" ").slice(1).join(" ").trim();
    const session = await getBotSession(ctx.from.id);
    session.userState = { ...(session.userState || { folder: "", currentPath: "" }), folder: f };
    await updateBotSession(ctx.from.id, session);
    ctx.reply(`✅ Destination: <b>${escapeHtml(f || "Root")}</b>`, { parse_mode: "HTML" });
  });

  bot.command("dashboard", (ctx) => ctx.reply(`🌐 *Dashboard*: ${process.env.APP_URL}`));

  bot.action(/^browse:(.*):(\d+)$/, async (ctx) => {
    const path = ctx.match[1];
    const page = parseInt(ctx.match[2]);
    const kb = await getBrowserKeyboard(path, page);
    const session = await getBotSession(ctx.from.id);
    session.userState = { 
      ...(session.userState || { folder: "", currentPath: "" }),
      folder: path, 
      currentPath: path,
      awaitingFolderIn: undefined,
      awaitingRenameFolder: undefined,
      awaitingRenameFileId: undefined
    };
    await updateBotSession(ctx.from.id, session);
    ctx.editMessageText(`📂 <b>Cloud Browser</b> (${escapeHtml(path || "Root")}) - Page ${page + 1}`, { parse_mode: "HTML", ...kb }).catch(() => {});
    ctx.answerCbQuery();
  });

  bot.action(/^action:mkdir:(.*)$/, async (ctx) => {
    const currentPath = ctx.match[1];
    const session = await getBotSession(ctx.from.id);
    session.userState = { 
      ...(session.userState || { folder: "", currentPath: "" }),
      awaitingFolderIn: currentPath || "Root",
      awaitingRenameFolder: undefined,
      awaitingRenameFileId: undefined
    };
    await updateBotSession(ctx.from.id, session);
    ctx.reply(`📁 *New Folder in ${currentPath || "Root"}*\n\nPlease enter the name of the folder you want to create:`, { 
      parse_mode: "Markdown"
    });
    ctx.answerCbQuery();
  });

  bot.action(/^action:upload:(.*)$/, (ctx) => {
    const path = ctx.match[1];
    ctx.reply(`📤 <b>Upload to ${escapeHtml(path || "Root")}</b>\n\nJust send me any file (Document, Photo, Video, Audio) and I will sync it to this location.`, { parse_mode: "HTML" });
    ctx.answerCbQuery();
  });

  bot.action(/^action:renamedir:(.*)$/, async (ctx) => {
    const path = ctx.match[1];
    const session = await getBotSession(ctx.from.id);
    session.userState = { 
      ...(session.userState || { folder: "", currentPath: "" }),
      awaitingRenameFolder: path,
      awaitingFolderIn: undefined,
      awaitingRenameFileId: undefined
    };
    await updateBotSession(ctx.from.id, session);
    ctx.reply(`✏️ Please enter a new name for the folder <b>${escapeHtml(path)}</b>:`, { 
      parse_mode: "HTML"
    });
    ctx.answerCbQuery();
  });

  bot.action(/^action:renamefile:(\d+)$/, async (ctx) => {
    const id = parseInt(ctx.match[1]);
    const f = await FileMetadata.findOne({ messageId: id });
    if (!f) return ctx.answerCbQuery("File not found");
    const session = await getBotSession(ctx.from.id);
    session.userState = { 
      ...(session.userState || { folder: "", currentPath: "" }),
      awaitingRenameFileId: id,
      awaitingFolderIn: undefined,
      awaitingRenameFolder: undefined
    };
    await updateBotSession(ctx.from.id, session);
    ctx.reply(`✏️ Please enter a new name for the file <b>${escapeHtml(f.name)}</b>:`, { 
      parse_mode: "HTML"
    });
    ctx.answerCbQuery();
  });

  bot.action(/^file:(\d+)$/, async (ctx) => {
    const id = parseInt(ctx.match[1]);
    let f = await FileMetadata.findOne({ messageId: id });
    if (!f) return ctx.answerCbQuery("File not found");

    // Clear any pending inputs when viewing file details
    const session = await getBotSession(ctx.from.id);
    session.userState = { 
      ...(session.userState || { folder: "", currentPath: "" }),
      awaitingFolderIn: undefined,
      awaitingRenameFolder: undefined,
      awaitingRenameFileId: undefined
    };
    await updateBotSession(ctx.from.id, session);

    // Lazy migration for legacy files missing shareId
    if (!f.shareId) {
      f.shareId = generateShareId();
      await f.save();
    }

    const domain = process.env.APP_URL || "";
    const shareUrl = `${domain}/s/${f.shareId}`;

    ctx.editMessageText(
      `📄 <b>File Details</b>\n\nName: <code>${escapeHtml(f.name)}</code>\nSize: ${formatSize(f.size)}\nPath: ${escapeHtml(f.folder || "Root")}\nMime: ${escapeHtml(f.mimeType)}`,
      {
        parse_mode: "HTML",
        ...Markup.inlineKeyboard([
          [
            Markup.button.callback("📤 Download", `send_file:${f.messageId}`),
            Markup.button.url("🌐 Link", shareUrl)
          ],
          [
            Markup.button.callback("✏️ Rename", `action:renamefile:${f.messageId}`),
            Markup.button.callback("🗑️ Delete", `del_conf:${id}`)
          ],
          [Markup.button.callback("⬅️ Back", `browse:${f.folder}:0`)]
        ])
      }
    );
  });

  bot.action(/^send_file:(\d+)$/, async (ctx) => {
    const id = parseInt(ctx.match[1]);
    if (!channelId) return ctx.answerCbQuery("Channel not set");
    
    try {
      await ctx.answerCbQuery("Preparing file...");
      const statusMsg = await ctx.reply(`📤 <b>Preparing cloud link</b>...\n📊 Status: <code>[          ] 0%</code>`, { parse_mode: "HTML" });
      await ctx.telegram.copyMessage(ctx.chat.id, channelId, id);
      await ctx.telegram.editMessageText(ctx.chat.id, statusMsg.message_id, undefined, `✅ <b>File sent to your chat!</b>`, { parse_mode: "HTML" }).catch(() => {});
    } catch (err: any) {
      ctx.reply("❌ Error sending file: " + err.message);
    }
  });

  bot.on("text", async (ctx, next) => {
    if (ctx.message.text.startsWith("/")) return next();

    const userId = ctx.from.id;
    const session = await getBotSession(userId);
    const authState = session.authState;

    if (authState) {
      const text = ctx.message.text;
      if (authState.step === 'username') {
        session.authState = { step: 'password', username: text };
        await updateBotSession(userId, session);
        await ctx.reply("🔑 Please enter your admin <b>password</b>:", { parse_mode: "HTML" });
        return;
      } else if (authState.step === 'password') {
        if (authState.username === ADMIN_USERNAME && text === ADMIN_PASSWORD) {
          authorizedCache.add(userId);
          delete session.authState;
          await updateBotSession(userId, session);
          
          if (mongoUri) {
            await BotAuth.findOneAndUpdate(
              { chatId: userId }, 
              { chatId: userId, username: ctx.from.username || "unknown" },
              { upsert: true }
            );
          }

          await ctx.reply("🔓 <b>Authentication Successful!</b>\n\nYou now have full access to TG-Drive. You can sync files by sending them here.", { parse_mode: "HTML" });
          await setAuthorizedCommands(userId);
        } else {
          delete session.authState;
          await updateBotSession(userId, session);
          await ctx.reply("❌ <b>Invalid credentials.</b>\nAuthentication failed. Use <code>/login</code> to try again.", { parse_mode: "HTML" });
        }
        return;
      }
    }

    const browserState = session.userState || { folder: "", currentPath: "" };
    if (browserState?.awaitingFolderIn) {
      const folderName = ctx.message.text.trim();
      const parentPath = browserState.awaitingFolderIn === "Root" ? "" : browserState.awaitingFolderIn;
      const fullPath = parentPath ? `${parentPath}/${folderName}` : folderName;

      if (folderName && mongoUri) {
        try {
          const existing = await FolderMetadata.findOne({ path: fullPath });
          if (!existing) {
            await FolderMetadata.create({ name: folderName, path: fullPath });
          }
          // Clear state
          session.userState = { ...browserState, awaitingFolderIn: undefined };
          await updateBotSession(userId, session);
          
          const kb = await getBrowserKeyboard(parentPath);
          ctx.reply(`✅ Created folder: *${folderName}*`, { 
            parse_mode: "Markdown",
            ...kb
          });
        } catch (err: any) {
          ctx.reply("❌ Error: " + err.message);
        }
      }
      return;
    }

    if (browserState?.awaitingRenameFolder) {
      const folderName = ctx.message.text.trim();
      const oldPath = browserState.awaitingRenameFolder;
      
      if (folderName && mongoUri) {
        try {
          const parentPath = oldPath.split("/").slice(0, -1).join("/");
          const newPath = parentPath ? `${parentPath}/${folderName}` : folderName;

          const oldFolder = await FolderMetadata.findOne({ path: oldPath });
          if (oldFolder) {
            oldFolder.path = newPath;
            oldFolder.name = folderName;
            await oldFolder.save();
          }

          const escapedOldPath = oldPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const nestedFolders = await FolderMetadata.find({ path: new RegExp(`^${escapedOldPath}/`) });
          for (const f of nestedFolders) {
            f.path = f.path.replace(oldPath, newPath);
            f.name = f.path.split("/").pop() || f.name;
            await f.save();
          }

          await FileMetadata.updateMany(
            { folder: oldPath },
            { $set: { folder: newPath } }
          );

          const nestedFiles = await FileMetadata.find({ folder: new RegExp(`^${escapedOldPath}/`) });
          for (const file of nestedFiles) {
            file.folder = file.folder.replace(oldPath, newPath);
            await file.save();
          }

          // Clear state
          session.userState = { ...browserState, awaitingRenameFolder: undefined };
          await updateBotSession(userId, session);
          const kb = await getBrowserKeyboard(newPath);
          ctx.reply(`✅ Renamed folder to: *${folderName}*`, { 
            parse_mode: "Markdown",
            ...kb
          });
        } catch (err: any) {
          ctx.reply("❌ Error: " + err.message);
        }
      }
      return;
    }

    if (browserState?.awaitingRenameFileId) {
      const fileName = ctx.message.text.trim();
      if (fileName && mongoUri) {
        try {
          const f = await FileMetadata.findOne({ messageId: browserState.awaitingRenameFileId });
          if (f) {
            f.name = fileName;
            await f.save();
            session.userState = { ...browserState, awaitingRenameFileId: undefined };
            await updateBotSession(userId, session);
            ctx.reply(`✅ Renamed file to: *${fileName}*`, { parse_mode: "Markdown" });
          }
        } catch (err: any) {
          ctx.reply("❌ Error: " + err.message);
        }
      }
      return;
    }

    return next();
  });

  bot.action(/^del_conf:(\d+)$/, (ctx) => {
    const id = ctx.match[1];
    ctx.editMessageText("⚠️ *Delete file?*", {
      parse_mode: "Markdown",
      ...Markup.inlineKeyboard([
        [Markup.button.callback("✅ Yes", `del_execute:${id}`), Markup.button.callback("❌ No", `file:${id}`)]
      ])
    });
    ctx.answerCbQuery();
  });

  bot.action(/^del_execute:(\d+)$/, async (ctx) => {
    await ctx.answerCbQuery("Deleting...").catch(() => {});
    try {
      const id = parseInt(ctx.match[1]);
      if (channelId) {
        try {
          await ctx.telegram.deleteMessage(channelId, id);
        } catch (e) {
          const telegram = await getTelegramClient();
          if (telegram) await telegram.deleteMessages(getGramJsPeer(channelId), [id], { revoke: true });
        }
        if (mongoUri) await FileMetadata.deleteOne({ messageId: id });
        ctx.editMessageText("✅ Deleted.").catch(() => {});
      }
    } catch (error: any) {
      ctx.editMessageText("❌ Delete failed: " + error.message).catch(() => {});
    }
  });

  const handleSyncMessage = async (ctx: any, file: any, type: string) => {
    if (!channelId) return ctx.reply("❌ Channel ID not set.");
    const session = await getBotSession(ctx.from.id);
    const folder = session.userState?.folder || "";
    const fileName = file.file_name || file.file_unique_id || "unnamed";
    
    const statusMsg = await ctx.reply(`☁️ *Uploading* \`${fileName}\`\n\n📊 Status: \`[          ] 0%\`\n🚀 Speed: \`0 B/s\``, { 
      parse_mode: "Markdown",
      reply_to_message_id: ctx.message.message_id
    });
    const startTime = Date.now();
    const caption = folder ? `F[${folder}] | ${fileName}` : fileName;
    
    try {
      const res = await ctx.telegram.copyMessage(channelId, ctx.chat.id, ctx.message.message_id, { caption });
      
      const elapsed = (Date.now() - startTime) / 1000;
      const speed = file.file_size ? formatSize(file.file_size / Math.max(elapsed, 0.1)) : "0 B/s";

      // Update with done state
      await ctx.telegram.editMessageText(ctx.chat.id, statusMsg.message_id, undefined, 
        `✅ *Upload Complete* \`${fileName}\`\n\n📊 Status: \`[██████████] 100%\`\n🚀 Final Speed: \`${speed}/s\`\n📦 Size: \`${formatSize(file.file_size || 0)}\`\n📁 Path: \`${folder || "Root"}\``, 
        { parse_mode: "Markdown" }
      ).catch(() => {});

      await FileMetadata.create({
        messageId: res.message_id,
        shareId: generateShareId(),
        name: fileName,
        size: file.file_size || 0,
        date: Math.floor(Date.now() / 1000),
        mimeType: file.mime_type || `${type}/octet-stream`,
        folder,
        caption
      });
    } catch (err: any) { ctx.reply("❌ Error: " + err.message); }
  };

  bot.on(["document", "photo", "video", "audio", "animation", "voice", "video_note", "sticker"], (ctx) => {
    const m = ctx.message as any;
    const file = m.document || 
                 m.photo?.[m.photo.length - 1] || 
                 m.video || 
                 m.audio || 
                 m.animation ||
                 m.voice ||
                 m.video_note ||
                 m.sticker;
    
    let type = "File";
    if (m.document) type = "Document";
    else if (m.photo) type = "Photo";
    else if (m.video) type = "Video";
    else if (m.audio) type = "Audio";
    else if (m.animation) type = "Animation";
    else if (m.voice) type = "Voice";
    else if (m.video_note) type = "Video Note";
    else if (m.sticker) type = "Sticker";

    handleSyncMessage(ctx, file, type);
  });

  bot.command("upload", (ctx) => {
    ctx.reply("⬆️ Just send any file, photo, or document to this chat. I will automatically sync it to your TG-Drive cloud.", { parse_mode: "HTML" });
  });

  bot.command("search", async (ctx) => {
    await ctx.sendChatAction("typing");
    const query = ctx.message.text.split(" ").slice(1).join(" ");
    if (!query) {
      return ctx.reply("🔍 <b>Search Files</b>\nUsage: <code>/search filename</code>", { parse_mode: "HTML" });
    }

    if (!mongoUri) return ctx.reply("❌ Database not connected.");

    try {
      const safeQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const results = await FileMetadata.find({ name: new RegExp(safeQuery, "i") }).limit(10);
      if (results.length === 0) {
        return ctx.reply(`❌ No files found matching <b>${escapeHtml(query)}</b>`, { parse_mode: "HTML" });
      }

      const domain = process.env.APP_URL || "";
      let text = `🔍 <b>Search Results for "${escapeHtml(query)}"</b>\n\n`;
      
      for (let i = 0; i < results.length; i++) {
        const file = results[i];
        if (!file.shareId) {
          file.shareId = generateShareId();
          await file.save();
        }
        const shareLink = `${domain}/s/${file.shareId}`;
        text += `${i + 1}. <code>${escapeHtml(file.name)}</code>\n   🔗 <a href="${shareLink}">Cloud Link</a>\n\n`;
      }

      ctx.reply(text, { parse_mode: "HTML", link_preview_options: { is_disabled: true } });
    } catch (err: any) {
      ctx.reply("❌ Search error: " + err.message);
    }
  });

  console.log("Starting Telegraf bot...");

  const launchBot = async () => {
    try {
      // First, try to remove any existing webhooks or polling sessions
      try {
        await bot!.telegram.deleteWebhook({ drop_pending_updates: true });
      } catch (e) {}

      await bot!.launch({
        allowedUpdates: ["message", "callback_query"],
      });
      console.log("✅ Telegraf bot launched and polling");
    } catch (err: any) {
      if (err.message.includes("409: Conflict")) {
        console.warn("⚠️ Bot conflict detected (409). Another instance might be running. Retrying in 5s...");
        setTimeout(launchBot, 5000);
      } else {
        console.error("❌ Bot launch failed:", err);
      }
    }
  };

  launchBot();

  // Enable graceful stop
  const stopBot = (signal: string) => {
    console.log(`Received ${signal}. Stopping bot...`);
    bot?.stop(signal);
  };
  process.once('SIGINT', () => stopBot('SIGINT'));
  process.once('SIGTERM', () => stopBot('SIGTERM'));
}

app.listen(PORT as number, "0.0.0.0", () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});
