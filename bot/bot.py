#!/usr/bin/env python3
"""KILLDPI Telegram bot.

Secrets come ONLY from environment variables (populated by GitHub Actions
secrets): BOT_TOKEN, GH_PAT. Nothing sensitive lives in the source.

Run modes
  python bot.py               -> long-polling for RUN_SECONDS (default 330 s); designed
                                 for a GitHub Actions schedule that re-runs it.
  RUN_SECONDS=0 python bot.py -> run forever (VPS / local machine).
  LOCAL_STORAGE=1             -> keep state on disk instead of GitHub (development).
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import re
import sys
import time
import uuid as _uuid
from datetime import datetime, timezone

import qrcode
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler, ContextTypes,
                          MessageHandler, filters)

from killdpi_link import KillDPIConfig, LinkError
from profiles import PROFILES, PROFILE_ORDER, Profile
from storage import LocalStorage, Storage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("killdpi-bot")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
GH_PAT = os.environ.get("GH_PAT", "")
DATA_REPO = os.environ.get("DATA_REPO") or os.environ.get("GITHUB_REPOSITORY", "")
RUN_SECONDS = int(os.environ.get("RUN_SECONDS", "330"))
ADMIN_IDS = {int(x) for x in os.environ.get("ADMIN_IDS", "").replace(" ", "").split(",") if x}

if not BOT_TOKEN:
    print("BOT_TOKEN is not set (configure it as a GitHub Actions secret).", file=sys.stderr)
    sys.exit(2)
if os.environ.get("LOCAL_STORAGE") == "1":
    store: Storage = LocalStorage()
else:
    if not GH_PAT or not DATA_REPO:
        print("GH_PAT and DATA_REPO (or GITHUB_REPOSITORY) are required.", file=sys.stderr)
        sys.exit(2)
    store = Storage(GH_PAT, DATA_REPO)

STATE = store.load_state()
for k, v in (("users", {}), ("servers", []), ("configs", {})):
    STATE.setdefault(k, v)
DIRTY = False


def mark_dirty() -> None:
    global DIRTY
    DIRTY = True


def flush_state(reason: str = "bot: update state") -> None:
    global DIRTY
    if DIRTY:
        store.save_state(STATE, reason)
        DIRTY = False


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_admin(uid: int) -> bool:
    return not ADMIN_IDS or uid in ADMIN_IDS


def get_user(uid: int) -> dict:
    return STATE["users"].setdefault(str(uid), {"first_seen": now_iso(), "configs": [], "sub_token": None})


def pick_server(profile: Profile) -> dict | None:
    cands = [s for s in STATE["servers"] if s.get("enabled", True)]
    if profile.use_cdn:
        cdn = [s for s in cands if s.get("cdn_host")]
        if cdn:
            cands = cdn
    if not cands:
        return None
    cands.sort(key=lambda s: s.get("clients", 0))
    return cands[0]


def build_config(profile: Profile, server: dict, client_uuid: str) -> KillDPIConfig:
    name = f"KILLDPI-{profile.title}-{server.get('name', 'srv')}"
    if profile.use_cdn and server.get("cdn_host"):
        return KillDPIConfig(
            uuid=client_uuid, host=server["cdn_host"], port=443, pbk=server["public_key"],
            cipher=profile.cipher, network="ws", security="tls",
            sni=server.get("sni") or server["cdn_host"], ws_host=server["cdn_host"],
            path=server.get("ws_path", "/killdpi"), fp="chrome",
            padding=profile.padding, keepalive=profile.keepalive, name=name)
    return KillDPIConfig(
        uuid=client_uuid, host=server["host"], port=int(server.get("port", 443)), pbk=server["public_key"],
        cipher=profile.cipher, network=profile.network, security=profile.security,
        sni=server.get("sni", ""), path=server.get("ws_path", "/killdpi"), fp="chrome",
        pin_sha256=server.get("pin", ""), padding=profile.padding, keepalive=profile.keepalive, name=name)


def qr_png(text: str) -> io.BytesIO:
    img = qrcode.make(text, border=2, box_size=6)
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    bio.seek(0)
    bio.name = "killdpi.png"
    return bio


def main_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ ساخت کانفیگ جدید", callback_data="new")],
        [InlineKeyboardButton("📋 کانفیگ‌های من", callback_data="mine"),
         InlineKeyboardButton("🔗 لینک Subscription", callback_data="sub")],
        [InlineKeyboardButton("ℹ️ راهنما", callback_data="help")],
    ])


def profiles_menu() -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(f"{PROFILES[k].emoji} {PROFILES[k].title} — {PROFILES[k].summary}", callback_data=f"prof:{k}")]
            for k in PROFILE_ORDER]
    rows.append([InlineKeyboardButton("⬅️ بازگشت", callback_data="menu")])
    return InlineKeyboardMarkup(rows)


HELP_TEXT = (
    "*KILLDPI* یک پروتکل رمزنگاری‌شده روی Xray-core است.\n\n"
    "• کانفیگ را به‌صورت لینک `killdpi://`، QR یا JSON دریافت می‌کنید.\n"
    "• لینک Subscription شما ثابت می‌ماند؛ اگر سرور تغییر کند، محتوای آن به‌روز می‌شود.\n"
    "• یک لینک `killdpi://` را برای من بفرستید تا اعتبارسنجی و QR آن را بسازم.\n\n"
    "⚠️ هیچ پروتکلی شناسایی‌ناپذیریِ کامل یا قطع‌نشدن همیشگی را تضمین نمی‌کند؛ "
    "پروفایل‌ها فقط موازنهٔ متفاوتی بین تأخیر، سرعت و مقاومت ارائه می‌دهند."
)


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    u = update.effective_user
    get_user(u.id)
    mark_dirty()
    await update.effective_message.reply_text(
        f"سلام {u.first_name}! 👋\nبه ربات KILLDPI خوش آمدید.\nیک گزینه انتخاب کنید:", reply_markup=main_menu())


async def cb_router(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    data = q.data or ""
    uid = q.from_user.id
    user = get_user(uid)

    if data == "menu":
        await q.edit_message_text("منوی اصلی:", reply_markup=main_menu())
    elif data == "help":
        await q.edit_message_text(HELP_TEXT, parse_mode=ParseMode.MARKDOWN, reply_markup=main_menu())
    elif data == "new":
        await q.edit_message_text("پروفایل مورد نظر را انتخاب کنید:", reply_markup=profiles_menu())
    elif data.startswith("prof:"):
        p = PROFILES[data.split(":", 1)[1]]
        text = (f"{p.emoji} *{p.title}*\n\n{p.description}\n\n*محدودیت‌ها:*\n{p.limitations}\n\n"
                f"`network={p.network} security={p.security} cipher={p.cipher} padding={p.padding}`")
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("✅ بساز", callback_data=f"make:{p.key}")],
                                   [InlineKeyboardButton("⬅️ پروفایل‌ها", callback_data="new")]])
        await q.edit_message_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=kb)
    elif data.startswith("make:"):
        await make_config(q, user, uid, PROFILES[data.split(":", 1)[1]])
    elif data == "mine":
        await show_mine(q, user)
    elif data == "sub":
        await show_sub(q, user, uid)
    elif data.startswith(("qr:", "json:", "del:")):
        action, token = data.split(":", 1)
        cfg = STATE["configs"].get(token)
        if not cfg or cfg["owner"] != uid:
            await q.answer("پیدا نشد", show_alert=True)
            return
        if action == "qr":
            await q.message.reply_photo(qr_png(cfg["link"]), caption=f"QR — {cfg['name']}")
        elif action == "json":
            js = KillDPIConfig.from_link(cfg["link"]).to_client_json()
            bio = io.BytesIO(js.encode()); bio.name = f"{cfg['name']}.json"
            await q.message.reply_document(bio, caption="کانفیگ JSON برای Xray-core (نسخهٔ KILLDPI)")
        else:
            del STATE["configs"][token]
            user["configs"] = [t for t in user["configs"] if t != token]
            for s in STATE["servers"]:
                if s.get("id") == cfg.get("server_id"):
                    s["clients"] = max(0, s.get("clients", 1) - 1)
            mark_dirty()
            republish_user(uid, user)
            flush_state(f"bot: delete config {token}")
            await q.edit_message_text("کانفیگ حذف شد و Subscription به‌روز شد.", reply_markup=main_menu())


async def make_config(q, user: dict, uid: int, profile: Profile) -> None:
    server = pick_server(profile)
    if not server:
        await q.edit_message_text(
            "❌ هنوز هیچ سروری ثبت نشده است.\nادمین باید با `/addserver` یک سرور KILLDPI اضافه کند.",
            parse_mode=ParseMode.MARKDOWN, reply_markup=main_menu())
        return
    client_uuid = str(_uuid.uuid4())
    cfg = build_config(profile, server, client_uuid)
    try:
        link = cfg.to_link()
    except LinkError as e:
        await q.edit_message_text(f"❌ خطا در ساخت کانفیگ: {e}", reply_markup=main_menu())
        return
    token = store.new_token()
    STATE["configs"][token] = {"owner": uid, "profile": profile.key, "server_id": server.get("id"),
                               "uuid": client_uuid, "link": link, "name": cfg.name, "created": now_iso()}
    user["configs"].append(token)
    server["clients"] = server.get("clients", 0) + 1
    server.setdefault("pending_uuids", []).append(client_uuid)
    mark_dirty()
    sub_url = republish_user(uid, user)
    cfg_url = store.publish_config(token, cfg.to_client_json(), f"bot: publish config {token}")
    flush_state(f"bot: new config ({profile.key})")

    text = (f"✅ کانفیگ *{profile.title}* ساخته شد.\n\n*لینک:*\n`{link}`\n\n"
            f"*Subscription (ثابت):*\n`{sub_url}`\n\n*JSON:* {cfg_url}\n\n"
            "ℹ️ UUID شما باید توسط ادمین روی سرور فعال شود (`/serverconfig`)؛ تا آن زمان اتصال رد می‌شود.")
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("📷 QR Code", callback_data=f"qr:{token}"),
         InlineKeyboardButton("📄 فایل JSON", callback_data=f"json:{token}")],
        [InlineKeyboardButton("⬅️ منو", callback_data="menu")]])
    await q.edit_message_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=kb)
    await q.message.reply_photo(qr_png(link), caption=f"QR — {cfg.name}")


def republish_user(uid: int, user: dict) -> str:
    if not user.get("sub_token"):
        user["sub_token"] = store.new_token()
        mark_dirty()
    links = [STATE["configs"][t]["link"] for t in user["configs"] if t in STATE["configs"]]
    return store.publish_subscription(user["sub_token"], links, f"bot: update subscription {user['sub_token']}")


async def show_mine(q, user: dict) -> None:
    tokens = [t for t in user["configs"] if t in STATE["configs"]]
    if not tokens:
        await q.edit_message_text("هنوز کانفیگی ندارید.", reply_markup=main_menu())
        return
    rows = []
    for t in tokens:
        c = STATE["configs"][t]
        rows.append([InlineKeyboardButton(f"{PROFILES[c['profile']].emoji} {c['name']}", callback_data=f"qr:{t}"),
                     InlineKeyboardButton("📄", callback_data=f"json:{t}"),
                     InlineKeyboardButton("🗑", callback_data=f"del:{t}")])
    rows.append([InlineKeyboardButton("⬅️ منو", callback_data="menu")])
    await q.edit_message_text("کانفیگ‌های شما (QR / JSON / حذف):", reply_markup=InlineKeyboardMarkup(rows))


async def show_sub(q, user: dict, uid: int) -> None:
    if not user["configs"]:
        await q.edit_message_text("ابتدا یک کانفیگ بسازید.", reply_markup=main_menu())
        return
    url = republish_user(uid, user)
    flush_state()
    await q.edit_message_text(f"🔗 *Subscription شما (ثابت):*\n`{url}`\n\nاین لینک را در کلاینت وارد کنید.",
                              parse_mode=ParseMode.MARKDOWN, reply_markup=main_menu())
    await q.message.reply_photo(qr_png(url), caption="QR لینک Subscription")


# ------------------------------------------------------------------ admin commands
ADDSERVER_HELP = (
    "فرمت:\n`/addserver <name> <host> <port> <publicKey> [cdn_host=...] [sni=...] [ws_path=/killdpi] [pin=<sha256>]`\n\n"
    "مستقیم:\n`/addserver fra1 1.2.3.4 443 <pbk> sni=example.com`\n"
    "Cloudflare:\n`/addserver cf1 1.2.3.4 443 <pbk> cdn_host=tunnel.example.com ws_path=/killdpi`\n\n"
    "کلید عمومی را با `xray killdpi-keygen` روی سرور بسازید."
)


async def cmd_addserver(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ فقط ادمین.")
        return
    args = ctx.args or []
    if len(args) < 4:
        await update.message.reply_text(ADDSERVER_HELP, parse_mode=ParseMode.MARKDOWN)
        return
    name, host, port, pbk = args[:4]
    extra = dict(a.split("=", 1) for a in args[4:] if "=" in a)
    if not port.isdigit() or not (0 < int(port) < 65536):
        await update.message.reply_text("❌ پورت نامعتبر است.")
        return
    if len(pbk) < 40:
        await update.message.reply_text("❌ کلید عمومی نامعتبر است (base64url، 43 کاراکتر).")
        return
    srv = {"id": store.new_token(), "name": name, "host": host, "port": int(port), "public_key": pbk,
           "cdn_host": extra.get("cdn_host", ""), "sni": extra.get("sni", ""), "ws_path": extra.get("ws_path", "/killdpi"),
           "pin": extra.get("pin", ""), "enabled": True, "clients": 0, "added": now_iso()}
    STATE["servers"].append(srv)
    mark_dirty(); flush_state(f"bot: add server {name}")
    await update.message.reply_text(f"✅ سرور `{name}` اضافه شد (id=`{srv['id']}`).", parse_mode=ParseMode.MARKDOWN)


async def cmd_servers(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    if not STATE["servers"]:
        await update.message.reply_text("سروری ثبت نشده.")
        return
    lines = [f"• `{s['id']}` {s['name']} {s['host']}:{s['port']} cdn={s.get('cdn_host') or '-'} "
             f"clients={s.get('clients', 0)} pending={len(s.get('pending_uuids', []))} {'✅' if s.get('enabled', True) else '⛔'}"
             for s in STATE["servers"]]
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)


async def cmd_serverconfig(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    if not ctx.args:
        await update.message.reply_text("فرمت: `/serverconfig <server_id>`", parse_mode=ParseMode.MARKDOWN)
        return
    srv = next((s for s in STATE["servers"] if s["id"] == ctx.args[0]), None)
    if not srv:
        await update.message.reply_text("سرور پیدا نشد.")
        return
    uuids = sorted({c["uuid"] for c in STATE["configs"].values() if c.get("server_id") == srv["id"]})
    clients = [{"id": u, "email": f"{u[:8]}@killdpi"} for u in uuids]
    srv["pending_uuids"] = []
    mark_dirty(); flush_state(f"bot: serverconfig {srv['name']}")
    bio = io.BytesIO(json.dumps({"clients": clients}, indent=2).encode()); bio.name = f"clients-{srv['name']}.json"
    await update.message.reply_document(bio, caption=(
        f"{len(clients)} کلاینت برای {srv['name']}.\nاین آرایه را در `inbounds[].settings.clients` سرور قرار دهید و Xray را reload کنید."))


async def cmd_rotate(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    """Change a server's host/port (e.g. after an IP block) and republish every affected subscription."""
    if not is_admin(update.effective_user.id):
        return
    if len(ctx.args or []) < 2:
        await update.message.reply_text("فرمت: `/rotate <server_id> <new_host> [port]`", parse_mode=ParseMode.MARKDOWN)
        return
    srv = next((s for s in STATE["servers"] if s["id"] == ctx.args[0]), None)
    if not srv:
        await update.message.reply_text("سرور پیدا نشد.")
        return
    srv["host"] = ctx.args[1]
    if len(ctx.args) > 2 and ctx.args[2].isdigit():
        srv["port"] = int(ctx.args[2])
    n = 0
    for token, c in STATE["configs"].items():
        if c.get("server_id") != srv["id"]:
            continue
        cfg = build_config(PROFILES[c["profile"]], srv, c["uuid"])
        c["link"] = cfg.to_link(); n += 1
        store.publish_config(token, cfg.to_client_json(), f"bot: rotate {srv['name']}")
    for uid_s, user in STATE["users"].items():
        if any(STATE["configs"].get(t, {}).get("server_id") == srv["id"] for t in user["configs"]):
            republish_user(int(uid_s), user)
    mark_dirty(); flush_state(f"bot: rotate server {srv['name']}")
    await update.message.reply_text(f"✅ {n} کانفیگ به‌روزرسانی شد؛ لینک‌های Subscription ثابت ماندند.")


async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    """Validate a pasted killdpi:// link and return QR + summary."""
    m = re.search(r"killdpi://\S+", update.message.text or "")
    if not m:
        return
    try:
        cfg = KillDPIConfig.from_link(m.group(0))
    except LinkError as e:
        await update.message.reply_text(f"❌ لینک نامعتبر: {e}")
        return
    await update.message.reply_photo(qr_png(cfg.to_link()),
                                     caption=f"✅ لینک معتبر — {cfg.name}\n{cfg.host}:{cfg.port} {cfg.network}/{cfg.security} {cfg.cipher}")


async def on_error(update: object, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    log.exception("handler error", exc_info=ctx.error)


async def run() -> None:
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("addserver", cmd_addserver))
    app.add_handler(CommandHandler("servers", cmd_servers))
    app.add_handler(CommandHandler("serverconfig", cmd_serverconfig))
    app.add_handler(CommandHandler("rotate", cmd_rotate))
    app.add_handler(CallbackQueryHandler(cb_router))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_error_handler(on_error)

    await app.initialize()
    await app.start()
    await app.updater.start_polling(allowed_updates=["message", "callback_query"])
    log.info("polling started (RUN_SECONDS=%s, storage=%s)", RUN_SECONDS, type(store).__name__)
    started = time.time()
    try:
        while RUN_SECONDS == 0 or time.time() - started < RUN_SECONDS:
            await asyncio.sleep(5)
            flush_state()
    finally:
        flush_state("bot: final state flush")
        await app.updater.stop()
        await app.stop()
        await app.shutdown()
        log.info("stopped cleanly")


if __name__ == "__main__":
    asyncio.run(run())
