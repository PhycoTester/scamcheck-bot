import sys
import os
import json
import asyncio
import logging

from dotenv import load_dotenv
import discord
from discord import app_commands

from scamcheck import load_config, extract_urls, score_url, score_email_text, label
from ratelimit import Cooldown


# -------------------------
# Windows asyncio policy
# -------------------------
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


# -------------------------
# Logging (file)
# -------------------------
logging.basicConfig(
    filename="bot.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
# capture prints + tracebacks too
sys.stdout = open("bot.log", "a", buffering=1, encoding="utf-8")
sys.stderr = open("bot.log", "a", buffering=1, encoding="utf-8")


# -------------------------
# Env + config
# -------------------------
load_dotenv()
TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
if not TOKEN:
    raise SystemExit("DISCORD_BOT_TOKEN missing in .env")

cfg = load_config("config.json")

cooldown_url = Cooldown(int(cfg.get("cooldown_seconds_per_user", 10)))
cooldown_img = Cooldown(max(15, int(cfg.get("cooldown_seconds_per_user", 10)) * 2))


def save_config(path: str = "config.json") -> None:
    # Save only known keys (keeps file clean)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def format_url_result(r: dict) -> str:
    if not r.get("ok"):
        return f"❌ Error: {r.get('error', 'Unknown')}"

    lines = []
    lines.append(f"**Verdict:** {label(r['verdict'])} | **Score:** `{r['score']}`")
    lines.append(f"**Final:** {r['final']}")
    lines.append(f"**Domain:** `{r['domain']['registered_domain']}`")

    if r.get("reasons"):
        lines.append("**Flags:** " + ", ".join(r["reasons"]))

    if len(r.get("chain", [])) > 1:
        lines.append("**Redirects:**")
        for u in r["chain"]:
            lines.append(f"- {u}")

    us = r.get("urlscan", {})
    if us.get("enabled") and us.get("result"):
        lines.append(f"**urlscan:** {us['result']}")

    return "\n".join(lines)


# -------------------------
# Discord client + tree
# -------------------------
intents = discord.Intents.default()
intents.message_content = True  # required for autoscan
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)


# -------------------------
# Autoscan (messages)
# -------------------------
@client.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return

    if not cfg.get("autoscan_enabled", True):
        return

    # Channel allow/block logic (IDs stored as strings)
    ch_id = str(message.channel.id)
    allow = set(cfg.get("autoscan_channels_allowlist", []))
    block = set(cfg.get("autoscan_channels_blocklist", []))

    if allow and ch_id not in allow:
        return
    if block and ch_id in block:
        return

    # cheap guard for huge spam messages
    content = message.content or ""
    if len(content) > 4000:
        return

    urls = extract_urls(content)
    if urls:
        max_urls = int(cfg.get("max_urls_per_message", 3))
        urls = urls[:max_urls]

        if cooldown_url.hit(str(message.author.id)):
            results = []
            for u in urls:
                try:
                    r = score_url(u, cfg)
                    results.append(format_url_result(r))
                except Exception as e:
                    results.append(f"❌ Error analyzing URL: {e}")

            if results:
                try:
                    await message.reply("\n\n".join(results), mention_author=False)
                except (discord.Forbidden, discord.HTTPException):
                    return

    # Image hint (baseline, no OCR)
    if message.attachments:
        img_ext = (".png", ".jpg", ".jpeg", ".webp")
        imgs = [a for a in message.attachments if (a.filename or "").lower().endswith(img_ext)]
        if imgs and cooldown_img.hit(f"img:{message.author.id}"):
            try:
                await message.reply(
                    "📸 Image detected. If this is a job/offer screenshot, paste the text and run `/check_email`.\n"
                    "Tip: watch for 'check to buy equipment', 'pre-offer', urgency, and mismatched email domains.",
                    mention_author=False
                )
            except (discord.Forbidden, discord.HTTPException):
                return


# -------------------------
# Slash commands
# -------------------------
@tree.command(name="check", description="Check a URL safely (expand redirects + optional reputation).")
@app_commands.describe(url="URL to analyze")
async def check(interaction: discord.Interaction, url: str):
    await interaction.response.defer(thinking=True, ephemeral=True)
    try:
        r = score_url(url, cfg)
        await interaction.followup.send(format_url_result(r), ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {e}", ephemeral=True)


@tree.command(name="check_email", description="Check email/message text for scam patterns.")
@app_commands.describe(text="Paste email/message content")
async def check_email(interaction: discord.Interaction, text: str):
    await interaction.response.defer(thinking=True, ephemeral=True)
    r = score_email_text(text)
    msg = f"**Verdict:** {label(r['verdict'])} | **Score:** `{r['score']}`"
    if r["hits"]:
        msg += "\n**Flags:** " + ", ".join(r["hits"])
    await interaction.followup.send(msg, ephemeral=True)


@tree.command(name="autoscan_on", description="Enable autoscan.")
async def autoscan_on(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True, ephemeral=True)
    cfg["autoscan_enabled"] = True
    save_config()
    await interaction.followup.send("✅ Autoscan enabled.", ephemeral=True)


@tree.command(name="autoscan_off", description="Disable autoscan.")
async def autoscan_off(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True, ephemeral=True)
    cfg["autoscan_enabled"] = False
    save_config()
    await interaction.followup.send("🛑 Autoscan disabled.", ephemeral=True)


@tree.command(name="autoscan_block_here", description="Disable autoscan in this channel.")
async def autoscan_block_here(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True, ephemeral=True)
    ch_id = str(interaction.channel_id)
    block = set(cfg.get("autoscan_channels_blocklist", []))
    block.add(ch_id)
    cfg["autoscan_channels_blocklist"] = sorted(block)
    save_config()
    await interaction.followup.send("✅ Autoscan blocked in this channel.", ephemeral=True)


@tree.command(name="autoscan_allow_here", description="Allow autoscan in this channel only (allowlist mode).")
async def autoscan_allow_here(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True, ephemeral=True)
    ch_id = str(interaction.channel_id)
    allow = set(cfg.get("autoscan_channels_allowlist", []))
    allow.add(ch_id)
    cfg["autoscan_channels_allowlist"] = sorted(allow)
    save_config()
    await interaction.followup.send("✅ Autoscan allowed in this channel (allowlist updated).", ephemeral=True)


@tree.command(name="reload_config", description="Reload config.json without restarting the bot.")
async def reload_config(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True, ephemeral=True)
    global cfg
    cfg = load_config("config.json")
    await interaction.followup.send("✅ Config reloaded.", ephemeral=True)


# -------------------------
# Startup
# -------------------------
@client.event
async def on_ready():
    await tree.sync()
    print(f"✅ Logged in as {client.user} | Commands synced")


client.run(TOKEN)
