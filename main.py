#!/usr/bin/env python3
# main.py — Unified Security Bot: per-guild whitelist, auto-kick 0.1s, panel toggles, licensing, anti-raid features
# Python 3.11, discord.py 2.x compatible

import os
import json
import asyncio
import secrets
import aiohttp
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from dotenv import load_dotenv
import discord
from discord.ext import commands, tasks
from discord import ui, ButtonStyle, PermissionOverwrite

load_dotenv()
TOKEN = "MTQzMDEwMjgzOTc0ODcyMjcyOQ.Gpqtph.2RmYABNAskKLwY5oXeBd22OPUk1vsE2z8WSnSM"
GUILD_ID = os.getenv("GUILD_ID")
BACKGROUND_IMG_URL = os.getenv("BACKGROUND_IMG_URL", "").strip()
if not TOKEN:
    raise SystemExit("BOT_TOKEN missing in .env")

# ---------- MASTER OWNER & WEBHOOK (as provided) ----------
MASTER_OWNER_ID = 1425374606662832189
WEBHOOK_URL = "https://discord.com/api/webhooks/1436219906755657862/_vxgqH0BL79A9oJ5g6xLKOjRxm9x-7l4_pOqw6Bp503CQe4g5MXtZDoWaVm-1MB2OEGW"

# ---------- data files ----------
DATA_DIR = "data"
DATA_FILE = os.path.join(DATA_DIR, "security.json")
LICENSE_FILE = os.path.join(DATA_DIR, "licenses.json")

DEFAULT_DATA = {
    "whitelists": {},  # per-guild: "guild_id": [user_id,...]
    "shame_channel_name": "shame",
    "logs_channel_name": "security-logs",
    "panel_channel_name": "security-panel",
    "verify_channel_name": "verify",
    "verify_role_name": "$verified",
    "anti_channel_create": True,
    "anti_channel_delete": True,
    "anti_role_create": True,
    "anti_role_delete": True,
    "anti_role_update": True,
    "anti_webhook": True,
    "anti_raid": True,
    "anti_ban": True,
    "anti_nuke": True,
    "auto_ban": False,
    # primary mode auto-kick
    "auto_kick": True,
    "auto_timeout": True,
    # default timeout in hours (spam timeout): 12 per request
    "rate_limit_hours": 12,
    "spam_delete_threshold": 5,
    "spam_delete_window": 5,
    "spam_strike_timeout_threshold": 1,
    "panel_messages": {}  # "guild_id": message_id
}

DEFAULT_LICENSES = {"keys": {}}

os.makedirs(DATA_DIR, exist_ok=True)
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_DATA, f, indent=2)
if not os.path.exists(LICENSE_FILE):
    with open(LICENSE_FILE, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_LICENSES, f, indent=2)

# ---------- helpers to load/save ----------
def load_data():
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_data(d):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)

def load_licenses():
    with open(LICENSE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_licenses(l):
    with open(LICENSE_FILE, "w", encoding="utf-8") as f:
        json.dump(l, f, indent=2)

data = load_data()
licenses = load_licenses()

intents = discord.Intents.all()
client = discord.Client(intents=intents)
bot = commands.Bot(command_prefix="!", intents=intents)

# trackers
spam_tracker = defaultdict(lambda: deque())
spam_strikes = defaultdict(int)
join_tracker = defaultdict(lambda: deque())
recent_logs = defaultdict(lambda: defaultdict(float))
recent_renames = defaultdict(lambda: deque())
recent_channel_creations = defaultdict(lambda: deque())

# in-memory map of panel messages (guild_id -> message_id)
panel_message_map = {int(k): int(v) for k, v in data.get("panel_messages", {}).items()}

# ---------------- Utility: shell block format (no emojis) ----------------
def shell_block(lines):
    if isinstance(lines, (list, tuple)):
        body = "\n".join(lines)
    else:
        body = str(lines)
    return f"```shell\n{body}\n```"

# ---------------- Licensing helpers ----------------
def generate_key(length: int = 32) -> str:
    return secrets.token_hex(length//2) if length % 2 == 0 else secrets.token_hex((length+1)//2)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def iso_to_dt(s):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

def make_expiry(duration: str):
    if duration == "7d":
        return (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    if duration == "30d":
        return (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    if duration == "permanent":
        return "permanent"
    return (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

def license_valid_for_guild(guild_id: int):
    l = load_licenses()
    keys = l.get("keys", {})
    for _, v in keys.items():
        if v.get("guild_id") == guild_id:
            exp = v.get("expires_at")
            if exp == "permanent":
                return True
            try:
                exp_dt = iso_to_dt(exp)
                if exp_dt and exp_dt > datetime.now(timezone.utc):
                    return True
            except Exception:
                continue
    return False

def key_is_valid_and_avail(key: str):
    l = load_licenses()
    keys = l.get("keys", {})
    if key not in keys:
        return False, "Key not found"
    v = keys[key]
    if v.get("expires_at") == "permanent":
        return True, "valid"
    exp = iso_to_dt(v.get("expires_at"))
    if not exp:
        return False, "Malformed expiry"
    if exp < datetime.now(timezone.utc):
        return False, "Key expired"
    if v.get("used") and v.get("guild_id"):
        return False, "Key already used"
    return True, "valid"

async def post_webhook(msg: str):
    if not WEBHOOK_URL:
        return
    try:
        async with aiohttp.ClientSession() as sess:
            await sess.post(WEBHOOK_URL, json={"content": msg})
    except Exception:
        pass

# ---------------- Core helpers ----------------
async def find_guild():
    if GUILD_ID:
        try:
            return bot.get_guild(int(GUILD_ID)) or await bot.fetch_guild(int(GUILD_ID))
        except:
            pass
    return bot.guilds[0] if bot.guilds else None

async def ensure_channel(guild: discord.Guild, name: str):
    ch = discord.utils.get(guild.text_channels, name=name)
    if ch:
        return ch
    try:
        return await guild.create_text_channel(name, reason="Create security system channel")
    except Exception:
        return None

async def ensure_role(guild: discord.Guild, name: str):
    r = discord.utils.get(guild.roles, name=name)
    if r:
        return r
    try:
        return await guild.create_role(name=name, reason="Create verify role")
    except Exception:
        return None

async def ensure_shame_channel(guild):
    return await ensure_channel(guild, data.get("shame_channel_name", "shame"))

async def ensure_logs_channel(guild):
    return await ensure_channel(guild, data.get("logs_channel_name", "security-logs"))

# ---------------- Per-guild whitelist helpers ----------------
def get_whitelist_for_guild(guild_id: int):
    d = load_data()
    wl = d.get("whitelists", {})
    lst = wl.get(str(guild_id), [])
    return set(int(x) for x in lst)

def is_whitelisted(guild_id: int, user_id: int) -> bool:
    wl = get_whitelist_for_guild(guild_id)
    return int(user_id) in wl

def add_whitelist_guild(guild_id: int, user_id: int):
    d = load_data()
    d.setdefault("whitelists", {})
    lst = d["whitelists"].setdefault(str(guild_id), [])
    if int(user_id) not in lst:
        lst.append(int(user_id))
    d["whitelists"][str(guild_id)] = sorted(list(set(lst)))
    save_data(d)

def remove_whitelist_guild(guild_id: int, user_id: int):
    d = load_data()
    d.setdefault("whitelists", {})
    lst = d["whitelists"].get(str(guild_id), [])
    lst = [int(x) for x in lst if int(x) != int(user_id)]
    d["whitelists"][str(guild_id)] = lst
    save_data(d)

# ---------------- Timeout compatibility ----------------
async def timeout_member(member: discord.Member, hours: int, reason: str = "Rate-limited by security bot"):
    if not member or not isinstance(member, discord.Member):
        return
    until = datetime.now(timezone.utc) + timedelta(hours=hours)
    try:
        await member.timeout(until=until, reason=reason)
        return
    except TypeError:
        try:
            await member.timeout(until, reason=reason)
            return
        except Exception as e:
            print(f"[!] Failed to timeout (positional) {member}: {e}")
    except AttributeError:
        try:
            await member.edit(timed_out_until=until, reason=reason)
            return
        except Exception as e:
            print(f"[!] Failed to timeout (edit) {member}: {e}")
    except discord.Forbidden:
        raise
    except Exception as e:
        print(f"[!] Timeout error: {e}")

# ---------------- Logging (shell-style) ----------------
async def log_shame_and_record(guild, attacker, action_str: str, status: str = "BLOCKED/LOGGED"):
    uid = getattr(attacker, "id", attacker)
    key = f"{uid}_{action_str}"
    now = asyncio.get_event_loop().time()
    if recent_logs[guild.id].get(key, 0) + 60 > now:
        return
    recent_logs[guild.id][key] = now

    shame_ch = await ensure_shame_channel(guild)
    logs_ch = await ensure_logs_channel(guild)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d • %H:%M:%S UTC")
    attacker_mention = f"<@{uid}>"
    lines = [
        "[SYSTEM: SECURITY ALERT]",
        "──────────────────────────────────────",
        f"User: {attacker_mention} (ID: {uid})",
        f"Action: {action_str}",
        f"Status: {status}",
        f"Time: {timestamp}",
        "──────────────────────────────────────"
    ]
    payload = shell_block(lines)
    for ch in (shame_ch, logs_ch):
        if ch:
            try:
                await ch.send(payload)
            except Exception:
                pass

# ---------------- Fast punish (0.1s) ----------------
async def fast_punish(guild: discord.Guild, actor, action_str: str):
    await asyncio.sleep(0.1)  # requested 0.1s
    # license check (MASTER OWNER bypass)
    if not license_valid_for_guild(guild.id) and getattr(actor, "id", None) != MASTER_OWNER_ID:
        await log_shame_and_record(guild, actor, action_str, status="LICENSE INACTIVE - SKIPPED PUNISH")
        return

    d = load_data()
    try:
        member = actor if isinstance(actor, discord.Member) else None
        if not member:
            aid = getattr(actor, "id", None)
            if aid:
                member = guild.get_member(aid)
                if not member:
                    try:
                        member = await guild.fetch_member(aid)
                    except Exception:
                        member = None
        if not member:
            await log_shame_and_record(guild, actor, f"User not found for fast punish {action_str}", status="USER NOT FOUND")
            return

        # whitelist check per guild
        if is_whitelisted(guild.id, member.id) or member.bot:
            return

        me = guild.me
        try:
            if member.top_role >= me.top_role:
                await log_shame_and_record(guild, member, f"Cannot punish higher-role member for {action_str}", status="HIERARCHY BLOCK")
                return
        except Exception:
            pass

        # Auto-Kick only (primary)
        if d.get("auto_kick", True):
            if not me.guild_permissions.kick_members:
                await log_shame_and_record(guild, member, f"Missing kick permission for fast punish {action_str}", status="MISSING PERM")
                return
            try:
                # no DM — silent quick kick
                await member.kick(reason=f"Auto-Kick (fast): {action_str}")
                await log_shame_and_record(guild, member, f"Auto-Kicked (fast) for {action_str}", status="AUTO-KICKED")
                return
            except Exception as e:
                print(f"[!] fast kick error: {e}")
                await log_shame_and_record(guild, member, f"Fast kick failed for {action_str}", status="FAILED")
                return

        # fallback: timeout
        if d.get("auto_timeout", True):
            if not me.guild_permissions.moderate_members:
                await log_shame_and_record(guild, member, f"Missing timeout permission for fast punish {action_str}", status="MISSING PERM")
                return
            try:
                hours = int(d.get("rate_limit_hours", 12))
                await timeout_member(member, hours, reason=f"Auto-Timeout (fast): {action_str}")
                await log_shame_and_record(guild, member, f"Timed Out (fast) for {action_str}", status="TIMED OUT")
                return
            except Exception as e:
                print(f"[!] fast timeout error: {e}")
                await log_shame_and_record(guild, member, f"Fast timeout failed for {action_str}", status="FAILED")
                return

    except Exception as e:
        print(f"[!] fast_punish error: {e}")

# ---------------- Generic handler ----------------
async def handle_attacker(guild: discord.Guild, attacker, action_str: str):
    if not license_valid_for_guild(guild.id) and getattr(attacker, "id", None) != MASTER_OWNER_ID:
        await log_shame_and_record(guild, attacker, action_str, status="LICENSE INACTIVE - SKIPPED")
        return
    d = load_data()
    if not guild or not attacker:
        return
    try:
        member = attacker if isinstance(attacker, discord.Member) else None
        if not member:
            aid = getattr(attacker, "id", None)
            if aid:
                member = guild.get_member(aid)
                if not member:
                    try:
                        member = await guild.fetch_member(aid)
                    except Exception:
                        member = None
        if not member:
            await log_shame_and_record(guild, attacker, f"User not found during {action_str}", status="USER NOT FOUND")
            return

        if is_whitelisted(guild.id, member.id) or member.bot:
            return

        me = guild.me
        try:
            if member.top_role >= me.top_role:
                await log_shame_and_record(guild, member, f"Cannot punish higher-role member for {action_str}", status="HIERARCHY BLOCK")
                return
        except Exception:
            pass

        if d.get("auto_kick", True):
            if not me.guild_permissions.kick_members:
                await log_shame_and_record(guild, member, f"Missing kick permission for {action_str}", status="MISSING PERM")
                return
            try:
                await member.kick(reason=f"Auto-Kick: {action_str}")
                await log_shame_and_record(guild, member, f"Auto-Kicked for {action_str}", status="AUTO-KICKED")
                return
            except discord.Forbidden:
                await log_shame_and_record(guild, member, f"Kick forbidden for {action_str}", status="FORBIDDEN")
                return
            except Exception as e:
                print(f"[!] Kick error: {e}")
                await log_shame_and_record(guild, member, f"Kick failed for {action_str}", status="FAILED")
                return

        if d.get("auto_timeout", True):
            if not me.guild_permissions.moderate_members:
                await log_shame_and_record(guild, member, f"Missing timeout permission for {action_str}", status="MISSING PERM")
                return
            try:
                hours = int(d.get("rate_limit_hours", 12))
                await timeout_member(member, hours, reason=action_str)
                await log_shame_and_record(guild, member, f"Timed Out for {action_str}", status="TIMED OUT")
                return
            except discord.Forbidden:
                await log_shame_and_record(guild, member, f"Timeout forbidden for {action_str}", status="FORBIDDEN")
                return
            except Exception as e:
                print(f"[!] Timeout error: {e}")
                await log_shame_and_record(guild, member, f"Timeout failed for {action_str}", status="FAILED")
                return

    except Exception as e:
        print(f"[!] handle_attacker error: {e}")

# ---------------- Security Panel UI ----------------
class SecurityPanel(ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    async def update_embed_for_guild(self, guild: discord.Guild, message: discord.Message):
        d = load_data()
        status = (
            f"Auto-Kick: {'ON' if d.get('auto_kick') else 'OFF'}\n"
            f"Auto-Timeout: {'ON' if d.get('auto_timeout') else 'OFF'}\n"
            f"Anti-ChannelCreate: {'ON' if d.get('anti_channel_create') else 'OFF'}\n"
            f"Anti-ChannelDelete: {'ON' if d.get('anti_channel_delete') else 'OFF'}\n"
            f"Anti-RoleCreate: {'ON' if d.get('anti_role_create') else 'OFF'}\n"
            f"Anti-RoleDelete: {'ON' if d.get('anti_role_delete') else 'OFF'}\n"
            f"Anti-RoleUpdate: {'ON' if d.get('anti_role_update') else 'OFF'}\n"
            f"Anti-Webhook: {'ON' if d.get('anti_webhook') else 'OFF'}\n"
            f"Anti-Rename: {'ON' if d.get('anti_raid') else 'OFF'}"
        )
        lic_info = "No active license"
        l = load_licenses()
        for k, v in l.get("keys", {}).items():
            if v.get("guild_id") == guild.id:
                exp = v.get("expires_at")
                if exp == "permanent":
                    lic_info = "Key: permanent"
                else:
                    exp_dt = iso_to_dt(exp)
                    if exp_dt:
                        now = datetime.now(timezone.utc)
                        remaining = exp_dt - now
                        if remaining.total_seconds() < 0:
                            lic_info = "Key: expired"
                        else:
                            days = remaining.days
                            hrs, rem = divmod(remaining.seconds, 3600)
                            mins, secs = divmod(rem, 60)
                            lic_info = f"Key expires in {days}d {hrs}h {mins}m {secs}s"
                break

        # show small whitelist count for the guild
        wl = get_whitelist_for_guild(guild.id)
        embed = discord.Embed(
            title="SECURITY CONTROL PANEL",
            description=f"Use the buttons to toggle features.\n\n{status}\n\nLicense: {lic_info}\nWhitelist count: {len(wl)}",
            color=0x2b2d31
        )
        try:
            await message.edit(embed=embed, view=self)
        except Exception:
            pass

    @ui.button(label="Add Whitelist (enter ID)", style=ButtonStyle.green)
    async def whitelist_add(self, interaction: discord.Interaction, button: ui.Button):
        await interaction.response.send_message("Send the User ID to add to whitelist (this guild):", ephemeral=True)
        def check(m): return m.author == interaction.user and m.channel == interaction.channel
        try:
            msg = await bot.wait_for("message", check=check, timeout=60)
            uid = int(msg.content.strip())
            add_whitelist_guild(interaction.guild.id, uid)
            await interaction.followup.send(f"Added <@{uid}> to whitelist for this server.", ephemeral=True)
            # refresh panel
            await self.update_embed_for_guild(interaction.guild, interaction.message)
        except asyncio.TimeoutError:
            await interaction.followup.send("Timeout waiting for ID.", ephemeral=True)
        except Exception as e:
            await interaction.followup.send(f"Error: {e}", ephemeral=True)

    @ui.button(label="Remove Whitelist (enter ID)", style=ButtonStyle.red)
    async def whitelist_remove(self, interaction: discord.Interaction, button: ui.Button):
        await interaction.response.send_message("Send the User ID to remove from whitelist (this guild):", ephemeral=True)
        def check(m): return m.author == interaction.user and m.channel == interaction.channel
        try:
            msg = await bot.wait_for("message", check=check, timeout=60)
            uid = int(msg.content.strip())
            remove_whitelist_guild(interaction.guild.id, uid)
            await interaction.followup.send(f"Removed <@{uid}> from whitelist for this server.", ephemeral=True)
            await self.update_embed_for_guild(interaction.guild, interaction.message)
        except asyncio.TimeoutError:
            await interaction.followup.send("Timeout waiting for ID.", ephemeral=True)
        except Exception as e:
            await interaction.followup.send(f"Error: {e}", ephemeral=True)

    @ui.button(label="Toggle Auto-Kick", style=ButtonStyle.gray)
    async def toggle_autokick(self, interaction: discord.Interaction, button: ui.Button):
        d = load_data()
        d["auto_kick"] = not d.get("auto_kick", True)
        if d["auto_kick"]:
            d["auto_timeout"] = False
        save_data(d)
        await self.update_embed_for_guild(interaction.guild, interaction.message)
        await interaction.followup.send(f"Auto-Kick set to {d['auto_kick']}", ephemeral=True)

    @ui.button(label="Toggle Auto-Timeout", style=ButtonStyle.secondary)
    async def toggle_autotimeout(self, interaction: discord.Interaction, button: ui.Button):
        d = load_data()
        d["auto_timeout"] = not d.get("auto_timeout", True)
        if d["auto_timeout"]:
            d["auto_kick"] = False
        save_data(d)
        await self.update_embed_for_guild(interaction.guild, interaction.message)
        await interaction.followup.send(f"Auto-Timeout set to {d['auto_timeout']}", ephemeral=True)

    @ui.button(label="Toggle Anti-ChannelCreate", style=ButtonStyle.blurple)
    async def toggle_anti_channel_create(self, interaction: discord.Interaction, button: ui.Button):
        d = load_data()
        d["anti_channel_create"] = not d.get("anti_channel_create", True)
        save_data(d)
        await self.update_embed_for_guild(interaction.guild, interaction.message)
        await interaction.followup.send(f"Anti-ChannelCreate set to {d['anti_channel_create']}", ephemeral=True)

    @ui.button(label="Toggle Anti-ChannelDelete", style=ButtonStyle.blurple)
    async def toggle_anti_channel_create(self, interaction: discord.Interaction, button: ui.Button):
        d = load_data()
        d["anti_channel_delete"] = not d.get("anti_channel_delete", True)
        save_data(d)
        await self.update_embed_for_guild(interaction.guild, interaction.message)
        await interaction.followup.send(f"Anti-ChannelDelete set to {d['anti_channel_delete']}", ephemeral=True)    

    @ui.button(label="Toggle Anti-RoleCreate", style=ButtonStyle.gray)
    async def toggle_anti_role_create(self, interaction: discord.Interaction, button: ui.Button):
        d = load_data()
        d["anti_role_create"] = not d.get("anti_role_create", True)
        save_data(d)
        await self.update_embed_for_guild(interaction.guild, interaction.message)
        await interaction.followup.send(f"Anti-RoleCreate set to {d['anti_role_create']}", ephemeral=True)

    @ui.button(label="Toggle Anti-RoleDelete", style=ButtonStyle.secondary)
    async def toggle_anti_role_delete(self, interaction: discord.Interaction, button: ui.Button):
        d = load_data()
        d["anti_role_delete"] = not d.get("anti_role_delete", True)
        save_data(d)
        await self.update_embed_for_guild(interaction.guild, interaction.message)
        await interaction.followup.send(f"Anti-RoleDelete set to {d['anti_role_delete']}", ephemeral=True)

    @ui.button(label="Toggle Anti-RoleUpdate", style=ButtonStyle.secondary)
    async def toggle_anti_role_update(self, interaction: discord.Interaction, button: ui.Button):
        d = load_data()
        d["anti_role_update"] = not d.get("anti_role_update", True)
        save_data(d)
        await self.update_embed_for_guild(interaction.guild, interaction.message)
        await interaction.followup.send(f"Anti-RoleUpdate set to {d['anti_role_update']}", ephemeral=True)

    @ui.button(label="Toggle Anti-Webhook", style=ButtonStyle.blurple)
    async def toggle_anti_webhook(self, interaction: discord.Interaction, button: ui.Button):
        d = load_data()
        d["anti_webhook"] = not d.get("anti_webhook", True)
        save_data(d)
        await self.update_embed_for_guild(interaction.guild, interaction.message)
        await interaction.followup.send(f"Anti-Webhook set to {d['anti_webhook']}", ephemeral=True)

    @ui.button(label="Refresh Panel", style=ButtonStyle.green)
    async def refresh_panel(self, interaction: discord.Interaction, button: ui.Button):
        await self.update_embed_for_guild(interaction.guild, interaction.message)
        await interaction.followup.send("Panel refreshed.", ephemeral=True)

# ---------------- Verify button ----------------
class VerifyButton(ui.View):
    def __init__(self, verify_role):
        super().__init__(timeout=None)
        self.verify_role = verify_role

    @ui.button(label="Verify", style=ButtonStyle.gray)
    async def verify(self, interaction: discord.Interaction, button: ui.Button):
        member = interaction.user
        try:
            if self.verify_role not in member.roles:
                await member.add_roles(self.verify_role, reason="Verified")
                await interaction.response.send_message("You have been verified!", ephemeral=True)
            else:
                await interaction.response.send_message("You are already verified.", ephemeral=True)
        except Exception:
            await interaction.response.send_message("Failed to add role (missing perms).", ephemeral=True)

# ---------------- Key management / master commands ----------------
@bot.command(name="genkey")
async def genkey(ctx: commands.Context, duration: str):
    if ctx.author.id != MASTER_OWNER_ID:
        return await ctx.send("Only the master owner can generate keys.", delete_after=8)
    if duration not in ("7d", "30d", "permanent"):
        return await ctx.send("Invalid duration. Use 7d, 30d, or permanent.", delete_after=8)
    key = generate_key(32)
    l = load_licenses()
    l.setdefault("keys", {})
    issued = now_iso()
    expires = make_expiry(duration)
    l["keys"][key] = {
        "duration": duration,
        "issued_at": issued,
        "expires_at": expires,
        "used": False,
        "user_id": None,
        "guild_id": None
    }
    save_licenses(l)
    try:
        await ctx.author.send(f"```Generated key: {key}\nDuration: {duration}\nExpires: {expires}```")
    except Exception:
        pass
    await ctx.send("Key generated and DM'd to you.")
    await post_webhook(f"Key generated by master owner. Key: {key} | duration: {duration} | expires: {expires}")

@bot.command(name="revoke")
async def revoke(ctx: commands.Context, key: str):
    if ctx.author.id != MASTER_OWNER_ID:
        return await ctx.send("Only the master owner can revoke keys.", delete_after=8)
    l = load_licenses()
    if key in l.get("keys", {}):
        rec = l["keys"][key]
        guild_id = rec.get("guild_id")
        del l["keys"][key]
        save_licenses(l)
        if guild_id:
            g = bot.get_guild(int(guild_id))
            if g:
                d = load_data()
                for ch_name in (d.get("panel_channel_name", "security-panel"), d.get("logs_channel_name", "security-logs"), d.get("shame_channel_name", "shame")):
                    ch = discord.utils.get(g.channels, name=ch_name)
                    if ch:
                        try:
                            await ch.delete(reason=f"Key {key} revoked by master owner")
                        except Exception:
                            pass
        await ctx.send("Key revoked.")
        await post_webhook(f"Key revoked by master owner: {key}")
    else:
        await ctx.send("Key not found.")

@bot.command(name="revokekey")
async def revokekey(ctx: commands.Context, userid: int):
    if ctx.author.id != MASTER_OWNER_ID:
        return await ctx.send("Only the master owner can revoke keys.", delete_after=8)
    l = load_licenses()
    changed = False
    for k, v in list(l.get("keys", {}).items()):
        if v.get("user_id") == userid:
            guild_id = v.get("guild_id")
            del l["keys"][k]
            changed = True
            if guild_id:
                g = bot.get_guild(int(guild_id))
                if g:
                    d = load_data()
                    for ch_name in (d.get("panel_channel_name", "security-panel"), d.get("logs_channel_name", "security-logs"), d.get("shame_channel_name", "shame")):
                        ch = discord.utils.get(g.channels, name=ch_name)
                        if ch:
                            try:
                                await ch.delete(reason=f"Key revoked for user {userid}")
                            except Exception:
                                pass
    if changed:
        save_licenses(l)
        await ctx.send("Revoked keys for that user and removed their server channels (if the bot is in that server).")
        await post_webhook(f"Keys revoked for user {userid} by master owner.")
    else:
        await ctx.send("No keys found for that user.")

@bot.command(name="listkeys")
async def listkeys(ctx: commands.Context):
    if ctx.author.id != MASTER_OWNER_ID:
        return await ctx.send("Only the master owner can list keys.", delete_after=8)
    l = load_licenses()
    lines = ["Key -> user_id -> guild_id -> expires_at -> used"]
    for k, v in l.get("keys", {}).items():
        lines.append(f"{k} -> {v.get('user_id')} -> {v.get('guild_id')} -> {v.get('expires_at')} -> {v.get('used')}")
    try:
        await ctx.author.send(shell_block(lines))
    except Exception:
        pass
    await ctx.send("Sent key list to master owner via DM.")

# ---------------- Buyer commands ----------------
@bot.command(name="login")
async def login(ctx: commands.Context, key: str):
    guild = ctx.guild or await find_guild()
    if not guild:
        return await ctx.send("This command must be used in a guild.")
    if ctx.author.id != guild.owner_id:
        return await ctx.send("Only the server owner can use this command.", delete_after=8)

    ok, reason = key_is_valid_and_avail(key)
    if not ok:
        return await ctx.send(f"Key invalid: {reason}", delete_after=12)

    l = load_licenses()
    rec = l["keys"].get(key)
    if not rec:
        return await ctx.send("Key not found (race).", delete_after=8)

    rec["used"] = True
    rec["user_id"] = ctx.author.id
    rec["guild_id"] = guild.id
    l["keys"][key] = rec
    save_licenses(l)

    await ctx.send("License activated for this server. Panel and anti features are enabled.")
    await post_webhook(f"Key used: {key} | guild: {guild.id} | user: {ctx.author.id} | expires: {rec.get('expires_at')}")

@bot.command(name="logout")
async def logout(ctx: commands.Context):
    guild = ctx.guild or await find_guild()
    if not guild:
        return await ctx.send("This command must be used in a guild.")
    if ctx.author.id != guild.owner_id:
        return await ctx.send("Only the server owner can use this command.", delete_after=8)

    l = load_licenses()
    changed = False
    for k, v in list(l.get("keys", {}).items()):
        if v.get("guild_id") == guild.id:
            v["guild_id"] = None
            v["user_id"] = None
            v["used"] = False
            l["keys"][k] = v
            changed = True
    if changed:
        save_licenses(l)
        await ctx.send("License removed from this server. Bot features are now disabled until reactivation.")
        await post_webhook(f"License removed for guild {guild.id} by owner {ctx.author.id}")
    else:
        await ctx.send("No active license found for this server.")

@bot.command(name="license")
async def license_info(ctx: commands.Context):
    guild = ctx.guild or await find_guild()
    if not guild:
        return await ctx.send("This command must be used in a guild.")
    l = load_licenses()
    for k, v in l.get("keys", {}).items():
        if v.get("guild_id") == guild.id:
            lines = [
                f"Key: {k}",
                f"Duration: {v.get('duration')}",
                f"Issued at: {v.get('issued_at')}",
                f"Expires at: {v.get('expires_at')}",
                f"Bound user: {v.get('user_id')}",
                f"Guild: {v.get('guild_id')}"
            ]
            return await ctx.send(shell_block(lines))
    return await ctx.send("No active license for this server.")

# ---------------- addpanel ----------------
@bot.command(name="addpanel")
@commands.has_permissions(administrator=True)
async def addpanel(ctx: commands.Context):
    guild = ctx.guild or await find_guild()
    if not guild:
        return await ctx.send("Guild not found.")

    if ctx.author.id != MASTER_OWNER_ID:
        if not license_valid_for_guild(guild.id):
            return await ctx.send("Your server is not licensed or license expired. Activate with !login <key>.", delete_after=12)

    d = load_data()
    panel_name = d.get("panel_channel_name", "security-panel")
    logs_name = d.get("logs_channel_name", "security-logs")
    shame_ch = await ensure_shame_channel(guild)
    verify_role = await ensure_role(guild, d.get("verify_role_name", "$verified"))

    async def ensure_verify_channel_inner(guild: discord.Guild, verify_role: discord.Role):
        verify_channel_name = d.get("verify_channel_name", "verify")
        existing = discord.utils.get(guild.text_channels, name=verify_channel_name)
        if existing:
            return existing
        overwrites = {
            guild.default_role: PermissionOverwrite(view_channel=True, send_messages=False, read_message_history=True),
            verify_role: PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
            guild.me: PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)
        }
        return await guild.create_text_channel(verify_channel_name, overwrites=overwrites, reason="Verify channel created")

    verify_ch = await ensure_verify_channel_inner(guild, verify_role)

    overwrite_everyone = PermissionOverwrite(view_channel=False)
    overwrite_owner = PermissionOverwrite(view_channel=True, send_messages=True, manage_messages=True)
    overwrite_bot = PermissionOverwrite(view_channel=True, send_messages=True, manage_messages=True)

    existing_panel = discord.utils.get(guild.text_channels, name=panel_name)
    panel = existing_panel or await guild.create_text_channel(
        panel_name,
        overwrites={guild.default_role: overwrite_everyone, ctx.author: overwrite_owner, guild.me: overwrite_bot},
        reason="Security panel created"
    )
    try:
        await panel.purge(limit=50)
    except Exception:
        pass

    existing_logs = discord.utils.get(guild.text_channels, name=logs_name)
    logs_ch = existing_logs or await guild.create_text_channel(
        logs_name,
        overwrites={guild.default_role: overwrite_everyone, ctx.author: overwrite_owner, guild.me: overwrite_bot},
        reason="Security logs channel"
    )

    parts = []
    if BACKGROUND_IMG_URL:
        parts.append(BACKGROUND_IMG_URL)
    if guild.icon:
        parts.append(str(guild.icon.url))
    for p in parts:
        try:
            await panel.send(p)
        except Exception:
            pass

    view = SecurityPanel()
    d = load_data()
    status = (
        f"Auto-Kick: {'ON' if d.get('auto_kick') else 'OFF'}\n"
        f"Auto-Timeout: {'ON' if d.get('auto_timeout') else 'OFF'}\n"
        f"Anti-ChannelCreate: {'ON' if d.get('anti_channel_create') else 'OFF'}\n"
        f"Anti-ChannelDelete: {'ON' if d.get('anti_channel_delete') else 'OFF'}\n"
        f"Anti-RoleCreate: {'ON' if d.get('anti_role_create') else 'OFF'}\n"
        f"Anti-RoleDelete: {'ON' if d.get('anti_role_delete') else 'OFF'}\n"
        f"Anti-RoleUpdate: {'ON' if d.get('anti_role_update') else 'OFF'}\n"
        f"Anti-Webhook: {'ON' if d.get('anti_webhook') else 'OFF'}\n"
        f"Anti-Rename: {'ON' if d.get('anti_raid') else 'OFF'}"
    )
    embed = discord.Embed(
        title="SECURITY CONTROL PANEL",
        description=f"Use the buttons below to manage whitelist and toggles.\n\n{status}",
        color=0x2b2d31
    )
    sent = await panel.send(embed=embed, view=view)

    # save panel message id for live updates
    panel_message_map[guild.id] = sent.id
    d.setdefault("panel_messages", {})[str(guild.id)] = sent.id
    save_data(d)

    if verify_ch:
        try:
            await verify_ch.send("Press the button below to verify yourself.", view=VerifyButton(verify_role))
        except Exception:
            pass

    try:
        await ctx.author.send(
            f"Panel created: {panel.mention}\n"
            f"Shame logs: {shame_ch.mention}\n"
            f"Security logs: {logs_ch.mention}\n"
            f"Verify channel: {verify_ch.mention}"
        )
    except Exception:
        pass

    await ctx.send(f"Security panel created in {panel.mention}")

# ---------------- Anti events ----------------
@bot.event
async def on_guild_channel_update(before: discord.abc.GuildChannel, after: discord.abc.GuildChannel):
    d = load_data()
    if not d.get("anti_raid", True):
        return
    guild = after.guild
    if not license_valid_for_guild(guild.id):
        return
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_update):
            actor = entry.user
            break
        else:
            return
    except Exception:
        return
    if is_whitelisted(guild.id, actor.id) or actor.bot:
        return
    if before.name != after.name:
        now = asyncio.get_event_loop().time()
        q = recent_renames[actor.id]
        q.append(now)
        while q and now - q[0] > 30:
            q.popleft()
        if len(q) >= 3:
            try:
                await after.edit(name=before.name, reason="Anti-Raid: mass rename revert")
            except Exception:
                pass
            await log_shame_and_record(guild, actor, "Mass Channel Rename Detected", status="REVERTED")
            await fast_punish(guild, actor, "Mass Channel Rename Detected")

@bot.event
async def on_webhooks_update(channel):
    d = load_data()
    if not d.get("anti_webhook", True):
        return
    guild = channel.guild
    if not license_valid_for_guild(guild.id):
        return
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.webhook_create):
            actor = entry.user
            break
        else:
            return
    except Exception:
        return
    if is_whitelisted(guild.id, actor.id) or actor.bot:
        return
    try:
        hooks = await channel.webhooks()
        for wh in hooks:
            try:
                await wh.delete(reason="Anti-Webhook: unauthorized")
            except Exception:
                pass
        await log_shame_and_record(guild, actor, "Unauthorized Webhook Creation", status="DELETED")
        await fast_punish(guild, actor, "Unauthorized Webhook Creation")
    except Exception:
        await log_shame_and_record(guild, actor, "Unauthorized Webhook Creation", status="ERROR")

@bot.event
async def on_guild_channel_create(channel):
    d = load_data()
    if not d.get("anti_channel_create", True):
        return
    guild = channel.guild
    if not license_valid_for_guild(guild.id):
        return
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_create):
            actor = entry.user
            break
        else:
            return
    except Exception:
        return
    if is_whitelisted(guild.id, actor.id) or actor.bot:
        return
    try:
        await channel.delete(reason="Anti-Raid: Unauthorized Channel Create")
    except Exception:
        pass
    await log_shame_and_record(guild, actor, "Unauthorized Channel Creation", status="DELETED")
    await fast_punish(guild, actor, "Unauthorized Channel Creation")

@bot.event
async def on_guild_channel_delete(channel):
    d = load_data()
    if not d.get("anti_channel_delete", True):
        return
    guild = channel.guild
    if not license_valid_for_guild(guild.id):
        return
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_delete):
            actor = entry.user
            break
        else:
            return
    except Exception:
        return
    if is_whitelisted(guild.id, actor.id) or actor.bot:
        return
    try:
        await channel.delete(reason="Anti-Raid: Unauthorized Channel Delete")
    except Exception:
        pass
    await log_shame_and_record(guild, actor, "Unauthorized Channel Delete", status="DELETED")
    await fast_punish(guild, actor, "Unauthorized Channel Delete")    

@bot.event
async def on_guild_role_create(role):
    d = load_data()
    if not d.get("anti_role_create", True):
        return
    guild = role.guild
    if not license_valid_for_guild(guild.id):
        return
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.role_create):
            actor = entry.user
            break
        else:
            return
    except Exception:
        return
    if is_whitelisted(guild.id, actor.id) or actor.bot:
        return
    try:
        await role.delete(reason="Anti-Raid: Unauthorized Role Creation")
    except Exception:
        pass
    await log_shame_and_record(guild, actor, "Unauthorized Role Creation", status="DELETED")
    await fast_punish(guild, actor, "Unauthorized Role Creation")

@bot.event
async def on_guild_role_delete(role):
    d = load_data()
    if not d.get("anti_role_delete", True):
        return
    guild = role.guild
    if not license_valid_for_guild(guild.id):
        return
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.role_delete):
            actor = entry.user
            break
        else:
            return
    except Exception:
        return
    if is_whitelisted(guild.id, actor.id) or actor.bot:
        return
    await log_shame_and_record(guild, actor, "Unauthorized Role Deletion", status="DETECTED")
    await fast_punish(guild, actor, "Unauthorized Role Deletion")

@bot.event
async def on_guild_role_update(before: discord.Role, after: discord.Role):
    d = load_data()
    if not d.get("anti_role_update", True):
        return
    guild = after.guild
    if not license_valid_for_guild(guild.id):
        return
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.role_update):
            actor = entry.user
            break
        else:
            return
    except Exception:
        return
    if is_whitelisted(guild.id, actor.id) or actor.bot:
        return
    perm_changed = before.permissions != after.permissions
    name_changed = before.name != after.name
    if perm_changed or name_changed:
        try:
            await after.edit(name=before.name, permissions=before.permissions, reason="Anti-Raid: revert role update")
        except Exception:
            pass
        await log_shame_and_record(guild, actor, "Unauthorized Role Update", status="REVERTED")
        await fast_punish(guild, actor, "Unauthorized Role Update")

@bot.event
async def on_guild_update(before: discord.Guild, after: discord.Guild):
    d = load_data()
    if not d.get("anti_raid", True):
        return
    guild = after
    if not license_valid_for_guild(guild.id):
        return
    try:
        before_v = getattr(before, "vanity_url_code", None)
        after_v = getattr(after, "vanity_url_code", None)
        if before_v == after_v:
            return
    except Exception:
        pass
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.guild_update):
            actor = entry.user
            break
        else:
            return
    except Exception:
        return
    if is_whitelisted(guild.id, actor.id) or actor.bot:
        return
    await log_shame_and_record(guild, actor, "Vanity URL Change Detected", status="DETECTED")
    await fast_punish(guild, actor, "Vanity URL Change Detected")

# ---------------- Spam detection -> timeout only ----------------
@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        await bot.process_commands(message)
        return
    d = load_data()
    threshold = int(d.get("spam_delete_threshold", 5))
    window = int(d.get("spam_delete_window", 5))
    strikes_needed = int(d.get("spam_strike_timeout_threshold", 1))
    uid = message.author.id
    now = asyncio.get_event_loop().time()
    q = spam_tracker[uid]
    q.append(now)
    while q and now - q[0] > window:
        q.popleft()
    if threshold > 0 and len(q) >= threshold:
        try:
            await message.channel.purge(limit=200, check=lambda m: m.author.id == uid)
        except Exception:
            pass
        spam_strikes[uid] += 1
        try:
            await log_shame_and_record(message.guild, message.author, "Spam messages auto-deleted", status="SPAM_DELETED")
        except Exception:
            pass
        if spam_strikes[uid] >= strikes_needed:
            try:
                await timeout_member(message.author, int(d.get("rate_limit_hours", 12)), reason="Spam rate-limit")
                spam_strikes[uid] = 0
            except Exception:
                pass
    await bot.process_commands(message)

# ---------------- Background tasks ----------------
@tasks.loop(minutes=1)
async def expire_check():
    l = load_licenses()
    changed = False
    for k, v in list(l.get("keys", {}).items()):
        exp = v.get("expires_at")
        if exp == "permanent":
            continue
        exp_dt = iso_to_dt(exp)
        if not exp_dt:
            continue
        if exp_dt < datetime.now(timezone.utc):
            if v.get("guild_id"):
                guild_id = v.get("guild_id")
                v["guild_id"] = None
                v["used"] = True
                v["user_id"] = None
                l["keys"][k] = v
                changed = True
                await post_webhook(f"License expired: key {k} expired and was unbound from guild {guild_id}")
                g = bot.get_guild(int(guild_id))
                if g:
                    d = load_data()
                    for ch_name in (d.get("panel_channel_name", "security-panel"), d.get("logs_channel_name", "security-logs"), d.get("shame_channel_name", "shame")):
                        ch = discord.utils.get(g.channels, name=ch_name)
                        if ch:
                            try:
                                await ch.delete(reason="License expired")
                            except Exception:
                                pass
    if changed:
        save_licenses(l)

@tasks.loop(seconds=5)
async def panel_updater():
    d = load_data()
    pm = d.get("panel_messages", {})
    for guild_id_str, msg_id in list(pm.items()):
        try:
            guild_id = int(guild_id_str)
            g = bot.get_guild(guild_id)
            if not g:
                continue
            ch = discord.utils.get(g.text_channels, name=d.get("panel_channel_name", "security-panel"))
            if not ch:
                continue
            try:
                msg = await ch.fetch_message(int(msg_id))
            except Exception:
                continue
            view = SecurityPanel()
            await view.update_embed_for_guild(g, msg)
        except Exception:
            continue

# ---------------- Bot ready ----------------
@bot.event
async def on_ready():
    print(f"Security Bot ready: {bot.user} (ID {bot.user.id})")
    try:
        await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="Anti-Raid-Bot"))
    except Exception:
        pass

    g = await find_guild()
    if g:
        await ensure_shame_channel(g)
        await ensure_logs_channel(g)
    else:
        print("Warning: No guild detected.")

    if not expire_check.is_running():
        expire_check.start()
    if not panel_updater.is_running():
        panel_updater.start()

# ---------------- Run ----------------
if __name__ == "__main__":
    bot.run(TOKEN)

 


