import asyncio
import logging
import re
from datetime import datetime

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.utils.chat_action import ChatActionSender

import aiohttp
import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)

BOT_TOKEN = os.getenv('BOT_TOKEN')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
DAILY_FREE_CHECKS = 5

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

URL_PATTERN = re.compile(
    r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
)

def init_db():
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            daily_checks INTEGER DEFAULT 0,
            last_check_date TEXT,
            total_checks INTEGER DEFAULT 0,
            referral_code TEXT UNIQUE,
            referred_by INTEGER,
            referral_count INTEGER DEFAULT 0,
            joined_date TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT,
            result TEXT,
            is_malicious BOOLEAN,
            checked_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def get_user(user_id):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            'user_id': row[0], 'username': row[1], 'first_name': row[2],
            'last_name': row[3], 'daily_checks': row[4], 'last_check_date': row[5],
            'total_checks': row[6], 'referral_code': row[7], 'referred_by': row[8],
            'referral_count': row[9], 'joined_date': row[10]
        }
    return None

def create_user(user_id, username, first_name, last_name, referred_by=None):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    referral_code = f"ref_{user_id}"
    cursor.execute('''
        INSERT OR IGNORE INTO users 
        (user_id, username, first_name, last_name, referral_code, referred_by)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, username, first_name, last_name, referral_code, referred_by))
    if referred_by:
        cursor.execute('UPDATE users SET referral_count = referral_count + 1 WHERE user_id = ?', (referred_by,))
    conn.commit()
    conn.close()

def check_daily_usage(user_id):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    today = datetime.now().strftime('%Y-%m-%d')
    cursor.execute('SELECT daily_checks, last_check_date FROM users WHERE user_id = ?', (user_id,))
    row = cursor.fetchone()
    if row:
        daily_checks, last_date = row
        if last_date == today:
            result = daily_checks, max(0, DAILY_FREE_CHECKS - daily_checks)
        else:
            cursor.execute('UPDATE users SET daily_checks = 0, last_check_date = ? WHERE user_id = ?', (today, user_id))
            conn.commit()
            result = 0, DAILY_FREE_CHECKS
    else:
        result = 0, DAILY_FREE_CHECKS
    conn.close()
    return result

def increment_checks(user_id):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    today = datetime.now().strftime('%Y-%m-%d')
    cursor.execute('UPDATE users SET daily_checks = daily_checks + 1, total_checks = total_checks + 1, last_check_date = ? WHERE user_id = ?', (today, user_id))
    conn.commit()
    conn.close()

def save_check_result(user_id, url, result_text, is_malicious):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO url_checks (user_id, url, result, is_malicious) VALUES (?, ?, ?, ?)', (user_id, url, result_text, is_malicious))
    conn.commit()
    conn.close()

async def check_url_virustotal(url):
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "your_virustotal_api_key_here":
        return {"malicious": False, "score": 0}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}) as response:
                if response.status != 200:
                    return {"malicious": False, "score": 0}
                result = await response.json()
                scan_id = result.get("data", {}).get("id")
            if scan_id:
                await asyncio.sleep(3)
                async with session.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers) as response:
                    if response.status == 200:
                        analysis = await response.json()
                        stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
                        malicious = stats.get("malicious", 0)
                        return {"malicious": malicious > 0, "score": malicious}
        except Exception as e:
            logging.error(f"VirusTotal error: {e}")
    return {"malicious": False, "score": 0}

async def analyze_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    vt_result = await check_url_virustotal(url)
    is_malicious = vt_result.get("malicious", False)
    return {
        "url": url,
        "is_malicious": is_malicious,
        "message": "🚨 ОБНАРУЖЕНА УГРОЗА!" if is_malicious else "✅ Ссылка безопасна"
    }

@dp.message(Command("start"))
async def cmd_start(message: Message):
    user = message.from_user
    args = message.text.split()
    referred_by = None
    if len(args) > 1 and args[1].startswith('ref_'):
        try:
            ref_user_id = int(args[1].split('_')[1])
            if ref_user_id != user.id:
                referred_by = ref_user_id
        except:
            pass
    if not get_user(user.id):
        create_user(user.id, user.username or "", user.first_name or "", user.last_name or "", referred_by)
    welcome_text = f"🛡️ Добро пожаловать, {user.first_name}!\n\nЯ помогу проверить любую ссылку на вирусы и фишинг.\n\n📊 У вас {DAILY_FREE_CHECKS} бесплатных проверок в день.\n👥 Приглашайте друзей и получайте больше проверок!\n\nПросто отправь мне ссылку или добавь меня в группу."
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👥 Реферальная система", callback_data="referral")],
        [InlineKeyboardButton(text="📊 Моя статистика", callback_data="stats")],
        [InlineKeyboardButton(text="➕ Добавить в группу", url=f"https://t.me/{bot._me.username}?startgroup=true")]
    ])
    await message.answer(welcome_text, reply_markup=keyboard)

@dp.message(F.text)
async def handle_message(message: Message):
    urls = URL_PATTERN.findall(message.text)
    if urls:
        await check_urls(message, urls)
    else:
        await message.answer("🔍 Отправьте мне ссылку для проверки.\nНапример: https://example.com")

async def check_urls(message: Message, urls):
    user_id = message.from_user.id
    if message.chat.type == 'private':
        used, remaining = check_daily_usage(user_id)
        if remaining <= 0:
            keyboard = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="👥 Пригласить друга", callback_data="referral")]
            ])
            await message.answer("⚠️ Вы исчерпали лимит бесплатных проверок на сегодня.\nПригласите друга, чтобы получить больше!", reply_markup=keyboard)
            return
    for url in urls[:3]:
        async with ChatActionSender.typing(bot=bot, chat_id=message.chat.id):
            result = await analyze_url(url)
            if message.chat.type == 'private':
                save_check_result(user_id, url, result['message'], result['is_malicious'])
                increment_checks(user_id)
            if result['is_malicious']:
                response = f"🚨 <b>ВНИМАНИЕ! ОБНАРУЖЕНА УГРОЗА!</b>\n\nСсылка: {result['url']}\nСтатус: ⚠️ {result['message']}\n\n❌ <b>Не переходите по этой ссылке!</b>"
            else:
                response = f"✅ <b>Ссылка безопасна</b>\n\nСсылка: {result['url']}\nСтатус: {result['message']}\n\n"
            await message.answer(response, parse_mode="HTML")
            await asyncio.sleep(1)

@dp.callback_query(F.data == "referral")
async def show_referral(callback: CallbackQuery):
    user = get_user(callback.from_user.id)
    if not user:
        await callback.answer("Ошибка!")
        return
    ref_link = f"https://t.me/{bot._me.username}?start={user['referral_code']}"
    text = f"👥 <b>Реферальная система</b>\n\nПриглашайте друзей и получайте бонусы:\n• За каждого друга +5 проверок в день\n\n📊 Вы пригласили: <b>{user['referral_count']} друзей</b>\n\n🔗 Ваша реферальная ссылка:\n{ref_link}\n\n<i>Просто отправьте эту ссылку друзьям!</i>"
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔗 Поделиться ссылкой", url=f"https://t.me/share/url?url={ref_link}&text=Проверяй%20ссылки%20на%20вирусы%20бесплатно!")],
        [InlineKeyboardButton(text="◀️ Назад", callback_data="main_menu")]
    ])
    await callback.message.edit_text(text, parse_mode="HTML", reply_markup=keyboard)
    await callback.answer()

@dp.callback_query(F.data == "stats")
async def show_stats(callback: CallbackQuery):
    user = get_user(callback.from_user.id)
    if not user:
        await callback.answer("Ошибка!")
        return
    used, remaining = check_daily_usage(callback.from_user.id)
    text = f"📊 <b>Ваша статистика</b>\n\n✅ Всего проверок: <b>{user['total_checks']}</b>\n📅 Использовано сегодня: <b>{used}/{DAILY_FREE_CHECKS}</b>\n💎 Осталось сегодня: <b>{remaining}</b>\n👥 Приглашено друзей: <b>{user['referral_count']}</b>\n📅 В боте с: {user['joined_date'][:10]}\n\n"
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👥 Реферальная система", callback_data="referral")],
        [InlineKeyboardButton(text="◀️ Назад", callback_data="main_menu")]
    ])
    await callback.message.edit_text(text, parse_mode="HTML", reply_markup=keyboard)
    await callback.answer()

@dp.callback_query(F.data == "main_menu")
async def main_menu(callback: CallbackQuery):
    user = callback.from_user
    text = f"🛡️ Главное меню, {user.first_name}!\n\nЯ помогу проверить любую ссылку на вирусы.\n\nПросто отправь мне ссылку."
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👥 Реферальная система", callback_data="referral")],
        [InlineKeyboardButton(text="📊 Моя статистика", callback_data="stats")],
        [InlineKeyboardButton(text="➕ Добавить в группу", url=f"https://t.me/{bot._me.username}?startgroup=true")]
    ])
    await callback.message.edit_text(text, reply_markup=keyboard)
    await callback.answer()

async def main():
    init_db()
    await bot.delete_webhook(drop_pending_updates=True)
    print("Бот запущен!")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
