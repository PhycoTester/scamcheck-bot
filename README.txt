ScamCheck Bot (Windows 10, Python 3.9)

1) Create Discord Bot:
   - Discord Developer Portal -> New Application -> Bot -> Reset Token
   - Enable "Message Content Intent" is NOT required for slash commands
   - OAuth2 -> URL Generator:
     scopes: bot, applications.commands
     permissions: Send Messages

2) Setup:
   py -3.9 -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   copy .env.example .env
   edit .env (put DISCORD_BOT_TOKEN)

3) Run:
   py bot.py

Commands (in Discord):
   /check url:https://tinyurl.com/xxxx
   /check_email text:(paste email content)
