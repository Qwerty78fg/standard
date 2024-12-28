import asyncio
import requests
from flask import Flask, redirect, request, jsonify, render_template, session
import discord
from threading import Thread
from functools import wraps
import logging
import sys
import json
import os

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, encoding='utf-8')
logger = logging.getLogger()

app = Flask(__name__)
app.secret_key = 'your_secret_key'

authorized_users = {}
#user_id_global = None  #Global variable
user_ids_global = []  #Global list
deauthorized_users = []


with open("token.txt", "r") as f:
    token = f.read().strip()

CLIENT_ID = "1305178785259196458"
CLIENT_SECRET = "FLQLcsMxlAYdoao2E8IUwjGBHYwLIXVp"
REDIRECT_URI = "http://localhost:5000/callback"

intents = discord.Intents.default()
intents.members = True
bot = discord.Client(intents=intents)

# Global variables
data_ready_event = asyncio.Event()
members_data = []
roles_data = []
user_access_tokens = {}

# OAuth2 URL to authorize the bot
OAUTH2_URL = (
    f"https://discord.com/oauth2/authorize"
    f"?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code"
    f"&scope=identify+guilds+guilds.join"
)

def save_tokens():
    with open('user_access_tokens.json', 'w') as f:
        json.dump(user_access_tokens, f)

def load_tokens():
    global user_access_tokens
    if os.path.exists('user_access_tokens.json') and os.path.getsize('user_access_tokens.json') > 0:
        try:
            with open('user_access_tokens.json', 'r') as f:
                user_access_tokens = json.load(f)
                print(f"loaded{user_access_tokens})")
        except json.JSONDecodeError:
            print('[ERROR] Failed to decode JSON. The file may be corrupted or empty.')
            user_access_tokens = {}  # Initialize to an empty dictionary if there's an error
    else:
        user_access_tokens = {}

load_tokens()
for user_id in user_access_tokens.keys():
    if user_id not in user_ids_global:
        user_ids_global.append(user_id)

    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f'[DEBUG] Checking login status: {session.get("logged_in")}')
        if not session.get('logged_in'):
            return redirect('/')  # Redirect to the login page if not logged in
        return f(*args, **kwargs)
    return decorated_function

@bot.event
async def on_ready():
    print(f'[DEBUG] Bot is logged in as {bot.user}')
    global members_data, roles_data
    if bot.guilds:
        # Get members from all guilds
        all_members = []
        for guild in bot.guilds:
            guild_members = [{"name": member.name, "id": member.id} for member in guild.members]
            all_members.extend(guild_members)
        # Remove duplicates
        seen_ids = set()
        members_data = [member for member in all_members 
                       if member['id'] not in seen_ids and not seen_ids.add(member['id'])]
        roles_data = [{"name": role.name, "id": role.id} for role in bot.guilds[0].roles]
    print(f'[DEBUG] Members data fetched: {len(members_data)} members')
    print(f'[DEBUG] Roles data fetched: {len(roles_data)} roles')
    data_ready_event.set()
    print('[DEBUG] data_ready_event set')

@app.route('/')
def home():
    return render_template('login.html')





@app.route('/invite')
def invite():
    print('[DEBUG] /invite route accessed')
    return redirect(OAUTH2_URL)

@app.route('/callback')
def callback():
    global user_ids_global
    code = request.args.get("code")
    print(f'[DEBUG] Callback route accessed with code: {code}')
    if not code:
        return jsonify({"error": "No code provided"}), 400

    # Exchange the code for an access token
    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    token_response = requests.post("https://discord.com/api/oauth2/token", data=token_data)
    if token_response.status_code != 200:
        return jsonify({"error": "Failed to exchange code for token"}), 400

    user_data = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"}
    ).json()

    # Store the user ID in the global list
    user_id = user_data.get("id")
    user_ids_global.append(user_id)  # Append the user ID to the list
    print(f"[DEBUG] Access token stored for user {user_id}: {token_response.json()['access_token']}")

    # Retrieve the user's ID with the access token BEFORE trying to use user_data
    user_response = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"}
    )
    print(f'[DEBUG] User info response status: {user_response.status_code}')
    
    if not user_response.ok:
        return jsonify({"error": "Failed to get user data"}), 500
        
    user_data = user_response.json()
    user_id = user_data.get("id")
    print(f'[DEBUG] Retrieved user ID: {user_id}')

    # Now store the access token
    user_access_tokens[user_id] = token_response.json()['access_token']
    authorized_users[user_id[:-2]] = token_response.json()['access_token']  # Store user ID without last two digits
    print(f"[DEBUG] Access token stored for user {user_id}: {token_response.json()['access_token']}")
    save_tokens()
    # Ensure the bot is in the guild
    if not bot.guilds:
        return jsonify({"error": "Bot is not in any guild"}), 400

    guild_id = bot.guilds[0].id

    # Add the user to the guild
    add_user_response = requests.put(
        f"https://discord.com/api/guilds/{guild_id}/members/{user_id}",
        headers={"Authorization": f"Bot {token}"},
        json={"access_token": token_response.json()['access_token']}
    )

    print(f'[DEBUG] Add user to guild response status: {add_user_response.status_code}')
    print(f'[DEBUG] Add user to guild response content: {add_user_response.text}')

    if add_user_response.status_code == 201:
        return jsonify({"success": "User added to guild"}), 201
    else:
        return jsonify({"error": f"Failed to add user to guild: {add_user_response.status_code}"}), add_user_response.status_code

@app.route('/members')
@login_required
def get_members():
    print('[DEBUG] /members route accessed')
    asyncio.run(data_ready_event.wait())
    print(f'user IDDDDDDDDDDDDDDDDDDDDD{user_ids_global}')
    print(jsonify(members_data))
    return jsonify(members_data)

@app.route('/roles')
@login_required
def get_roles():
    print('[DEBUG] /roles route accessed')
    asyncio.run(data_ready_event.wait())
    return jsonify(roles_data)

@app.route('/servers')
@login_required
def get_servers():
    servers = [{"id": guild.id, "name": guild.name} for guild in bot.guilds]
    return jsonify(servers)

@app.route('/add_user_to_second_server', methods=['POST'])
@login_required
def add_user_to_second_server():
    global user_ids_global  # Use the global list
    data = request.json
    user_index = data.get('user_index')  # Get the index of the user from the request
    server_index = data.get('server_index')  # Get server index from request

    # Convert user_index to integer
    try:
        user_index = int(user_index)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid user index"}), 400

    print(f'[DEBUG] Attempting to add user {user_ids_global[user_index]} to server index {server_index}')
    
    if user_index is None or server_index is None or user_index >= len(user_ids_global):
        return jsonify({"error": "Missing user_index or server_index"}), 400

    user_id = user_ids_global[user_index]  # Get the user ID from the global list

    # Check if we have the user's access token
    if user_id not in user_access_tokens:
        return jsonify({"error": "User hasn't authenticated yet"}), 401

    user_in_guild_0 = None
    for member in bot.guilds[0].members:
        if str(member.id) == user_id:
            user_in_guild_0 = member
            break
    
    if not user_in_guild_0:
        return jsonify({"error": "User not found in the first guild"}), 404

    headers = {"Authorization": f"Bot {token}"}
    add_user_response = requests.put(
        f"https://discord.com/api/guilds/{bot.guilds[1].id}/members/{user_in_guild_0.id}",
        headers=headers,
        json={"access_token": user_access_tokens[user_id]}  # Use stored access token
    )

    if add_user_response.status_code == 201:
        return jsonify({"success": True}), 201
    else:
        print(f'[DEBUG] Failed to add user: {add_user_response.status_code}, Response: {add_user_response.text}')
        return jsonify({"error": f"Failed to add user: {add_user_response.status_code}"}), add_user_response.status_code



@app.route('/guilds', methods=['GET'])
def guilds():
    global user_ids_global  # Use the global list
    user_index = request.args.get('user_index')

    # Convert user_index to integer
    try:
        user_index = int(user_index)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid user index"}), 400

    print(f'[DEBUG] Attempting to get user guilds')
    
    user_id = user_ids_global[user_index]  # Get the user ID from the global list

    # Check if we have the user's access token
    if user_id not in user_access_tokens:
        return jsonify({"error": "User hasn't authenticated yet"}), 401

    access_token = user_access_tokens[user_id]
    if not access_token:
        return redirect('/invite')

    headers = {'Authorization': f"Bearer {access_token}"}
    response = requests.get("https://discord.com/api/users/@me/guilds", headers=headers)
    
    if response.status_code != 200:
        return jsonify({"error": "Failed to fetch guilds"}), response.status_code

    guilds = response.json()
    logger.debug(guilds)
    return jsonify(guilds)





@app.route('/get_user_ids', methods=['GET'])
def get_user_ids():
    global user_ids_global, bot
    user_info = []
    
    for user_id in user_ids_global:
        if user_id in user_access_tokens:
            username = None
            for guild in bot.guilds:
                member = guild.get_member(int(user_id))
                if member:
                    username = f"{member.name}#{member.discriminator}"
                    break
            
            if username:
                user_info.append({
                    "id": user_id,
                    "name": username
                })
            else:
                user_info.append({
                    "id": user_id,
                    "name": f"User {user_id}"  # Fallback if username not found
                })
    
    return jsonify(user_info)

def run_flask():
    print('[DEBUG] Flask app is starting...')
    app.run(debug=True, use_reloader=False)

@bot.event
async def on_member_join(member):
    print(f'[DEBUG] New member joined: {member.name}')
    global members_data
    # Update members_data with new member
    members_data = [{"name": member.name, "id": member.id} for member in bot.guilds[0].members]
    print(f'[DEBUG] Members data updated: {len(members_data)} members')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    password = data.get('password')

    # Check if the password is correct
    if password == "1234":
        session['logged_in'] = True  # Set session variable
        print('[DEBUG] User logged in successfully.')
        return jsonify({"success": True}), 200
    else:
        return jsonify({"success": False, "error": "Incorrect password"}), 401

@app.route('/admin')
def admin_panel():
    if not session.get('logged_in'):
        return redirect('/')  # Redirect to the login page if not logged in
    return render_template('index.html')  # Render the admin panel

@app.route('/ban_user', methods=['POST'])
@login_required
def ban_user():
    data = request.json
    user_id = data.get('user_id')

    # Debugging
    print(f'[DEBUG] Attempting to ban user: {user_id}')
    print(f'[DEBUG] Current user_access_tokens: {user_access_tokens}')

    # (string or integer)
    if user_id in user_access_tokens:
        del user_access_tokens[user_id]
        print(f'[DEBUG] User {user_id} has been banned and removed from access tokens.')
        save_tokens()
        return jsonify({"success": True}), 200
        
    else:
        return jsonify({"error": "User not found in access tokens"}), 404

print(user_access_tokens)
print(user_ids_global)


if __name__ == "__main__":
    print('[DEBUG] Starting Flask in a separate thread...')
    flask_thread = Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    print('[DEBUG] Starting bot...')
    bot.run(token)
