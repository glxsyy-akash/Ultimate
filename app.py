from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
from google.protobuf.json_format import MessageToDict
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2

app = Flask(__name__)

def load_tokens(server_name):
    if server_name == "IND":
        with open("token_ind.json", "r") as f:
            return json.load(f)
    elif server_name in {"BR", "US", "SAC", "NA"}:
        with open("token_br.json", "r") as f:
            return json.load(f)
    else:
        with open("token_bd.json", "r") as f:
            return json.load(f)

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%' 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()

async def send_request(encrypted_uid, token, url):
    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB48"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=edata, headers=headers) as response:
            if response.status != 200:
                print(f"Request failed with status code: {response.status}")
            return response.status

async def send_multiple_requests(uid, server_name, url):
    region = server_name
    protobuf_message = create_protobuf_message(uid, region)
    encrypted_uid = encrypt_message(protobuf_message)

    tasks = []
    tokens = load_tokens(server_name)
    for i in range(100):
        token = tokens[i % len(tokens)]["token"]
        tasks.append(send_request(encrypted_uid, token, url))

    results = await asyncio.gather(*tasks)
    return results

def create_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return message.SerializeToString()

def enc(uid):
    protobuf_data = create_protobuf(uid)
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypt)

    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB48"
    }

    response = requests.post(url, data=edata, headers=headers, verify=False)
    hex_data = response.content.hex()
    binary = bytes.fromhex(hex_data)
    decode = decode_protobuf(binary)
    return decode

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:  # Fixed exception handling
        print(f"Error decoding Protobuf data: {e}")
        return None

def validate_api_key(api_key):
    """ Dummy function to validate API key (replace with actual logic) """
    valid_keys = ["akash"]  # Replace with actual keys
    return api_key in valid_keys

@app.route('/like', methods=['GET'])
def handle_requests():
    api_key = request.args.get("api_key")

    # ✅ Step 1: Check if API key is provided
    if not api_key:
        return jsonify({"error": "API Key is required"}), 401

    # ✅ Step 2: Validate API key
    if not validate_api_key(api_key):
        return jsonify({"error": "Invalid API Key"}), 403

    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()

    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    def process_request():
        data = load_tokens(server_name)
        token = data[0]['token']
        encrypt = enc(uid)

        before = make_request(encrypt, server_name, token)
        jsone = MessageToJson(before)
        data = json.loads(jsone)
        before_like = int(data['AccountInfo'].get('Likes', 0))

        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        asyncio.run(send_multiple_requests(uid, server_name, url))

        after = make_request(encrypt, server_name, token)
        jsone = MessageToJson(after)
        data = json.loads(jsone)
        after_like = int(data['AccountInfo']['Likes'])
        player_id = int(data['AccountInfo']['UID'])
        name = str(data['AccountInfo']['PlayerNickname'])
        like_given = after_like - before_like
        status = 1 if like_given != 0 else 2

        result = {
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": name,
            "UID": player_id,
            "status": status
        }
        return result

    return jsonify(process_request())  # Fixed duplicate return statements

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
    
