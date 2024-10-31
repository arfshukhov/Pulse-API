import datetime
import time
import jwt

import os
from pprint import pprint

import werkzeug.exceptions

os.environ["POSTGRES_HOST"]="localhost"
os.environ["POSTGRES_PASSWORD"]="573045"
os.environ["SERVER_ADDRESS"] = "0.0.0.0:8000"
os.environ["SERVER_PORT"]="8000"
os.environ["POSTGRES_DATABASE"]="postgres"
os.environ["POSTGRES_USERNAME"]="postgres"
os.environ["POSTGRES_PORT"]="5432"
#from env import *

from flask import Flask, request, jsonify

from db_ops import *

app = Flask(__name__)
app.config["SECRET_KEY"] = 'de36694d1c124c248bb8a3ec660ad7f4'


@app.route('/api/ping', methods=['GET'])
def send():
    return jsonify({"status": "ok"}), 200


@app.route('/api/countries', methods=['GET'])
def countries():
    true_regions = ["Europe", "Africa", "Americas", "Oceania", "Asia"]
    countries = []
    res = []
    try:
        regions = request.args.getlist('region')
    except:
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 400
    for i in regions:
        if i not in true_regions:
            return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 400
        else:
            countries.extend(Country_processor.get_by_region(i))
    countries.sort(key=lambda x: x.alpha2)
    for i in countries:
        res.append({"name":i.name, "alpha2":i.alpha2, "alpha3":i.alpha3,"region":i.region})
    return jsonify(res), 200


@app.route("/api/countries/<alpha2>", methods=['GET'])
def countries_by_alpha2(alpha2):
    try:
        country = Country_processor.get_by_alpha2(alpha2)
        return jsonify({"name":country.name, "alpha2":country.alpha2,
                         "alpha3":country.alpha3,"region":country.region}), 200
    except:
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 404


@app.route("/api/auth/register", methods=['POST'])
def auth_register():
    login = User_processor.validate_login(request.json.get("login"))
    email = User_processor.validate_email(request.json.get("email"))
    password_hash = User_processor.validate_password(request.json.get("password"))
    countryCode = User_processor.validate_country_code(request.json.get("countryCode").upper())
    isPublic = request.json.get("isPublic")
    phone = request.json.get("phone")
    if phone != None:
        phone = User_processor.validate_phone(phone)
    image = request.json.get("image")
    jsn = {
            "login": login, "email": email, "countryCode": countryCode,
            "password_hash": password_hash, "isPublic": isPublic, "phone": phone, "image":image
        }
    if not (login and email and password_hash and countryCode):
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 400
    try:
        User_processor.register(jsn)
        jsn.pop("password_hash")
        print(len(password_hash))
        pprint(jsn)
        if image == None:
            jsn.pop("image")
        return jsonify({"profile":jsn}), 201
    except Exception as e:
        print(e)
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 409


@app.route("/api/auth/sign-in", methods=["POST"])
def auth_sign_in():
    try:
        login = request.json.get("login")
        password = request.json.get("password")
        print(login, password)
        if User_processor.match_password(login, password):
            jwt_token = jwt.encode({
                "login":login,
                "expiration":str(datetime.datetime.now()+datetime.timedelta(seconds=60**2*4))
            },
                app.config["SECRET_KEY"], algorithm='HS256')
            print(jwt_token)
            Token_processor.add_token(login, jwt_token)
            return jsonify({"token":jwt_token}),200
        else:
            return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
    except:
        jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401


@app.route("/api/me/profile", methods=["GET", "PATCH"])
def get_profile():
    try:
        jwt_token = request.headers["Authorization"].split(" ")[1]
        print(request.headers.get("Authorization"))
        data = jwt.decode(jwt_token, app.config["SECRET_KEY"], algorithms='HS256')
        Token_processor.match_for_revoke(data["login"], jwt_token)
    except:
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
    if datetime.datetime.now() < datetime.datetime.strptime(data["expiration"], "%Y-%m-%d %H:%M:%S.%f"):
        try:
            jsn = request.json
            print(jsn)
        except:
            user = User_processor.get_user_by_login(data["login"])
            ret = {
                "login": user.login, "email": user.email,
                "countryCode": user.country_code, "isPublic": user.is_public
            }
            if user.phone not in ["None", None]:
                ret["phone"] = user.phone
            if user.image not in ["None", None]:
                ret["image"] = user.image
            return jsonify(ret), 200
        try:
            res = User_processor.update_user(data["login"], jsn)
            if res == 400:
                return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 400
            else:
                ret = {
                    "login":res.login, "email":res.email, "countryCode":res.country_code, "isPublic":res.is_public
                }
                if res.phone not in ["None", None]:
                    ret["phone"] = res.phone
                if res.image not in ["None", None]:
                    ret["image"] = res.phone
                print(jwt_token, ret)
                return jsonify(ret), 200
        except Exception as e:
            return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 409
    else:
        return jsonify({ "reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401


@app.route("/api/profiles/<login>", methods=["GET"])
def profiles(login):
    try:
        jwt_token = request.headers["Authorization"].split(" ")[1]
        print(request.headers.get("Authorization"))
        data = jwt.decode(jwt_token, app.config["SECRET_KEY"], algorithms='HS256')
        Token_processor.match_for_revoke(data["login"], jwt_token)
    except Exception as e:
        print(e)
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
    if datetime.datetime.now() < datetime.datetime.strptime(data["expiration"], "%Y-%m-%d %H:%M:%S.%f"):
        try:
            res = User_processor.get_user_by_login(login)
            ret = {
                "login": res.login, "email": res.email, "countryCode": res.country_code, "isPublic": res.is_public
            }
            if res.phone not in ["None", None]:
                ret["phone"] = res.phone
            if res.image not in ["None", None]:
                ret["image"] = res.phone
            print(jwt_token, ret)
            return jsonify(ret), 200
        except:
            return jsonify({ "reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 409
    else:
        return jsonify({ "reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401


@app.route("/api/me/updatePassword", methods=["POST"])
def update_password():
    try:
        jwt_token = request.headers["Authorization"].split(" ")[1]
        print(request.headers.get("Authorization"))
        data = jwt.decode(jwt_token, app.config["SECRET_KEY"], algorithms='HS256')
        Token_processor.match_for_revoke(data["login"], jwt_token)
    except Exception as e:
        print(e)
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
    if datetime.datetime.now() < datetime.datetime.strptime(data["expiration"], "%Y-%m-%d %H:%M:%S.%f"):
        try:
            old_password = request.json["oldPassword"]
            new_password = request.json["newPassword"]
            validate_password = User_processor.validate_password(new_password)
            if User_processor.match_password(data["login"], old_password):
                if validate_password:
                    User_processor.update_user(data["login"], {"password": new_password})
                    Token_processor.revoke_tokens(data["login"])
                    return jsonify({"status": "ok"}), 200
                else:
                    return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 400
            else:
                return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 403
        except Exception as e:
            print(e)
            return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
    else:
        return jsonify({ "reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401


@app.route("/api/friends/add", methods=["POST"])
def add_friend():
    try:
        jwt_token = request.headers["Authorization"].split(" ")[1]
        print(request.headers.get("Authorization"))
        data = jwt.decode(jwt_token, app.config["SECRET_KEY"], algorithms='HS256')
        Token_processor.match_for_revoke(data["login"], jwt_token)
    except Exception as e:
        print(e)
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
    if datetime.datetime.now() < datetime.datetime.strptime(data["expiration"], "%Y-%m-%d %H:%M:%S.%f"):
        try:
            friend_login = request.json["login"]
            if Friends_processor.check_exists(friend_login):
                Friends_processor.add_friend(data["login"], friend_login)
                return jsonify({"status": "ok"}), 200
            else:
                return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 404
        except Exception as e:
            print(e)
            return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401

    else:
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401


@app.route("/api/friends/remove", methods=["POST"])
def remove_friend():
    try:
        jwt_token = request.headers["Authorization"].split(" ")[1]
        print(request.headers.get("Authorization"))
        data = jwt.decode(jwt_token, app.config["SECRET_KEY"], algorithms='HS256')
        Token_processor.match_for_revoke(data["login"], jwt_token)
    except Exception as e:
        print(e)
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
    if datetime.datetime.now() < datetime.datetime.strptime(data["expiration"], "%Y-%m-%d %H:%M:%S.%f"):
        try:
            friend_login = request.json["login"]
            if Friends_processor.check_exists(friend_login):
                Friends_processor.remove_friend(data["login"], friend_login)
                return jsonify({"status": "ok"}), 200
            else:
                return jsonify({"status": "ok"}), 200
        except Exception as e:
            print(e)
            return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401

    else:
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401


@app.route("/api/friends", methods=["GET"])
def get_friends():
    try:
        jwt_token = request.headers["Authorization"].split(" ")[1]
        #print(request.headers.get("Authorization"))
        data = jwt.decode(jwt_token, app.config["SECRET_KEY"], algorithms='HS256')
        Token_processor.match_for_revoke(data["login"], jwt_token)
    except Exception as e:
        print(e)
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
    if datetime.datetime.now() < datetime.datetime.strptime(data["expiration"], "%Y-%m-%d %H:%M:%S.%f"):
        try:
            offset = request.args["offset"]
            limit = request.args["limit"]
            res = Friends_processor.get_friends(data["login"], int(limit), int(offset))
            lst = []
            for i in res:
                #print(i.added_at)
                lst.append({"login":i.friend, "addedAt":i.added_at})
            #print(lst)
            lst.sort(key=lambda x:  x.get("addedAt"), reverse=True)
            return jsonify(lst), 200
        except Exception as e:
            print(e)
            return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
    else:
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401


"""@app.route("/api/posts/new", methods=["POST"])
def new_post():
    try:
        jwt_token = request.headers["Authorization"].split(" ")[1]
        #print(request.headers.get("Authorization"))
        data = jwt.decode(jwt_token, app.config["SECRET_KEY"], algorithms='HS256')
        Token_processor.match_for_revoke(data["login"], jwt_token)
    except Exception as e:
        print(e)
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
    if datetime.datetime.now() < datetime.datetime.strptime(data["expiration"], "%Y-%m-%d %H:%M:%S.%f"):
        #try:
        content = request.json["content"]
        tags = request.json["tags"]
        author = data["login"]
        post = Post_processor.new_post(content, author,tags)
        res = {
            "id":post.uid, "content":post.content, "author":post.author, "tags":json.loads(post.tags),
            "createdAt":post.created_at, "likesCount":post.likes_count, "dislikesCount":post.dislikes_count
        }
        return jsonify(res), 200
        #except:
        jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
    else:
        return jsonify({"reason": "<объяснение, почему запрос пользователя не может быть обработан>"}), 401
"""





if __name__ == "__main__":
    server_env = Environment()
    #print(datetime.datetime.now(datetime.timezone.utc).isoformat())
    #print(datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ%z"))
    for i in Users.select():
        print(i.login)
    a = [1, 2, 3, 4, 5, 6, 7, 8,]
    b = 5
    c = 5
    print(a[b:b+c])
    #print([i.login for i in Users.select()])
    app.run(
        host=server_env.__repr__()["SERVER_ADDRESS"].split(":")[0],
        port=int(server_env.__repr__()["SERVER_PORT"]),
        debug=False
    )
"""
{
  "login": "yellowMonkey10000",
  "email": "yellowstone1980@you.ru",
  "password": "$aba4821FWfew01#.fewA$",   $aba4821FWfew01#.fewA$$
  "countryCode": "RU",
  "isPublic": true,
  "phone": "+74951239922"
}
{
  "login": "yellowMonkey1000",
  "email": "yellowstone180@you.ru",
  "password": "$aba4821FWfew01#.fewA$",
  "countryCode": "RU",
  "isPublic": true,
  "phone": "+74951239923"
}
"""
