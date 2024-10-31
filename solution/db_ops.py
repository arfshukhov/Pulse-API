import datetime
import json
import uuid
from typing import *
import re
from database import *
import requests
from json import *

from cryptographer import crypto


def db_init():
    data = \
        loads(requests.get(
            "https://github.com/lukes/ISO-3166-Countries-with-Regional-Codes/blob/master/all/all.json").json()[
                  "payload"]["blob"]["rawLines"][0])
    for i in data:
        try:
            countries(name=i["name"], alpha2=i["alpha-2"], alpha3=i["alpha-3"], region=i["region"]).save()
        except Exception as e:
            continue


class Country_processor:
    @classmethod
    def get_by_region(cls, region) -> List[countries]:
        _countries = []
        for i in countries.select().where(countries.region == region):
            _countries.append(i)
        return _countries

    @classmethod
    def get_by_alpha2(cls, alpha2) -> countries:
        _countries = []
        for i in countries.select().where(countries.alpha2 == alpha2):
            _countries.append(i)
        if len(_countries) == 0:
            raise ValueError
        else:
            return _countries[0]

    @classmethod
    def validate_coutry(cls, name):
        for i in countries.select():
            if i.alpha2 == name:
                return name
            else:
                return 0


class User_processor:
    @classmethod
    def register(cls, jsn):
        Users(
            login=jsn["login"], email=jsn["email"], password_hash=jsn["password_hash"],
            country_code=jsn["countryCode"], is_public=jsn["isPublic"], phone=str(jsn["phone"]), image=str(jsn["image"])
        ).save()

    @classmethod
    def validate_login(cls, login)->Optional[str| bool]:
        pattern = r'^[a-zA-Z0-9-]+$'
        if 1 <= len(login) <= 30 and re.match(pattern, login):
            return login
        else:
            return 0

    @classmethod
    def validate_email(cls, email)->Optional[str| bool]:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if 1 <= len(email) <= 50 and re.match(pattern, email):
            return email
        else:
            return 0

    @classmethod
    def validate_password(cls, password)->Optional[str| bool]:
        if len(password) < 6:
            return 0
        if not re.search(r'[a-z]', password) or not re.search(r'[A-Z]', password):
            return 0
        if not re.search(r'\d', password):
            return 0

        return crypto.encrypt(password)

    @classmethod
    def validate_country_code(cls, country_code)->Optional[str| bool]:
        if len(country_code) == 2 and re.match(r"[a-zA-Z]{2}", country_code):
            return country_code
        else:
            return 0

    @classmethod
    def validate_phone(cls, phone)->Optional[str| bool]:
        pattern = r'^\+\d{1,20}$'
        if re.match(pattern, phone):
            return phone
        else:
            return 0

    @classmethod
    def match_password(cls,login, password)->bool:
        account = Users.select().where(Users.login==login).get()
        if account.password_hash == crypto.encrypt(password):
            return 1
        else:
            return 0

    @classmethod
    def update_user(cls, login, jsn):
        actions = []
        for i in jsn.keys():
            match i:
                case "login":
                    if User_processor.validate_login(jsn["login"]):
                        actions.append(Users.update({Users.login:jsn["login"]}).where(Users.login==login))
                    else:
                        db.rollback()
                        return 400
                case "email":
                    if cls.validate_email(jsn["email"]):
                        actions.append(Users.update({Users.email:jsn["email"]}).where(Users.login==login))
                    else:
                        db.rollback()
                        return 400
                case "password":
                    validate_password = cls.validate_password(jsn["password"])
                    if validate_password:
                        actions.append(Users.update({Users.password_hash:validate_password}).where(Users.login==login))
                    else:
                        return 400
                case "countryCode":
                    country = countries.select().where(countries.alpha2 == jsn["countryCode"].upper())
                    if len(country) != 0:
                        actions.append(Users.update({Users.country_code: jsn["countryCode"].upper()})\
                            .where(Users.login == login))
                    else:
                        db.rollback()
                        return 400
                case "isPublic":
                    if isinstance(jsn["isPublic"], bool):
                        actions.append(Users.update({Users.is_public: jsn["isPublic"]}).where(Users.login == login))
                    else:
                        db.rollback()
                        return 400
                case "phone":
                    if cls.validate_phone(jsn["phone"]):
                        actions.append(Users.update({Users.phone: jsn["phone"]}).where(Users.login == login))
                    else:
                        db.rollback()
                        return 400
                case "image":
                    if len(jsn["image"]) <= 200:
                        actions.append(Users.update({Users.image: jsn["image"]}).where(Users.login == login))
                    else:
                        db.rollback()
                        return 400
        for i in actions:
            i.execute()
        return Users.select().where(Users.login==login).get()

    @classmethod
    def get_user_by_login(cls, login):
        return Users.select().where(Users.login==login).get()


class Token_processor:
    @classmethod
    def add_token(cls, login, token):
        Tokens_List(login=login, token=token, revoked=False).save()

    @classmethod
    def revoke_tokens(cls, login):
        Tokens_List.update({Tokens_List.revoked:True}).where(Tokens_List.login==login).execute()

    @classmethod
    def match_for_revoke(cls, login, token):
        data = [i for i in Tokens_List.select().where(
            Tokens_List.login==login, Tokens_List.token == token, Tokens_List.revoked == True)]
        print(data)
        for i in data:
            print(i.token, i.login, i.revoked)
        if len(data) != 0:
            raise Exception("token in blacklist")


class Friends_processor:
    @classmethod
    def add_friend(cls, login, friend):
        now = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ%z")
        Friends(login=login, friend=friend, added_at=now)\
            .save()

    @classmethod
    def remove_friend(cls, login, friend):
        Friends.delete().where(Friends.login==login, Friends.friend==friend).execute()

    @classmethod
    def get_friends(cls, login, limit, offset):
        friends = [i for i in Friends.select().where(Friends.login == login)]
        return friends[offset:offset+limit]

    @classmethod
    def check_exists(cls, login):
        logins = [i for i in Users.select().where(Users.login==login)]
        if len(logins) != 0:
            return 1
        else:
            return 0


class Post_processor:
    @classmethod
    def new_post(cls, content, author, tags):
        now = str(datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ%z"))
        _id = uuid.uuid4().hex+"XYZ"
        print(_id, author, dump := json.dumps(tags), now)


        Posts(uid=_id, content=content, author=author, tags=json.dumps(tags),
              created_at=now, likes_count=0, dislikes_count=0).save()
        print("ids", [i.id for i in Posts.select()])
        return [i for i in Posts.select().where(Posts.id==str(_id))][0]

    @classmethod
    def get_post(cls, id, user,):
        posts = [i for i in Posts.select().where(Posts.id==id)]
        if len(posts) != 0:
            post = posts[0]
            author = post.author
            is_friend = [i for i in Friends.select().where(Friends.login==author, Friends.friend==user)]
            if len(is_friend) !=0:
                return post
            else:
                return 404
        else:
            return 404
