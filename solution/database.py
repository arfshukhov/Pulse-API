from _env import *

from peewee import *

db_env = Environment().env_values


db = PostgresqlDatabase(
    database=db_env["POSTGRES_DATABASE"],host=db_env["POSTGRES_HOST"],
    port=int(db_env["POSTGRES_PORT"]), user=db_env["POSTGRES_USERNAME"],
    password=db_env["POSTGRES_PASSWORD"],
)


class countries(Model):
    id = PrimaryKeyField()
    name = TextField(unique=True)
    alpha2 = TextField()
    alpha3 = TextField()
    region = TextField()

    class Meta:
        database = db
        db_table = "countries"


class Users(Model):
    login = CharField(max_length=30, unique=True)
    email = CharField(max_length=50, unique=True)
    password_hash = CharField(max_length=200)
    country_code = CharField(max_length=3)
    is_public = BooleanField()
    phone = CharField(max_length=20, null=True, unique=True)
    image = CharField(max_length=100, null=True)

    class Meta:
        database = db
        db_table = "Users"


class Tokens_List(Model):
    login = CharField(max_length=30)
    token = TextField()
    revoked = BooleanField()

    class Meta:
        database = db
        db_table = "Tokens_Blacklist"


class Friends(Model):
    login = CharField(max_length=30)
    friend = CharField(max_length=30)
    added_at = TextField()

    class Meta:
        database = db
        db_table = "Friends"


class Posts(Model):
    uid = CharField(max_length=100)
    content = TextField()
    author = CharField(max_length=30)
    tags = TextField()
    created_at = TextField()
    likes_count = IntegerField()
    dislikes_count = IntegerField()

    class Meta:
        database = db
        db_table = "Posts"


db.connect()
#db.drop_tables([Posts])
db.create_tables([countries, Users, Tokens_List, Friends, Posts])
