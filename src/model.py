from peewee import *

db = SqliteDatabase("passwords.db")

class Password(Model):
    id = AutoField()
    title = CharField(unique=True)
    email = CharField(null=True)
    notes = TextField(null=True)
    url = CharField(null=True)
    safe_password = TextField()
    password = TextField()

    class Meta:
        database = db