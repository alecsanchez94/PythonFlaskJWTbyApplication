import flask_server
from flask_server import db
from app_admin.models import Role, User
from datetime import datetime, timedelta

db.drop_all()
db.create_all()

developer_role = Role(name='Developer')
admin_role = Role(name='Admin')
tester = Role(name='Tester')

developer_role.save()
admin_role.save()

test = User(
    email='test_user@somedomain.com',
    password='Somepassword',
    first_name='A',
    last_name='User',
    is_activated=True,
    activated_on=datetime.now()
)
test.roles=[tester,admin_role]
test.hash_password()
test.save()



print("Completed database update")

