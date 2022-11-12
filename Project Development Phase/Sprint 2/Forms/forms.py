from wtforms import Form, TextField, BooleanField, PasswordField, validators,  widgets

class RegistrationForm(Form):
	"""docstring for RegistrationForm"""
	username = TextField('Username', [validators.Length(min=4, max=10)])
	name = TextField('Name',[validators.DataRequired(message="Name should not be empty")])#, widget=widgets.TextArea())
	email = TextField('Email',[validators.DataRequired(message="Email should not be empty")])    #email vaidation
	password = PasswordField('Password', [validators.InputRequired(), validators.EqualTo('confirm', message="Passwords must match")])
	confirm = PasswordField('Repeat Password')
	


class LoginForm(Form):
	"""docstring for RegistrationForm"""
	username = TextField('Username', [validators.Length(min=4, max=20)])
	password = PasswordField('Password', [validators.InputRequired()])


