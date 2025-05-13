from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Configuração do aplicativo Flask
app = Flask(__name__)
# Chave secreta para segurança da sessão (você pode alterar isso)
app.config['SECRET_KEY'] = 'chave_super_secreta'
# Configuração do banco de dados SQLite (o arquivo inventory.db será criado na mesma pasta)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'inventory.db')
# Inicialização do SQLAlchemy
db = SQLAlchemy(app)

# Definição do modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    inventories = db.relationship('Inventory', backref='user', lazy=True)

# Definição do modelo de Inventário
class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Função para criar as tabelas do banco de dados (será chamada na inicialização)
def create_database():
    with app.app_context():
        db.create_all()

# Rota para a página inicial (redireciona para a listagem de estoque se logado, senão para o login)
@app.route('/')
def index():
    if 'user_id' in session:
        inventories = Inventory.query.filter_by(user_id=session['user_id']).all()
        return render_template('estoque.html', inventories=inventories)
    return redirect(url_for('login'))

# Rota para a página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Usuário ou senha inválidos')
    return render_template('login.html')

# Rota para a página de cadastro de novo usuário
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Nome de usuário já existe')

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# Rota para adicionar um novo item ao estoque
@app.route('/add', methods=['POST'])
def add_item():
    if 'user_id' in session:
        item_name = request.form['item_name']
        quantity = request.form['quantity']
        new_item = Inventory(item_name=item_name, quantity=quantity, user_id=session['user_id'])
        db.session.add(new_item)
        db.session.commit()
        return redirect(url_for('index'))
    return redirect(url_for('login'))

# Rota para remover um item do estoque
@app.route('/remove/<int:item_id>')
def remove_item(item_id):
    if 'user_id' in session:
        item = Inventory.query.filter_by(id=item_id, user_id=session['user_id']).first()
        if item:
            db.session.delete(item)
            db.session.commit()
        return redirect(url_for('index'))
    return redirect(url_for('login'))

# Rota para fazer logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_database() # Cria as tabelas do banco de dados se não existirem
    app.run(debug=True)