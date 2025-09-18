from flask import Flask, flash, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_use, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import os


#configuraçao inicial
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sql:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_required.init_app(app)
login_manager.login_view = 'login'

#----------------------------------------------------
#  MODELS
#----------------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100))
    email = db.Column(db.email(100), unique = True, nullable = True)
    password = db.Column(db.String(20), nullable = False)
    tasks = db.relationship('Task', backref = 'user', lazy = True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(150))
    status = db.Column(db.String(20, default = "Pendente"))
    user_id = db.Column(db.Integer, db.ForeidnKey('user.id'), nullabel = False)

#-------------------------------------------------
#LOGIN MANAGER
#-------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#--------------------------------------------------
# ROTAS
#--------------------------------------------------
@app.route("/")
def index():
    return render_template('index.html')

#cadastro de usuario == CREATE
@app.route('/register', methods = ['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        #verificar se o usuario ja existe
        user = User.query.filter_by(email=email).first()
        if user:
            flash('email ja esta cadastrado', 'warning')
            return redirect(url_for('register'))
        
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash('cadastro realizado com sucesso! faça login', 'sucesso')
        return redirect(url_for('login'))
    return render_template('register.html')

#login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user) 
            return redirect(url_for('tasks'))
        else:
            flash('Email ou senha incorreto', 'danger') 

        return  render_template('login.html')   

#logaut
@app.route('/logaut')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

#listar tarefas --  READ
@app.route('/tasks')
@login_required
def tasks():
    user_tasks: Task.query.filter_by(user_id=current_user.id).all() # type: ignore
    return render_template('tasks.html', tasks=user_tasks)


#adicionar tarefas
@app.route('/add_task', methods=['GET', 'POST'])
@login_required
def add_task():
    if request.method == 'POST':
        title = request.form['title']

        new_task = Task(title=title, user_id=current_user.id)

        db.session.add(new_task)
        db.session.commit()

        flash('tarefa adicionada com sucesso!', 'success')
        return redirect(url_for('tasks'))
    return render_template('add_tasks.html')

#atualizar status da tarefa = UPDATE
@app.route('/update_task/<int:id>')
@login_required
def update_task(id):
    task = Task.query.get_or_404(id)

    if Task.user_id != current_user.id:
        flash('voce nao tem permissao para isso', 'danger')
        return redirect(url_for('tasks'))
    
    task.status = 'Conclusao' if task.status == 'Pendente' else 'Pendente'
    db.session.commit()
    return redirect

#deletar tarefa -- DELETE
@app.route('/delete_task/<int:id>')
@login_required
def delete_task(id):
    task = Task.query.get_or_404(id)

    if task.user_id != current_user.id:
        flash('voce nao tem permissao para isso', 'danger')
        return redirect(url_for('task'))
    
    db.session.delete(task)
    db.session.commit()
    flash('tarefa excluida com  sucesso', 'info')
    return redirect(url_for('tasks'))


#--------------------------------------------------
# CRIAR BANCO NA PRIMEIRA EXECUÇAO
#--------------------------------------------------


if __name__ == '__main__':
    if not os.path.exists("database.db"):
        with app.app_context():
            db.create_all()

    app.run(debug=True)