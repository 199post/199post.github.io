from flask import render_template, request, redirect, url_for, flash
from app import app, db, bcrypt
from app.models import User
from datetime import datetime

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Получение данных из формы
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Проверка уникальности пользователя
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('register'))

        # Хеширование пароля
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Сохранение пользователя в базу данных
        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))  # Переход на страницу логина

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            return redirect(url_for('index'))  # Переход на главную страницу после логина
        else:
            flash('Login failed. Check your email and/or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/')
def index():
    return render_template('index.html')  # Главная страница


@app.route('/current_time')
def current_time():
    # Получаем текущее время
    now = datetime.now()
    formatted_time = now.strftime('%Y-%m-%d %H:%M:%S')
    # Передаем время в шаблон
    return render_template('current_time.html', time=formatted_time)
