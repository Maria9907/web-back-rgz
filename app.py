from flask import (
    Flask, url_for, request, redirect, make_response, 
    abort, render_template, current_app, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import psycopg2
import sqlite3
from psycopg2.extras import RealDictCursor
from os import path
import os
import uuid


app = Flask(__name__)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'секретно-секретный секрет')
app.config['DB_TYPE'] = os.getenv('DB_TYPE', 'postgres')



def db_connect():
    """Подключение к базе данных"""
    if current_app.config['DB_TYPE'] == 'postgres':
        conn = psycopg2.connect(
            host='127.0.0.1',
            database='pharmacy_matyushkina',
            user='pharmacy_matyushkina',
            password='123'
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)
    else:
        dir_path = path.dirname(path.realpath(__file__))
        db_path = path.join(dir_path, "database.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
    
    return conn, cur

def db_close(conn, cur):
    """Закрытие соединения с базой данных"""
    conn.commit()
    cur.close()
    conn.close()


@app.context_processor
def inject_user():
    user_info = {
        'student_name': "Матюшкина Мария Дмитриевна",
        'student_group': "ФБИ-32",
        'current_user': None,
        'is_admin': False
    }
    
    if 'user_id' in session:
        user_info['current_user'] = {
            'id': session['user_id'],
            'username': session['username']
        }
        user_info['is_admin'] = session.get('is_admin', False)
    
    return user_info

@app.errorhandler(400)
def bad_request(err):
    return "Неправильный, некорректный запрос", 400


@app.errorhandler(401)
def unauthorized(err):
    return "Не авторизован", 401


@app.errorhandler(403)
def forbidden(err):
    return "Запрещено (не уполномочен)", 403


@app.errorhandler(405)
def method_not_allowed(err):
    return "Метод не поддерживается", 405


@app.errorhandler(500)
def internal_server_error(err):
    return "Внутренняя ошибка сервера", 500

access_log = []


@app.errorhandler(404)
def not_found(err):

    client_ip = request.remote_addr
    access_time = datetime.datetime.now()
    requested_url = request.url

    log_entry = (
        f"[{access_time}, пользователь {client_ip}] зашёл на адрес: {requested_url}"
    )
    access_log.append(log_entry)

    

    log_html = ""
    for entry in access_log:
        log_html += f"<p class='log-entry'>{entry}</p>"

    return render_template('404.html', 
                         client_ip=client_ip, 
                         access_time=access_time,
                         log_html=log_html), 404

access_log = []

# Главная страница
@app.route("/")
@app.route("/index")
def index():
    return render_template('index.html')



# Поиск лекарств
@app.route('/search')
def search_medicines():
    # Получаем параметры поиска из GET-запроса
    name = request.args.get('name', '').strip()
    min_price = request.args.get('min_price', '').strip()
    max_price = request.args.get('max_price', '').strip()
    prescription_required = request.args.get('prescription_required', '').strip()
    
    # Пагинация
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Показывать по 10 лекарств на странице
    
    # Подключаемся к БД
    conn, cur = db_connect()
    
    try:
        # Строим базовый запрос
        query = "SELECT * FROM medicines WHERE 1=1"
        params = []
        
        # Добавляем условия поиска
        if name:
            query += " AND name ILIKE %s"
            params.append(f'%{name}%')
        
        if min_price:
            query += " AND price >= %s"
            params.append(float(min_price))
        
        if max_price:
            query += " AND price <= %s"
            params.append(float(max_price))
        
        if prescription_required == '1':
            query += " AND prescription_required = TRUE"
        elif prescription_required == '0':
            query += " AND prescription_required = FALSE"
        
        # Получаем общее количество для пагинации
        count_query = f"SELECT COUNT(*) as total FROM ({query}) as subquery"
        
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute(count_query, params)
        else:
            # Заменяем %s на ? для SQLite
            count_query = count_query.replace('%s', '?')
            cur.execute(count_query, params)
        
        total_count = cur.fetchone()['total']
        total_pages = (total_count + per_page - 1) // per_page
        
        # Добавляем пагинацию к основному запросу
        offset = (page - 1) * per_page
        query += " ORDER BY name LIMIT %s OFFSET %s"
        params.extend([per_page, offset])
        
        # Выполняем основной запрос
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute(query, params)
        else:
            # Заменяем %s на ? для SQLite
            query = query.replace('%s', '?')
            cur.execute(query, params)
        
        medicines = cur.fetchall()
        
    except Exception as e:
        print(f"Ошибка при поиске лекарств: {e}")
        medicines = []
        total_pages = 1
        total_count = 0
    finally:
        db_close(conn, cur)

    search_params = request.args.copy()
    if 'page' in search_params:
        search_params.pop('page')

    return render_template('search.html',
                         medicines=medicines,
                         page=page,
                         total_pages=total_pages,
                         total_count=total_count,
                         search_params=search_params)

# Система аутентификации
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    conn, cur = db_connect()
    
    try:
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        else:
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        
        user = cur.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            flash("Вход выполнен успешно!", "success")
            
            # Перенаправляем администратора в админ-панель
            if user['is_admin']:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Неверный логин или пароль")
            
    except Exception as e:
        print(f"Ошибка при входе: {e}")
        return render_template('login.html', error="Ошибка при входе")
    finally:
        db_close(conn, cur)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()
    
    # Валидация
    if not username or not password:
        return render_template('register.html', error="Логин и пароль не могут быть пустыми")
    
    if len(username) < 3:
        return render_template('register.html', error="Логин должен содержать минимум 3 символа")
    
    if len(password) < 6:
        return render_template('register.html', error="Пароль должен содержать минимум 6 символов")
    
    if password != confirm_password:
        return render_template('register.html', error="Пароли не совпадают")
    
    conn, cur = db_connect()
    
    try:
        # Проверяем, существует ли пользователь
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        else:
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        
        if cur.fetchone():
            return render_template('register.html', error="Пользователь с таким логином уже существует")
        
        # Хешируем пароль
        password_hash = generate_password_hash(password)
        
        # Определяем, является ли пользователь первым (станет администратором)
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT COUNT(*) as count FROM users")
        else:
            cur.execute("SELECT COUNT(*) as count FROM users")
        
        count_result = cur.fetchone()
        user_count = count_result['count'] if count_result else 0
        is_admin = user_count == 0
        
        # Создаем пользователя
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s)",
                (username, password_hash, is_admin)
            )
        else:
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (username, password_hash, is_admin)
            )
        
        conn.commit()
        
        # Автоматически логиним пользователя после регистрации
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT id, username, is_admin FROM users WHERE username = %s", (username,))
        else:
            cur.execute("SELECT id, username, is_admin FROM users WHERE username = ?", (username,))
        
        user = cur.fetchone()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = user['is_admin']
        
        flash("Регистрация прошла успешно!", "success")
        
        # Перенаправляем администратора в админ-панель, обычного пользователя на главную
        if user['is_admin']:
            return redirect(url_for('admin_panel'))
        else:
            return redirect(url_for('index'))
        
    except Exception as e:
        print(f"Ошибка при регистрации: {e}")
        return render_template('register.html', error="Ошибка при регистрации")
    finally:
        db_close(conn, cur)

@app.route('/logout')
def logout():
    session.clear()
    flash("Вы вышли из системы", "info")
    return redirect(url_for('index'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn, cur = db_connect()
    
    try:
        user_id = session['user_id']
        
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        else:
            cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        conn.commit()
        session.clear()
        flash("Ваш аккаунт был удален", "info")
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"Ошибка при удалении аккаунта: {e}")
        flash("Ошибка при удалении аккаунта", "error")
        return redirect(url_for('index'))
    finally:
        db_close(conn, cur)

# Панель администратора
@app.route('/admin')
def admin_panel():
    if not session.get('is_admin'):
        flash("Доступ запрещен. Требуются права администратора", "error")
        return redirect(url_for('index'))
    
    conn, cur = db_connect()
    
    try:
        # Получаем статистику
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT COUNT(*) as total FROM medicines")
            total_medicines = cur.fetchone()['total']
            
            cur.execute("SELECT COUNT(*) as total FROM medicines WHERE prescription_required = TRUE")
            prescription_medicines = cur.fetchone()['total']
            
            cur.execute("SELECT COUNT(*) as total FROM medicines WHERE quantity = 0")
            out_of_stock = cur.fetchone()['total']
        else:
            cur.execute("SELECT COUNT(*) as total FROM medicines")
            total_medicines = cur.fetchone()['total']
            
            cur.execute("SELECT COUNT(*) as total FROM medicines WHERE prescription_required = 1")
            prescription_medicines = cur.fetchone()['total']
            
            cur.execute("SELECT COUNT(*) as total FROM medicines WHERE quantity = 0")
            out_of_stock = cur.fetchone()['total']
        
    except Exception as e:
        print(f"Ошибка при получении статистики: {e}")
        total_medicines = prescription_medicines = out_of_stock = 0
    finally:
        db_close(conn, cur)
    
    return render_template('admin.html', 
                         total_medicines=total_medicines,
                         prescription_medicines=prescription_medicines,
                         out_of_stock=out_of_stock)

@app.route('/admin/medicine/add', methods=['GET', 'POST'])
def add_medicine():
    if not session.get('is_admin'):
        flash("Доступ запрещен. Требуются права администратора", "error")
        return redirect(url_for('index'))
    
    if request.method == 'GET':
        return render_template('add_medicine.html')
    
    # Получаем данные из формы
    name = request.form.get('name', '').strip()
    generic_name = request.form.get('generic_name', '').strip()
    description = request.form.get('description', '').strip() 
    prescription_required = bool(request.form.get('prescription_required'))
    price = request.form.get('price', '0').strip()
    quantity = request.form.get('quantity', '0').strip()
    
    # Валидация
    errors = []
    if not name:
        errors.append("Название лекарства обязательно")
    
    try:
        price = float(price)
        if price <= 0:
            errors.append("Цена должна быть положительной")
    except ValueError:
        errors.append("Некорректная цена")
    
    try:
        quantity = int(quantity)
        if quantity < 0:
            errors.append("Количество не может быть отрицательным")
    except ValueError:
        errors.append("Некорректное количество")
    
    
    if errors:
        return render_template('add_medicine.html', errors=errors)
    
    conn, cur = db_connect()
    
    try:
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("""
                INSERT INTO medicines (name, generic_name, description, prescription_required, price, quantity)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, generic_name, prescription_required, price, quantity))
        else:
            cur.execute("""
                INSERT INTO medicines (name, generic_name, description, prescription_required, price, quantity)
                VALUES (?, ?, ?, ?, ?)
            """, (name, generic_name, description, prescription_required, price, quantity))
        
        conn.commit()
        flash("Лекарство успешно добавлено", "success")
        return redirect(url_for('admin_panel'))
        
    except Exception as e:
        print(f"Ошибка при добавлении лекарства: {e}")
        return render_template('add_medicine.html', errors=["Ошибка при добавлении лекарства"])
    finally:
        db_close(conn, cur)

# Редактирование лекарства (админ)
@app.route('/admin/medicine/<int:medicine_id>/edit', methods=['GET', 'POST'])
def edit_medicine(medicine_id):
    if not session.get('is_admin'):
        flash("Доступ запрещен. Требуются права администратора", "error")
        return redirect(url_for('index'))
    
    conn, cur = db_connect()
    
    try:
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT * FROM medicines WHERE id = %s", (medicine_id,))
        else:
            cur.execute("SELECT * FROM medicines WHERE id = ?", (medicine_id,))
        
        medicine = cur.fetchone()
        
        if not medicine:
            flash("Лекарство не найдено", "error")
            return redirect(url_for('admin_panel'))
        
        if request.method == 'GET':
            return render_template('edit_medicine.html', medicine=medicine)
        
        # Получаем данные из формы
        name = request.form.get('name', '').strip()
        generic_name = request.form.get('generic_name', '').strip()
        description = request.form.get('description', '').strip()
        prescription_required = bool(request.form.get('prescription_required'))
        price = request.form.get('price', '0').strip()
        quantity = request.form.get('quantity', '0').strip()
        
        # Валидация
        errors = []
        if not name:
            errors.append("Название лекарства обязательно")
        
        try:
            price = float(price)
            if price <= 0:
                errors.append("Цена должна быть положительной")
        except ValueError:
            errors.append("Некорректная цена")
        
        try:
            quantity = int(quantity)
            if quantity < 0:
                errors.append("Количество не может быть отрицательным")
        except ValueError:
            errors.append("Некорректное количество")
        
        
        if errors:
            return render_template('edit_medicine.html', medicine=medicine, errors=errors)
        
        # Обновляем лекарство в БД
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("""
                UPDATE medicines 
                SET name = %s, generic_name = %s, description = %s, prescription_required = %s, 
                    price = %s, quantity = %s
                WHERE id = %s
            """, (name, generic_name, description, prescription_required, price, quantity, medicine_id))
        else:
            cur.execute("""
                UPDATE medicines 
                SET name = ?, generic_name = ?, description = ?, prescription_required = ?, 
                    price = ?, quantity = ?
                WHERE id = ?
            """, (name, generic_name, description, prescription_required, price, quantity, medicine_id))
        
        conn.commit()
        flash("Лекарство успешно обновлено", "success")
        return redirect(url_for('admin_panel'))
        
    except Exception as e:
        print(f"Ошибка при редактировании лекарства: {e}")
        return render_template('edit_medicine.html', medicine=medicine, errors=["Ошибка при редактировании"])
    finally:
        db_close(conn, cur)

@app.route('/admin/medicines')
def admin_medicines():
    if not session.get('is_admin'):
        flash("Доступ запрещен. Требуются права администратора", "error")
        return redirect(url_for('index'))

    # Пагинация
    page = request.args.get('page', 1, type=int)
    per_page = 10

    conn, cur = db_connect()

    try:
        # Получаем общее количество
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT COUNT(*) as total FROM medicines")
        else:
            cur.execute("SELECT COUNT(*) as total FROM medicines")
        
        total_count = cur.fetchone()['total']
        total_pages = (total_count + per_page - 1) // per_page
        
        # Получаем лекарства для текущей страницы
        offset = (page - 1) * per_page
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT * FROM medicines ORDER BY id LIMIT %s OFFSET %s", (per_page, offset))
        else:
            cur.execute("SELECT * FROM medicines ORDER BY id LIMIT ? OFFSET ?", (per_page, offset))
        
        medicines = cur.fetchall()
        
    except Exception as e:
        print(f"Ошибка при получении списка лекарств: {e}")
        medicines = []
        total_pages = 1
        total_count = 0
    finally:
        db_close(conn, cur)

    return render_template('admin_medicines.html', 
                            medicines=medicines,
                            page=page,
                            total_pages=total_pages,
                            total_count=total_count)

    # Удаление лекарства
@app.route('/admin/medicine/<int:medicine_id>/delete', methods=['POST'])
def delete_medicine(medicine_id):
    if not session.get('is_admin'):
        flash("Доступ запрещен. Требуются права администратора", "error")
        return redirect(url_for('index'))

    conn, cur = db_connect()

    try:
        # Проверяем существование лекарства
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT * FROM medicines WHERE id = %s", (medicine_id,))
        else:
            cur.execute("SELECT * FROM medicines WHERE id = ?", (medicine_id,))
        
        medicine = cur.fetchone()
        
        if not medicine:
            flash("Лекарство не найдено", "error")
            return redirect(url_for('admin_medicines'))
        
        # Удаляем лекарство
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("DELETE FROM medicines WHERE id = %s", (medicine_id,))
        else:
            cur.execute("DELETE FROM medicines WHERE id = ?", (medicine_id,))
        
        conn.commit()
        flash("Лекарство успешно удалено", "success")
        
    except Exception as e:
        print(f"Ошибка при удалении лекарства: {e}")
        flash("Ошибка при удалении лекарства", "error")
    finally:
        db_close(conn, cur)

    return redirect(url_for('admin_medicines'))

if __name__ == "__main__":
    app.run(debug=True)