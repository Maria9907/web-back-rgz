import os
from flask import (
    Flask,
    url_for,
    request,
    redirect,
    make_response,
    abort,
    render_template,

)
import datetime
import psycopg2

app = Flask(__name__)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'секретно-секретный секрет')
app.config['DB_TYPE'] = os.getenv('DB_TYPE', 'postgres')

@app.context_processor
def inject_user():
    return dict(
        student_name="Матюшкина Мария Дмитриевна",
        student_group="ФБИ-32"
    )


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

if __name__ == "__main__":
    app.run(debug=True)