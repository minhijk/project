import eventlet
eventlet.monkey_patch() 
import sqlite3
import uuid
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, emit, join_room
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app, async_mode='eventlet')

def log_admin_action(admin_id, action):
    db = get_db()
    cursor = db.cursor()
    log_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute(
        "INSERT INTO admin_logs (id, admin_id, action, timestamp) VALUES (?, ?, ?, ?)",
        (log_id, admin_id, action, timestamp)
    )
    db.commit()
    
# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_active BOOLEAN DEFAULT 1
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        # 관리자 로그 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_logs (
                id TEXT PRIMARY KEY,
                admin_id TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        # balance 컬럼 추가
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN balance INTEGER DEFAULT 10000")
        except sqlite3.OperationalError:
            pass  # 이미 컬럼이 존재하면 무시
        # is_admin 컬럼 추가
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError:
            pass

        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자입니다.')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_pw))
        db.commit()
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            if not user['is_active']:
                flash('휴면 상태의 계정입니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))

            session['user_id'] = user['id']
            session['is_admin'] = int(user['is_admin'])

            # 관리자일 경우 관리자 페이지로 이동
            if int(user['is_admin']) == 1:
                flash('관리자 로그인 성공!')
                return redirect(url_for('admin_panel'))

            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

    return render_template('login.html')


# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 🔍 검색 키워드 처리
    keyword = request.args.get('q', '')
    if keyword:
        cursor.execute("""
            SELECT product.*, user.username AS seller_name
            FROM product
            JOIN user ON product.seller_id = user.id
            WHERE product.title LIKE ?
        """, (f'%{keyword}%',))
    else:
        cursor.execute("""
            SELECT product.*, user.username AS seller_name
            FROM product
            JOIN user ON product.seller_id = user.id
        """)
    all_products = cursor.fetchall()

    return render_template('dashboard.html', user=current_user, products=all_products, keyword=keyword)


# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if request.method == 'POST':
        bio = request.form.get('bio', '')
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')

        # 비밀번호 변경 요청이 있을 경우
        if current_pw and new_pw:
            if bcrypt.checkpw(current_pw.encode('utf-8'), user['password']):
                hashed_new_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_new_pw, user['id']))
                flash('비밀번호가 변경되었습니다.')
            else:
                flash('현재 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('profile'))

        # 소개글 업데이트
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, user['id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)


@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())

        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()

    return render_template('new_product.html', message='상품이 등록되었습니다.')

@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()

    # 상품 정보 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()

    return render_template('view_product.html', product=product, seller=seller)


@app.route('/report/<target_id>', methods=['GET', 'POST'])
def report(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        reason = request.form['reason']
        report_id = str(uuid.uuid4())

        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()

        # 사용자 여부 확인
        cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
        user = cursor.fetchone()

        if user:
            # 바로 휴면 처리
            cursor.execute("UPDATE user SET is_active = 0 WHERE id = ?", (target_id,))
            db.commit()
            flash('해당 사용자가 신고로 인해 휴면 처리되었습니다.')
        else:
            # 상품은 즉시 삭제
            cursor.execute("DELETE FROM product WHERE id = ?", (target_id,))
            db.commit()
            flash('해당 상품은 신고되어 삭제되었습니다.')

        return redirect(url_for('dashboard'))

    return render_template('report.html', target_id=target_id)

@app.route('/reports')
def view_reports():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT report.*, 
            u1.username AS reporter_name, 
            u2.username AS target_name
        FROM report
        LEFT JOIN user u1 ON report.reporter_id = u1.id
        LEFT JOIN user u2 ON report.target_id = u2.id
    """)
    reports = cursor.fetchall()
    return render_template('view_reports.html', reports=reports)

@app.route('/my-products')
def my_products():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    products = cursor.fetchall()

    return render_template('my_products.html', products=products)

@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 가져오기
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    # 판매자 본인 확인
    if not product or product['seller_id'] != session['user_id']:
        flash('수정 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']

        cursor.execute("""
            UPDATE product
            SET title = ?, description = ?, price = ?
            WHERE id = ?
        """, (title, description, price, product_id))
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('my_products'))

    return render_template('edit_product.html', product=product)

@app.route('/product/delete/<product_id>')
def delete_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 가져오기
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('admin_panel'))

    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 관리자 또는 본인만 삭제 가능
    if int(current_user['is_admin']) != 1 and product['seller_id'] != session['user_id']:
        flash('삭제 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    # 삭제 처리
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()

    if int(current_user['is_admin']) == 1:
        log_admin_action(current_user['id'], f"상품 {product_id} 삭제")
        
    flash('상품이 삭제되었습니다.')

    # 관리자면 관리자 페이지로, 일반 사용자는 내 상품 목록으로 이동
    if int(current_user['is_admin']) == 1:
        return redirect(url_for('admin_panel'))
    else:
        return redirect(url_for('my_products'))

@app.route('/user/<user_id>')
def view_user(user_id):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    return render_template('view_user.html', user=user)

@app.route('/chat/<receiver_id>')
def chat(receiver_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    if session['user_id'] == receiver_id:
        flash('자기 자신과는 채팅할 수 없습니다.')
        return redirect(url_for('dashboard'))

    room_id = '_'.join(sorted([session['user_id'], receiver_id]))
    return redirect(url_for('chat_room', room_id=room_id))


@app.route('/chat/room/<room_id>')
def chat_room(room_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    ids = room_id.split('_')
    user_id = session['user_id']

    if user_id in ids:
        receiver_id = ids[1] if ids[0] == user_id else ids[0]
    else:
        flash('잘못된 채팅방 접근입니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (receiver_id,))
    receiver = cursor.fetchone()

    if not receiver:
        flash('대화 상대를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    print("DEBUG - receiver:", receiver['id'], receiver['username'])

    return render_template("chat_private.html", room_id=room_id, receiver=receiver)



@socketio.on('join')
def handle_join(data):
    print(f"join room: {data['room']}")
    join_room(data['room'])

@socketio.on('private_message')
def handle_private_message(data):
    print(f"msg to {data['room']}: {data['message']}")
    emit('private_message', {'message': data['message']}, room=data['room'])

@app.route('/chat')
def global_chat():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    return render_template('chat.html', user=user)


# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        receiver_username = request.form['receiver_username']
        amount = int(request.form['amount'])

        # 현재 유저 정보
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        sender = cursor.fetchone()

        # 받는 유저 정보
        cursor.execute("SELECT * FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()

        if not receiver:
            flash('받는 사용자가 존재하지 않습니다.')
            return redirect(url_for('transfer'))

        if sender['id'] == receiver['id']:
            flash('자기 자신에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))

        if sender['balance'] < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        # 송금 처리
        cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, sender['id']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))
        db.commit()

        flash(f"{receiver['username']}님에게 {amount}원을 송금했습니다.")
        return redirect(url_for('dashboard'))

    return render_template('transfer.html')

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 명확하게 정수로 체크
    if int(current_user['is_admin']) != 1:
        flash('관리자만 접근 가능한 페이지입니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()

    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()
    
    cursor.execute("""
        SELECT log.*, u.username AS admin_name
        FROM admin_logs log
        JOIN user u ON log.admin_id = u.id
        ORDER BY log.timestamp DESC
        LIMIT 20
    """)
    logs = cursor.fetchall()

    return render_template('admin.html', users=users, products=products, logs=logs)

@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
    db.commit()
    
    log_admin_action(session['user_id'], f"사용자 {user_id} 삭제")
    flash("사용자가 삭제되었습니다.")
    return redirect(url_for('admin_panel'))

# 예: admin이라는 username을 가진 유저를 관리자 지정
# 아래 코드 app.py에 일시적으로 추가 (이후 삭제해도 됨)
@app.route('/make-admin/<username>')
def make_admin(username):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET is_admin = 1 WHERE username = ?", (username,))
    db.commit()
    return f"{username} 계정이 관리자 권한을 갖게 되었습니다."

@app.route('/admin/update_balance/<user_id>', methods=['POST'])
def update_balance(user_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 로그인한 유저가 관리자 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    admin_user = cursor.fetchone()
    if not admin_user or int(admin_user['is_admin']) != 1:
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('dashboard'))

    try:
        new_balance = int(request.form['new_balance'])
        cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (new_balance, user_id))
        db.commit()
        log_admin_action(session['user_id'], f"{user_id}의 포인트를 {new_balance}원으로 수정")
        flash('포인트가 수정되었습니다.')
    except:
        flash('잘못된 요청입니다.')

    return redirect(url_for('admin_panel'))


@app.route('/admin/toggle_admin/<user_id>')
def toggle_admin(user_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    admin_user = cursor.fetchone()
    if not admin_user or int(admin_user['is_admin']) != 1:
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    target_user = cursor.fetchone()

    if not target_user:
        flash("해당 사용자를 찾을 수 없습니다.")
        return redirect(url_for('admin_panel'))

    # 권한 토글
    new_status = 0 if target_user['is_admin'] else 1
    cursor.execute("UPDATE user SET is_admin = ? WHERE id = ?", (new_status, user_id))
    db.commit()

    # 로그 기록
    status_text = '부여' if new_status == 1 else '해제'
    log_admin_action(session['user_id'], f"{user_id}에 대해 관리자 권한 {status_text}")

    flash("권한이 변경되었습니다.")
    return redirect(url_for('admin_panel'))



if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
