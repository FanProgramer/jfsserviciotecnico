import io
import os
import sqlite3
from flask import Flask, g, jsonify, render_template, request, redirect, url_for, flash, session, send_file
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
import pytz
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import Flask
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet




app = Flask(__name__)
app.secret_key = 'Fanfanfan'  # Clave secreta estática
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///punto_venta.db'  # Ruta a tu base de datos SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Ruta para la página de login


DATABASE = 'punto_venta.db'

DATABASE_VENTAS = 'ventas.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS productos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                cantidad INTEGER NOT NULL,
                precio REAL NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS ventas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                producto_id INTEGER NOT NULL,
                cantidad INTEGER NOT NULL,
                total REAL NOT NULL,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (producto_id) REFERENCES productos(id)
            )
        ''')
        conn.commit()
        conn.close()

init_db()


# Definición del modelo de usuario
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Puede ser 'admin' o 'cajero'

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password, password)
    

# Configuración de Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Creación de la base de datos
with app.app_context():
    db.create_all()

# Ruta principal
@app.route('/')
@login_required
def index():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT SUM(ganancia) FROM ventas WHERE DATE(fecha) = DATE("now")')
    ganancias_dia = c.fetchone()[0]
    if ganancias_dia is None:
        ganancias_dia = 0

    # Obtener productos agregados a la venta
    productos_agregados = session.get('productos_agregados', [])
    total = sum([p['precio'] * p['cantidad'] for p in productos_agregados])

    return render_template('index.html', ganancias_dia=ganancias_dia, productos=[], productos_agregados=productos_agregados, total=total, mostrar_registros=current_user.role == 'admin')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Credenciales inválidas. Por favor, inténtelo nuevamente.', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Se ha cerrado sesión correctamente.', 'success')
    return redirect(url_for('index'))


from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        role = 'admin'

        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Usuario administrador registrado exitosamente.', 'success')
        return redirect(url_for('index'))

    return render_template('register_admin.html')



@app.route('/registro_cajeros', methods=['GET', 'POST'])
@login_required
def register_cajero():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verificar si ya existe un usuario con ese username
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('El nombre de usuario ya está en uso.', 'error')
            return render_template('registro_cajeros.html')

        # Crear un nuevo usuario cajero
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        role = 'cajero'
        new_user = User(username=username, password=hashed_password, role=role)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Usuario cajero registrado exitosamente.', 'success')
            return redirect(url_for('index'))  # Redirige al index del administrador
        except Exception as e:
            flash(f'Error al registrar usuario cajero: {str(e)}', 'error')
            db.session.rollback()

    return render_template('registro_cajeros.html')


@app.route('/login_cajero', methods=['GET', 'POST'])
def login_cajero():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, role='cajero').first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Inicio de sesión como cajero exitoso.', 'success')
            return redirect(url_for('index'))  # Redirige al index del cajero
        else:
            flash('Credenciales inválidas para cajero. Por favor, inténtelo nuevamente.', 'error')

    return render_template('login_cajero.html')



# Ruta para ver y gestionar cajeros (solo accesible por administradores)
@app.route('/admin/cajeros')
@login_required
def manage_cajeros():
    if current_user.role != 'admin':
        flash('Acceso no autorizado.', 'error')
        return redirect(url_for('index'))

    cajeros = User.query.filter_by(role='cajero').all()
    return render_template('manage_cajeros.html', cajeros=cajeros)

# Ruta para editar un cajero
@app.route('/admin/editar_cajero/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_cajero(user_id):
    if current_user.role != 'admin':
        flash('Acceso no autorizado.', 'error')
        return redirect(url_for('index'))

    cajero = User.query.get(user_id)

    if request.method == 'POST':
        new_username = request.form['username']
        new_password = request.form['password']

        # Verificar si el nuevo nombre de usuario ya está en uso
        if new_username != cajero.username and User.query.filter_by(username=new_username).first():
            flash('El nombre de usuario ya está en uso.', 'error')
            return redirect(url_for('edit_cajero', user_id=user_id))

        cajero.username = new_username
        if new_password:
            cajero.set_password(new_password)

        try:
            db.session.commit()
            flash('Cajero actualizado correctamente.', 'success')
            return redirect(url_for('manage_cajeros'))
        except Exception as e:
            flash(f'Error al actualizar cajero: {str(e)}', 'error')
            db.session.rollback()

    return render_template('edit_cajero.html', cajero=cajero)

# Ruta para eliminar un cajero
@app.route('/admin/eliminar_cajero/<int:user_id>', methods=['POST'])
@login_required
def delete_cajero(user_id):
    if current_user.role != 'admin':
        flash('Acceso no autorizado.', 'error')
        return redirect(url_for('index'))

    cajero = User.query.get(user_id)
    if cajero:
        db.session.delete(cajero)
        db.session.commit()
        flash('Cajero eliminado correctamente.', 'success')
    else:
        flash('No se encontró el cajero especificado.', 'error')

    return redirect(url_for('manage_cajeros'))


# Configuración de la zona horaria
TIMEZONE = 'America/Argentina/Buenos_Aires'

# Función para conectar a la base de datos SQLite
def connect_db():
    return sqlite3.connect(DATABASE)

# Conectar y crear la tabla si no existe
def create_table():
    connection = sqlite3.connect('punto_venta.db')
    cursor = connection.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cajeros (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
    )
    ''')
    connection.commit()
    connection.close()

create_table()


# Función para convertir una fecha de UTC a la zona horaria local
def convertir_a_zona_horaria(fecha_utc):
    tz = pytz.timezone(TIMEZONE)
    fecha_utc = fecha_utc.replace(tzinfo=pytz.utc)
    fecha_pilar = fecha_utc.astimezone(tz)
    return fecha_pilar

# Ejemplo de uso en una vista o función de Flask
@app.route('/ejemplo')
def ejemplo():
    # Obtener la fecha y hora actual en UTC
    fecha_actual_utc = datetime.utcnow()

    # Convertir a la zona horaria local (America/Argentina/Buenos_Aires)
    fecha_local = convertir_a_zona_horaria(fecha_actual_utc)

    return render_template('ejemplo.html', fecha_local=fecha_local)


# Función para obtener la conexión a la base de datos
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Esto convierte cada fila en un objeto Row
    return db

# Función para configurar la base de datos
def setup_db():
    with app.app_context():
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS ventas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                producto_id INTEGER NOT NULL,
                cantidad INTEGER NOT NULL,
                total REAL NOT NULL DEFAULT 0,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ganancia REAL NOT NULL DEFAULT 0,
                FOREIGN KEY (producto_id) REFERENCES productos(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS clientes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                telefono TEXT NOT NULL,
                email TEXT
            )
        ''')
        conn.commit()
        conn.close()


# Función para obtener la conexión a la base de datos
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Esto convierte cada fila en un objeto Row
    return db

# Función para inicializar la base de datos y crear tablas si no existen
def init_db():
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS productos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        cantidad INTEGER NOT NULL,
        precio REAL NOT NULL
    )
    ''')
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS ventas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        producto_id INTEGER NOT NULL,
        cantidad INTEGER NOT NULL,
        total REAL NOT NULL,
        fecha TEXT NOT NULL,
        FOREIGN KEY (producto_id) REFERENCES productos (id)
    )
    ''')
    
    conn.commit()
    conn.close()


# Función para registrar una venta
def obtener_ventas(fecha_inicio=None, fecha_fin=None):
    conn = get_db()
    c = conn.cursor()
    if fecha_inicio and fecha_fin:
        c.execute('''
            SELECT v.id, p.nombre AS producto, v.cantidad, v.total, v.fecha
            FROM ventas v
            JOIN productos p ON v.producto_id = p.id
            WHERE v.fecha BETWEEN ? AND ?
        ''', (fecha_inicio, fecha_fin))
    else:
        c.execute('''
            SELECT v.id, p.nombre AS producto, v.cantidad, v.total, v.fecha
            FROM ventas v
            JOIN productos p ON v.producto_id = p.id
        ''')
    ventas = c.fetchall()
    conn.close()
    return [dict(venta) for venta in ventas]



# Función para generar el reporte de ventas en PDF
def generar_reporte_ventas_pdf(fecha_inicio=None, fecha_fin=None):
    conn = get_db()
    c = conn.cursor()

    try:
        if fecha_inicio and fecha_fin:
            c.execute('''
                SELECT v.id, p.nombre AS producto, v.cantidad, v.total, v.fecha
                FROM ventas v
                JOIN productos p ON v.producto_id = p.id
                WHERE v.fecha BETWEEN ? AND ?
            ''', (fecha_inicio, fecha_fin))
        else:
            c.execute('''
                SELECT v.id, p.nombre AS producto, v.cantidad, v.total, v.fecha
                FROM ventas v
                JOIN productos p ON v.producto_id = p.id
            ''')

        ventas = c.fetchall()

        # Crear el PDF
        pdf_buffer = io.BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=A4)
        elements = []

        # Obtener los estilos de párrafo predefinidos
        styles = getSampleStyleSheet()

        # Añadir título
        elements.append(Paragraph("Reporte de Ventas", styles['Title']))

        # Crear la tabla
        data = [["ID Venta", "Producto", "Cantidad", "Total", "Fecha"]]
        for venta in ventas:
            data.append([venta['id'], venta['producto'], venta['cantidad'], f"${venta['total']:.2f}", venta['fecha']])

        table = Table(data, colWidths=[3*cm, 6*cm, 3*cm, 3*cm, 5*cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        elements.append(table)
        doc.build(elements)
        pdf_buffer.seek(0)

        return pdf_buffer

    except Exception as e:
        return f'Error al generar reporte de ventas en PDF: {str(e)}'


# Ruta para ver el reporte de ventas en PDF
@app.route('/ver_reporte_ventas_pdf', methods=['GET'])
def ver_reporte_ventas_pdf():
    try:
        fecha_inicio = request.args.get('fecha_inicio')
        fecha_fin = request.args.get('fecha_fin')

        # Generar el reporte en PDF y enviarlo como archivo adjunto para descargar
        pdf_buffer = generar_reporte_ventas_pdf(fecha_inicio, fecha_fin)
        return send_file(pdf_buffer, as_attachment=True, download_name='reporte_ventas.pdf', mimetype='application/pdf')

    except Exception as e:
        return f'Error al generar reporte de ventas en PDF: {str(e)}'

# Ruta para mostrar los reportes de ventas
@app.route('/reportes', methods=['GET', 'POST'])
def reportes():
    ventas = []
    fecha_inicio = None
    fecha_fin = None

    if request.method == 'POST':
        fecha_inicio = request.form['fecha_inicio']
        fecha_fin = request.form['fecha_fin']
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT v.id, p.nombre AS producto, v.cantidad, v.total, v.fecha
            FROM ventas v
            JOIN productos p ON v.producto_id = p.id
            WHERE v.fecha BETWEEN ? AND ?
        ''', (fecha_inicio, fecha_fin))
        ventas = c.fetchall()
        conn.close()

    return render_template('reportes.html', ventas=ventas, fecha_inicio=fecha_inicio, fecha_fin=fecha_fin)

    

# Ruta para registrar productos
@app.route('/registro_productos')
def registro_productos():
    return render_template('registro_productos.html')

# Guardar un nuevo producto
@app.route('/guardar_producto', methods=['POST'])
def guardar_producto():
    nombre = request.form['nombre']
    costo = float(request.form['costo'])
    precio_venta = float(request.form['precio_venta'])
    stock = int(request.form['stock'])

    if nombre and costo > 0 and precio_venta > 0 and stock >= 0:
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO productos (nombre, costo, precio_venta, stock) VALUES (?, ?, ?, ?)',
                  (nombre, costo, precio_venta, stock))
        conn.commit()
        flash('Producto guardado con éxito', 'success')
    else:
        if not nombre:
            flash('Nombre del producto inválido', 'error')
        if not costo > 0:
            flash('Costo del producto inválido', 'error')
        if not precio_venta > 0:
            flash('Precio de venta del producto inválido', 'error')
        if not stock >= 0:
            flash('Stock del producto inválido', 'error')

    return redirect(url_for('registro_productos'))

# Buscar productos por nombre
@app.route('/buscar_producto', methods=['POST'])
def buscar_producto():
    nombre = request.form['nombre']
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, nombre, precio_venta, stock FROM productos WHERE nombre LIKE ?', ('%' + nombre + '%',))
    productos = c.fetchall()

    # Asegurar manejo correcto de valores nulos en precio_venta
    productos = [(p[0], p[1], p[2] if p[2] is not None else 0, p[3]) for p in productos]

    return render_template('index.html', productos=productos)

# Lista para productos agregados en la venta
productos_agregados = []

# Ruta para quitar un producto del carrito de venta
@app.route('/quitar_producto', methods=['POST'])
def quitar_producto():
    try:
        producto_id = request.form['producto_id']
        global productos_agregados
        productos_agregados = [p for p in productos_agregados if p[0] != producto_id]

        return render_template('index.html', productos=productos_agregados)

    except Exception as e:
        flash(f'Error al quitar producto: {str(e)}', 'error')
        return redirect(url_for('index'))

# Agregar un producto al carrito de venta
@app.route('/agregar_producto', methods=['POST'])
def agregar_producto():
    data = request.json
    producto_id = data['producto_id']
    nombre = data['nombre']
    cantidad = int(data['cantidad'])
    precio = float(data['precio'])

    # Verificar si el producto ya está en la lista
    for producto in productos_agregados:
        if producto['id'] == producto_id:
            producto['cantidad'] += cantidad
            break
    else:
        productos_agregados.append({
            'id': producto_id,
            'nombre': nombre,
            'cantidad': cantidad,
            'precio': precio
        })

    total = sum(p['cantidad'] * p['precio'] for p in productos_agregados)

    return jsonify({'productos_agregados': productos_agregados, 'total': total})


@app.route('/calcular_total', methods=['POST'])
def calcular_total():
    conn = get_db()
    c = conn.cursor()

    data = request.get_json()
    producto_id = data['producto_id']
    cantidad = int(data['cantidad'])

    c.execute('SELECT precio FROM productos WHERE id = ?', (producto_id,))
    producto = c.fetchone()
    if producto:
        precio = producto[0]
        total = precio * cantidad
    else:
        total = 0

    conn.close()

    return {'total': total}


productos_agregados = []
ventas_realizadas = [] 

# Procesar la venta y actualizar inventario
@app.route('/realizar_venta', methods=['POST'])
def realizar_venta():
    global productos_agregados, ventas_realizadas
    conn = get_db()
    c = conn.cursor()

    try:
        for producto in productos_agregados:
            producto_id = producto['id']
            cantidad = producto['cantidad']
            precio_total = producto['cantidad'] * producto['precio']

            c.execute('SELECT stock, costo, precio_venta FROM productos WHERE id = ?', (producto_id,))
            producto_info = c.fetchone()

            if producto_info is None:
                flash(f'Producto con ID: {producto_id} no encontrado', 'error')
                conn.rollback()
                return redirect(url_for('index'))

            current_stock, costo, precio_venta = producto_info

            if current_stock is None or costo is None or precio_venta is None:
                flash(f'Error en los datos del producto con ID: {producto_id}', 'error')
                conn.rollback()
                return redirect(url_for('index'))

            if not isinstance(cantidad, int) or cantidad <= 0:
                flash(f'Cantidad no válida para el producto con ID: {producto_id}', 'error')
                conn.rollback()
                return redirect(url_for('index'))

            if not isinstance(costo, (int, float)) or not isinstance(precio_venta, (int, float)):
                flash(f'Error en los datos del producto con ID: {producto_id}: Costo o precio de venta no válido', 'error')
                conn.rollback()
                return redirect(url_for('index'))

            if cantidad > current_stock:
                flash(f'Stock insuficiente para el producto con ID: {producto_id}', 'error')
                conn.rollback()
                return redirect(url_for('index'))

            ganancia = (precio_venta - costo) * cantidad

            c.execute('UPDATE productos SET stock = stock - ? WHERE id = ?', (cantidad, producto_id))
            c.execute('INSERT INTO ventas (producto_id, cantidad, total, ganancia) VALUES (?, ?, ?, ?)',
                      (producto_id, cantidad, precio_total, ganancia))

        conn.commit()
        flash('Venta realizada con éxito', 'success')
        
        # Guardar la venta realizada en la lista de ventas_realizadas
        ventas_realizadas.append({
            'productos': productos_agregados,
            'total': sum(producto['cantidad'] * producto['precio'] for producto in productos_agregados)
        })
        
        # Limpiar la lista de productos_agregados después de una venta exitosa
        productos_agregados = []

    except Exception as e:
        conn.rollback()
        flash(f'Error al realizar la venta: {str(e)}', 'error')

    return redirect(url_for('index'))

# Ruta para ver el último ticket de venta
@app.route('/ver_ultimo_ticket')
def ver_ultimo_ticket():
    global ventas_realizadas

    if not ventas_realizadas:
        return "No hay ventas registradas."

    # Obtener la última venta realizada
    ultima_venta = ventas_realizadas[-1]

    # Renderizar el template del ticket con los datos de la última venta
    return render_template('ticket.html', productos=ultima_venta['productos'], total=ultima_venta['total'])


# Importar Flask y render_template si aún no están importados
from flask import Flask, render_template

# Ruta para mostrar inventario de productos
@app.route('/inventario')
def inventario():
    conn = get_db()  # Ajusta según cómo obtienes la conexión a tu base de datos
    c = conn.cursor()
    c.execute('SELECT id, nombre, costo, precio_venta, stock FROM productos')
    productos = c.fetchall()

    # Calcular el total de costo considerando el stock
    total_costo = sum(producto[2] * producto[4] for producto in productos)

    # Filtrar productos con stock bajo
    productos_bajo_stock = [producto for producto in productos if producto[4] < 4]

    return render_template('inventario.html', productos=productos, total_costo=total_costo, productos_bajo_stock=productos_bajo_stock)

# Ruta para editar un producto
@app.route('/editar_producto/<int:producto_id>', methods=['GET', 'POST'])
@login_required
def editar_producto(producto_id):
    if current_user.role != 'admin':
        flash('Acceso no autorizado. Solo los administradores pueden editar productos.', 'danger')
        return redirect(url_for('inventario'))

    conn = get_db()
    if request.method == 'POST':
        nombre = request.form['nombre']
        costo = float(request.form['costo'])
        precio_venta = float(request.form['precio_venta'])
        stock = int(request.form['stock'])

        # Actualizar el producto en la base de datos
        try:
            c = conn.cursor()
            c.execute('''
                UPDATE productos SET nombre=?, costo=?, precio_venta=?, stock=?
                WHERE id=?
            ''', (nombre, costo, precio_venta, stock, producto_id))
            conn.commit()
            flash('Producto actualizado correctamente', 'success')
            return redirect(url_for('inventario'))
        except Exception as e:
            flash(f'Error al actualizar el producto: {str(e)}', 'error')

    # Obtener los datos actuales del producto para mostrar en el formulario de edición
    try:
        c = conn.cursor()
        c.execute('SELECT * FROM productos WHERE id=?', (producto_id,))
        producto = c.fetchone()
        conn.close()
        if not producto:
            flash('Producto no encontrado', 'error')
            return redirect(url_for('inventario'))
        return render_template('editar_producto.html', producto=producto)
    except Exception as e:
        flash(f'Error al buscar el producto: {str(e)}', 'error')
        return redirect(url_for('inventario'))

# Ruta para agregar stock a un producto específico
@app.route('/agregar_stock/<int:producto_id>', methods=['GET', 'POST'])
@login_required
def agregar_stock(producto_id):
    if current_user.role != 'admin':
        flash('Acceso no autorizado. Solo los administradores pueden agregar stock.', 'danger')
        return redirect(url_for('inventario'))

    conn = get_db()
    c = conn.cursor()

    if request.method == 'POST':
        cantidad_agregada = int(request.form['cantidad'])

        c.execute('SELECT stock FROM productos WHERE id = ?', (producto_id,))
        current_stock = c.fetchone()[0]

        if current_stock is None:
            flash(f'Producto con ID: {producto_id} no encontrado', 'error')
            return redirect(url_for('inventario'))

        nuevo_stock = current_stock + cantidad_agregada

        c.execute('UPDATE productos SET stock = ? WHERE id = ?', (nuevo_stock, producto_id))
        conn.commit()

        flash(f'Se agregaron {cantidad_agregada} unidades al stock del producto', 'success')
        return redirect(url_for('inventario'))

    else:
        c.execute('SELECT nombre FROM productos WHERE id = ?', (producto_id,))
        nombre_producto = c.fetchone()[0]
        return render_template('agregar_stock.html', producto_id=producto_id, nombre_producto=nombre_producto)

# Ruta para eliminar un producto del inventario
@app.route('/eliminar_producto/<int:producto_id>', methods=['POST'])
@login_required
def eliminar_producto(producto_id):
    if current_user.role != 'admin':
        flash('Acceso no autorizado. Solo los administradores pueden eliminar productos.', 'danger')
        return redirect(url_for('inventario'))

    conn = get_db()  # Obtener la conexión a la base de datos, ajusta según tu implementación
    c = conn.cursor()
    
    # Ejecutar la consulta para eliminar el producto por su ID
    c.execute('DELETE FROM productos WHERE id = ?', (producto_id,))
    conn.commit()  # Confirmar la eliminación en la base de datos

    # Redirigir a la página de inventario después de eliminar
    return redirect('/inventario')

@app.route('/clientes')
def clientes():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, nombre, email, telefono FROM clientes')
    clientes = c.fetchall()
    conn.close()
    return render_template('clientes.html', clientes=clientes)

# Ruta para agregar un nuevo cliente
@app.route('/agregar_cliente', methods=['GET', 'POST'])
def agregar_cliente():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        telefono = request.form['telefono']
        
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO clientes (nombre, email, telefono) VALUES (?, ?, ?)', (nombre, email, telefono))
        conn.commit()
        conn.close()
        
        return redirect(url_for('clientes'))
    
    return render_template('agregar_cliente.html')


@app.route('/buscar_cliente', methods=['POST'])
def buscar_cliente():
    buscar = request.form['buscar']
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, nombre, email, telefono FROM clientes WHERE nombre LIKE ? OR email LIKE ? OR telefono LIKE ?',
              ('%' + buscar + '%', '%' + buscar + '%', '%' + buscar + '%'))
    resultados = c.fetchall()
    conn.close()
    return render_template('clientes.html', resultados=resultados)


@app.route('/eliminar_cliente/<int:cliente_id>', methods=['POST'])
def eliminar_cliente(cliente_id):
    conn = get_db()
    c = conn.cursor()
    
    try:
        c.execute('DELETE FROM clientes WHERE id = ?', (cliente_id,))
        conn.commit()
        flash('Cliente eliminado correctamente', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al eliminar el cliente: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('clientes'))


# Ruta para modificar un cliente existente
@app.route('/modificar_cliente/<int:id>', methods=['GET', 'POST'])
def modificar_cliente(id):
    conn = get_db()
    c = conn.cursor()
    
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        telefono = request.form['telefono']
        
        c.execute('UPDATE clientes SET nombre = ?, email = ?, telefono = ? WHERE id = ?', (nombre, email, telefono, id))
        conn.commit()
        conn.close()
        
        return redirect(url_for('clientes'))
    
    c.execute('SELECT id, nombre, email, telefono FROM clientes WHERE id = ?', (id,))
    cliente = c.fetchone()
    conn.close()
    
    return render_template('modificar_cliente.html', cliente=cliente)

# Manejador de errores 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404




# Ejecutar la aplicación
if __name__ == '__main__':
    setup_db()
    app.run(debug=True)
    