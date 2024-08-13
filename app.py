from flask import Flask, render_template, redirect, url_for, flash, request,jsonify
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Bootstrap and SQLAlchemy
Bootstrap(app)
db = SQLAlchemy(app)

# Initialize LoginManager
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Database Models
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    sale_percentage = db.Column(db.Float, default=0)  # Sale percentage, 0 means no sale
    quantity = db.Column(db.Integer, nullable=False, default=0)  # Quantity in stock

    def __repr__(self):
        return f'<Product {self.name}>'


class SalesRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product = db.relationship('Product', backref=db.backref('sales', lazy=True))
    quantity_sold = db.Column(db.Integer, nullable=False)
    sale_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<SalesRecord {self.product_id} - {self.quantity_sold} units sold>'


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product = db.relationship('Product')
    quantity = db.Column(db.Integer, nullable=False, default=1)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<CartItem {self.product.name} - {self.quantity}>'


class WishlistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product = db.relationship('Product')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<WishlistItem {self.product.name}>'



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    cart_items = db.relationship('CartItem', backref='user', lazy=True)
    wishlist_items = db.relationship('WishlistItem', backref='user', lazy=True)
    is_admin = db.Column(db.Boolean, default=False)  # New field for admin check

    def __repr__(self):
        return f'<User {self.username}>'


# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already in use.')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is already taken.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route('/')
@app.route('/home')
def home():
    products = Product.query.all()
    return render_template('home.html', products=products)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        # Log the user in after registration
        login_user(user, remember=True)
        return redirect(url_for('home'))
    
    return render_template('register.html', title='Register', form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')
    
    return render_template('login.html', title='Login', form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/admin/add-product', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = float(request.form.get('price'))
        image = request.form.get('image')
        category = request.form.get('category')
        sale_percentage = int(request.form.get('sale_percentage', 0))
        quantity = int(request.form.get('quantity'))
        
        product = Product(
            name=name,
            description=description,
            price=price,
            image=image,
            category=category,
            sale_percentage=sale_percentage,
            quantity=quantity
        )
        db.session.add(product)
        db.session.commit()
        flash(f'Product {name} added successfully.', 'success')
        return redirect(url_for('home'))
    
    return render_template('add_product.html')

@app.route('/admin/update-product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def update_product(product_id):
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    
    if request.method == 'POST':
        product.name = request.form.get('name')
        product.description = request.form.get('description')
        product.price = float(request.form.get('price'))
        product.image = request.form.get('image')
        product.category = request.form.get('category')
        product.sale_percentage = int(request.form.get('sale_percentage', 0))
        product.quantity = int(request.form.get('quantity'))
        
        db.session.commit()
        flash(f'Product {product.name} updated successfully.', 'success')
        return redirect(url_for('home'))
    
    return render_template('update_product.html', product=product)

@app.route('/admin/remove-product/<int:product_id>', methods=['POST'])
@login_required
def remove_product(product_id):
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    
    # Delete all sales records related to this product
    sales_records = SalesRecord.query.filter_by(product_id=product_id).all()
    for record in sales_records:
        db.session.delete(record)
    
    # Now delete the product
    db.session.delete(product)
    db.session.commit()
    
    flash(f'Product {product.name} removed successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/product/<int:product_id>/report', methods=['GET'])
def product_report(product_id):
    product = Product.query.get_or_404(product_id)
    sales = SalesRecord.query.filter_by(product_id=product_id).all()
    sales_data = [
        {
            'date': sale.sale_date.strftime('%Y-%m-%d'),
            'quantity_sold': sale.quantity_sold
        }
        for sale in sales
    ]
    return render_template('product_report.html', product=product, sales_data=sales_data)


@app.route('/overall-report', methods=['GET'])
@login_required
def overall_report():
    sales = SalesRecord.query.all()
    total_sales_per_product = {}
    monthly_sales = {}

    for sale in sales:
        product_id = sale.product_id
        sale_date = sale.sale_date.strftime('%Y-%m')
        quantity_sold = sale.quantity_sold

        # Sum sales per product
        if product_id in total_sales_per_product:
            total_sales_per_product[product_id] += quantity_sold
        else:
            total_sales_per_product[product_id] = quantity_sold

        # Sum sales per month
        if sale_date in monthly_sales:
            monthly_sales[sale_date] += quantity_sold
        else:
            monthly_sales[sale_date] = quantity_sold

    # Sort products by total sales
    sorted_products = sorted(total_sales_per_product.items(), key=lambda item: item[1], reverse=True)
    top_products = [
        {
            'name': Product.query.get(product_id).name,
            'image': Product.query.get(product_id).image,
            'total_sales': total_sales
        }
        for product_id, total_sales in sorted_products
    ]

    # Convert monthly sales into a sorted list of months
    sorted_months = sorted(monthly_sales.items())

    # Calculate sales predictions using a simple moving average
    num_months_for_prediction = 3  # Using the last 3 months for the moving average
    prediction_labels = []
    prediction_data = []

    for i in range(num_months_for_prediction, len(sorted_months)):
        avg_sales = sum([x[1] for x in sorted_months[i - num_months_for_prediction:i]]) / num_months_for_prediction
        prediction_labels.append(sorted_months[i][0])
        prediction_data.append(avg_sales)

    # Adding future months for prediction
    last_month = datetime.strptime(sorted_months[-1][0], '%Y-%m')
    for i in range(1, 6):  # Predicting for the next 5 months
        future_month = (last_month + timedelta(days=i * 30)).strftime('%Y-%m')
        avg_sales = sum([x[1] for x in sorted_months[-num_months_for_prediction:]]) / num_months_for_prediction
        prediction_labels.append(future_month)
        prediction_data.append(avg_sales)

    overall_sales_data = [
        {
            'date': sale.sale_date.strftime('%Y-%m-%d'),
            'quantity_sold': sale.quantity_sold
        }
        for sale in sales
    ]

    return render_template(
        'overall_report.html',
        overall_sales_data=overall_sales_data,
        top_products=top_products,
        prediction_labels=prediction_labels,
        prediction_data=prediction_data
    )

@app.route('/new-collection', methods=['GET'])
def new_collection():
    products = Product.query.filter(Product.sale_percentage == 0).all()
    return render_template('new-collection.html', title='New Collection', products=products)


@app.route('/sale', methods=['GET'])
def sale():
    sort_order = request.args.get('sort')
    if sort_order == 'price_asc':
        products = Product.query.filter(Product.sale_percentage > 0).order_by(Product.price).all()
    elif sort_order == 'price_desc':
        products = Product.query.filter(Product.sale_percentage > 0).order_by(Product.price.desc()).all()
    else:
        products = Product.query.filter(Product.sale_percentage > 0).all()
    return render_template('sale.html', title='Sale', products=products)


@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    in_wishlist = False
    in_wishlist_route = 'add_to_wishlist'

    if current_user.is_authenticated:
        wishlist_item = WishlistItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if wishlist_item:
            in_wishlist = True
            in_wishlist_route = 'remove_from_wishlist'

    return render_template('product_detail.html', product=product, in_wishlist=in_wishlist, in_wishlist_route=in_wishlist_route)



@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()  # Get and strip the search query
    if not query:
        flash('Search query cannot be empty.', 'warning')
        return redirect(url_for('home'))
    
    # Perform the search with case-insensitive matching
    products = Product.query.filter(
        (Product.name.ilike(f'%{query}%')) |
        (Product.description.ilike(f'%{query}%'))
    ).all()
    
    return render_template('search_results.html', products=products, query=query)



@app.route('/cart')
@login_required
def view_cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    return render_template('cart.html', cart_items=cart_items)


@app.route('/add-to-cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    quantity = int(request.form.get('quantity', 1))

    cart_item = CartItem.query.filter_by(product_id=product_id, user_id=current_user.id).first()

    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(product_id=product_id, quantity=quantity, user_id=current_user.id)
        db.session.add(cart_item)

    db.session.commit()
    flash(f'Added {quantity} {product.name}(s) to your cart.', 'success')
    return redirect(url_for('view_cart'))


@app.route('/remove-from-cart/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    cart_item = CartItem.query.get_or_404(item_id)
    db.session.delete(cart_item)
    db.session.commit()
    flash('Item removed from your cart.', 'success')
    return redirect(url_for('view_cart'))


@app.route('/wishlist')
@login_required
def view_wishlist():
    wishlist_items = WishlistItem.query.filter_by(user_id=current_user.id).all()
    return render_template('wishlist.html', wishlist_items=wishlist_items)


@app.route('/add-to-wishlist/<int:product_id>', methods=['POST'])
@login_required
def add_to_wishlist(product_id):
    product = Product.query.get_or_404(product_id)
    wishlist_item = WishlistItem.query.filter_by(product_id=product_id, user_id=current_user.id).first()
    
    if wishlist_item:
        flash('Product is already in your wishlist.', 'info')
    else:
        wishlist_item = WishlistItem(product_id=product_id, user_id=current_user.id)
        db.session.add(wishlist_item)
        db.session.commit()
        flash(f'Added {product.name} to your wishlist.', 'success')
    
    # Redirect to the referring page
    return redirect(request.referrer)

@app.route('/remove-from-wishlist/<int:product_id>', methods=['POST'])
@login_required
def remove_from_wishlist(product_id):
    wishlist_item = WishlistItem.query.filter_by(product_id=product_id, user_id=current_user.id).first_or_404()
    db.session.delete(wishlist_item)
    db.session.commit()
    flash('Item removed from your wishlist.', 'success')
    
    # Redirect to the referring page
    return redirect(request.referrer )

@app.route('/initialize-db')
def initialize_db():
    try:
        db.create_all()
        flash('Database initialized successfully!', 'success')
    except Exception as e:
        flash(f'Error initializing database: {str(e)}', 'danger')
    return redirect(url_for('home'))

@app.route('/about')
def about():
    pass

from faker import Faker
import random
from datetime import datetime, timedelta

fake = Faker()

def generate_fake_products_and_sales(count=20):
    categories = ['T-Shirts', 'Jeans', 'Jackets', 'Sweaters', 'Dresses', 'Skirts']
    
    # Create lists to hold the products and sales records
    products = []
    sales_records = []

    for _ in range(count):
        product = Product(
            name=fake.word().capitalize(),
            description=fake.text(),
            price=round(random.uniform(10.0, 100.0), 2),
            image=f'https://picsum.photos/200/300?random={random.randint(1, 1000)}',
            category=random.choice(categories),
            sale_percentage=random.choice([0, 10, 20, 30, 50]),
            quantity=random.randint(1, 100)
        )
        products.append(product)

    # Add all products and commit to get their IDs
    db.session.add_all(products)
    db.session.commit()

    for product in products:
        for _ in range(random.randint(1, 5)):
            sales_record = SalesRecord(
                product_id=product.id,
                quantity_sold=random.randint(1, 10),
                sale_date=datetime.utcnow() - timedelta(days=random.randint(0, 30))
            )
            sales_records.append(sales_record)

    # Add all sales records and commit
    db.session.add_all(sales_records)
    db.session.commit()

def create_admin_user():
    username = 'ibbi'
    password = '123'  # Change this to a secure password
    email='ibbi@gmail.com'
    
    # Check if the admin user already exists
    admin_user = User.query.filter_by(username=username).first()
    if admin_user:
        print('Admin user already exists.')
        return
    
    # Create a new admin user
    hashed_password = generate_password_hash(password=password, method='pbkdf2:sha256')
    admin_user = User(username=username, email=email, password=hashed_password,is_admin=True)

    
    
    
    # Add and commit the new user to the database
    db.session.add(admin_user)
    db.session.commit()
    print('Admin user created successfully.')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(debug=True)

