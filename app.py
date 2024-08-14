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
    comments = db.relationship('Comment', backref='product', lazy=True)  # Relationship with comments

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



class PurchaseHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    product_price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    purchase_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    

    def __repr__(self):
        return f'<PurchaseHistory {self.product_name} by User {self.user_id}>'

# Update the User model to include the relationship
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    cart_items = db.relationship('CartItem', backref='user', lazy=True)
    wishlist_items = db.relationship('WishlistItem', backref='user', lazy=True)
    purchase_history = db.relationship('PurchaseHistory', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)  # Relationship with comments
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

    
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    image_url = db.Column(db.String(255), nullable=True)  # New column for storing the image URL
    rating = db.Column(db.Integer, nullable=False, default=0)  # New column for rating

    def __repr__(self):
        return f'<Comment {self.content[:20]}... by User {self.user_id}>'




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
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')
    
    return render_template('login.html', title='Login', form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total_price = sum(item.product.price * item.quantity for item in cart_items)

    if request.method == 'POST':
        return redirect(url_for('process_checkout'))

    return render_template('checkout.html', cart_items=cart_items, total_price=total_price)



@app.route('/process_checkout', methods=['POST'])
@login_required
def process_checkout():
    # Extract billing information from the form
    billing_name = request.form.get('billing_name')
    billing_email = request.form.get('billing_email')
    billing_address = request.form.get('billing_address')
    billing_city = request.form.get('billing_city')
    billing_state = request.form.get('billing_state')
    billing_zip = request.form.get('billing_zip')
    billing_country = request.form.get('billing_country')
    
    # Extract payment information from the form
    card_name = request.form.get('card_name')
    card_number = request.form.get('card_number')
    card_expiry = request.form.get('card_expiry')
    card_cvc = request.form.get('card_cvc')

    # Retrieve the cart items
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total_price = 0
    
    for item in cart_items:
        # Calculate total price
        total_price += item.product.price * item.quantity
        
        # Create SalesRecord
        sales_record = SalesRecord(
            product_id=item.product_id,
            quantity_sold=item.quantity,
            sale_date=datetime.utcnow()  # Update with current date and time
        )
        db.session.add(sales_record)
        
        # Update product quantity in stock
        item.product.quantity -= item.quantity
        
        # Add PurchaseHistory record
        purchase_history = PurchaseHistory(
            user_id=current_user.id,
            product_name=item.product.name,
            product_price=item.product.price,
            quantity=item.quantity,
            purchase_date=datetime.utcnow()  # Update with current date and time
        )
        db.session.add(purchase_history)
        
        # Remove the item from the cart
        db.session.delete(item)
    
    db.session.commit()

    # Render the confirmation page with the correct total price
    return render_template('proceed_checkout.html', total_price=total_price)


@app.route('/purchase_history')
@login_required
def purchase_history():
    user_id = current_user.id

    # Get all purchases for the logged-in user
    purchases = PurchaseHistory.query.filter_by(user_id=user_id).all()

    # Convert purchases to a serializable format
    purchases_list = [
        {
            'purchase_date': purchase.purchase_date.strftime('%Y-%m-%d %H:%M:%S'),
            'product_name': purchase.product_name,
            'product_price': purchase.product_price,
            'quantity': purchase.quantity
        }
        for purchase in purchases
    ]

    # Group purchases by date and calculate totals
    grouped_purchases = {}
    for purchase in purchases:
        date_key = purchase.purchase_date.strftime('%Y-%m-%d')
        if date_key not in grouped_purchases:
            grouped_purchases[date_key] = 0
        grouped_purchases[date_key] += purchase.product_price * purchase.quantity

    return render_template('purchase_history.html', purchases=purchases_list, grouped_purchases=grouped_purchases)






@app.route('/admin/add-product', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin:
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
        return redirect(url_for('home'))
    
    return render_template('add_product.html')

@app.route('/admin/update-product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def update_product(product_id):
    if not current_user.is_admin:
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
        return redirect(url_for('home'))
    
    return render_template('update_product.html', product=product)

@app.route('/admin/remove-product/<int:product_id>', methods=['POST'])
@login_required
def remove_product(product_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    
    # Delete all sales records related to this product
    sales_records = SalesRecord.query.filter_by(product_id=product_id).all()
    for record in sales_records:
        db.session.delete(record)
    
    # Now delete the product
    db.session.delete(product)
    db.session.commit()
    
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

    prediction_labels = []
    prediction_data = []

    if sorted_months:
        # Calculate sales predictions using a simple moving average
        num_months_for_prediction = 3  # Using the last 3 months for the moving average

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
        # Check if the product is in the user's wishlist
        wishlist_item = WishlistItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if wishlist_item:
            in_wishlist = True
            in_wishlist_route = 'remove_from_wishlist'

        # Handle the review form submission
        if request.method == 'POST':
            if 'comment' in request.form:  # Check if the form submission is for adding a comment
                comment_content = request.form.get('comment')
                rating = request.form.get('rating')
                image_url = request.form.get('image_url')  # Retrieve the image URL from the form

                if comment_content and rating:
                    new_comment = Comment(
                        content=comment_content,
                        rating=int(rating),
                        user_id=current_user.id,
                        product_id=product.id,
                        image_url=image_url  # Store the image URL directly
                    )

                    db.session.add(new_comment)
                    db.session.commit()
                    return redirect(url_for('product_detail', product_id=product.id))

            elif 'delete_comment' in request.form:  # Handle the comment deletion
                comment_id = request.form.get('delete_comment')
                comment = Comment.query.get_or_404(comment_id)

                if comment.user_id == current_user.id:
                    db.session.delete(comment)
                    db.session.commit()
                    flash('Comment deleted successfully.', 'success')
                else:
                    flash('You are not authorized to delete this comment.', 'danger')

                return redirect(url_for('product_detail', product_id=product.id))

    # Fetch all comments for the product
    comments = Comment.query.filter_by(product_id=product_id).order_by(Comment.date_posted.desc()).all()
    return render_template('product_detail.html', product=product, in_wishlist=in_wishlist, in_wishlist_route=in_wishlist_route, comments=comments)


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id == current_user.id:
        db.session.delete(comment)
        db.session.commit()
        flash('Comment deleted successfully.', 'success')
    else:
        flash('You are not authorized to delete this comment.', 'danger')
    return redirect(url_for('product_detail', product_id=comment.product_id))



@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()  # Get and strip the search query
    if not query:
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
    return redirect(url_for('view_cart'))


@app.route('/remove-from-cart/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    cart_item = CartItem.query.get_or_404(item_id)
    db.session.delete(cart_item)
    db.session.commit()
    return redirect(url_for('view_cart'))


@app.route('/wishlist')
@login_required
def view_wishlist():
    wishlist_items = WishlistItem.query.filter_by(user_id=current_user.id).all()

    # Remove invalid wishlist items (i.e., items pointing to deleted products)
    valid_wishlist_items = []
    for item in wishlist_items:
        if item.product is not None:
            valid_wishlist_items.append(item)
        else:
            db.session.delete(item)
            db.session.commit()

    return render_template('wishlist.html', wishlist_items=valid_wishlist_items)



@app.route('/add-to-wishlist/<int:product_id>', methods=['POST'])
@login_required
def add_to_wishlist(product_id):
    product = Product.query.get_or_404(product_id)
    wishlist_item = WishlistItem.query.filter_by(product_id=product_id, user_id=current_user.id).first()
    
    if wishlist_item:
        pass
    else:
        wishlist_item = WishlistItem(product_id=product_id, user_id=current_user.id)
        db.session.add(wishlist_item)
        db.session.commit()
    
    # Redirect to the referring page
    return redirect(request.referrer)

@app.route('/remove-from-wishlist/<int:product_id>', methods=['POST'])
@login_required
def remove_from_wishlist(product_id):
    wishlist_item = WishlistItem.query.filter_by(product_id=product_id, user_id=current_user.id).first_or_404()
    db.session.delete(wishlist_item)
    db.session.commit()
    
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
    return render_template('aboutUs.html')

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
        #db.drop_all()
        db.create_all()
        create_admin_user()
    app.run(debug=True)

