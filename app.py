import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify, get_flashed_messages
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from bson import errors as bson_errors
from docx import Document
from ebooklib import epub
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
import re
import mimetypes
import random
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key



# MongoDB configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/online_library"
mongo = PyMongo(app)

load_dotenv()  # Load variables from .env file

# File Upload Configuration
# Define the path for the upload folder (inside static folder)
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'doc', 'docx', 'txt', 'jpg', 'png'}
IMAGE_FOLDER = 'static/images'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(IMAGE_FOLDER, exist_ok=True)
app.config['PROFILE_FOLDER'] = PROFILE_FOLDER
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20MB max file size
app.config['IMAGE_FOLDER'] = IMAGE_FOLDER

def convert_docx_to_html(docx_path):
    doc = Document(docx_path)
    html_content = "".join(f"<p>{para.text}</p>" for para in doc.paragraphs)
    return html_content

def convert_epub_to_html(epub_path):
    book = epub.read_epub(epub_path)
    html_content = "".join(BeautifulSoup(item.content, 'lxml').prettify() for item in book.get_items() if item.get_type() == epub.ITEM_DOCUMENT)
    return html_content

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('home.html')


# Password validation function
def validate_password(password):
    if (len(password) < 8 or
        not re.search(r'[A-Z]', password) or
        not re.search(r'[a-z]', password) or
        not re.search(r'\d', password) or
        not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
        return False
    return True

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        phone_number = request.form['phone']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('register'))

        # Validate password strength
        if not validate_password(password):
            flash("Password must be at least 8 characters long and include an uppercase letter, lowercase letter, number, and special character!","error")
            return redirect(url_for('register'))

        # Check if email already exists
        existing_user = mongo.db.users.find_one({"$or": [{"username": username}, {"email": email}]})
        if existing_user:
            flash("Username or Email already exists!", "error")
            return redirect(url_for('register'))

        # Check if an admin already exists
        if role == 'admin':
            existing_admin = mongo.db.users.find_one({"role": "admin"})
            if existing_admin:
                flash("Only one admin is allowed!", "error")
                return redirect(url_for('register'))

        # Store user in MongoDB
        user_data = {
            "username": username,
            "phone_number": phone_number,
            "email": email,
            "password": generate_password_hash(password),  # In a real app, hash the password!
            "role": role
        }
        mongo.db.users.insert_one(user_data)
        flash("Registered successfully!", "success")
    
    messages = get_flashed_messages(with_categories=True)
    category, message = messages[0] if messages else (None, None)
    return render_template('register.html',category=category, message=message)


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        email = request.form['email']

        # Fetch the user from MongoDB
        user = mongo.db.users.find_one({"email": email})

        if user:
            # Check if the entered password matches the stored password
            if check_password_hash(user['password'], password):  # In production, hash and check the password!
                # Store user info in session
                session['user_id'] = str(user['_id'])
                session['email'] = user['email']
                session['role'] = user['role']

                # Redirect to the user or admin dashboard based on the role
                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('user_dashboard'))
            else:
                flash("Sorry, you have entered incorrect password", "error")
                return redirect(url_for('login'))
        else:
            flash("We couldn't find your account. Please register to get started.", "error")
            return redirect(url_for('login'))
    messages = get_flashed_messages(with_categories=True)
    category, message = messages[0] if messages else (None, None)
    return render_template('login.html',category=category , message=message)

def send_otp_email(to_email, otp):
    sender_email = os.getenv("EMAIL_USER")
    sender_password = os.getenv("EMAIL_PASS")  # Use App Password (Gmail)
    
    msg = MIMEText(f"Your OTP for resetting password is: {otp}")
    msg['Subject'] = "Reset Password - OTP Verification"
    msg['From'] = sender_email
    msg['To'] = to_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        return True
    except Exception as e:
        print("Email send error:", e)
        return False
    

from datetime import datetime, timedelta

@app.route('/resend_otp', methods=['GET'])
def resend_otp():
    email = session.get('reset_email')
    if email:
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()  # 5-minute validity

        if send_otp_email(email, otp):
            flash("New OTP has been sent to your email.", "success")
            return redirect(url_for('verify_otp'))
        else:
            flash("Failed to send OTP. Please try again.", "error")
            return redirect(url_for('verify_otp'))
    else:
        flash("Session expired. Please go back and enter your email again.", "crucial_error")
    messages = get_flashed_messages(with_categories=True)
    category, message = messages[0] if messages else (None, None)
    return render_template('verify-otp.html', category=category, message=message)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = mongo.db.users.find_one({'email': email})
        
        if user:
            otp = str(random.randint(100000, 999999))
            session['reset_email'] = email
            session['otp'] = otp
            if send_otp_email(email, otp):
                flash("OTP sent to your email!", "otp_sent")
                return redirect(url_for("verify_otp"))
            else:
                flash("Failed to send OTP. Try again later.", "error")
                return redirect(url_for("forgot_password"))
        else:
            flash("No user found with this email.", "error")
            return redirect(url_for("forgot_password"))

    messages = get_flashed_messages(with_categories=True)
    category, message = messages[0] if messages else (None, None)
    return render_template('forgot_password.html', category=category, message=message)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('otp'):
            flash("OTP verified successfully!", "otp_verified")
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid OTP.", "error")
    messages = get_flashed_messages(with_categories=True)
    category, message = messages[0] if messages else (None, None)
    return render_template('verify-otp.html', category=category, message=message)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Validate password strength
        if not validate_password(new_password):
            flash("Password must be at least 8 characters long and include an uppercase letter, lowercase letter, number, and special character!", "error")
            return redirect(url_for('reset_password'))

        if new_password == confirm_password:
            # Update password in the database
            hashed_password = generate_password_hash(new_password)
            mongo.db.users.update_one({'email': session['reset_email']}, {'$set': {'password': hashed_password}})
            session.pop('reset_email', None)
            session.pop('otp', None)
            flash("Your password has been reset successfully.", "success")
            return redirect(url_for("login"))
        else:
            flash("Passwords do not match.", "error")
            return redirect(url_for('reset_password'))
        
    messages = get_flashed_messages(with_categories=True)
    category, message = messages[0] if messages else (None, None)
    return render_template('reset_password.html', category=category, message=message)

# Route to display the user's profile
@app.route('/profile', methods=['GET'])
def profile():
    if 'user_id' in session:
        user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
        return render_template('profile.html', user=user)
    else:
        flash('You need to log in first', 'error')
        return redirect(url_for('login'))

@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    updated_data = {
        'username': request.form['username'],
        'email': request.form['email'],
        'phone_number': request.form.get('phone_number', '')
    }

    mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': updated_data})
    flash('Profile updated successfully!', 'success')

    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    return render_template('profile.html', user=user)



@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' in session and session['role'] == 'admin':
        # Fetch all users from the MongoDB collection
        users = mongo.db.users.find({})
    
        # Convert users to a list of dictionaries and prepare for template rendering
        users_list = []
        for user in users:
            users_list.append({
                'role': user.get('role', ''),
                'username': user.get('username', ''),
                'email': user.get('email', ''),
                'phone_number': user.get('phone_number', ''),
                'password': user.get('password', ''),  # Consider encrypting this in a real app
                '_id': str(user['_id'])  # Convert ObjectId to string for template rendering
            })

        # Render the admin template with the users data
        return render_template('admin_dashboard.html', users=users_list)
    flash('Unauthorized access!')
    return redirect(url_for('login'))


@app.route('/user_dashboard')
def user_dashboard():
    categories = mongo.db.books.distinct("category")  # Get all unique categories from the books collection
    selected_category = request.args.get('category', '')  # Get selected category from request
    search_query = request.args.get('query', '')  # Get search query from request

    # MongoDB Query for filtering by category and search query
    query = {}
    if selected_category:
        query['category'] = selected_category
    if search_query:
        query['$or'] = [
            {'title': {'$regex': search_query, '$options': 'i'}},
            {'author': {'$regex': search_query, '$options': 'i'}}
        ]
    if 'user_id' in session:
        user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})

    books = list(mongo.db.books.find(query))

    return render_template('user_dashboard.html', books=books, user=user, categories=categories, selected_category=selected_category, search_query=search_query)



@app.route('/static/html/<filename>')
def serve_html(filename):
    return send_from_directory(app.config['HTML_FOLDER'], filename)

@app.route('/book/<book_id>')
def book_details(book_id):
    if 'user_id' not in session:
        flash("You must be logged in to view book details.")
        return redirect(url_for('login'))
    
    try:
        user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
        book = mongo.db.books.find_one({'_id': ObjectId(book_id)})
        return render_template('book_details.html', user=user, book=book)
    except bson_errors.InvalidId:
        flash("Invalid book ID!")
        return redirect(url_for('user_dashboard'))



@app.route('/search_books', methods=['GET'])
def search_books():
    categories = mongo.db.books.distinct("category")  # Get all unique categories from the books collection
    selected_category = request.args.get('category', '')  # Get the selected category from request
    search_query = request.args.get('query', '')  # Get the search query from request

    # MongoDB Query for filtering by category and search query
    query = {}
    if selected_category:
        query['category'] = selected_category
    if search_query:
        query['$or'] = [
            {'title': {'$regex': search_query, '$options': 'i'}},  # Search in book titles
            {'author': {'$regex': search_query, '$options': 'i'}}  # Search in author names
        ]

    books = list(mongo.db.books.find(query))

    return render_template('user_dashboard.html', books=books, categories=categories, selected_category=selected_category, search_query=search_query)


# Route to display the book upload form (Admin Only)
@app.route('/upload_book', methods=['GET', 'POST'])
def upload_book():
    # Ensure the user is logged in and is an admin
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    if not user or user.get('role') != 'admin':
        flash('You do not have permission to upload books.', 'error')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        # Get form data
        title = request.form['book_name']
        author = request.form['author_name']
        category = request.form['category']
        description = request.form['description']


        # Handle book file upload
        file = request.files['book_file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Handle book image upload
        image = request.files['book_image']
        image_filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        # Insert new book into MongoDB
        mongo.db.books.insert_one({
            'title': title,
            'author': author,
            'category': category,
            'description': description,
            'file': filename,
            'image': image_filename
        })
        flash('Book uploaded successfully!', 'success')
        return redirect(url_for('upload_book'))
    
    books = mongo.db.books.find()
    return render_template('upload_book.html', books=books)



@app.route('/manage_book')
def manage_book():
    if 'user_id' in session and session['role'] == 'admin':
        # Fetch the list of books from MongoDB
        books = mongo.db.books.find()
        return render_template('manage_book.html', books=books)

    flash('Unauthorized access!')
    return redirect(url_for('login'))



@app.route('/edit_book/<book_id>', methods=['GET', 'POST'])
def edit_book(book_id):
    if 'user_id' in session and session['role'] == 'admin':
        book = mongo.db.books.find_one({'_id': ObjectId(book_id)})

        if request.method == 'POST':
            title = request.form.get('title')
            author = request.form.get('author')
            description=request.form.get('description')
            category = request.form.get('category')
            file = request.files.get('file')
            image = request.files.get('image')

            updated_data = {'title': title, 'author': author, 'description': description, 'category': category}
            if file:
                filename = file.filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                updated_data['filename'] = filename
            if image:
                image_filename = image.filename
                image.save(os.path.join(app.config['IMAGE_FOLDER'], image_filename))
                updated_data['image'] = image_filename

            mongo.db.books.update_one({'_id': ObjectId(book_id)}, {'$set': updated_data})
            flash('Book updated successfully!')
            return redirect(url_for('manage_book'))

        return render_template('edit_book.html', book=book)

    flash('Unauthorized access!')
    return redirect(url_for('login'))


@app.route('/delete_book_admin/<book_id>', methods=['DELETE'])
def delete_book_admin(book_id):
    # Delete the book from the MongoDB collection
    result = mongo.db.books.delete_one({'_id': ObjectId(book_id)})

    # Return success or failure response based on the result
    if result.deleted_count > 0:
        return jsonify({'message': 'Book deleted successfully'}), 200
    else:
        return jsonify({'message': 'Book not found'}), 404


# Route to delete a user
@app.route('/api/delete_user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if user and user.get("role") == "admin":
            return jsonify({"error": "Cannot delete an admin user"}), 403  # Forbidden action

        # Delete user from the database if not admin
        mongo.db.users.delete_one({'_id': ObjectId(user_id)})
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/read_book/<book_id>', methods=['GET'])
def read_book(book_id):
    # Fetch the book from the database based on book_id
    book = mongo.db.books.find_one({"_id": ObjectId(book_id)})

    if not book:
        return "Book not found", 404

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], book['file'])
    file_type = mimetypes.guess_type(file_path)[0]

    if file_type == 'application/pdf':
        # Render the template to show PDF in an iframe
        return render_template('read_book.html', book=book, file_type='pdf', file_url=url_for('static', filename=f'uploads/{book["filename"]}'))

    elif file_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
        # Convert DOCX to HTML and display it
        html_content = convert_docx_to_html(file_path)
        return render_template('read_book.html', book=book, file_type='docx', content=html_content)

    elif file_type == 'application/epub+zip':
        # Convert EPUB to HTML and display it
        html_content = convert_epub_to_html(file_path)
        return render_template('read_book.html', book=book, file_type='epub', content=html_content)

    elif file_type == 'text/plain':
        # Read plain text files and display
        with open(file_path, 'r', encoding='utf-8') as text_file:
            text_content = text_file.read()
        return render_template('read_book.html', book=book, file_type='text', content=text_content)

    else:
        # Unsupported file format
        flash('Unsupported file format.')
        return redirect(url_for('user_dashboard'))


@app.route('/on_click/<book_id>', methods=['GET'])
def on_click(book_id):
    # Fetch the main book details using its ID
    main_book = mongo.db.books.find_one({"_id": ObjectId(book_id)})
    
    if not main_book:
        # If book is not found, redirect or show an error
        return "Book not found", 404

    # Fetch other books from the same category (excluding the current book)
    other_books = mongo.db.books.find({
        "_id": {"$ne": ObjectId(book_id)},
        "category": main_book['category']
    })

    return render_template('on_click.html', main_book=main_book, other_books=other_books)

@app.route('/wishlist')
def wishlist():
    user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
    return render_template('wishlist.html', user=user)

@app.route('/about')
def about():
    user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
    return render_template('about.html', user=user)

@app.route('/api/total_books')
def total_books():
    count = mongo.db.books.count_documents({})
    return {'count': count}

@app.route('/api/total_users')
def total_users():
    count = mongo.db.users.count_documents({})
    return {'count': count}


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
