from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, FileField, SelectField
from wtforms.validators import DataRequired, Email, Length
from datetime import datetime
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///insurance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    claims = db.relationship('Claim', backref='user', lazy=True)

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    company_name = db.Column(db.String(120), nullable=False)
    agent_code = db.Column(db.String(20), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_claims = db.relationship('Claim', backref='reviewed_by_agent', lazy=True, foreign_keys='Claim.reviewed_by')

class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reference_id = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    policy_type = db.Column(db.String(50), nullable=False)
    claim_amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    document_path = db.Column(db.String(200))
    status = db.Column(db.String(20), default='Pending')
    reviewed_by = db.Column(db.Integer, db.ForeignKey('agent.id'))
    review_notes = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Forms
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])

class AgentRegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    company_name = StringField('Company Name', validators=[DataRequired(), Length(min=3)])
    agent_code = StringField('Agent Code', validators=[DataRequired(), Length(min=5, max=20)])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class ClaimForm(FlaskForm):
    policy_type = StringField('Policy Type', validators=[DataRequired()])
    claim_amount = StringField('Claim Amount', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=10)])

class ClaimReviewForm(FlaskForm):
    action = SelectField('Action', choices=[('', 'Select Action'), ('Approved', 'Approve'), ('Rejected', 'Reject')], validators=[DataRequired()])
    review_notes = TextAreaField('Review Notes', validators=[DataRequired(), Length(min=10)])

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def agent_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'agent_id' not in session:
            flash('Please login as an agent first.', 'warning')
            return redirect(url_for('agent_login'))
        return f(*args, **kwargs)
    return decorated_function

# Helper functions
def generate_reference_id():
    import random
    import string
    timestamp = datetime.now().strftime('%Y%m%d')
    random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"CLM-{timestamp}-{random_str}"

# USER ROUTES (Original - INS-F-001, INS-F-002, INS-F-008)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    elif 'agent_id' in session:
        return redirect(url_for('agent_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if '@' not in form.email.data:
            flash('Invalid email address!', 'danger')
            return render_template('register.html', form=form)
        
        existing_user = User.query.filter(
            (User.email == form.email.data) | (User.username == form.username.data)
        ).first()
        
        if existing_user:
            flash('User already exists.', 'danger')
            return render_template('register.html', form=form)
        
        new_user = User(
            email=form.email.data,
            username=form.username.data,
            password=form.password.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/clear-session')
def clear_session():
    session.clear()
    flash('Session cleared successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Session expired. Please login again.', 'warning')
        return redirect(url_for('login'))
    claims = Claim.query.filter_by(user_id=user.id).order_by(Claim.submitted_at.desc()).all()
    return render_template('dashboard.html', user=user, claims=claims)

@app.route('/submit-claim', methods=['GET', 'POST'])
@login_required
def submit_claim():
    form = ClaimForm()
    
    if form.validate_on_submit():
        try:
            claim_amount = float(form.claim_amount.data)
            
            # Handle file upload
            document_path = None
            if 'document' in request.files:
                file = request.files['document']
                if file and file.filename:
                    filename = f"{generate_reference_id()}_{file.filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    document_path = filename
            
            # Create claim
            new_claim = Claim(
                reference_id=generate_reference_id(),
                user_id=session['user_id'],
                policy_type=form.policy_type.data,
                claim_amount=claim_amount,
                description=form.description.data,
                document_path=document_path
            )
            
            db.session.add(new_claim)
            db.session.commit()
            
            flash(f'Claim submitted successfully! Reference ID: {new_claim.reference_id}', 'success')
            return redirect(url_for('dashboard'))
            
        except ValueError:
            flash('Invalid claim amount. Please enter a valid number.', 'danger')
    
    return render_template('submit_claim.html', form=form)

@app.route('/claim/<reference_id>')
@login_required
def view_claim(reference_id):
    claim = Claim.query.filter_by(reference_id=reference_id, user_id=session['user_id']).first()
    
    if not claim:
        flash('Claim not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('view_claim.html', claim=claim)

# AGENT ROUTES (NEW - INS-F-009)

@app.route('/agent/register', methods=['GET', 'POST'])
def agent_register():
    form = AgentRegistrationForm()
    if form.validate_on_submit():
        if '@' not in form.email.data:
            flash('Invalid email address!', 'danger')
            return render_template('agent_register.html', form=form)
        
        existing_agent = Agent.query.filter(
            (Agent.email == form.email.data) | 
            (Agent.username == form.username.data) | 
            (Agent.agent_code == form.agent_code.data)
        ).first()
        
        if existing_agent:
            flash('Agent with this email, username, or agent code already exists.', 'danger')
            return render_template('agent_register.html', form=form)
        
        new_agent = Agent(
            email=form.email.data,
            username=form.username.data,
            password=form.password.data,
            company_name=form.company_name.data,
            agent_code=form.agent_code.data
        )
        db.session.add(new_agent)
        db.session.commit()
        flash('Agent registration successful! Please login.', 'success')
        return redirect(url_for('agent_login'))
    
    return render_template('agent_register.html', form=form)

@app.route('/agent/login', methods=['GET', 'POST'])
def agent_login():
    form = LoginForm()
    if form.validate_on_submit():
        agent = Agent.query.filter_by(username=form.username.data).first()
        if agent and agent.password == form.password.data:
            session['agent_id'] = agent.id
            session['agent_username'] = agent.username
            session['agent_company'] = agent.company_name
            flash('Agent logged in successfully!', 'success')
            return redirect(url_for('agent_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('agent_login.html', form=form)

@app.route('/agent/logout')
def agent_logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('agent_login'))

@app.route('/agent/dashboard')
@agent_login_required
def agent_dashboard():
    agent = Agent.query.get(session['agent_id'])
    
    # Get statistics
    pending_claims = Claim.query.filter_by(status='Pending').count()
    approved_claims = Claim.query.filter_by(reviewed_by=agent.id, status='Approved').count()
    rejected_claims = Claim.query.filter_by(reviewed_by=agent.id, status='Rejected').count()
    
    # Get all claims
    all_claims = Claim.query.order_by(Claim.submitted_at.desc()).all()
    
    return render_template('agent_dashboard.html', 
                         agent=agent, 
                         claims=all_claims,
                         pending_claims=pending_claims,
                         approved_claims=approved_claims,
                         rejected_claims=rejected_claims)

@app.route('/agent/claim/<reference_id>', methods=['GET', 'POST'])
@agent_login_required
def agent_review_claim(reference_id):
    claim = Claim.query.filter_by(reference_id=reference_id).first()
    
    if not claim:
        flash('Claim not found.', 'danger')
        return redirect(url_for('agent_dashboard'))
    
    form = ClaimReviewForm()
    
    if form.validate_on_submit():
        claim.status = form.action.data
        claim.review_notes = form.review_notes.data
        claim.reviewed_by = session['agent_id']
        claim.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'Claim {reference_id} has been {form.action.data.lower()}!', 'success')
        return redirect(url_for('agent_dashboard'))
    
    return render_template('agent_review_claim.html', claim=claim, form=form)

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)