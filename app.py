import pandas as pd
from flask import Flask, request, jsonify, render_template
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, roc_curve, auc, classification_report
import validators
import re
import math
import whois
from datetime import datetime
from collections import Counter
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import requests
import os
import plotly.express as px
import matplotlib.pyplot as plt
import seaborn as sns

app = Flask(__name__)

IMG_DIR = os.path.join('static', 'images')
os.makedirs(IMG_DIR, exist_ok=True)

model = None
is_model_initialized = False
ds = None
numerical_features = None

scaler = StandardScaler()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/predict', methods = ['POST'])
def make_prediction():
    data = request.get_json()
    url = data.get('url').strip('/')
    if url.startswith(('http://', 'https://')):
        url = url[url.index('://')+3:]
    print(url)
    if not url or not is_valid_url(url):
        return jsonify({'error': 'Invalid URL provided'}), 400
    
    if not is_model_initialized or ds is None:
        return jsonify({'error': 'The model has not yet been initialized'}), 400

    features = extract_features(url)
    print(features)
    features[numerical_features] = scaler.transform(features[numerical_features])
    prediction = model.predict(features)
    result = ['Legitimate', 'Phishing'][prediction[0]]
    print(f"Result: {result}")
    return jsonify({'result': result}), 200

@app.route('/api/classification-report', methods = ['GET'])    
def get_classification_report():
    try:
        with open(os.path.join(IMG_DIR, 'classification_report.txt'), 'r') as file:
            report = file.read()
        return jsonify({"data": report})
    except Exception as e:
        return jsonify({"error": f"{e}"}), 500

def is_valid_url(url):
    normalized_url = url
    if not normalized_url.startswith(('http://', 'https://')):
        if normalized_url.startswith('www.'):
            normalized_url = 'http://' + normalized_url
        else:
            normalized_url = 'http://www.' + normalized_url
    
    return validators.url(normalized_url)

def calc_digit_letter_ratio(url):
    if not isinstance(url, str):
        return 0
    digits = 0
    letters = 0
    for c in url:
        if c.isalpha():
            letters += 1
            continue
        if c.isdigit():
            digits += 1
    return digits / letters if letters > 0 else 0

def extract_features(url):
    url_length = len(url)
    starts_with_ip = is_ip_address(url)
    url_entropy = calc_entropy(url)
    digit_letter_ratio = calc_digit_letter_ratio(url)
    dot_count = 0
    at_count = 0
    dash_count = 0
    tld_count = get_tld_count(url)
    for c in url:
        if c == '.': dot_count += 1
        elif c == '@': at_count += 1
        elif c == '-': dash_count += 1
    
    subdomain_count = get_subdomain_count(url)
    domain_age_days = get_domain_age(url)
    domain_age_days = domain_age_days if domain_age_days is not None else ds['domain_age_days'].median()
    nan_char_entropy = calc_entropy(get_nan_chars(url))

    return pd.DataFrame({
        'url_length': [url_length],
        'starts_with_ip': [starts_with_ip],
        'url_entropy': [url_entropy],
        'has_punycode': [contains_punycode(url)],
        'digit_letter_ratio': [digit_letter_ratio],
        'dot_count': [dot_count],
        'at_count': [at_count],
        'dash_count': [dash_count],
        'tld_count': [tld_count],
        'domain_has_digits': [domain_has_digits(url)],
        'subdomain_count': [subdomain_count],
        'nan_char_entropy': [nan_char_entropy],
        'has_internal_links': [has_internal_links(url)],
        'domain_age_days': [domain_age_days],  
    })

def get_subdomain_count(url):
    try:
        domain = urlparse(url).netloc
        domain = domain.lstrip('www.')
        domain_parts = domain.split('.')
        if len(domain_parts) > 2:
            return len(domain_parts) - 2
        return 0
    except Exception as e:
        print(f"An error occured {e}")
        return 0
    
def get_tld_count(url):
    try:
        known_tlds = [
            '.com', '.org', '.net', '.edu', '.gov', '.co', '.us', '.io', '.info', 
            '.biz', '.online', '.me', '.ai', '.dev', '.tech', '.app', 
        ]
        parsed = urlparse(url)
        subdirectory = parsed.path
        if '/' not in subdirectory:
            return 0
        subdirectory = subdirectory[subdirectory.index('/'):]
        print(subdirectory)
        count = 0
        for tld in known_tlds:
            if tld in subdirectory:
                count += 1
        return count
    except Exception as e:
        print(f"An error occured: {e}")
        return 0

def domain_has_digits(url):
    for c in urlparse(url).netloc:
        if c.isdigit():
            return 1
    return 0

def has_internal_links(url):
    try:
        if not urlparse(url).scheme:
            url = 'https://' + url

        parsed = urlparse(url)
        base_domain = f"{parsed.scheme}://{parsed.netloc}"

        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return 0

        #parse html content for links and check for internal links
        soup = BeautifulSoup(response.text, 'html.parser')

        links = soup.find_all('a', href=True)

        #check if links are internal (points to same domain/subdirectory)
        for link in links:
            print(link)
            href = link['href']
            full_url = urljoin(base_domain, href)
            link_parsed = urlparse(full_url)
            if link_parsed.netloc == parsed.netloc and link_parsed.path.startswith(parsed.path):
                return 1
            
    except requests.RequestException as e:
        print(f"Error fetching the url: {e}")
    except Exception as e:
        print(f"An error occured: {e}")

    return 0

def contains_punycode(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if hostname and any(segment.startswith('xn--') for segment in hostname.split('.')):
            return True
        
    except Exception as e:
        print(f"Error parsing URL: {e}")
                            
    return False
def get_nan_chars(url):
    result = ''
    for c in url:
        if not c.isalpha() and not c.isdigit():
            result += c
    return result

def get_domain_age(url):
    try:
        domain = whois.whois(url)
        creation_date = domain.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return None

        days = (datetime.now() - creation_date).days

        return days
    
    except Exception as e:
        print(f"Error fetching domain age for {url}: {e}")
    return None

def is_ip_address(url):
    regex = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    return [0, 1][re.search(regex, url) is not None]

def calc_entropy(url):
    freq = Counter(url)
    total = len(url)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())
                   
def clean_data(ds):
    # Check if the digit_letter_ratio column has NaN values and fill them with value calculated from url
    ds['digit_letter_ratio'] = ds.apply(
        lambda row: calc_digit_letter_ratio(row['url']) if pd.isna(row['digit_letter_ratio']) else row['digit_letter_ratio'], 
        axis=1
    )

    # replace NaN values in domain_age_days with mean
    ds['domain_age_days'] = ds['domain_age_days'].fillna(ds['domain_age_days'].median())

    return ds

def create_model():
    print('Reading, cleaning and preprocessing data')
    # read in dataset csv and clean if clean csv doesn't exist
    global ds

    if not os.path.exists('cleaned.csv'):
        ds = pd.read_csv('raw.csv')
        ds = clean_data(ds)
        ds.to_csv('cleaned.csv', index=False)
    else:
        ds = pd.read_csv('cleaned.csv')

    # prepare features X and labels y
    X = ds.drop(columns=['url', 'label', 'source', 'whois_data']) # drop all str features from the features as they are not numeric

    #convert label to binary: 1 for phishing 0 for legitimate
    y = ds['label'].map({'phishing': 1, 'legitimate': 0})

    global numerical_features
    numerical_features = ['url_length', 'url_entropy', 'domain_age_days', 'digit_letter_ratio', 'nan_char_entropy', 'dot_count', 'at_count', 'dash_count', 'tld_count', 'subdomain_count']

    # convert all bool columns to numeric types
    for feature in numerical_features:
        X[feature] = pd.to_numeric(X[feature], errors='coerce')

    # split data into training and testing sets 70/30 training/testing
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # scale numerical features
    for set in (X_train, X_test):
        set[numerical_features] = scaler.fit_transform(set[numerical_features])

    # initialize and train logistic regression model
    print("Initializing and training model")
    global model
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train, y_train) 
    global is_model_initialized
    is_model_initialized = True
    print("Model initialized")

    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1] #for ROC curve

    #generate and save plots if they don't already exist
    save_confusion_matrix(y_test, y_pred, filename='confusion_matrix.png')
    save_roc_curve(y_test, y_pred_proba, filename='roc_curve.png')
    save_classification_report(y_test, y_pred, filename='classification_report.txt')
    save_heatmap(X[numerical_features])

    print(classification_report(y_test, y_pred))

def check_if_plot_exists(filename):
    return os.path.exists(os.path.join(IMG_DIR, filename))

# Function to generate and save a confusion matrix plot
def save_confusion_matrix(y_test, y_pred, filename='confusion_matrix.png'):
    if check_if_plot_exists(filename):
        print(f"{filename} already exists, skipping generation.")
        return
    
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    
    # Save the plot as a PNG file
    plt.savefig(os.path.join(IMG_DIR, filename))
    plt.close()

# Function to generate and save an ROC curve plot
def save_roc_curve(y_test, y_pred_proba, filename='roc_curve.png'):
    if check_if_plot_exists(filename):
        print(f"{filename} already exists, skipping generation.")
        return
    
    fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(6, 4))
    plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic')
    plt.legend(loc='lower right')

    # Save the plot as a PNG file
    plt.savefig(os.path.join(IMG_DIR, filename))
    plt.close()

def save_heatmap(ds, filename='heatmap.png'):
    if check_if_plot_exists(filename):
        print(f"{filename} already exists, skipping generation.")
        return
    
    plt.figure(figsize=(10, 8))
    # Compute the correlation matrix
    correlation = ds.corr()

    # Generate a heatmap
    sns.heatmap(correlation, annot=True, fmt='.2f', cmap='coolwarm', square=True, cbar_kws={"shrink": .8})
    
    plt.title('Heatmap of Numerical Features')
    plt.savefig(os.path.join(IMG_DIR, filename))
    plt.close()

# Function to save classification report as a text file
def save_classification_report(y_test, y_pred, filename='classification_report.txt'):
    if check_if_plot_exists(filename):
        print(f"{filename} already exists, skipping generation.")
        return
    
    report = classification_report(y_test, y_pred)
    
    # Save the report to a text file
    with open(os.path.join(IMG_DIR, filename), 'w') as f:
        f.write(report)
        print(f"Saved classification report to {filename}")

if __name__ == "__main__":
    create_model()
    if is_model_initialized:
        app.run(debug=True)
    else:
        print("Error initializing model. Flask app will not run")