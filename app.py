from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from urllib.parse import urlparse
import re
from googlesearch import search
from sklearn.preprocessing import LabelEncoder
from urllib.parse import urlparse
from tld import get_tld

app = Flask(__name__)


df = pd.read_csv('malicious_phish.csv')

df_phish = df[df.type=='phishing']
df_malware = df[df.type=='malware']
df_deface = df[df.type=='defacement']
df_benign = df[df.type=='benign']

# Feature extraction functions
def having_ip_address(url):
    match = re.search(
    '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
    '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

df['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0

df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))

from googlesearch import search

def google_index(url):
    site = search(url, 5)
    return 1 if site else 0
df['google_index'] = df['url'].apply(lambda i: google_index(i))

def count_dot(url):
    return url.count('.')

df['count.'] = df['url'].apply(lambda i: count_dot(i))

def count_www(url):
    return url.count('www')

df['count-www'] = df['url'].apply(lambda i: count_www(i))

def count_atrate(url):
    return url.count('@')

df['count@'] = df['url'].apply(lambda i: count_atrate(i))

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                    'tr\.im|link\.zip\.net',
                    url)
    if match:
        return 1
    else:
        return 0

df['short_url'] = df['url'].apply(lambda i: shortening_service(i))

'''def count_https(url):
    return url.count('https')

df['count-https'] = df['url'].apply(lambda i : count_https(i))

def count_http(url):
    return url.count('http')

df['count-http'] = df['url'].apply(lambda i : count_http(i))'''

def count_per(url):
    return url.count('%')

df['count%'] = df['url'].apply(lambda i : count_per(i))

def count_ques(url):
    return url.count('?')

df['count?'] = df['url'].apply(lambda i: count_ques(i))

def count_hyphen(url):
    return url.count('-')

df['count-'] = df['url'].apply(lambda i: count_hyphen(i))

def count_equal(url):
    return url.count('=')

df['count='] = df['url'].apply(lambda i: count_equal(i))

def url_length(url):
    return len(str(url))

df['url_length'] = df['url'].apply(lambda i: url_length(i))

def hostname_length(url):
    return len(urlparse(url).netloc)

df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                    url)
    if match:
        return 1
    else:
        return 0

df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

df['count-digits']= df['url'].apply(lambda i: digit_count(i))

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

df['count-letters']= df['url'].apply(lambda i: letter_count(i))

def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

df['fd_length'] = df['url'].apply(lambda i: fd_length(i))

#Length of Top Level Domain
df['tld'] = df['url'].apply(lambda i: get_tld(i,fail_silently=True))

def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

df['tld_length'] = df['tld'].apply(lambda i: tld_length(i))
df = df.drop("tld", axis=1)

# Load label encoder
lb_make = LabelEncoder()
df["type_code"] = lb_make.fit_transform(df["type"])
df["type_code"].value_counts()

# Load your trained Random Forest model
# Assuming you already have X_train and y_train from your training script
#'count-https', 'count-http'
rf_model = RandomForestClassifier(n_estimators=100, max_features='sqrt', random_state=5)
X_train = df[['use_of_ip', 'abnormal_url', 'google_index', 'count.', 'count-www', 'count@', 'count_dir', 'count_embed_domian',
              'short_url', 'count%', 'count?', 'count-', 'count=', 'url_length',
              'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits', 'count-letters']]
y_train = df['type_code']
rf_model.fit(X_train, y_train)

def main(url):
    features = []

    # Apply feature extraction functions
    features.append(having_ip_address(url))
    features.append(abnormal_url(url))
    features.append(google_index(url))
    features.append(count_dot(url))
    features.append(count_www(url))
    features.append(count_atrate(url))
    features.append(no_of_dir(url))
    features.append(no_of_embed(url))
    features.append(shortening_service(url))
    #features.append(count_https(url))
    #features.append(count_http(url))
    features.append(count_per(url))
    features.append(count_ques(url))
    features.append(count_hyphen(url))
    features.append(count_equal(url))
    features.append(url_length(url))
    features.append(hostname_length(url))
    features.append(suspicious_words(url))
    features.append(digit_count(url))
    features.append(letter_count(url))
    features.append(fd_length(url))
    tld = get_tld(url, fail_silently=True)
    features.append(tld_length(tld))

    return features

def get_prediction_from_url(test_url):
    features_test = main(test_url)
    features_test = np.array(features_test).reshape((1, -1))

    print("Features used for prediction:", features_test)  # Add this line for debugging

    pred = rf_model.predict(features_test)
    predicted_class = int(pred[0])

    print("Predicted class:", predicted_class)  # Add this line for debugging

    class_mapping = {0.0: "SAFE", 1.0: "DEFACEMENT", 2.0: "PHISHING", 3.0: "MALWARE"}
    result = class_mapping[predicted_class]

    return result


@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form['urlInput']
        result = get_prediction_from_url(url)
    return render_template('index.html', result=result)

''''@app.route('/api/predict', methods=['POST'])
def api_predict():
    data = request.get_json()
    url = data.get('url')
    result = get_prediction_from_url(url)
    return jsonify({'result': result})'''

if __name__ == '__main__':
    app.run(debug=True)