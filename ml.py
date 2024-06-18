import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from urllib.parse import urlparse
import tldextract, validators
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, ExtraTreesClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.naive_bayes import GaussianNB
from joblib import dump

def get_spec_chars(url):
    count_c=0
    spec_char=[':', ';', '#', '!', '%', '~', '+', '_', '?', '=', '&', '[', ']', '{', '}', '$']
    for c in url:
        if c in spec_char:
            count_c = count_c + 1
    return count_c

# Function for verifying URL is valid
def is_valid_url(url):
    return validators.url(url)


# Function for extracting top-level-domain from the URL
def process_tld(url):
    try:
        result = tldextract.extract(url)
        if result.domain and result.suffix:
            return f"{result.domain}.{result.suffix}"
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
    return "unknown"


# Upload dataset
data = pd.read_csv('malicious_phish.csv')
print(data.head())
print(data.info())
print(data.isnull().sum())

# Verify URL is valid
data['url'] = data['url'].apply(lambda x: x if is_valid_url(x) else 'invalid')
data = data[data['url'] != 'invalid']

# Extract top-level-domain
data['domain'] = data['url'].apply(process_tld)

# Visualisation of Distribution of URL types
count = data['type'].value_counts()
plt.figure(figsize=(10, 6))
bar_plot = sns.barplot(x=count.index, y=count.values)
plt.xlabel('Types')
plt.ylabel('Count')
plt.title('Distribution of URL Types')

# Format the bar
for p in bar_plot.patches:
    bar_plot.annotate(format(p.get_height(), '.2f'),
                      (p.get_x() + p.get_width() / 2., p.get_height()),
                      ha='center', va='center', xytext=(0, 9), textcoords='offset points')

plt.show()

# Converting categories to numeric values
category_mapping = {"benign": 0, "defacement": 1, "phishing": 2, "malware": 3}
data['Category'] = data['type'].map(category_mapping)

# Pre-processing features
data['url_len'] = data['url'].apply(len)
data['https'] = data['url'].apply(lambda x: 1 if urlparse(x).scheme == 'https' else 0)
data['digits'] = data['url'].apply(lambda x: sum(c.isdigit() for c in x))
data['letters'] = data['url'].apply(lambda x: sum(c.isalpha() for c in x))
data['shortening_service'] = data['url'].apply(lambda x: 1 if 'bit.ly' in x or 'goo.gl' in x else 0)
data['spec_chars'] = data['url'].apply(get_spec_chars)


# Train model
X = data.drop(['url', 'type', 'Category', 'domain'], axis=1)
y = data['Category']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=2)

models = [
    DecisionTreeClassifier(),
    RandomForestClassifier(),
    AdaBoostClassifier(algorithm='SAMME'),
    KNeighborsClassifier(),
    ExtraTreesClassifier(),
    GaussianNB()
]

# Loop to predict and report every model
for model in models:
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    print(f'Model: {model.__class__.__name__}')
    print('Accuracy:', accuracy_score(y_test, pred))
    print('Classification Report:\n', classification_report(y_test, pred, zero_division=0))
    cf_matrix = confusion_matrix(y_test, pred)

    plt.figure(figsize=(10, 6))
    heatmap = sns.heatmap(cf_matrix, annot=True, fmt='d', cmap='Blues')
    heatmap.set_title(f'Confusion Matrix for {model.__class__.__name__}', fontsize=16)
    heatmap.set_xlabel('Predicted labels')
    heatmap.set_ylabel('True labels')

    plt.show()

# Saving models
dump(models[1], 'RandomForestClassifier.pkl')
dump(models[2], 'AdaBoostClassifier')
dump(models[3], 'KNeighborsClassifier')
dump(models[4], 'ExtraTreesClassifier')
dump(models[5], 'GaussianNB')
