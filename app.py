from flask import Flask, render_template, request
import requests
from API import get_prediction

app = Flask(__name__)
model_path = r"C:\Users\rajnish chaurasia\Downloads\one more\one more\Malicious_URL_Prediction.h5"

@app.route('/pricing', methods=['GET', 'POST'])
def pricing():
    if request.method == 'POST':
        website_url = request.form.get('website_url')
        if website_url:
            url = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
            parameters = {
                "url": website_url,
                "strategy": "mobile",
                "key": "AIzaSyAsd4bWrWHxKKOJlfTFaqd5E_WQitCHNig",  # Replace with your actual Google PageSpeed Insights API key
                "category": ["performance", "seo", "accessibility", "best-practices", "pwa"]
            }

            res = requests.get(url, params=parameters)

            if res.status_code == 200:
                data = res.json()
                page_url = data["lighthouseResult"]["finalUrl"]
                category_scores = {category: data["lighthouseResult"]["categories"][category]["score"]*100 for category in data["lighthouseResult"]["categories"]}
                return render_template('index.html', page_url=page_url, category_scores=category_scores)
            else:
                return f"Error: {res.status_code}"

    return render_template('pricing.html')
@app.route("/")
def index():
    return render_template('index.html')
@app.route("/signup")
def signup():
    return render_template('signup.html')
@app.route("/about")
def about():
    return render_template('about.html')

@app.route("/signin")
def signin():
    return render_template('signin.html')



if __name__ == '__main__':
    app.run(debug=True)
