from API import get_prediction
from wepage_analyzer import get_page_content,get_images,compare_images,compare_image_lists,hash_content,compare_texts,is_malicious,compare_web_pages

# path to trained model
model_path = r"C:\Users\rajnish chaurasia\Downloads\Phishing-Attack-Domain-Detection-main\Phishing-Attack-Domain-Detection-main\models\Malicious_URL_Prediction.h5"

# input url
url = "https://shubhayu.dev/"

# returns probability of url being malicious
prediction = get_prediction(url,model_path)
print(prediction)