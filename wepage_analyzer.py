import hashlib
import requests
import urllib.parse
import numpy as np
import tensorflow as tf
import tensorflow_hub as hub
import cv2
from bs4 import BeautifulSoup
from skimage.metrics import structural_similarity as compare_ssim

# Function to fetch and parse web page content
def get_page_content(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return BeautifulSoup(response.text, 'html.parser')
    except Exception as e:
        print(f"Error fetching page content: {e}")
        return None

# Function to fetch images from a web page
def get_images(soup, base_url):
    images = []
    for img in soup.find_all('img'):
        img_url = img.get('src')
        if img_url:
            img_url = urllib.parse.urljoin(base_url, img_url)
            images.append(img_url)
    return images

# Function to compare two images using SSIM
def compare_images(img1, img2):
    img1_gray = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
    img2_gray = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)
    ssim_score = compare_ssim(img1_gray, img2_gray)
    return ssim_score

# Function to compare two lists of images
def compare_image_lists(images1, images2):
    if len(images1) != len(images2):
        return False

    for img_url1, img_url2 in zip(images1, images2):
        response1 = requests.get(img_url1)
        response2 = requests.get(img_url2)
        img1 = cv2.imdecode(np.asarray(bytearray(response1.content), dtype="uint8"), cv2.IMREAD_COLOR)
        img2 = cv2.imdecode(np.asarray(bytearray(response2.content), dtype="uint8"), cv2.IMREAD_COLOR)

        similarity_score = compare_images(img1, img2)
        if similarity_score < 0.9:  # Adjust the threshold as needed
            return False

    return True

# Function to hash content
def hash_content(content):
    return hashlib.sha256(str(content).encode()).hexdigest()

# Function to compare two content texts using Universal Sentence Encoder (USE)
def compare_texts(text1, text2):
    embed = hub.load("https://tfhub.dev/google/universal-sentence-encoder/4")
    embeddings1 = embed([text1])
    embeddings2 = embed([text2])
    similarity_score = np.inner(embeddings1, embeddings2)
    return similarity_score[0][0]

# Function to check if a website is malicious using VirusTotal
def is_malicious(url):
    # Replace with your VirusTotal API key
    api_key = 'afd20e2361107531762aca6b57279b7967c620ad02a274adb1d7545af0880c6d'
    params = {'apikey': api_key, 'resource': url}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                             params=params)
    result = response.json()

    if result['response_code'] == 1:
        if result['positives'] > 0:
            print(f"WARNING: This website is reported as malicious by {result['positives']} antivirus engines.")
            return True
        else:
            print("The website is not reported as malicious.")
            return False
    else:
        print("Error querying VirusTotal.")
        return False

# Function to compare two web pages
def compare_web_pages(url1, url2):
    if is_malicious(url1) or is_malicious(url2):
        print("At least one of the websites is reported as malicious.")
        return False

    page1_content = get_page_content(url1)
    page2_content = get_page_content(url2)

    if page1_content is None or page2_content is None:
        return False

    page1_hash = hash_content(str(page1_content))
    page2_hash = hash_content(str(page2_content))

    if page1_hash != page2_hash:
        return False

    page1_images = get_images(page1_content, url1)
    page2_images = get_images(page2_content, url2)

    if not compare_image_lists(page1_images, page2_images):
        return False

    page1_text = page1_content.get_text()
    page2_text = page2_content.get_text()
    text_similarity = compare_texts(page1_text, page2_text)

    if text_similarity < 0.9:  # Adjust the threshold as needed
        return False

    return True

# Replace with the URLs of the original and potentially malicious websites
original_url = 'https://github.com'
malicious_url = 'https://github.com'

if compare_web_pages(original_url, malicious_url):
    print('The pages are identical or highly similar.')
else:
    print('The pages are different.')
