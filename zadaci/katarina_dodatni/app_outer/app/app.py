from flask import Flask, request, render_template_string
import tarfile
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template_string('''
    <h1>Upload a File</h1>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
''')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    if file:
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        with tarfile.open(filepath) as tar:
            tar.extractall(path=UPLOAD_FOLDER)  # Vulnerable extraction
        return 'File uploaded and extracted'
    return 'Upload failed'

if __name__ == '__main__':
    app.run(debug=True)
