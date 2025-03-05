
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

import config
from functions import*
import json
from jsonfile import*
import metakeys_config
from regex import*
import ipaddress
from config import*
from time import perf_counter

app = Flask(__name__)
UPLOAD_FOLDER = os.path.abspath("uploads")
configuration = metakeys_config.Elasticsearch
# configuration = metakeys_config.RSANetWitness
# configuration = metakeys_config.QRadar
# create directory for storing anonzymized logs
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
# load configuration
app.config.from_pyfile('config.py')

@app.route('/anonymize/singlecategory')
def home():
    # Render template, which contains the form for input
    return render_template('singlecat.html')
#endpoint for performing anonymization for only chosen categories
@app.route('/anonymize/singlecategory', methods=['POST'])
def anonymize():
    file = request.files['file']  # Get the uploaded file from the form
    checkbox_state = request.form.get('checkbox')
    if file.filename.endswith(('.log')):  # Check if file has .json or .log extension
        # choose encoding
        content = file.read().decode('utf-8')
        anon_content = ''
        for line in content.splitlines():
            if config.EMAIL:  # Check if EMAIL in config is True
                line = Regex.anonymize_email_line(line) #call corresponding anonymization function from regex.py
            if config.IPV4:  # Check if IP in config is True
                line = Regex.anonymize_ipv4_line(line) #call corresponding anonymization function from regex.py
            if config.IPV6: # Check if IPv6 in config is True
                line = Regex.anonymize_ipv6_line(line) #call corresponding anonymization function from regex.py
            if config.LINKLOCAL: # Check if linkolocal in config is True
                line = Regex.anonymize_linklocal_line(line) #call corresponding anonymization function from regex.py
            if config.DOMAIN: # Check if domain in config is True
                line = Regex.anonymize_domain_line(line) #call corresponding anonymization function from regex.py
            if config.MAC: # Check if MAC in config is True
                line = Regex.anonymize_mac_line(line) #call corresponding anonymization function from regex.py
            if config.URL: # Check if URL in config is True
                line = Regex.anonymize_url_line(line) #call corresponding anonymization function from regex.py
            if config.WINDOWS_DIR: # Check if Windows directory in config is True
                line = Regex.anonymize_windows_line(line) #call corresponding anonymization function from regex.py

            else:
                line = line
                # Append the modified line to the anonymized content
            anon_content += line + '\n'

        # Save anonymized content to a file in "uploads" directory
        output_filename = 'anonymized_output.log' #Specify the output file name
        output_path = os.path.join('uploads', output_filename) #create output path
        with open(output_path, 'w') as output_file: #open the output file
            output_file.write(anon_content) #place the anonymized content into the file
        if checkbox_state == 'checked':
            empty_dictionaries() #if checkbox is checked, clear dictionaries
        return f'<pre>{anon_content}</pre>' #Return the anonymized content as a string wrapped in HTML <pre> tags for better formatting and display
    elif file.filename.endswith(('.json')): #if file has .json extension
        if request.method == 'POST': #if there is a POST request and a file is selected
            file = request.files['file']
            if file.filename != '':
                file.save(secure_filename(file.filename))#save uploaded file
                with open(file.filename) as f:#open and load data from the uploaded file
                    data = json.load(f)

                anonymized_data = Process.anonymize_data_single_category(data, configuration) #anonymize by calling corresponding function
                if checkbox_state == 'checked':
                    empty_dictionaries() #empty dictionaries if checkbox is checked
                return anonymized_data
        return "No file selected."
    else:
        return 'Invalid file format. Please upload a .json or .log file.' #If the file format is neither a .json nor a .log file, return an error message indicating the invalid file format


@app.route('/')
def upload_form():
    # Render template, which contains the form for input of raw logs
    return render_template('upload.html')
@app.route('/anonymize/json')
def index():
    # Render template, which contains the form for input of JSON logs
    return render_template('json.html')

@app.route('/anonymize/json', methods=['POST'])
def json_file():
    if request.method == 'POST': #if HTTP request is POST
        file = request.files['jsonfile'] #get the uploaded JSON from the request
        if file.filename != '':
            file.save(secure_filename(file.filename))#save and load the data
            with open(file.filename) as f:
                data = json.load(f)
            checkbox_state = request.form.get('checkbox')#check the checkbox state
            # anonymized_data = Process.anonymize_nested_keys(data, configuration)
            anonymized_data = Process.anonymize_data(data, configuration) #anonymize data using proper configuration
            # Set the output file by appending _anonymized to the original name
            output_filename = os.path.splitext(file.filename)[0] + '_anonymized'
            # set the path to the folder
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

            # Convert the anonymized data to a JSON string
            anonymized_json = json.dumps(anonymized_data)

            # Save the output to disk
            with open(output_path, 'w') as f:
                f.write(anonymized_json)

            if checkbox_state == 'checked':
                empty_dictionaries() #emptying dictionaries if the button is checked
            return anonymized_data #anonymized data returned as response
    return "No file selected."
# might be used in cases that require direct sending of JSON objects
# @app.route('/anonymize/json', methods=['POST'])
# def json_file():
#     if request.method == 'POST':
#         data = request.json
#         anonymized_data = anonymize_data(data, configuration)
#         return anonymized_data
#
#     return "No data received."


@app.route('/', methods=['POST'])
def upload_file():
    # Get the uploaded file from the request
    file = request.files['file']

    # Get the file extension
    file_extension = os.path.splitext(file.filename)[1]

    # Check the file extension and set the output file extension
    if file_extension == '.log':
        output_extension = '.log'
    else:
        # Return an error message if the file extension is not supported
        return 'Error: Unsupported file type.'

    # Perform anonymization and get the output
    function = Regex.complete_anonymization(file)


    # Set the output file name and path
    output_filename = os.path.splitext(file.filename)[0] + '_anonymized' + output_extension
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

    # Save the output to disk
    with open(output_path, 'w') as f:
        f.write(function)

    # Clear the global dictionaries if the checkbox is checked
    checkbox_state = request.form.get('checkbox')
    if checkbox_state == 'checked':
        empty_dictionaries()
    return '<pre>' + function + '</pre>'
#function for emptying dictionaries, prints size of the dictionary to the console to verify the dictionary is emptied
#size of the empty dictionary is 64
def empty_dictionaries():
    Functions.clear_dicts()
    print(sys.getsizeof(Functions.ip_dictionary))
    return ' '


if __name__ == '__main__':
    app.run(debug=True)




