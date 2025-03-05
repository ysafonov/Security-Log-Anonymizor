# Security-Log-Anonymizor

## Overview

**Security Incident and Event Management (SIEM)** systems are vital cybersecurity tools widely deployed across sectors such as critical infrastructure, healthcare, and more. These systems generate vast amounts of normalized data, offering significant potential for advancing security research and AI-driven analytics. However, the sensitive nature of log data presents privacy and legal challenges, restricting its full potential in security monitoring.

This tool provides a secure solution for applying deep learning techniques to sensitive log data while ensuring full compliance with privacy and legal requirements, particularly within the European context. Unlike traditional anonymization methods, this tool preserves essential log-specific attributes necessary for effective AI learning.

## Features

- **Log Data Sensitivity Categorization**: Analyzes and categorizes commonly occurring log data based on sensitivity from widely used SIEM systems.
- **Risk Assessment**: Performs comprehensive risk assessments to ensure the secure handling of sensitive log data.
- **Data Integrity Preservation**: Utilizes noise-based randomization and pseudovalue replacement to preserve data integrity while maintaining log correlations within a session — a key feature often overlooked in existing anonymization tools.
- **Legal Compliance**: Specifically designed to meet stringent privacy and legal requirements, particularly in the European Union.

## Motivation and Impact

This tool is driven by the need to enhance AI applications in cybersecurity while addressing the challenges posed by data privacy concerns. By enabling secure sharing and analysis of sensitive log data, the tool has the potential to foster scientific progress in the field of cybersecurity, allowing organizations to leverage deep learning for advanced threat detection and improved security monitoring.

## Technical Description

The program is developed in **Python 3.12.0** using the **Flask** development framework. Python was selected due to its simplicity, readability, extensive support of pre-built libraries, and a large community, all of which facilitate development and simplify task execution for this project.

**Flask** is used to set up an API for handling communication between different devices. The application supports three types of input:

1. A **single raw log file** representing an unstructured log format.
2. A **file of logs** in the same unstructured format.
3. **JSON logs** representing a semi-structured log format.

The tool’s primary goal is to actively search for predefined sensitive data in logs and replace those values with random ones. To ensure the tool's effectiveness for anonymization in artificial intelligence applications, the anonymization process must preserve the original data format to maintain the accuracy of AI training.

In this tool, we focus on anonymizing **10 categories of security log data**, which are considered the most vulnerable in terms of data privacy. 

The code is organized into several Python files for better maintainability, clarity, and customization to the user's needs:

- **`app.py`**: This is the main executable file. It contains the initialization of Flask and various endpoints that call the HTML render templates.
- **`functions.py`**: This is the largest file, containing the logic of the program. It includes anonymization functions for each data category and a function for clearing dictionaries. Users should avoid modifying this file.
- **`jsonfile.py`**: Contains functions for anonymizing JSON log files through meta keys. The keys are loaded from the `metakeys_config.py` file based on the chosen configuration and mapped to the corresponding anonymization functions from `functions.py` using a dictionary.
- **`replace.py`**: This file contains functions to replace values that have been anonymized in the JSON log key-value pairs and in the raw log strings to prevent breaches.
- **`regex.py`**: This file includes functions with regular expressions used to extract values from raw log files. The functions process files line by line and replace each match with values generated by functions in `functions.py`.
- **`metakeys_config.py`**: This file defines classes for **Elasticsearch**, **RSANetWitness**, and **QRadar**. It applies to JSON logs and contains predefined meta keys for sensitive values, grouped into categories based on the type of data they refer to. The meta keys are organized in lists, making it easy to extend for future needs. Objects of these classes are used in `functions.py`.
- **`config.py`**: Contains simple settings and information about the application, such as the IP address and port number. It also includes settings that allow the user to anonymize individual values by setting the desired data type to `True`. Keeping settings in a separate file provides clarity and makes it easy to adjust the default configurations if needed.

Technical representation of the program workflow is given below.

<div style="text-align: center;">
    <img src="images/flow-chart.png" alt="Flowchart diagram of the anonymization tool." width="700"/>
</div>


## Anonymization of Sensitive Data Using Meta Keys

To effectively anonymize the detected sensitive values using meta keys, it is essential to perform the mapping of these meta keys. The meta keys were categorized into lists based on the type of data they represent and then mapped to more general data categories, as shown in **Table 1**, **Table 2** and **Table 3**. This approach simplifies the process, as many meta keys point to the same data category but use different names.

To ensure that the data maintains its original format while only the values are changed, the generalized categories are further mapped to corresponding anonymization functions.

As part of this work, we performed the mapping of three widely-used SIEM meta keys to more general categories. These tables provide an overview of meta key categorization, including a brief description of each data category and the associated risk.


**Table 1: Selected meta keys for anonymization from NetWitness XDR.**
<div style="text-align: center;">
    <img src="images/netwitness.jpeg" alt="Flowchart diagram of the anonymization tool." width="600"/>
</div>

**Table 2: Selected meta keys for anonymization from IBM QRadar.**
<div style="text-align: center;">
    <img src="images/qradar.jpeg" alt="Flowchart diagram of the anonymization tool." width="600"/>
</div>

**Table 3: Selected meta keys for anonymization from Elastic Stack.**
<div style="text-align: center;">
    <img src="images/elk.jpeg" alt="Flowchart diagram of the anonymization tool." width="600"/>
</div>


## Future Prospects

The tool is poised to become a critical asset in AI-driven security research and implementation, contributing to the development of effective and compliant solutions for advanced threat detection and strengthened security monitoring.

## Authors

- **Ariela Stastna**  
  The University of Law, 2 Bunhill Row, London EC1Y 8HQ, United Kingdom  
  ORCID: [0009-0006-6013-6219](https://orcid.org/0009-0006-6013-6219)  
  Email: [ariela.stastna95@law.ac.uk](mailto:ariela.stastna95@law.ac.uk)

- **Yehor Safonov**  
  Faculty of Electrical Engineering and Communication, Brno University of Technology, Technická 3058/10, 61600 Brno, Czechia  
  ORCID: [0000-0002-3549-2178](https://orcid.org/0000-0002-3549-2178)  
  Email: [yehor.safonov@vut.cz](mailto:yehor.safonov@vut.cz)
