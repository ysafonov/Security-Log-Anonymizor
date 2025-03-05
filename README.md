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

Technical representation of the program workflow is shown below.

![Sensitive Log Data Categories](flow-chart.png)

Mentioned categories are detailed in the following table.



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
