import sys
import xlsxwriter
import xml.etree.ElementTree as ET
from copy import deepcopy

try:
    #  Taking input
    xml_file_name = sys.argv[1]
    log_file_name = sys.argv[2]

    #  Checking for xml extension
    if xml_file_name.split(".")[-1] != "xml":
        print("Please provide an xml file only")
        exit()

    #  Parsing the xml file
    tree = ET.parse(xml_file_name)
    root = tree.getroot()


#  Handling absence of files in command lines
except IndexError as e:
    print("Usage: python AppScan_parser.py <xml file> <log file>")
    exit()

#  Handling improper structured xml file
except ET.ParseError as e:
    print("Could not parse the given XML file, please check the format")
    exit()

#  Open log file
log_file = open(log_file_name, "r")

#  Count keeping variables
no_of_vulnerabilities = 0
no_of_login_endpoints = 0
no_of_logout_endpoints = 0
no_of_visited_urls = 0
no_of_skipped_urls = 0

#  Variables for log file parsing
vulnerability_dict = {}
login_requested_endpoints = []
logout_requested_endpoints = []
visited_urls = set()
skipped_urls = {}

#  Variables for xml file parsing
vulnerability_name = []
vulnerability_description = []
recommendations = []
reference_id = []
url = []
temp_urls = []
urls = []

#  Headers for excel report file (Log parsing)
categories = {"serial": "S. No",
              "visited": "Visited URLs",
              "skipped": "Skipped URLs",
              "vulnerability": "Vulnerabilities Found",
              "login": "Login Endpoints",
              "logout": "Logout Endpoints"}


#  Function to find URLs visited by AppScan
def find_visited_urls(relevant):
    visited_url = relevant.split(" ")
    visited_url = visited_url[2]

    return visited_url


#  Function to find skipped URLs
def find_skipped_urls(relevant):
    skipped_url_start = relevant.find(": ")
    skipped_url = relevant[skipped_url_start + 2:]

    reason_start = relevant.find("(")
    reason_end = relevant.find(")")

    reason = relevant[reason_start + 1: reason_end]

    return [skipped_url, reason]


#  Function to find login endpoints
def find_login_endpoints(relevant):
    extracted_url = relevant.split(" ")
    extracted_url = extracted_url[3]

    return extracted_url


#  Function to find logout endpoints
def find_logout_endpoints(relevant):
    extracted_url = relevant.split(" ")
    extracted_url = extracted_url[3]

    return extracted_url


#  Function to find vulnerabilities from log
def find_vulnerability(relevant):
    start = relevant.find("(")
    end = relevant.find(")")

    vulnerability = relevant[start + 1: end]

    return vulnerability


#  Function to provide stats of captured data
def capture_statistics():
    global no_of_vulnerabilities
    global no_of_login_endpoints
    global no_of_logout_endpoints
    global no_of_visited_urls
    global no_of_skipped_urls

    for key in vulnerability_dict.keys():
        no_of_vulnerabilities += len(vulnerability_dict[key])

    no_of_login_endpoints = len(login_requested_endpoints)

    no_of_logout_endpoints = len(logout_requested_endpoints)

    no_of_visited_urls = len(visited_urls)

    for key in skipped_urls.keys():
        no_of_skipped_urls += len(skipped_urls[key])


#  The main driver function
def main():
    #  Parsing the log file
    for line in log_file:

        relevant = line.strip().split(" ")
        relevant = ' '.join(relevant[7:])  # Skips all timestamps and irrelevant information

        #  Check for visited pages
        if "Visited page: " in relevant:
            visited_urls.add(find_visited_urls(relevant))

        #  Check for skipped URLs
        elif "Skipping URL " in relevant:
            skipped_url, reason = find_skipped_urls(relevant)

            if reason not in skipped_urls.keys():
                skipped_urls[reason] = []

            if skipped_url not in skipped_urls[reason]:
                skipped_urls[reason].append(skipped_url)

        #  Check for login request endpoints
        elif "Login request detected:" in relevant:
            extracted_url = find_login_endpoints(relevant)

            if extracted_url not in login_requested_endpoints:
                login_requested_endpoints.append(extracted_url)

        #  Check for logout request endpoints
        elif "Logout request detected:" in relevant:
            extracted_url = find_logout_endpoints(relevant)

            if extracted_url not in logout_requested_endpoints:
                logout_requested_endpoints.append(extracted_url)

        #  Check for tested vulnerabilities
        elif "Test " in relevant:
            vulnerability = find_vulnerability(relevant)

            if vulnerability not in vulnerability_dict.keys():
                vulnerability_dict[vulnerability] = []

            url_start = relevant.find("on: ")

            url = relevant[url_start + 4:]

            #  Extracting parameters
            if "(parameter =" in url:
                parameter_start = url.find("(parameter =")
                parameter = url[parameter_start + 13: -1]
                url = url[:parameter_start - 1]

            else:
                parameter = ''

            #  Checking for duplicate entries
            if (url, parameter) not in vulnerability_dict[vulnerability]:
                vulnerability_dict[vulnerability].append((url, parameter))


#  Function to populate Visited URLs in excel file
def fill_visited_urls(worksheet):
    row = 3
    column = 0

    #  Check for empty list
    if bool(visited_urls):
        for url in visited_urls:
            worksheet.write(row, column, url)
            row += 1


#  Function to populate Skipped URLs in excel file
def fill_skipped_urls(worksheet):
    row = 3
    column = 1

    #  Check for empty list
    if bool(skipped_urls):
        for reason in skipped_urls.keys():
            for url in skipped_urls[reason]:
                worksheet.write(row, column, reason)
                worksheet.write(row, column + 1, url)

                row += 1
                column = 1


#  Function to populate Vulnerabilities found in excel file
def fill_vulnerabilities_found(worksheet):
    row = 3
    column = 3

    #  Check for empty dictionary
    if bool(vulnerability_dict):
        for vuln in vulnerability_dict.keys():
            for url in vulnerability_dict[vuln]:
                worksheet.write(row, column, vuln)
                worksheet.write(row, column + 1, url[0])
                worksheet.write(row, column + 2, url[1])

                row += 1
                column = 3


# Function to populate Login Endpoints in excel file
def fill_login_endpoints(worksheet):
    row = 3
    column = 6

    for url in login_requested_endpoints:
        worksheet.write(row, column, url)

        row += 1


#  Function to populate Logout Endpoints found in excel file
def fill_logout_endpoints(worksheet):
    row = 3
    column = 7

    for url in logout_requested_endpoints:
        worksheet.write(row, column, url)

        row += 1


#  Function to save details in excel file
def save_in_excel():
    #  Creating a new Excel file
    workbook = xlsxwriter.Workbook('AppScan Report.xlsx')

    #  Worksheets declaration
    worksheet_xml = workbook.add_worksheet('XML Report')
    worksheet_log = workbook.add_worksheet('Log Report')

    #  Setting the header text formatting
    header_format = workbook.add_format({
        'bold': True,
        'border': True,
        'align': 'center',
        'valign': 'vcenter',
        'font_color': '#FFFFFF',  # White
        'bg_color': '#1E88E5'})  # Blue

    #  Setting the text formatting
    text_format = workbook.add_format({
        'align': 'left',
        'valign': 'vcenter',
        'text_wrap': True})

    #  Save xml report analysis
    save_xml_analysis(worksheet_xml, header_format, text_format)

    #  Save log report analysis
    save_log_analysis(worksheet_log, header_format)

    #  Setting the zoom factor of the excel sheet
    worksheet_xml.set_zoom(70)
    worksheet_log.set_zoom(70)

    #  Closing the workbook
    workbook.close()


#  Function to save xml analysis report
def save_xml_analysis(worksheet, header_format, text_format):
    #  Setting the column width
    worksheet.set_column('A:A', 30)
    worksheet.set_column('B:B', 50)
    worksheet.set_column('C:C', 50)
    worksheet.set_column('D:D', 40)

    #  Populating the header field
    #  Vulnerability Name
    worksheet.write('A1', "Vulnerability Name", header_format)

    #  Vulnerability Description
    worksheet.write('B1', "Vulnerability Description", header_format)

    #  Recommendations
    worksheet.write('C1', "Recommendations", header_format)

    #  Affected URL
    worksheet.write('D1', "Affected URL", header_format)

    #  Parsing the xml file for relevant data
    #  Finding vulnerability name
    for child in root.findall('.//issue-type-group/item/name'):
        vuln_name = ''.join(child.itertext()).strip()
        vulnerability_name.append(vuln_name)

    #  Finding vulnerability Description
    for child in root.findall('.//advisory-group/item/advisory/testTechnicalDescription'):
        vuln_description = ''.join(child.itertext()).strip()
        vulnerability_description.append(vuln_description)

    #  Getting relevant recommendations
    for child in root.findall('.//fix-recommendation-group/item/general'):
        recom = ''.join(child.itertext()).strip()
        recommendations.append(recom)

    # Getting Affected URLs
    for child in root.findall('.//issue-type-group/item/advisory/ref'):
        ref_id = ''.join(child.itertext()).strip()
        reference_id.append(ref_id)

    for i in range(0, len(reference_id)):
        for child in root.findall('.//url-group/item'):
            if reference_id[i] == child.find('issue-type').text:
                temp_url = child.find('name').text
                url.append(temp_url)
                # print (url)
            else:
                continue
        temp_urls = deepcopy(url)
        urls.append(temp_urls)
        url.clear()

    row = 1
    column = 0
    #  Filling all the data
    for i in range(0, len(recommendations)):
        data = (vulnerability_name[i],
                vulnerability_description[i],
                recommendations[i],
                urls[i])

        for j in range(0, len(data)):
            column = j

            if column == 3:
                worksheet.write_row(row, column, data[column], text_format)
            else:
                worksheet.write(row, column, data[column], text_format)

        row += 1


#  Function to save log analysis report
def save_log_analysis(worksheet, header_format):
    #  Setting the column width
    worksheet.set_column('A:A', 40)
    worksheet.set_column('B:B', 30)
    worksheet.set_column('C:C', 40)
    worksheet.set_column('D:D', 30)
    worksheet.set_column('E:E', 40)
    worksheet.set_column('F:F', 30)
    worksheet.set_column('G:G', 40)
    worksheet.set_column('H:H', 40)

    #  Populating the header field
    #  Visited URLs
    worksheet.merge_range("A1:A2", categories["visited"], header_format)
    worksheet.write("A3", "Total Visited: {}".format(no_of_visited_urls), header_format)

    #  Skipped URLs
    worksheet.merge_range("B1:C1", categories["skipped"], header_format)
    worksheet.write("B2", "Reason", header_format)
    worksheet.write("C2", "URL Skipped", header_format)
    worksheet.merge_range("B3:C3", "Total Skipped: {}".format(no_of_skipped_urls), header_format)

    #  Vulnerabilities found
    worksheet.merge_range("D1:F1", categories["vulnerability"], header_format)
    worksheet.write("D2", "Vulnerability", header_format)
    worksheet.write("E2", "Affected URL", header_format)
    worksheet.write("F2", "Vulnerable Parameters", header_format)
    worksheet.merge_range("D3:F3", "Total Found: {}".format(no_of_vulnerabilities), header_format)

    #  Login endpoints
    worksheet.merge_range("G1:G2", categories["login"], header_format)
    worksheet.write("G3", "Total Found: {}".format(no_of_login_endpoints), header_format)

    #  Logout endpoints
    worksheet.merge_range("H1:H2", categories["logout"], header_format)
    worksheet.write("H3", "Total Found: {}".format(no_of_logout_endpoints), header_format)

    #  Populating the values
    #  Visited URLs
    fill_visited_urls(worksheet)

    #  Skipped URLs
    fill_skipped_urls(worksheet)

    #  Vulnerabilities found
    fill_vulnerabilities_found(worksheet)

    #  Login endpoints
    fill_login_endpoints(worksheet)

    #  Logout endpoints
    fill_logout_endpoints(worksheet)


if __name__ == "__main__":
    main()
    capture_statistics()
    save_in_excel()

    print("Report created successfully")
