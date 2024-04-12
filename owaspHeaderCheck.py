import requests
import argparse, sys

# Remove ugly warning print.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

silentMode = False
countInSecurities = 0

# All guideline types
OWASP_GUIDELINES = 0
NOREA_GUIDELINES = 1
API_GUIDELINES = 2

# Resource: https://owasp.org/www-project-secure-headers/ci/headers_remove.json
headersToRemove = ['$wsep', 'Host-Header', 'K-Proxy-Request', 'Liferay-Portal', 'OracleCommerceCloud-Version', 'Pega-Host', 
    'Powered-By', 'Product', 'SourceMap', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Atmosphere-error', 
    'X-Atmosphere-first-request', 'X-Atmosphere-tracking-id', 'X-B3-ParentSpanId', 'X-B3-Sampled', 'X-B3-SpanId', 'X-B3-TraceId', 
    'X-BEServer', 'X-CF-Powered-By', 'X-CMS', 'X-CalculatedBETarget', 'X-Cocoon-Version', 'X-Content-Encoded-By', 'X-DiagInfo', 
    'X-Envoy-Attempt-Count', 'X-Envoy-External-Address', 'X-Envoy-Internal', 'X-Envoy-Original-Dst-Host', 'X-Envoy-Upstream-Service-Time',
    'X-FEServer', 'X-Framework', 'X-Generated-By', 'X-Generator', 'X-LiteSpeed-Cache', 'X-LiteSpeed-Purge', 'X-LiteSpeed-Tag', 
    'X-LiteSpeed-Vary', 'X-Litespeed-Cache-Control', 'X-Mod-Pagespeed', 'X-Nextjs-Cache', 'X-Nextjs-Matched-Path', 'X-Nextjs-Page', 
    'X-Nextjs-Redirect', 'X-OWA-Version', 'X-Old-Content-Length', 'X-OneAgent-JS-Injection', 'X-Page-Speed', 'X-Php-Version', 
    'X-Powered-By', 'X-Powered-By-Plesk', 'X-Powered-CMS', 'X-Redirect-By', 'X-Server-Powered-By', 'X-SourceFiles', 'X-SourceMap', 
    'X-Turbo-Charged-By', 'X-Umbraco-Version', 'X-Varnish-Backend', 'X-Varnish-Server', 'X-dtAgentId', 'X-dtHealthCheck', 
    'X-dtInjectedServlet', 'X-ruxit-JS-Agent', 'X-XSS-Protection'
]

# For formatting and error printing.
def correctPrint(header, comment = None):

    # If we don't want to print any good rules.
    if silentMode:
        return

    if comment:
        print(f"{header:40}| \033[32mSafe\033[0m (only when {comment})")
    else:
        print(f"{header:40}| \033[32mSafe\033[0m")

def invalidPrint(header, comment = None, shouldBeThere = False):

    globals()['countInSecurities'] += 1
    condition = "Missing" if shouldBeThere else "Shouldn't be there"
    errorMessage = "Missing" if shouldBeThere else "Warning"

    if comment:
        print(f"{header:40}| \033[1;31m{errorMessage}\033[0m (\033[93m{comment}\033[0m)")
    else:
        print(f"{header:40}| \033[1;31m{errorMessage}\033[0m (\033[93m{condition}\033[0m)")

# Check for all the headers that should be removed
def checkToRemoveHeaders(headers):

    for item in headersToRemove:
        if headers.get(item):
            invalidPrint(item, shouldBeThere=False, comment="Should be removed")
        else:
            correctPrint(item)
    
def checkServerHeader(header, value):

    value = value.lower()
    
    # Detection list of what it shouldn't detect.
    detectionList = [
        "apache", "werkzeug", "php", "java", "nginx", "http file server", "tomcat"
    ]

    for item in detectionList:
        if item in value:
            invalidPrint(header, shouldBeThere=False, comment=f"Detected string '{item}'")
            return
    
    correctPrint(header)

#https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#security-headers
def scanHeadersAPI(headers):

    print("---------------- Using OWASP API guidelines --------------------")

    # The Cache-Control value should contain 'nostore, max-age=0'.
    if headers.get("Cache-Control"):
        if headers['Cache-Control'] == 'no-store':
            correctPrint('Cache-Control')
        else:
            invalidPrint('Cache-Control', shouldBeThere=True, comment=f"Incorrect value [{headers['Cache-Control']}], should be 'no-store'")
    else:
        invalidPrint('Cache-Control', shouldBeThere=True, comment="Value should be 'no-store'")
    
    # The X-Content-Type-Options header should have the value 'nosniff'.
    if headers.get("X-Content-Type-Options"):
        if headers["X-Content-Type-Options"] == "nosniff":
            correctPrint("X-Content-Type-Options")
        else:
            invalidPrint("X-Content-Type-Options", comment="Incorrect value, should be 'nosniff'")
    else:
        invalidPrint("X-Content-Type-Options", shouldBeThere=True, comment="Value should be 'nosniff'")

    # The X-Frame-Options (XFO) value should contain the value 'DENY' or 'none'.
    if headers.get("X-Frame-Options") and headers.get("Content-Security-Policy"):
        if headers['X-Frame-Options'] == 'DENY' and 'frame-ancestors: none' in headers['Content-Security-Policy'].lower() or \
                headers['X-Frame-Options'] == 'same-origin' and 'frame-ancestors: self' in headers['Content-Security-Policy'].lower():
            correctPrint('X-Frame-Options')
        else:
            invalidPrint('X-Frame-Options', shouldBeThere=True, comment=f"Incorrect value, should be 'DENY' when CSP has 'frame-ancestors: none'. Or should be 'none' when CSP has 'frame-ancestors: self")
    else:
        invalidPrint('X-Frame-Options', shouldBeThere=True, comment="Value should be 'DENY' when CSP has 'frame-ancestors: none'. Or should be 'none' when CSP has 'frame-ancestors: self'")

    # The Strict-Transport-Security value should contain the value 'max-age=63072000; includeSubDomains; preload'.
    if headers.get("Strict-Transport-Security"):
        if headers['Strict-Transport-Security'].strip() == 'max-age=31536000;includeSubDomains;preload':
            correctPrint("Strict-Transport-Security")
        else:
            invalidPrint("Strict-Transport-Security", comment=f"Incorrect value [{headers['Strict-Transport-Security']}], should be 'max-age=31536000 ; includeSubDomains ; preload'")
    else:
        invalidPrint('Strict-Transport-Security', shouldBeThere=True, comment="Value should be 'max-age=31536000;includeSubDomains;preload'")
    
    # The Permission-Policy should be set to disable geolocation, microphone and camera.abs
    if headers.get('Permissions-Policy'):
        if 'geolocation=()' in headers['Permissions-Policy'] and 'microphone=()' in headers['Permissions-Policy'] \
            and 'camera=()' in headers['Permissions-Policy'] and 'interest-cohort=()' in headers['Permissions-Policy']:
            correctPrint("Permissions-Policy")
        else:
            invalidPrint('Permissions-Policy', shouldBeThere=True, comment=f"Incorrect value [{headers['Permissions-Policy']}], should be 'geolocation=(), camera=(), microphone=(), interest-cohort=()'")
    else:
        invalidPrint('Permissions-Policy', shouldBeThere=True, comment=f"Value should be 'geolocation=(), camera=(), microphone=(), interest-cohort=()'")

    # The Referrer-Policy value should contain 'no-referrer' or 'same-origin'
    if headers.get("Referrer-Policy"):
        if headers['Referrer-Policy'] == 'no-referrer' or headers['Referrer-Policy'] == 'same-origin':
            correctPrint('Referrer-Policy')
        else:
            invalidPrint('Referrer-Policy', shouldBeThere=True, comment=f"Incorrect value [{headers['Referrer-Policy']}], should be 'no-referrer' or 'same-origin'")
    else:
        invalidPrint('Referrer-Policy', shouldBeThere=True, comment="Value should be 'no-referrer' or 'same-origin'")



def scanHeadersNOREA(headers):
    print("---------------- Using NOREA guidelines --------------------")

    # The Server header should contain a value that doesn't describe the version or server type.
    if headers.get("Server"):
        checkServerHeader("Server", headers['Server'])
    else:
        correctPrint("Server")

    # Iterate trough the forbidden list with headers.
    checkToRemoveHeaders(headers)

    # The Public-Key-Pins is a deprecated header and shouldn't be used anymore.
    if headers.get("Public-Key-Pins"):
        invalidPrint("Public-Key-Pins", shouldBeThere=False)
    else:
        correctPrint("Public-Key-Pins")

    # The X-Content-Type-Options header should have the value 'nosniff'.
    if headers.get("X-Content-Type-Options"):
        if headers["X-Content-Type-Options"] == "nosniff":
            correctPrint("X-Content-Type-Options")
        else:
            invalidPrint("X-Content-Type-Options", comment="Incorrect value, should be 'nosniff'")
    else:
        invalidPrint("X-Content-Type-Options", shouldBeThere=True, comment="Value should be 'nosniff'")

    # The Strict-Transport-Security value should contain the value 'max-age=63072000; includeSubDomains'.
    if headers.get("Strict-Transport-Security"):
        if headers['Strict-Transport-Security'].strip() == 'max-age=31536000;includeSubDomains':
            correctPrint("Strict-Transport-Security")
        else:
            invalidPrint("Strict-Transport-Security", comment=f"Incorrect value [{headers['Strict-Transport-Security']}], should be 'max-age=31536000 ; includeSubDomains'")
    else:
        invalidPrint('Strict-Transport-Security', shouldBeThere=True, comment="Value should be 'max-age=31536000;includeSubDomains'")

    # The X-Frame-Options (XFO) value should contain the value 'DENY' or 'none'.
    if headers.get("X-Frame-Options") and headers.get("Content-Security-Policy"):
        if headers['X-Frame-Options'] == 'DENY' and 'frame-ancestors: none' in headers['Content-Security-Policy'].lower() or \
                headers['X-Frame-Options'] == 'same-origin' and 'frame-ancestors: self' in headers['Content-Security-Policy'].lower():
            correctPrint('X-Frame-Options')
        else:
            invalidPrint('X-Frame-Options', shouldBeThere=True, comment=f"Incorrect value, should be 'DENY' when CSP has 'frame-ancestors: none'. Or should be 'none' when CSP has 'frame-ancestors: self")
    else:
        invalidPrint('X-Frame-Options', shouldBeThere=True, comment="Value should be 'DENY' when CSP has 'frame-ancestors: none'. Or should be 'none' when CSP has 'frame-ancestors: self'")

    # The Referrer-Policy value should contain 'no-referrer' or 'same-origin'
    if headers.get("Referrer-Policy"):
        if headers['Referrer-Policy'] == 'no-referrer' or headers['Referrer-Policy'] == 'same-origin':
            correctPrint('Referrer-Policy')
        else:
            invalidPrint('Referrer-Policy', shouldBeThere=True, comment=f"Incorrect value [{headers['Referrer-Policy']}], should be 'no-referrer' or 'same-origin'")
    else:
        invalidPrint('Referrer-Policy', shouldBeThere=True, comment="Value should be 'no-referrer' or 'same-origin'")


# Guidelines based on https://owasp.org/www-project-secure-headers/ci/headers_add.json
def scanHeadersOWASP(headers):
    print("---------------- Using OWASP guidelines --------------------")

    # The Server header should contain a value that doesn't describe the version or server type.
    if headers.get("Server"):
        checkServerHeader("Server", headers['Server'])
    else:
        correctPrint("Server")

    # Iterate trough the forbidden list with headers.
    checkToRemoveHeaders(headers)

    # The Public-Key-Pins is a deprecated header and shouldn't be used anymore.
    if headers.get("Public-Key-Pins"):
        invalidPrint("Public-Key-Pins", shouldBeThere=False)
    else:
        correctPrint("Public-Key-Pins")

    # The X-Content-Type-Options header should have the value 'nosniff'.
    if headers.get("X-Content-Type-Options"):
        if headers["X-Content-Type-Options"] == "nosniff":
            correctPrint("X-Content-Type-Options")
        else:
            invalidPrint("X-Content-Type-Options", comment="Incorrect value, should be 'nosniff'")
    else:
        invalidPrint("X-Content-Type-Options", shouldBeThere=True, comment="Value should be 'nosniff'")

    # The Strict-Transport-Security value should contain the value 'max-age=63072000; includeSubDomains; preload'.
    if headers.get("Strict-Transport-Security"):
        if headers['Strict-Transport-Security'].strip() == 'max-age=31536000;includeSubDomains;preload':
            correctPrint("Strict-Transport-Security")
        else:
            invalidPrint("Strict-Transport-Security", comment=f"Incorrect value [{headers['Strict-Transport-Security']}], should be 'max-age=31536000 ; includeSubDomains ; preload'")
    else:
        invalidPrint('Strict-Transport-Security', shouldBeThere=True, comment="Value should be 'max-age=31536000;includeSubDomains;preload'")
    
    # The X-Frame-Options (XFO) value should contain the value 'DENY'.
    if headers.get("X-Frame-Options"):
        if headers['X-Frame-Options'] == 'DENY':
            correctPrint('X-Frame-Options')
        else:
            invalidPrint('X-Frame-Options', comment=f"Incorrect value [{headers['X-Frame-Options']}], should be 'DENY'")
    else:
        invalidPrint('X-Frame-Options', shouldBeThere=True, comment="Value should be 'DENY'")

    # The Referrer-Policy value should contain 'no-referrer'.
    if headers.get("Referrer-Policy"):
        if headers['Referrer-Policy'] == 'no-referrer':
            correctPrint('Referrer-Policy')
        else:
            invalidPrint('Referrer-Policy', shouldBeThere=True, comment=f"Incorrect value [{headers['Referrer-Policy']}], should be 'no-referrer'")
    else:
        invalidPrint('Referrer-Policy', shouldBeThere=True, comment="Value should be 'no-referrer'")

    # The Access-Control-Allow-Origin value shouldn't contain an asteriks.
    if headers.get("Access-Control-Allow-Origin"):
        if headers['Access-Control-Allow-Origin'] != '*' and headers['Access-Control-Allow-Origin'] != 'null':
            correctPrint('Access-Control-Allow-Origin')
        else:
            invalidPrint('Access-Control-Allow-Origin', shouldBeThere=False, comment=f"Incorrect value [{headers['Access-Control-Allow-Origin']}]")
    else:
        invalidPrint('Access-Control-Allow-Origin', shouldBeThere=True, comment='Value should be origin domain')

    # The Permission-Policy should be set to disable geolocation, microphone and camera.abs
    if headers.get('Permissions-Policy'):
        if 'geolocation=()' in headers['Permissions-Policy'] and 'microphone=()' in headers['Permissions-Policy'] \
            and 'camera=()' in headers['Permissions-Policy'] and 'interest-cohort=()' in headers['Permissions-Policy']:
            correctPrint("Permissions-Policy")
        else:
            invalidPrint('Permissions-Policy', shouldBeThere=True, comment=f"Incorrect value [{headers['Permissions-Policy']}], should be 'geolocation=(), camera=(), microphone=(), interest-cohort=()'")
    else:
        invalidPrint('Permissions-Policy', shouldBeThere=True, comment=f"Value should be 'geolocation=(), camera=(), microphone=(), interest-cohort=()'")

    # The X-DNS-Prefetch-Control value should be turned off.
    if headers.get('X-DNS-Prefetch-Control'):
        if headers.get("X-DNS-Prefetch-Control") == "off":
            correctPrint("X-DNS-Prefetch-Control")
        else:
            invalidPrint("X-DNS-Prefetch-Control", shouldBeThere=True, comment=f"Incorrect value [{headers['X-DNS-Prefetch-Control']}], should be 'off'")
    else:
        invalidPrint("X-DNS-Prefetch-Control", shouldBeThere=True, comment=f"Value should be 'off'")

    # The X-Permitted-Cross-Domain-Policies value should contain 'none'.
    if headers.get("X-Permitted-Cross-Domain-Policies"):
        if headers['X-Permitted-Cross-Domain-Policies'] == 'none':
            correctPrint('X-Permitted-Cross-Domain-Policies')
        else:
            invalidPrint('X-Permitted-Cross-Domain-Policies', shouldBeThere=True, comment="Incorrect value, should be 'none'")
    else:
        invalidPrint("X-Permitted-Cross-Domain-Policies", shouldBeThere=True, comment="Value should be 'none'")

    #
    #   Here are all the optional headers.
    #

    # The Cache-Control value should contain 'nostore, max-age=0'.
    if headers.get("Cache-Control"):
        if headers['Cache-Control'] == 'no-store,max-age=0':
            correctPrint('Cache-Control')
        else:
            invalidPrint('Cache-Control', shouldBeThere=False, comment="Optional: Value should be 'no-store,max-age=0'")

    # The Cross-Origin-Embedder-Policy value should contain 'require-corp'.
    if  headers.get("Cross-Origin-Embedder-Policy"):
        if headers['Cross-Origin-Embedder-Policy'] == 'require-corp':
            correctPrint('Cross-Origin-Embedder-Policy')
        else:
            invalidPrint('Cross-Origin-Embedder-Policy', shouldBeThere=False, comment="Optional: Value should be 'require-corp")

    # The Cross-Origin-Opener-Policy value should contain 'same-origin'.
    if headers.get("Cross-Origin-Opener-Policy"):
        if headers['Cross-Origin-Opener-Policy'] == 'same-origin':
            correctPrint('Cross-Origin-Opener-Policy')
        else:
            invalidPrint('Cross-Origin-Opener-Policy', shouldBeThere=False, comment="Optional: Value should be 'same-origin")

    # The Cross-Origin-Resource-Policy value should contain 'same-origin'.
    if headers.get("Cross-Origin-Resource-Policy"):
        if headers['Cross-Origin-Resource-Policy'] == 'same-origin':
            correctPrint('Cross-Origin-Resource-Policy')
        else:
            invalidPrint('Cross-Origin-Resource-Policy', shouldBeThere=False, comment="Optional: Value should be 'same-origin")

    # The Clear-Site-Data value should contain '"cache","cookies","storage"'.
    if headers.get("Clear-Site-Data"):
        if headers['Clear-Site-Data'].strip() == '"cache","cookies","storage"':
            correctPrint("Clear-Site-Data")
        else:
            invalidPrint("Clear-Site-Data", shouldBeThere=False,comment='Optional: Value should be \'"cache","cookies","storage"\'')


def scanURL(URL, followRedirects, guidelinesType = 0, cookies = None, credentials = None, outputType = None):

    if not ("http://" in URL or "https://" in URL):
        print("URL input string is not an URL, Skipping...")
        return None
    
    # Check what kind of request it is.
    headers = {}
    try:
        match URL:
            case "GET":
                headers = requests.get(URL, cookies=cookies, verify=False, timeout=5).headers
            case "POST":
                headers = requests.post(URL, cookies=cookies, verify=False, timeout=5).headers
            case "HEAD":
                headers = requests.head(URL, cookies=cookies, verify=False, timeout=5).headers
            case "PUT":
                headers = requests.put(URL, cookies=cookies, verify=False, timeout=5).headers
            case "DELETE":
                headers = requests.delete(URL, cookies=cookies, verify=False, timeout=5).headers
            case "OPTIONS":
                headers = requests.options(URL, cookies=cookies, verify=False, timeout=5).headers
            case _:
                headers = requests.get(URL, cookies=cookies,verify=False, timeout=5).headers
                
    except requests.exceptions.ConnectionError:
        print("\033[1;31mConnection to the server failed!\033[0m ")
        return
    except requests.exceptions.ReadTimeout:
        print("\033[1;31mConnection to the server timed out!\033[0m ")
        return
    except requests.exceptions.SSLError:
        print("\033[1;31mSSL error occured while connecting to the server!\033[0m ")
        return
    except:
        print("\033[1;31mFailed to retrieve the HTTP headers!\033[0m ")
        print("Reason unknown...")
        return

    match guidelinesType:
        case 0:
            return scanHeadersOWASP(headers)
        case 1:
            return scanHeadersNOREA(headers)
        case 2:
            return scanHeadersAPI(headers)
        case _:
            return scanHeadersOWASP(headers)

def main():
    parser = argparse.ArgumentParser(
        prog=sys.argv[0],
        usage=sys.argv[0] + " [options] URL",
        epilog="The script follows the OWASP or NOREA guidelines for HTTP security headers."
    )

    parser.add_argument("-s", "--silent", action="store_true", default=False, dest="silentMode", help="Silent mode, print only if it goes wrong")
    parser.add_argument("-f", "--file", action="store_true", help="Use input file with targets. (URL is input file)")
    parser.add_argument("-d", "--use-digid", action="store_true", dest="noreaGuidelines", help="Use the DigiD guidelines; default: OWASP guidelines.")
    parser.add_argument("-a", "--api", action="store_true", dest="apiGuidelines", help="Use the API guidelines")
    parser.add_argument("-H", "--headers", action="store", dest="headersToUse", help="Headers to use (not working yet)")
    parser.add_argument("-c", "--cookies", action="store", dest="cookies", help="Cookies to use")
    parser.add_argument("-F", "--follow", action="store_true", dest="followRedirects", help="Follow redirections")
    parser.add_argument("-p", "--post", action="store", choices=["POST", "GET", "HEAD", "OPTIONS", "PUT", "DELETE"], dest="postRequest", help="Specify the request")
    parser.add_argument("-b", "--burp", action="store", dest="BURP", help="Uses BURP response request file for input")
    parser.add_argument("URL", help="The URL to scan or input file to use (when -f is specified)")

    args = parser.parse_args()

    # Check if we want silent mode.
    globals()['silentMode'] = args.silentMode 

    # Check which guidelines to follow.
    guidelineType = 0
    if args.apiGuidelines == True:
        guidelinesType = API_GUIDELINES
        
    elif args.noreaGuidelines == True:
        guidelinesType = NOREA_GUIDELINES

    else:
        guidelinesType = OWASP_GUIDELINES

    results = [] # To store the results in.

    # Check if URL is an file.
    if args.file == False:
        print("Scanning ==> " + args.URL)
        results.append(scanURL(args.URL, args.followRedirects, guidelinesType, args.cookies))
    else:
        print("Scanning URLs from input file " + args.URL)
        with open(args.URL, "r") as r:
            lines = r.readlines()

            for urlLine in lines:
                print("\nScanning ==> " + urlLine)
                results.append(scanURL(urlLine, args.followRedirects, guidelinesType, args.cookies))
    
    if countInSecurities > 0:
        print("\nFound %d count of insecure headers!" % countInSecurities)
    else:
        print("\nFound no insecure headers.")

    # Format results.
    # print(results)

def banner():
    print("""██   ██ ███████  █████  ██████  ██   ██ ██    ██ ███    ██ ████████ ███████ ██████  
██   ██ ██      ██   ██ ██   ██ ██   ██ ██    ██ ████   ██    ██    ██      ██   ██ 
███████ █████   ███████ ██   ██ ███████ ██    ██ ██ ██  ██    ██    █████   ██████  
██   ██ ██      ██   ██ ██   ██ ██   ██ ██    ██ ██  ██ ██    ██    ██      ██   ██ 
██   ██ ███████ ██   ██ ██████  ██   ██  ██████  ██   ████    ██    ███████ ██   ██ 

 version 1.0 by ramb0
  (dips on the name by vZhao)
 """)

if __name__ == "__main__":
    banner()
    main()
