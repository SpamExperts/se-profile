import json
import requests
def main():
    result = requests.get('http://www.google.com', verify=False)
    result = result.status_code

if __name__ == "__main__":
    main()
