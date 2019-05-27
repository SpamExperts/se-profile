# se-profile
se-profile repository contains profiling tests written for SpamAssassin and OrangeAssasin

# Installing notes
```
git clone git@github.com:SpamExperts/se-profile.git #clone the repository
cd se-profile
pip install -r requirements.txt
```
# Testing
Run the profile script, passing another script as parameter (the script passed as param must be included without .py extension and must have a main function defined) , to retrieve info (CPU usage, Memory usage, etc.) about it.
### Script example
your_script.py
```
import json
import requests
def main():
    print(requests.get('http://www.google.com', verify=False))

if __name__ == "__main__":
    main()
```
### Running the profiler for the script above
 ```
python se_profile/profile.py -m your_script -p --debug
cat .profile_results/profiler-result.txt
```
### Output example
```
Profiler
---------------------------------------------------------------------------------------------------
    ===========================================================================================
    |      Max MB       Min MB       Avg MB FILE                                              |
    ===========================================================================================
    |     23.492       14.215       20.572  se_profile/profile.py                             |
    |     23.492       23.137       23.314  your_script.py                                    |
    ===========================================================================================
    |     23.492       14.215       21.181  TOTAL                                             |
    ===========================================================================================

      23.492  - Memory peak
      22.863  - Memory at import
      23.492  - Memory at end of run
       0.629  - Memory increment
```
