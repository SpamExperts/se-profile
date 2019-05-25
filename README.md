# se-profile
se-profile repository contains profiling tests written for SpamAssassin and OrangeAssasin

# Installing notes
```
git clone git@github.com:SpamExperts/se-profile.git #clone the repository
cd se-profile
pip install -r requirements.txt
```
# Testing
Run the profile script, passing another script as parameter, to retrieve info (CPU usage, Memory usage, etc.) about it.
 ```
python se_profile/profile.py -m your_script -p --debug
cat .profile_results/profiler-result.txt
```
