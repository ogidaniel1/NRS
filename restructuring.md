## NOTES
This is to explain certain code choices in the restructured code

### FILES NOT IN THE APP FOLDER
- model and notebook folder contains all the notebooks and model files needed. likely used for exploration
- tests folder contains tests if needed for this deployment
- gitignore file updated to reflect all possible auto-generated python file/folders
- env_sample gives a sample of all the expected variables in the .env file. you can edit this and use
- run.py serves as the entry point to the application 

### FILES IN THE APP FOLDER
- init.py serves as the initialization of the app.
- config.py cotains all configurtation needded for by flask and any other extensions we might use
- extensions.py contains the intialization of flask exttensions that makes coding easier


### CODING CHOICES
- validating user input will be done in the form used to collect the data. any error is rendered back to the user
- 