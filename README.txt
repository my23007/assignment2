1- How to run the code

The code uses the concept of object oriented programming, it has the functions for user registration, login, SQL injection, XSS attack and a user class , customer class inherited from user class and another class for web application firewall.
To run this code, you need python3 installed on your local host, use pip install <library name> to install needed libraries,
then you can run the python code from its location
myounes@myouneslap MINGW64 ~/Desktop/Essex/assignment1/main
$ python assignment2_main.py

Welcome to the online shopping System
1. Register
2. Login
3. Browse product catalog
4. Exit

The code begins by importing necessary modules and libraries. 
The User class handles user registration, login, and searching for products. It connects to a database to store user information and product data.
Moreover, to keep the password hidden while typing it, the code uses the getpass module.
getpass.getpass("Enter a password: ") securely gets the password from the user. It doesn't show the password on the screen.

The code provides a simple text-based menu for users.
Users can choose to register, log in, search for products, or exit.

-Register User:

Users can register by entering a username and password.
The code checks if the username already exists and securely stores the user's information in the database.

-Login User:

Users can log in by entering their username and password.
The code checks if the provided username and password match the stored information in the database.

-Search for Products:

Users can search for products by entering a query.
The code checks for matching products and displays them.

-Exiting the Program:

Users can choose to exit the program at any time.


Passwords are kept hidden when entered, improving security.
The code also takes measures to prevent SQL injection and cross-site scripting (XSS) attacks. Furthermore, The code manages a database to store user and product data.


2- testing scenario and data

Welcome to the online shopping System
1. Register
2. Login
3. Browse product catalog
4. Exit
Enter your choice: 1
Enter a new username: user4
Enter a password: ········
Username already exists. Please choose another one.

Welcome to the online shopping System
1. Register
2. Login
3. Browse product catalog
4. Exit
Enter your choice: 2
Enter your username: user3
Enter your password: ········
Invalid username or password. Please try again.

Welcome to the online shopping System
1. Register
2. Login
3. Browse product catalog
4. Exit
Enter your choice: 3
Enter a search query: lemon
No products matching the given query.

Welcome to the online shopping System
1. Register
2. Login
3. Browse product catalog
4. Exit
Enter your choice: 4
Goodbye!


# testing example and expected output

if __name__ == "__main__":
    waf = WebApplicationFirewall()

    # Simulated user input
    user_input_sql_injection = "SELECT * FROM users"
    user_input_xss = "<script>alert('XSS')</script>"
    safe_user_input = "Hello, World!"

    result_sql_injection = waf.protect(user_input_sql_injection)
    result_xss = waf.protect(user_input_xss)
    result_safe = waf.protect(safe_user_input)

    print(result_sql_injection)  # Output: SQL Injection Detected! Request Blocked.
    print(result_xss)  # Output: XSS Attack Detected! Request Blocked.
    print(result_safe)  # Output: Request Passed WebApplicationFirewall Security Check.Welcome to the online shopping system



The use of sanitization in the code is based on scientific research and peer reviewed articles.For example,Shar and Tan (2013) argue that input sanitization code is usuaully deployed in web applications to mitigate SQL injection and XSS attacks, they highlight that the sanitized input removes, escapes or replaces suspicious characters from user input to avoid unintended actions or operations. Moreover, Hydara et el (2015) highlight that XSS attacks impacts web applications and can occur in cases where improper sanitization of user inputs are seen.
Shar and Tan (2013) argue the use of insufficient escaping methods leading to XSS vulnerability attacks is usually common in practice.


3- Limitations:
Please note that this is still an example used for educational purposes for this assignment. In a real-world application, an online shopping system would require a lot more complexity and security considerations. In the code provided, it was a simple database and user access, but arguably the real-world application in a production environment should contain user access permissions to the database. Security should be a top priority, and should follow best practices for secure coding and regularly update the system to patch any vulnerabilities. 

4- Future enhancements:
As we are now in the age of machine learning and artificial intelligence, the deployment of advanced machine learning models in this domain has attracted the attention of practitioners. For example, Yang and Lu (2022) propose the use of convolutional neural network to recognize the SQL injection attacks more efficiently and in an accurate manner. Dawadi et al (2023) propose the use of deep learning techniques with web application firewalls to mitigate denial of service, SQL injection and XSS pattern detection. Dawadi et al (2023) concluded that the deep learning model was 97.57% accurate in denial of service detection and 89.34% accurate in SQL injection/XSS pattern detection.

5- Conclusion:
In summary, this code allows users to interact with an online shopping system, register, log in securely, search for products, and perform these actions in a way that protects against security threats. The use of getpass makes password input more secure by not showing the password on the screen. The code has limitations and future enhancements were proposed for next stage as company growns.

References:

Dawadi, B.R., Adhikari, B. and Srivastava, D.K. (2023). ‘Deep Learning Technique-Enabled Web Application Firewall for the Detection of Web Attacks’. Sensors, 23(4), p.2073. doi:https://doi.org/10.3390/s23042073

Shar, L. K. & Tan, H. B. K. (2013) Predicting SQL injection and cross site scripting vulnerabilities through mining input sanitization patterns. Information and software technology. [Online] 55 (10), 1767–1780.

Hydara, I., Sultan, A.B.Md., Zulzalil, H. and Admodisastro, N. (2015). Current state of research on cross-site scripting (XSS) – A systematic literature review. Information and Software Technology, 58, pp.170–186. doi:https://doi.org/10.1016/j.infsof.2014.07.010.

Yang, S. & Lu, H. (2022) ‘A SQL Injection Attack Recognition Model Based on 1D Convolutional Neural Network’, in Artificial Intelligence and Robotics. [Online]. Singapore: Springer. pp. 281–289.