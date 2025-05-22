Flask Authentication System with Email OTP Verification
````````````````````````````````````````````````````````
This is a secure user authentication web application built using the Flask framework. It features user registration with email-based OTP verification, secure password storage using bcrypt, session management with Flask-Login, and email handling using Flask-Mail.

Features
`````````
- User Registration with OTP Email Verification

- Secure Login & Session Handling

- Password Change & Account Deletion

- Dummy Network Logs Dashboard (Sample UI)

- Environment-based Secret Management via .env

- SQLite Database Integration with SQLAlchemy

- OTP Expiry Handling with ItsDangerous Serializer

Tech Stack
```````````
- Flask & Flask-Login

- Flask-Mail

- Flask-SQLAlchemy

- Passlib (bcrypt)

- ItsDangerous (for OTP tokenization)

- SQLite (can be upgraded to PostgreSQL or MySQL)

- dotenv for environment variable management

Email Setup Notes
``````````````````
- Ensure you use an app password if using Gmail.

- Mail settings are configured for SSL (MAIL_USE_SSL=True, MAIL_PORT=465).

Dummy Log View
```````````````
- Check /logs route to visualize mock cybersecurity logs — useful for extending into a full monitoring dashboard.

Security Note
``````````````
This app is suitable for educational or internal tooling. For production:

- Use HTTPS

- Sanitize user input

- Apply rate limiting

- Store secrets securely (e.g., AWS Secrets Manager)

Contact
```````
Developed by Sreevishnu V.
Feel free to connect for collaboration or feedback.
