# Phase 3 – Implementing Security Best Practices for User Profile Dashboard

## Project Overview
This project extends my earlier secure portfolio application by adding a protected user dashboard and secure profile update functionality. In this phase, I focused on protecting user profile data through input validation, sanitization, safe output handling, encryption, and dependency security checks.

ere is the full Markdown version you can copy into a README.md file:

# Setup Instructions

## Prerequisites

Make sure these are installed:

- Node.js and npm
- MongoDB Community Server
- MongoDB Compass
- Git

## Installation

1. Clone or download the repository.
2. Open the project folder in VS Code.
3. Install dependencies:

```bash
npm install

Create a .env file in the project root and add:
PORT=3000
MONGO_URI=mongodb://127.0.0.1:27017/portfolioAuth
SESSION_SECRET=mySuperSecureSessionSecret123
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=https://localhost:3000/auth/google/callback
JWT_SECRET=your_super_secret_jwt_key_123
JWT_REFRESH_SECRET=your_super_secret_refresh_key_456
PROFILE_ENCRYPTION_KEY=your_secret_key_here

Make sure MongoDB is running locally.

Start the application:
node server.js

Open the application in your browser:
https://localhost:3000

Input Validation Techniques

I used server-side validation to make sure only safe and expected data is accepted before saving profile information. The name field is limited to 3 to 50 alphabetic characters, the email field must follow a valid email format, and the bio field is limited to 500 characters with only allowed safe characters. I also trimmed extra spaces and converted the email to lowercase before saving. This helps reduce the risk of invalid input, malicious content, and unexpected data being stored in the database.

Output Encoding Methods

To safely display profile data on the dashboard, I used safe frontend output methods such as textContent instead of inserting user input directly with HTML. This helps prevent cross-site scripting (XSS) because user content is displayed as plain text rather than being interpreted by the browser as executable code.


Encryption Techniques Used

I used Node.js built-in crypto module to encrypt sensitive profile data before storing it in MongoDB. In my project, the user bio is encrypted using AES encryption. When the bio is saved, the application generates a random initialization vector (IV), encrypts the bio, and stores the encrypted value in bioEncrypted and the IV in bioIv. When the user loads the dashboard, the bio is decrypted on the server and then displayed back to the authenticated user. This ensures that the bio is not stored in plain text in the database.

Third-Party Libraries Dependency Management

To manage dependency security, I used npm audit to check installed packages for known vulnerabilities. This helped identify outdated or vulnerable libraries in the project. I reviewed the suggested fixes and used safe update options where appropriate. I also added a GitHub Actions workflow to automate dependency checks, so security issues can be identified whenever the project is pushed to GitHub. This improves long-term maintenance and helps reduce the risk of using vulnerable third-party packages.

## AI Tools Used
I used AI tools to support the permitted parts of this project, mainly for dashboard HTML structure, CSS styling, JavaScript structure, GitHub Actions workflow YAML. I used ChatGPT to generate layout ideas, improve code structure, and help format documentation. After using AI-generated suggestions, I reviewed the code carefully, tested it in my application, and adjusted it where needed. I verified the output by running the project locally, checking that the dashboard loaded correctly, confirming that profile updates worked, and making sure encrypted bio data was stored properly in MongoDB Compass.

---

## Lessons Learned
This phase taught me that protecting user data requires more than just login and authentication. I learned how input validation, sanitization, safe output handling, and encryption all work together to make a user profile system more secure. One challenge I faced was connecting the dashboard frontend with the backend routes correctly, because the page design worked first but the profile data could not load until the protected routes matched the frontend requests. Another challenge was adding encryption without breaking the dashboard flow. I resolved this by encrypting the bio before saving it in MongoDB and decrypting it only when the logged-in user’s profile was loaded. I also learned that dependency management is important because security issues can come from third-party libraries as well as my own code.

## Reflection Checkpoint – Part B
Improper input validation can lead to several security problems, including cross-site scripting, broken application logic, malformed data, and injection-style attacks. If a form accepts unsafe input without checking it properly, attackers may be able to store harmful scripts or unexpected content in the database. Output encoding helps prevent XSS attacks because it makes sure user input is displayed as plain text instead of being treated as code by the browser. One challenge I faced with encryption was adding it into the profile update flow without breaking the dashboard. I resolved this by encrypting the bio before storing it in MongoDB and decrypting it only when the authenticated user’s profile was loaded.

## Reflection Checkpoint – Part C
It is risky to use outdated third-party libraries because they may contain known vulnerabilities that attackers can exploit. Even if my own code is secure, insecure dependencies can still create weaknesses in the application. Automation helps with dependency management because it makes it easier to run regular security checks and quickly identify vulnerable packages. In my project, using npm audit and GitHub Actions helped me review dependency issues more consistently. However, automation also has risks because not all updates are safe to apply automatically. Some upgrades may introduce breaking changes or affect application functionality, so the results still need to be reviewed carefully.

## Reflection Checkpoint – Part D
The vulnerabilities that were most challenging to address were those related to user input, because they affected both the frontend and backend of the application. I had to make sure the profile form validated input correctly, displayed user data safely, and stored sensitive information securely. Testing the encrypted bio flow was also challenging because I needed to confirm that the data was encrypted in MongoDB but still displayed properly after decryption. Additional testing tools and strategies that could improve the process include automated test scripts, dependency monitoring tools, and more structured security testing for edge cases. Using MongoDB Compass, browser developer tools, and realistic malicious test inputs also helped me verify that the security features were working correctly.
