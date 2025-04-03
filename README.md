## Digital Legacy Manager - AI-Powered Virtual Assistant

### Overview

The Digital Legacy Manager is a Python-based application designed to help users plan and manage their digital assets and information for transfer to designated beneficiaries in the event of incapacitation or death.  It provides a secure and organized way to store important documents, beneficiary information, and legacy plans.  The application includes a command-line interface (CLI) and is designed with a modular architecture to facilitate future expansion, such as a web interface and enhanced AI integration.

### Features

* **User Management:**

    * Secure user registration and authentication.
    * User profile management (view, update).
    * Password management (update).
    * User deletion.

* **Legacy Planning:**

    * Creation, retrieval, updating, and deletion of legacy plans.
    * Storage of documents (file paths, not actual files) associated with a plan.
    * Storage of beneficiary information (name, email, relationship).

* **Data Storage:**

    * SQLite database for persistent data storage.

* **Security:**

    * Password hashing using PBKDF2.
    * Data encryption using Fernet.

* **AI Integration (Placeholder):**

    * Placeholder for future integration with AI models for natural language processing and task automation.

* **Task Automation (Placeholder):**

    * Placeholder for future automation of legacy-related tasks, such as document distribution.

* **Command-Line Interface (CLI):**

    * Basic CLI for user interaction.

* **Error Handling:**

    * Custom exceptions and a centralized error handler.

* **Configuration:**

    * Configuration loaded from a JSON file.

* **Documentation:**

    * README and code-level documentation.

### Technical Details

* **Programming Language:** Python 3.9+
* **Data Storage:** SQLite
* **Libraries:**

    * Pydantic: Data validation and modeling.
    * cryptography: Encryption and hashing.

* **Architecture:** Modular, object-oriented.
* **Logging:** Uses Python's `logging` module.

### Setup

1.  **Prerequisites:**

    * Python 3.9 or higher.
    * Ensure that you have `pip` installed.

2.  **Installation:**

    * Clone the repository:

        ```
        git clone [https://github.com/adonisjimenezzz/AI-Digital-Legacy-Manager](https://github.com/adonisjimenezzz/AI-Digital-Legacy-Manager)
        cd digital-legacy-manager
        ```

    * Create a virtual environment (recommended):

        ```
        python -m venv venv
        source venv/bin/activate  # On Linux/macOS
        venv\Scripts\activate  # On Windows
        ```

    * Install the required packages:

        ```
        pip install -r requirements.txt
        ```

3.  **Configuration:**

    * The application uses a `config.json` file for configuration.  A default `config.json` is provided.  You can modify this file to change settings such as the database URL and log file location.
    * **Important:** The `secret_key` in `config.json` is used for data encryption.  **Do not share this key.** The application will generate one if one does not exist.
    * The `password_salt` in `config.json` is used for password hashing.  You can change it, but it's not strictly necessary.

4.  **Database:**

    * The application uses an SQLite database file (`legacy_data.db` by default).  This file will be created automatically in the application directory when the application is run.  The database file name and location can be changed in the `config.json` file.

5.  **Running the Application:**

    * To run the CLI:

        ```
        python interaction.py --mode cli
        ```

### Usage (CLI)

1.  **Running the CLI:**

    * Open a terminal and navigate to the application directory.
    * Run the command: `python interaction.py --mode cli`

2.  **Commands:**

    * `help`: Displays a list of available commands.
    * `create_user`: Creates a new user account.  You will be prompted for a username, password, and email address.
    * `login`: Logs in to an existing user account.  You will be prompted for your username and password.
    * `exit`: Exits the application.

3.  **User Commands (after login):**

    * `create_plan`: Creates a new legacy plan.  You will be prompted for a plan name, and then you can enter documents and beneficiaries.
    * `get_plan`: Retrieves a legacy plan by its ID.  You will be prompted for the plan ID.
    * `update_plan`: Updates an existing legacy plan.  You will be prompted for the plan ID, and then you can update the plan name, documents, and beneficiaries.
    * `delete_plan`: Deletes a legacy plan.  You will be prompted for the plan ID.
    * `profile`: Displays your user profile.
    * `update_profile`: Updates your user profile (username and email).
    * `update_password`: Updates your user password.
    * `delete_user`: Deletes your user account.  You will be prompted for confirmation.
    * `process_text`:  A placeholder command to demonstrate AI text processing (currently a placeholder).
    * `distribute`: A placeholder command to demonstrate document distribution to beneficiaries.
    * `user_exit`: Exits the user command mode and returns to the main menu.

### Data Model

The application uses the following data model, defined using Pydantic:

* **User:**

    * `user_id` (str): Unique user ID.
    * `username` (str): Username.
    * `password` (str): Hashed password.
    * `email` (str): Email address.
    * `legacy_plans` (dict): Dictionary of legacy plans, keyed by plan ID.
    * `salt` (str): Salt used for password hashing.

* **LegacyPlan:**

    * `plan_id` (str): Unique plan ID.
    * `plan_name` (str): Plan name.
    * `documents` (list): List of `Document` objects.
    * `beneficiaries` (list): List of `Beneficiary` objects.
    * `creation_date` (str): Date the plan was created.

* **Document:**

    * `title` (str): Document title.
    * `description` (str): Document description.
    * `file_path` (str): Path to the document file.

* **Beneficiary:**

    * `name` (str): Beneficiary name.
    * `email` (str): Beneficiary email address.
    * `relationship` (str): Beneficiary relationship to the user.

### Modules

The application is organized into the following modules:

* **`config.py`**: Handles application configuration.  The `Config` class loads settings from `config.json` and provides methods to access them.

* **`error_handling.py`**: Defines custom exceptions (e.g., `UserNotFoundException`, `LegacyPlanNotFoundException`) and a centralized error handling mechanism.  The `ErrorHandler` class provides a `handle_exception` method to log and display errors.

* **`utils.py`**: Provides utility functions, including:

    * `generate_uuid()`: Generates a unique ID.
    * `get_fernet()`: Gets a Fernet instance for encryption.
    * `encrypt_data()`/`decrypt_data()`: Encrypts and decrypts data.
    * `format_date()`: Formats a datetime object.
    * `hash_password()`/`verify_password()`: Hashes and verifies passwords.

* **`models.py`**: Defines the data models (`User`, `LegacyPlan`, `Document`, `Beneficiary`) using Pydantic.  These models provide data validation and serialization.

* **`data_storage.py`**: Manages data persistence using SQLite.  The `DataStorage` class provides methods to create, retrieve, update, and delete data from the database.  It handles database connections, table creation, and data access.

* **`user_management.py`**: Handles user authentication and management.  The `UserManagement` class provides methods to create, authenticate, retrieve, update, and delete users.

* **`legacy_planning.py`**: Handles the creation and management of legacy plans.  The `LegacyPlanning` class provides methods to create, retrieve, update, and delete legacy plans, including their associated documents and beneficiaries.

* **`ai_integration.py`**: (Placeholder) This module is intended to integrate with AI models for natural language processing and task automation.  Currently, it contains a placeholder `AIIntegration` class with a placeholder `process_text()` method.

* **`task_automation.py`**: (Placeholder) This module is intended to automate legacy-related tasks.  Currently, it contains a placeholder `TaskAutomation` class with placeholder methods like `distribute_documents()` and `manage_accounts()`.

* **`interaction.py`**: Manages user interactions.  The `Interaction` class provides a command-line interface (CLI) for users to interact with the application.  It handles user input, calls the appropriate methods from other modules, and displays output.

* **`security.py`**: Implements security measures such as password hashing and data encryption.  (Partially implemented in `utils.py` and `config.py`).

### Future Enhancements

* **Web Interface:** Develop a web-based user interface using a framework.

* **Enhanced AI Integration:** Integrate with a specific AI model (e.g., OpenAI GPT) to:

    * Analyze documents.
    * Generate summaries.
    * Provide personalized recommendations.
    * Automate tasks based on user instructions.

* **Task Automation:** Implement the task automation features, such as:

    * Automatic distribution of documents to beneficiaries.
    * Management of digital accounts (e.g., transferring ownership or closing accounts).
    * Sending notifications to relevant parties.

* **Advanced Security:**

    * Implement more robust security measures, such as:

        * Two-factor authentication.
        * Regular security audits.
        * Key rotation.

* **Testing:** Implement a comprehensive suite of unit and integration tests.

* **Documentation:** Expand the documentation with more detailed explanations and examples.

* **Internationalization:** Support multiple languages.

* **More Robust CLI:** Improve the CLI with better error handling, input validation, and user-friendly features.

### Contribution

* Contributions are welcome.
* Feel free to fork the repository, make changes, and submit pull requests.
* Please follow the existing code style and conventions.
* Write tests for any new features or changes.
* Update the documentation as needed.

### License

MIT License

