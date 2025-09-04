# ED4281 Radio Request Tracker

A Flask-based web application for tracking radio equipment requests and approvals.

## Features

- **Request Management**: Create and track radio equipment requests
- **Workflow Management**: Multi-stage approval process (District Review → DevOps Costing → Commander Approval → Manager Approval)
- **User Management**: Role-based access control (Admin, Manager, User)
- **Document Management**: Upload and version control for ED4281 forms and supporting documents
- **Email Notifications**: Automated notifications for request assignments (configurable)
- **Audit Trail**: Complete history tracking of all status changes and actions
- **Reporting**: Export request data to CSV format

## Radio Types Supported

- **Mobile**: V, V/7, V/U/7 frequencies
- **Portable**: V, V/7, V/U/7 frequencies  
- **Desk Mount**: V, U, 7 frequencies

## Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager

### Quick Setup (Windows)

1. Run the installer:
   ```bash
   python installer.py
   ```

2. Follow the prompts to select installation directory

3. Run the application:
   ```bash
   run.bat
   ```

### Manual Setup (Linux/Mac)

1. Create virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python app.py
   ```

## Usage

1. Access the application at: http://localhost:5000
2. Default login credentials:
   - Username: `admin`
   - Password: `admin`

3. **First Steps**:
   - Change the default admin password
   - Create user accounts for your team
   - Configure email settings if needed (edit EMAIL_CONFIG in app.py)

## Configuration

### Email Notifications

To enable email notifications, edit the `EMAIL_CONFIG` dictionary in `app.py`:

```python
EMAIL_CONFIG = {
    'enabled': True,  # Set to True to enable
    'smtp_server': 'smtp.office365.com',
    'smtp_port': 587,
    'smtp_username': 'your-email@domain.com',
    'smtp_password': 'your-password',
    'from_email': 'radiotracker@domain.com',
    'domain': 'domain.com'  # Used for generating employee emails
}
```

## Project Structure

```
ED4281/
├── app.py              # Main Flask application
├── installer.py        # Automated installer script
├── requirements.txt    # Python dependencies
├── run.bat            # Windows launcher
├── setup.bat          # Windows setup script
├── database.db        # SQLite database (created on first run)
└── uploads/           # Document storage directory
```

## Database Schema

- **users**: User accounts and roles
- **requests**: Radio request records
- **documents**: Uploaded files and versions
- **approvals**: Approval history
- **status_history**: Complete audit trail
- **email_log**: Email notification tracking

## Security Notes

- Change the default admin password immediately
- Update the `app.secret_key` in production
- Consider using environment variables for sensitive configuration
- Implement HTTPS in production environments

## License

This project is for internal use only.

## Support

For issues or questions, please contact the development team.