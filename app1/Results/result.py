#  Result Page
# API Endpoints:
                # GET /search: Search for trips based on filters like destination, price, duration, etc.
# Database Models:
# Same as the models mentioned above for trips and locations.


import smtplib
from email.message import EmailMessage

def send_test_email():
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        from_mail = "amanmit38481490@gmail.com"
        app_password = "hghx fquo fvet lnke"
        server.login(from_mail, app_password)

        msg = EmailMessage()
        msg["Subject"] = "Test Email"
        msg["From"] = from_mail
        msg["To"] = "recipient-email@example.com"
        msg.set_content("This is a test email.")

        server.send_message(msg)
        print("Test email sent successfully!")
    except Exception as e:
        print(f"Failed to send test email: {e}")
    finally:
        server.quit()

send_test_email()
