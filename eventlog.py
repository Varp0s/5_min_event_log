import win32evtlog
import win32security
import time
import smtplib

# Şüpheli giriş etkinliği için arama süresi 5 dk
search_time = int(time.time() - 300)

# Etkinlik günlüğünde arama yapma
hand = win32evtlog.OpenEventLog(None, "Security")
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
events = win32evtlog.ReadEventLog(hand, flags, 0)

# Şüpheli etkinlikleri arama
while events:
    event = events[0]
    if event.TimeGenerated >= search_time:
        if event.EventType == win32evtlog.EVENTLOG_AUDIT_FAILURE:
            sid = event.Sid
            user_name, domain_name, type = win32security.LookupAccountSid(None, sid)
            if event.EventID == 4625 and event.LogonType == 3:
                #bildirim gönderme kodu
                recipients = ["email1@example.com", "email2@example.com"]
                sender = "siem@example.com"
                message = "Subject: Şüpheli Giriş Bildirimi\n\nŞüpheli giriş tespit edildi!"

                smtp_server = "mail.example.com"
                smtp_port = 587
                smtp_username = "siem@example.com"
                smtp_password = "password"

                # SMTP sunucusuna bağlanma ve e-posta gönderme
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(smtp_username, smtp_password)
                server.sendmail(sender, recipients, message)
                server.quit()
                events = win32evtlog.ReadEventLog(hand, flags, 0)
win32evtlog.CloseEventLog(hand)