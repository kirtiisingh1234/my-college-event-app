# CampusFest - College Event Management System

Stack: Flask (backend) + SQLite (database) + HTML/CSS/JS (frontend, pink theme)

## Run
```
pip install flask
python app.py
```
Open http://127.0.0.1:5000

## Default admin
Email: admin@college.edu | Password: admin123

## Structure
```
college-events/
  app.py            # REST API, auth, DB (creates events.db automatically)
  static/index.html # Single-page frontend
```

## Features
- Roles: student, organizer, admin (role-based access)
- Register / login / logout with hashed passwords
- Organizers create and delete events; admin approves or rejects
- Venue double-booking prevention
- Search and category filter
- Register / unregister with capacity limit and duplicate check
- My Registrations page
- Participant list as CSV download
- Admin dashboard with stats and registrations-per-event bars

## Ideas to extend
QR tickets, email notifications, certificates, feedback and ratings, calendar view, waitlist.
