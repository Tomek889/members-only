# Members-Only

A simple web app that allows users to sign up, log in, and post messages. Only authenticated members can see authors’ names, and admins have the ability to delete messages. Includes role-based access control with three membership levels: basic, member, and admin.

## Features

- User authentication (sign up, log in, log out)
- Role-based membership: basic, member, admin
- Members see author names; basic users see "Author: hidden"
- Admins can delete messages
- Secure password hashing with bcrypt
- Passcode-protected membership upgrades (join club and become admin)
