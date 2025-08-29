# 📄 Product Requirements Document (PRD)

## 🚀 Project Camp Backend

### 1. 🌟 Product Overview

**Product Name:** Project Camp Backend  
**Version:** 1.0.0  
**Product Type:** Backend API for Project Management System

Project Camp Backend is a robust RESTful API service crafted to empower **collaborative project management**. It helps teams efficiently **organize projects**, **manage tasks & subtasks**, **maintain project notes**, and ensure **secure user authentication** with **role-based access control**.

---

### 2. 🎯 Target Users

- 👑 **Project Administrators** – Create & manage projects, assign roles, and oversee activities
- 🛠️ **Project Admins** – Manage tasks and content within assigned projects
- 👥 **Team Members** – View projects, update task status, and access information

---

### 3. 🔑 Core Features

#### 3.1 🔐 User Authentication & Authorization

- ✅ **User Registration** with email verification
- 🔑 **Secure Login** with JWT tokens
- 🔄 **Password Management** (change, reset, recovery)
- 📧 **Email Verification** for account security
- ♻️ **Token Refresh** mechanism
- 🛡️ **Role-Based Access Control** (Admin, Project Admin, Member)

#### 3.2 📂 Project Management

- ➕ Create, view, update, and delete projects
- 👥 Member count tracking per project
- 🔒 Admin-exclusive actions for updates & deletion

#### 3.3 👥 Team Member Management

- 📩 Invite members via email
- 👨‍👩‍👧 View all team members
- 🎚️ Update member roles (Admin only)
- ❌ Remove members (Admin only)

#### 3.4 ✅ Task Management

- 📝 Create tasks with title, description & assignee
- 📋 View all tasks in a project
- 🔍 Task details with attachments
- ✏️ Update & assign tasks
- 📌 Status tracking: **Todo → In Progress → Done**

#### 3.5 🔄 Subtask Management

- ➕ Create subtasks under tasks
- 🖊️ Update subtask details & completion
- ✅ Members can mark subtasks as complete
- ❌ Delete subtasks (Admin/Project Admin only)

#### 3.6 🗒️ Project Notes

- 📝 Add notes (Admin only)
- 📖 View & update notes
- ❌ Delete notes (Admin only)

#### 3.7 🩺 System Health

- 🌐 API health check endpoint

---

### 4. ⚙️ Technical Specifications

#### 4.1 🛣️ API Endpoints Structure

- **Auth Routes** – Registration, login, tokens, email verification, password reset
- **Project Routes** – Create, update, delete, members management
- **Task Routes** – Manage tasks, subtasks, and attachments
- **Note Routes** – Create, update, delete, and view notes
- **Health Check** – System monitoring

#### 4.2 🔒 Permission Matrix

| Feature                    | Admin | Project Admin | Member |
| -------------------------- | ----- | ------------- | ------ |
| Create Project             | ✅    | ❌            | ❌     |
| Update/Delete Project      | ✅    | ❌            | ❌     |
| Manage Members             | ✅    | ❌            | ❌     |
| Create/Update/Delete Tasks | ✅    | ✅            | ❌     |
| View Tasks                 | ✅    | ✅            | ✅     |
| Update Subtask Status      | ✅    | ✅            | ✅     |
| Create/Delete Subtasks     | ✅    | ✅            | ❌     |
| Create/Update/Delete Notes | ✅    | ❌            | ❌     |
| View Notes                 | ✅    | ✅            | ✅     |

#### 4.3 🗂️ Data Models

- **User Roles:** `admin`, `project_admin`, `member`
- **Task Status:** `todo`, `in_progress`, `done`

---

### 5. 🔐 Security Features

- JWT authentication with refresh tokens
- Role-based middleware
- Input validation on endpoints
- Email verification & password reset security
- Secure file uploads (Multer)
- CORS configuration

---

### 6. 📁 File Management

- 📎 Multiple file attachments on tasks
- 📂 Storage in `public/images`
- 🏷️ Metadata tracking (URL, type, size)
- 🔒 Secure upload handling

---

### 7. 🏆 Success Criteria

- ✅ Secure authentication & authorization
- ✅ End-to-end project lifecycle management
- ✅ Hierarchical task & subtask system
- ✅ Role-based access control
- ✅ File attachments for collaboration
- ✅ Email notifications for verification & resets
- ✅ Well-documented API endpoints

---
